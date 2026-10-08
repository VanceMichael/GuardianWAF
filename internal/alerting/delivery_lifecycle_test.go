package alerting

// Delivery lifecycle regressions: cooldown is committed ONLY by successful
// delivery; in-flight ownership prevents concurrent duplicate sends; failed,
// dropped (pool full / closing) and panicked attempts release ownership so a
// later matching event retries immediately; delete/rebuild isolates old
// goroutines from new targets; the same event settles independently per
// target.

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// waitFor polls cond until it returns true or timeout elapses.
func waitFor(t *testing.T, cond func() bool, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("condition not met within %s", timeout)
}

// A failed delivery must not commit a cooldown; the next matching event for
// the same (target, event key) is delivered immediately.
func TestFailedWebhookReleaseAllowsImmediateRetry(t *testing.T) {
	var mu sync.Mutex
	attempts := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		attempts++
		n := attempts
		mu.Unlock()
		if n == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	m := NewManager([]WebhookTarget{{
		Name: "retry", URL: srv.URL, Type: "generic", Events: []string{"all"}, Cooldown: time.Hour,
	}})

	m.HandleEvent(testEvent(engine.ActionBlock, 80, "1.2.3.4"))
	waitFor(t, func() bool { return m.GetStats().Failed == 1 }, time.Second)

	// Same event key again — the failed attempt must not suppress it.
	m.HandleEvent(testEvent(engine.ActionBlock, 80, "1.2.3.4"))
	waitFor(t, func() bool { return m.GetStats().Sent == 1 }, time.Second)

	mu.Lock()
	if attempts != 2 {
		t.Fatalf("expected 2 delivery attempts, got %d", attempts)
	}
	mu.Unlock()
	if got := m.GetStats().CooldownSuppressed; got != 0 {
		t.Fatalf("CooldownSuppressed = %d, want 0 (failures must not commit cooldown)", got)
	}
}

// A successful delivery commits the target cooldown: matching events are
// suppressed and counted, a different key still delivers.
func TestSuccessCommitsCooldownWithCounter(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	m := NewManager([]WebhookTarget{{
		Name: "cd", URL: srv.URL, Type: "generic", Events: []string{"all"}, Cooldown: time.Hour,
	}})

	m.HandleEvent(testEvent(engine.ActionBlock, 80, "1.2.3.4"))
	waitFor(t, func() bool { return m.GetStats().Sent == 1 }, time.Second)

	m.HandleEvent(testEvent(engine.ActionBlock, 80, "1.2.3.4"))
	waitFor(t, func() bool { return m.GetStats().CooldownSuppressed == 1 }, time.Second)
	if hits.Load() != 1 {
		t.Fatalf("expected 1 delivery after cooldown commit, got %d", hits.Load())
	}

	m.HandleEvent(testEvent(engine.ActionBlock, 80, "5.6.7.8"))
	waitFor(t, func() bool { return m.GetStats().Sent == 2 }, time.Second)
	if hits.Load() != 2 {
		t.Fatalf("expected 2 deliveries for a different key, got %d", hits.Load())
	}
}

// Concurrent events for the same (target, event key) result in exactly one
// in-flight delivery; the rest are de-duplicated by ownership.
func TestConcurrentEventsSingleInFlightDelivery(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		close(started)
		<-release
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	m := NewManager([]WebhookTarget{{
		Name: "concurrent", URL: srv.URL, Type: "generic", Events: []string{"all"}, Cooldown: time.Hour,
	}})

	var callers sync.WaitGroup
	for i := 0; i < 20; i++ {
		callers.Add(1)
		go func() {
			defer callers.Done()
			m.HandleEvent(testEvent(engine.ActionBlock, 80, "1.2.3.4"))
		}()
	}

	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("the winning delivery never started")
	}
	waitFor(t, func() bool { return m.GetStats().InflightSuppressed == 19 }, 2*time.Second)
	if hits.Load() != 1 {
		t.Fatalf("concurrent events produced %d deliveries, want exactly 1", hits.Load())
	}

	close(release)
	callers.Wait()
	waitFor(t, func() bool { return m.GetStats().Sent == 1 }, time.Second)
}

// When the dispatch pool is full, the unenqueued attempt is dropped+failed
// but its claim is released: after a slot frees, the same key delivers.
func TestDispatchFullReleasesClaimForRetry(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	m := NewManager([]WebhookTarget{{
		Name: "full", URL: srv.URL, Type: "generic", Events: []string{"all"},
	}})

	for i := 0; i < maxAlertDispatchConcurrency; i++ {
		m.sem <- struct{}{}
	}

	m.HandleEvent(testEvent(engine.ActionBlock, 80, "1.2.3.4"))
	s := m.GetStats()
	if s.Dropped != 1 || s.Failed != 1 {
		t.Fatalf("Dropped=%d Failed=%d, want 1/1 for a full pool", s.Dropped, s.Failed)
	}

	for i := 0; i < maxAlertDispatchConcurrency; i++ {
		<-m.sem
	}

	// Same key again — would return claimInflight forever had the dropped
	// attempt not released ownership.
	m.HandleEvent(testEvent(engine.ActionBlock, 80, "1.2.3.4"))
	waitFor(t, func() bool { return m.GetStats().Sent == 1 }, time.Second)
	if hits.Load() != 1 {
		t.Fatalf("expected 1 delivery after pool drained, got %d", hits.Load())
	}
}

// Deleting and rebuilding a target under the same name must not let the old
// goroutine's late result settle against the new target.
func TestTargetDeleteRebuildNoSettlePollution(t *testing.T) {
	oldStarted := make(chan struct{})
	releaseOld := make(chan struct{})
	oldSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(oldStarted)
		<-releaseOld
		w.WriteHeader(http.StatusOK)
	}))
	defer oldSrv.Close()

	var newHits atomic.Int64
	newSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		newHits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer newSrv.Close()

	m := NewManager([]WebhookTarget{{
		Name: "g", URL: oldSrv.URL, Type: "generic", Events: []string{"all"}, Cooldown: time.Hour,
	}})

	m.HandleEvent(testEvent(engine.ActionBlock, 80, "1.2.3.4"))
	select {
	case <-oldStarted:
	case <-time.After(time.Second):
		t.Fatal("old delivery never started")
	}

	oldFlights := m.webhooks[0].flights
	if !m.RemoveWebhook("g") {
		t.Fatal("RemoveWebhook returned false")
	}
	// Simulate config reload rebuilding the same target name against the
	// new endpoint (AddWebhook rejects httptest URLs regardless of the
	// test-mode flag; the real reload path appends directly).
	m.mu.Lock()
	m.webhooks = append(m.webhooks, newWebhookEntry(WebhookTarget{
		Name: "g", URL: newSrv.URL, Type: "generic", Events: []string{"all"}, Cooldown: time.Hour,
	}))
	newFlights := m.webhooks[0].flights
	m.mu.Unlock()

	close(releaseOld)
	waitFor(t, func() bool {
		oldFlights.mu.Lock()
		defer oldFlights.mu.Unlock()
		return len(oldFlights.inflight) == 0
	}, time.Second)

	// The new target must carry no state from the old goroutine.
	if n := countEntries(newFlights.lastFire); n != 0 {
		t.Fatalf("new target lastFire polluted by old goroutine: %d entries", n)
	}
	m.HandleEvent(testEvent(engine.ActionBlock, 80, "1.2.3.4"))
	waitFor(t, func() bool { return newHits.Load() == 1 }, time.Second)
	if got := m.GetStats().CooldownSuppressed; got != 0 {
		t.Fatalf("CooldownSuppressed = %d, want 0 — old settle leaked into the rebuilt target", got)
	}
}

// The same event must settle independently per target: one target's failure
// is retried on the next event while the successful target is cooldown
// suppressed.
func TestSameEventDifferentTargetsSettleIndependently(t *testing.T) {
	var failHits, okHits atomic.Int64
	failSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		failHits.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer failSrv.Close()
	okSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		okHits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer okSrv.Close()

	m := NewManager([]WebhookTarget{
		{Name: "fails", URL: failSrv.URL, Type: "generic", Events: []string{"all"}, Cooldown: time.Hour},
		{Name: "works", URL: okSrv.URL, Type: "generic", Events: []string{"all"}, Cooldown: time.Hour},
	})

	m.HandleEvent(testEvent(engine.ActionBlock, 80, "1.2.3.4"))
	waitFor(t, func() bool {
		st := m.GetStats()
		return st.Failed == 1 && st.Sent == 1
	}, time.Second)

	m.HandleEvent(testEvent(engine.ActionBlock, 80, "1.2.3.4"))
	waitFor(t, func() bool {
		st := m.GetStats()
		return st.Failed == 2 && st.CooldownSuppressed == 1
	}, time.Second)

	if failHits.Load() != 2 {
		t.Fatalf("failing target saw %d requests, want 2 (retry after release)", failHits.Load())
	}
	if okHits.Load() != 1 {
		t.Fatalf("successful target saw %d requests, want 1 (cooldown suppressed)", okHits.Load())
	}
}

// SMTP failures release ownership just like webhook failures: two sequential
// failed attempts for the same key both run and neither is in-flight
// suppressed.
func TestEmailFailureReleasesOwnership(t *testing.T) {
	ResetEmailStats()
	defer ResetEmailStats()

	m := NewManagerWithEmail(nil, []config.EmailConfig{{
		Name: "mail-fail", SMTPHost: "127.0.0.1", SMTPPort: 1,
		From: "waf@example.test", To: []string{"ops@example.test"},
		Events: []string{"all"},
	}})
	m.SetLogger(func(level, msg string) {})

	m.HandleEvent(testEvent(engine.ActionBlock, 80, "1.2.3.4"))
	waitFor(t, func() bool { return m.GetStats().Failed == 1 }, time.Second)

	m.HandleEvent(testEvent(engine.ActionBlock, 80, "1.2.3.4"))
	waitFor(t, func() bool { return m.GetStats().Failed == 2 }, time.Second)

	if got := m.GetStats().InflightSuppressed; got != 0 {
		t.Fatalf("InflightSuppressed = %d, want 0 — failed email attempt must release ownership", got)
	}
	if got := GetEmailStats().Failed; got != 2 {
		t.Fatalf("email failed = %d, want 2", got)
	}
}

// The in-flight gauge is 1 while a delivery is running and back to 0 once it
// settles.
func TestInFlightGaugeLifecycle(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(started)
		<-release
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	m := NewManager([]WebhookTarget{{
		Name: "gauge", URL: srv.URL, Type: "generic", Events: []string{"all"},
	}})

	m.HandleEvent(testEvent(engine.ActionBlock, 80, "1.2.3.4"))
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("delivery never started")
	}
	if got := m.GetStats().InFlight; got != 1 {
		t.Fatalf("InFlight = %d during delivery, want 1", got)
	}

	close(release)
	waitFor(t, func() bool { return m.GetStats().InFlight == 0 }, time.Second)
}
