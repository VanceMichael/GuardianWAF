package docker

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var dockerLog = slog.Default().With(slog.String("component", "docker/watcher"))

// Watcher monitors Docker for container changes and triggers proxy rebuilds.
type Watcher struct {
	client       *Client
	labelPrefix  string
	network      string
	pollInterval time.Duration

	// syncMu serializes snapshot refreshes (and their notifications) so a
	// burst of events or an event overlapping a poll tick cannot interleave
	// two list/inspect rounds or publish them out of order.
	syncMu sync.Mutex

	mu       sync.RWMutex
	services map[string]*DiscoveredService // containerID → service — the last
	// complete, valid Docker snapshot. Only sync() may replace it, and only
	// with the parsed result of a fully successful list+inspect round.
	stopCh chan struct{}
	wg     sync.WaitGroup

	callbackMu sync.RWMutex
	onChange   func()
	logFn      func(level, msg string)

	running              atomic.Bool
	eventStreamConnected atomic.Bool
	lastSyncOK           atomic.Bool
	syncFailures         atomic.Int64
	lastAttempt          atomic.Int64 // unix nano of last sync attempt
	lastSuccess          atomic.Int64 // unix nano of last successful full sync
	lastError            atomic.Value // string: last sync error
}

// WatcherStats contains bounded operational state for Docker auto-discovery.
type WatcherStats struct {
	Running              bool      `json:"running"`
	EventStreamConnected bool      `json:"event_stream_connected"`
	LastSyncOK           bool      `json:"last_sync_ok"`
	SyncFailures         int64     `json:"sync_failures"`
	ServiceCount         int       `json:"service_count"`
	LastAttempt          time.Time `json:"last_attempt,omitempty"`
	LastSuccess          time.Time `json:"last_success,omitempty"`
	LastError            string    `json:"last_error,omitempty"`
	// Converged reports that the running state mirrors the latest complete
	// snapshot. Stale reports that the most recent sync failed while an
	// earlier snapshot remains in use — traffic still flows against the old
	// routes/targets until a later sync succeeds.
	Converged bool `json:"converged"`
	Stale     bool `json:"stale"`
}

// NewWatcher creates a Docker container watcher.
func NewWatcher(client *Client, labelPrefix, network string, pollInterval time.Duration) *Watcher {
	if labelPrefix == "" {
		labelPrefix = defaultLabelPrefix
	}
	if network == "" {
		network = "bridge"
	}
	if pollInterval <= 0 {
		pollInterval = 5 * time.Second
	}
	return &Watcher{
		client:       client,
		labelPrefix:  labelPrefix,
		network:      network,
		pollInterval: pollInterval,
		services:     make(map[string]*DiscoveredService),
		stopCh:       make(chan struct{}),
		logFn:        func(_, _ string) {},
	}
}

// SetOnChange sets the callback for when services change.
func (w *Watcher) SetOnChange(fn func()) {
	w.callbackMu.Lock()
	w.onChange = fn
	w.callbackMu.Unlock()
}

// SetLogger sets the log function.
func (w *Watcher) SetLogger(fn func(level, msg string)) {
	w.callbackMu.Lock()
	w.logFn = fn
	w.callbackMu.Unlock()
}

// Start begins watching Docker for container changes.
// It does an initial sync, then tries event streaming with poll fallback.
func (w *Watcher) Start() {
	w.running.Store(true)
	w.safeLog("WARN", "Docker socket is mounted — if GuardianWAF is compromised, attackers can read all container configs, env vars, and network topology. Prefer a read-only socket proxy or restrict access to the daemon.")

	// Initial snapshot — published immediately so discovered routes/targets
	// are in force from startup rather than waiting for the first event or
	// an event-stream failure. refresh() notifies only when a complete
	// snapshot differs from the empty starting state.
	w.refresh("startup")

	w.wg.Add(1)
	go w.loop()

	// Periodic full-snapshot sync running alongside event streaming: a
	// container network change (or any event this filtered stream does not
	// cover) converges within one poll interval even while the stream is
	// healthy. Unchanged rounds are cheap — refresh() suppresses rebuilds.
	w.wg.Add(1)
	go w.runPeriodicSync()
}

// runPeriodicSync refreshes the snapshot on every poll interval in both
// event-driven and fallback modes.
func (w *Watcher) runPeriodicSync() {
	defer w.wg.Done()

	ticker := time.NewTicker(w.pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			w.refresh("periodic")
		case <-w.stopCh:
			return
		}
	}
}

// refresh runs one snapshot sync and, when the snapshot changed, publishes
// the change. Every discovery trigger — initial sync, Docker container
// events, poll ticks — funnels through here, so every update of running
// state derives from the same last complete, valid Docker snapshot. Failed
// or unchanged rounds never reach the callback.
func (w *Watcher) refresh(reason string) {
	w.syncMu.Lock()
	defer w.syncMu.Unlock()
	if w.sync() {
		w.notifyChange()
	}
}

// Stop gracefully stops the watcher.
func (w *Watcher) Stop() {
	_ = w.StopWithContext(context.Background())
}

// StopWithContext gracefully stops the watcher without waiting past ctx.
func (w *Watcher) StopWithContext(ctx context.Context) error {
	select {
	case <-w.stopCh:
	default:
		close(w.stopCh)
	}
	done := make(chan struct{})
	go func() {
		w.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		w.running.Store(false)
		w.eventStreamConnected.Store(false)
		return nil
	case <-ctx.Done():
		w.eventStreamConnected.Store(false)
		return ctx.Err()
	}
}

// Services returns the current discovered services.
func (w *Watcher) Services() []DiscoveredService {
	w.mu.RLock()
	defer w.mu.RUnlock()

	result := make([]DiscoveredService, 0, len(w.services))
	for _, svc := range w.services {
		result = append(result, *svc)
	}
	return result
}

// ServiceCount returns the number of discovered services.
func (w *Watcher) ServiceCount() int {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return len(w.services)
}

// Stats returns bounded operational state for metrics and dashboards.
func (w *Watcher) Stats() WatcherStats {
	count := w.ServiceCount()
	lastOK := w.lastSyncOK.Load()
	lastErr, _ := w.lastError.Load().(string)

	stats := WatcherStats{
		Running:              w.running.Load(),
		EventStreamConnected: w.eventStreamConnected.Load(),
		LastSyncOK:           lastOK,
		SyncFailures:         w.syncFailures.Load(),
		ServiceCount:         count,
		LastError:            lastErr,
		Converged:            lastOK,
		Stale:                !lastOK && count > 0,
	}
	if v := w.lastAttempt.Load(); v > 0 {
		stats.LastAttempt = time.Unix(0, v)
	}
	if v := w.lastSuccess.Load(); v > 0 {
		stats.LastSuccess = time.Unix(0, v)
	}
	return stats
}

// loop is the main watcher loop that tries event streaming with poll fallback.
func (w *Watcher) loop() {
	defer w.wg.Done()
	defer func() {
		if r := recover(); r != nil {
			select {
			case <-w.stopCh:
				// Shutting down — do not restart; Stop() owns the final state.
				dockerLog.Error("docker watcher panic recovered during shutdown", "panic", r)
			default:
				// Restart the loop (same pattern as internal/ai/analyzer.go) so a
				// panicking callback cannot kill discovery for the process lifetime.
				// Sleep first to avoid a hot restart spin on a persistently panicking callback.
				dockerLog.Error("docker watcher panic recovered — restarting watcher loop", "panic", r)
				time.Sleep(time.Second)
				w.wg.Add(1)
				go w.loop()
			}
		}
	}()

	for {
		select {
		case <-w.stopCh:
			return
		default:
		}

		// Try event-driven mode first
		err := w.streamEvents()
		if err != nil {
			w.safeLog("warn", "Docker event stream disconnected: "+err.Error()+", falling back to polling")
		}

		// If streaming fails, fall back to polling
		w.pollLoop()
	}
}

// streamEvents connects to Docker event stream.
// Returns when stream disconnects or stop is requested.
func (w *Watcher) streamEvents() error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w.eventStreamConnected.Store(true)
	defer w.eventStreamConnected.Store(false)

	// Stop on shutdown
	go func() {
		select {
		case <-w.stopCh:
			cancel()
		case <-ctx.Done():
		}
	}()

	eventCh := make(chan Event, 32)
	errCh := make(chan error, 1)

	go func() {
		defer func() {
			if r := recover(); r != nil {
				errCh <- fmt.Errorf("event stream panic: %v", r)
			}
		}()
		errCh <- w.client.StreamEvents(ctx, w.labelPrefix, eventCh)
	}()

	w.safeLog("info", "Docker event stream connected")

	for {
		select {
		case event := <-eventCh:
			w.handleEvent(event)

		case err := <-errCh:
			return err

		case <-w.stopCh:
			cancel()
			return nil
		}
	}
}

// pollLoop holds the main loop goroutine after the event stream disconnects.
// Periodic convergence is supplied by the background ticker started in
// Start (which keeps running in this mode), so this only blocks until
// shutdown — the fallback behavior is otherwise identical to before.
func (w *Watcher) pollLoop() {
	<-w.stopCh
}

// handleEvent processes a single Docker event. Container lifecycle events
// never mutate the service set directly: each one re-reads a complete
// snapshot. This makes stop/destroy/remove deterministic (the container is
// absent from a successful list) and safe across restarts (die followed by
// start: a failed resync keeps the old snapshot instead of leaving the
// container half-deleted).
func (w *Watcher) handleEvent(event Event) {
	switch event.Action {
	case "start", "stop", "die", "destroy":
		name := sanitizeLogValue(event.Actor.Attributes["name"])
		w.safeLog("info", "Docker: container "+event.Action+": "+name+" — resyncing snapshot")
		w.refresh("event:" + event.Action)
	}
}

// sync fetches the current container list and atomically replaces the
// services map only with a complete snapshot that actually differs.
// Returns true when the snapshot changed and was applied.
func (w *Watcher) sync() bool {
	w.lastAttempt.Store(time.Now().UnixNano())

	containers, err := w.client.ListContainers(w.labelPrefix)
	if err != nil {
		w.recordSyncFailure(err)
		return false
	}

	wasStale := !w.lastSyncOK.Load()
	w.lastSyncOK.Store(true)
	w.lastSuccess.Store(time.Now().UnixNano())
	w.lastError.Store("")

	services := DiscoverFromContainers(containers, w.labelPrefix, w.network)

	w.mu.Lock()
	defer w.mu.Unlock()

	// Full-field comparison: the previous check compared only the target URL
	// and host, so label changes to path, port, weight, load-balancer,
	// strip-prefix, TLS or health-check parameters never converged until an
	// unrelated change happened. Every field of DiscoveredService is
	// comparable and every derived value (network IP, port) is now chosen
	// deterministically, so identical rounds compare equal.
	if !snapshotChanged(w.services, services) {
		// A successful read of an unchanged snapshot still ends a stale
		// period: state flips to converged above without rebuilding.
		if wasStale {
			w.safeLog("info", "Docker: sync recovered — snapshot unchanged, running state confirmed against the latest snapshot")
		}
		return false
	}

	// Replace the map wholesale only after a complete, changed snapshot —
	// failed or partial list calls never reach this point, so the previous
	// snapshot stays intact for the duration of any Docker outage.
	next := make(map[string]*DiscoveredService, len(services))
	for i := range services {
		s := services[i]
		next[s.ContainerID] = &s
	}
	w.services = next

	w.safeLog("info", "Docker: snapshot converged ("+itoa(len(services))+" services)")
	if wasStale {
		w.safeLog("info", "Docker: sync recovered after failure — running state now matches the latest snapshot")
	}
	return true
}

// snapshotChanged reports whether the next service list differs from the
// current map: different cardinality, an added/removed container ID, or any
// field change on a surviving container.
func snapshotChanged(current map[string]*DiscoveredService, next []DiscoveredService) bool {
	if len(current) != len(next) {
		return true
	}
	for i := range next {
		existing, ok := current[next[i].ContainerID]
		if !ok || *existing != next[i] {
			return true
		}
	}
	return false
}

// recordSyncFailure marks the sync failed and records the diagnostic while
// leaving the current snapshot (and therefore routes, target pools and
// health checkers) untouched. The log line states explicitly whether the
// process is serving a retained snapshot or has none.
func (w *Watcher) recordSyncFailure(err error) {
	w.lastSyncOK.Store(false)
	w.syncFailures.Add(1)
	msg := sanitizeLogValue(err.Error())
	w.lastError.Store(msg)

	retained := w.ServiceCount()
	if retained > 0 {
		w.safeLog("warn", "Docker: sync failed: "+msg+" — retaining last valid snapshot ("+itoa(retained)+" services); next sync will retry")
	} else {
		w.safeLog("warn", "Docker: sync failed: "+msg+" — no previous snapshot available; routing stays on static configuration")
	}
}

// notifyChange calls the onChange callback if set.
func (w *Watcher) notifyChange() {
	w.callbackMu.RLock()
	fn := w.onChange
	w.callbackMu.RUnlock()
	if fn != nil {
		fn()
	}
}

func (w *Watcher) safeLog(level, msg string) {
	w.callbackMu.RLock()
	fn := w.logFn
	w.callbackMu.RUnlock()
	if fn != nil {
		fn(level, msg)
	}
}

// sanitizeLogValue strips control characters (newlines, ANSI escapes) from
// external values to prevent log injection.
func sanitizeLogValue(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r == '\n' || r == '\r' || r == '\x1b' || r < 0x20 {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf) - 1
	for n > 0 {
		buf[i] = byte('0' + n%10)
		n /= 10
		i--
	}
	return string(buf[i+1:])
}
