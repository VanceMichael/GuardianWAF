// Package alerting provides webhook and email-based alert delivery for GuardianWAF.
// Sends notifications to Slack, Discord, custom HTTP endpoints, or via SMTP email when
// security events occur (blocks, challenges, high-score events).
package alerting

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"log/slog"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/engine"
)

var webhookLog = slog.Default().With(slog.String("component", "alerting/webhook"))

// WebhookTarget defines a single webhook target for the alerting manager.
type WebhookTarget struct {
	Name     string
	URL      string
	Type     string   // "slack", "discord", "generic", "pagerduty"
	Events   []string // "block", "challenge", "log", "all"
	MinScore int
	Cooldown time.Duration
	Headers  map[string]string
}

// Alert is the payload sent to webhooks.
type Alert struct {
	Timestamp string   `json:"timestamp"`
	EventID   string   `json:"event_id"`
	ClientIP  string   `json:"client_ip"`
	Method    string   `json:"method"`
	Path      string   `json:"path"`
	Action    string   `json:"action"`
	Score     int      `json:"score"`
	Findings  []string `json:"findings"`
	UserAgent string   `json:"user_agent,omitempty"`
}

// Manager manages webhook and email delivery for security events.
type Manager struct {
	mu           sync.RWMutex
	webhooks     []webhook
	emailTargets []*EmailTarget
	httpClient   *http.Client
	logFn        atomic.Value // func(level, msg string)

	// Semaphore to limit concurrent webhook/email goroutines
	sem chan struct{}
	wg  sync.WaitGroup

	// dispatchMu serializes goroutine registration with shutdown so CloseWithContext
	// cannot race with new WaitGroup.Add calls.
	dispatchMu sync.Mutex
	closing    atomic.Bool

	// Stats
	sent               atomic.Int64
	failed             atomic.Int64
	dropped            atomic.Int64
	cooldownSuppressed atomic.Int64
	inflightSuppressed atomic.Int64
	inFlight           atomic.Int64
}

const maxAlertDispatchConcurrency = 32

type webhook struct {
	config   WebhookTarget
	cooldown time.Duration
	lastFire *sync.Map // IP → cooldown timestamp of last SUCCESSFUL delivery
	flights  *flightState
}

// newWebhookEntry builds a webhook target and its private delivery-lifecycle
// state. The flightState is never shared with another target, so a target
// removed and later re-added under the same name gets fresh state that old
// goroutines cannot reach.
func newWebhookEntry(t WebhookTarget) webhook {
	cd := t.Cooldown
	if cd <= 0 {
		cd = 30 * time.Second
	}
	lf := &sync.Map{}
	return webhook{config: t, cooldown: cd, lastFire: lf, flights: newFlightState(cd, lf)}
}

// Stats holds alerting statistics.
type Stats struct {
	Sent               int64      `json:"sent"`
	Failed             int64      `json:"failed"`
	Dropped            int64      `json:"dropped"`
	CooldownSuppressed int64      `json:"cooldown_suppressed"`
	InflightSuppressed int64      `json:"inflight_suppressed"`
	InFlight           int64      `json:"in_flight"`
	WebhookCount       int        `json:"webhook_count"`
	EmailCount         int        `json:"email_count"`
	MaxDispatch        int        `json:"max_dispatch"`
	Email              EmailStats `json:"email,omitempty"`
}

// NewManager creates an alerting manager with the given webhook targets.
func NewManager(targets []WebhookTarget) *Manager {
	m := &Manager{
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				DialContext:           webhookSSRFDialContext(),
				IdleConnTimeout:       90 * time.Second,
				TLSHandshakeTimeout:   10 * time.Second,
				ResponseHeaderTimeout: 30 * time.Second,
				ExpectContinueTimeout: 1 * time.Second,
			},
			CheckRedirect: func(req *http.Request, _ []*http.Request) error {
				if allowWebhookPrivate.Load() {
					return nil
				}
				if err := ValidateWebhookURL(req.URL.String()); err != nil {
					return fmt.Errorf("redirect URL rejected: %w", err)
				}
				return nil
			},
		},
		sem: make(chan struct{}, maxAlertDispatchConcurrency),
	}

	for _, t := range targets {
		// Validate webhook URL — reject non-HTTPS and private IPs (skip in test mode)
		if !allowWebhookPrivate.Load() {
			if err := ValidateWebhookURL(t.URL); err != nil {
				webhookLog.Warn("webhook rejected", "name", t.Name, "err", err)
				continue
			}
		}
		m.webhooks = append(m.webhooks, newWebhookEntry(t))
	}

	m.logFn.Store(func(_, _ string) {})
	return m
}

// log safely calls the stored log function with comma-ok type assertion.
func (m *Manager) log(level, msg string) {
	if logFn, ok := m.logFn.Load().(func(string, string)); ok {
		logFn(level, msg)
	}
}

// NewManagerWithEmail creates an alerting manager with both webhook and email targets.
func NewManagerWithEmail(targets []WebhookTarget, emails []config.EmailConfig) *Manager {
	m := NewManager(targets)

	for _, cfg := range emails {
		if cfg.SMTPHost != "" && len(cfg.To) > 0 {
			m.emailTargets = append(m.emailTargets, NewEmailTarget(cfg))
		}
	}

	return m
}

// SetLogger sets the log callback.
func (m *Manager) SetLogger(fn func(level, msg string)) {
	if fn == nil {
		fn = func(_, _ string) {}
	}
	m.logFn.Store(fn)
}

// GetStats returns alerting statistics.
func (m *Manager) GetStats() Stats {
	m.mu.RLock()
	wc := len(m.webhooks)
	ec := len(m.emailTargets)
	m.mu.RUnlock()
	return Stats{
		Sent:               m.sent.Load(),
		Failed:             m.failed.Load(),
		Dropped:            m.dropped.Load(),
		CooldownSuppressed: m.cooldownSuppressed.Load(),
		InflightSuppressed: m.inflightSuppressed.Load(),
		InFlight:           m.inFlight.Load(),
		WebhookCount:       wc,
		EmailCount:         ec,
		MaxDispatch:        cap(m.sem),
		Email:              GetEmailStats(),
	}
}

// HandleEvent processes a WAF event and fires matching webhooks and emails.
func (m *Manager) HandleEvent(event *engine.Event) {
	if event == nil || m.closing.Load() {
		return
	}

	action := event.Action.String()

	findings := make([]string, 0, len(event.Findings))
	for _, f := range event.Findings {
		findings = append(findings, fmt.Sprintf("%s: %s (score=%d)", f.DetectorName, f.Description, f.Score))
	}

	alert := Alert{
		Timestamp: event.Timestamp.Format(time.RFC3339),
		EventID:   event.ID,
		ClientIP:  event.ClientIP,
		Method:    event.Method,
		Path:      event.Path,
		Action:    action,
		Score:     event.Score,
		Findings:  findings,
		UserAgent: event.UserAgent,
	}

	// Snapshot webhooks and email targets under read lock
	m.mu.RLock()
	whooks := make([]webhook, len(m.webhooks))
	copy(whooks, m.webhooks)
	emails := make([]*EmailTarget, len(m.emailTargets))
	copy(emails, m.emailTargets)
	m.mu.RUnlock()

	// Process webhooks
	for i := range whooks {
		wh := &whooks[i]

		// Check if this webhook cares about this event type
		if !matchesEvent(wh.config.Events, action) {
			continue
		}

		// Check minimum score
		if wh.config.MinScore > 0 && event.Score < wh.config.MinScore {
			continue
		}

		// Claim in-flight ownership for this (target, event key). A cooldown
		// entry exists only after a SUCCESSFUL delivery, so failed or
		// unenqueued attempts never suppress the next matching event.
		key := event.ClientIP
		switch wh.flights.claim(key) {
		case claimCooldown:
			m.cooldownSuppressed.Add(1)
			continue
		case claimInflight:
			m.inflightSuppressed.Add(1)
			continue
		}

		// Fire async with concurrency limit. The claim settles inside the
		// goroutine (cooldown on success, release on failure/panic). If the
		// attempt is not accepted, release the claim synchronously so a
		// later event can retry immediately.
		cfg := wh.config
		a := alert
		flights := wh.flights
		if res := m.dispatch(func() {
			m.inFlight.Add(1)
			defer m.inFlight.Add(-1)
			if err := m.deliverWebhook(&cfg, &a); err != nil {
				flights.release(key)
				return
			}
			flights.commitSuccess(key)
		}); res != dispatchOK {
			flights.release(key)
			m.dropped.Add(1)
			m.failed.Add(1)
		}
	}

	// Process email alerts
	for _, et := range emails {
		cfg := et.config

		// Check if this email target cares about this event type
		if !matchesEvent(cfg.Events, action) {
			continue
		}

		// Check minimum score
		if cfg.MinScore > 0 && event.Score < cfg.MinScore {
			continue
		}

		// Claim in-flight ownership, same lifecycle as webhooks.
		key := event.ClientIP
		switch et.flights.claim(key) {
		case claimCooldown:
			m.cooldownSuppressed.Add(1)
			continue
		case claimInflight:
			m.inflightSuppressed.Add(1)
			continue
		}

		// Send email async (with same concurrency limit as webhooks)
		target := et
		if res := m.dispatch(func() {
			m.inFlight.Add(1)
			defer m.inFlight.Add(-1)
			if err := m.deliverEmail(target, event); err != nil {
				target.flights.release(key)
				return
			}
			target.flights.commitSuccess(key)
		}); res != dispatchOK {
			target.flights.release(key)
			m.dropped.Add(1)
			m.failed.Add(1)
		}
	}

	// Prune cooldown maps for BOTH target kinds. Expired entries are pure
	// garbage (the suppression check treats them as absent) and the count
	// cap keeps the most recent entries by timestamp. The previous prune
	// covered only webhooks — email maps grew without bound — and evicted by
	// Go's randomized map iteration order, which could drop fresh suppression
	// state while retaining expired entries. Running the prune after all
	// Stores keeps the bounded invariant at return time.
	for i := range whooks {
		if cd := whooks[i].cooldown; cd > 0 {
			pruneCooldownEntries(whooks[i].lastFire, cd, maxCooldownEntries)
		}
	}
	for i := range emails {
		if cd := emails[i].cooldown; cd > 0 {
			pruneCooldownEntries(emails[i].lastFire, cd, maxCooldownEntries)
		}
	}
}

// maxCooldownEntries caps per-target cooldown state.
const maxCooldownEntries = 1000

// pruneCooldownEntries garbage-collects a per-target cooldown map. Entries
// older than cooldown can never suppress again (the lookup treats them as
// absent), so they are always deleted; if the map still exceeds max, the
// OLDEST entries by timestamp are evicted — "keep last N" by recency, not by
// Go's randomized map iteration order, which could evict fresh suppression
// state while retaining expired entries.
func pruneCooldownEntries(m *sync.Map, cooldown time.Duration, max int) {
	type stamped struct {
		key any
		t   time.Time
	}
	now := time.Now()
	live := make([]stamped, 0, 64)
	m.Range(func(key, val any) bool {
		t, _ := val.(time.Time)
		if t.IsZero() || now.Sub(t) >= cooldown {
			m.Delete(key)
			return true
		}
		live = append(live, stamped{key: key, t: t})
		return true
	})
	if len(live) <= max {
		return
	}
	sort.Slice(live, func(i, j int) bool { return live[i].t.Before(live[j].t) })
	for _, s := range live[:len(live)-max] {
		m.Delete(s.key)
	}
}

type dispatchResult int

const (
	dispatchOK dispatchResult = iota
	dispatchClosed
	dispatchFull
)

// flightState owns the per-event-key delivery lifecycle of one target:
// exclusive in-flight ownership plus cooldown timestamps recorded only on
// success. A separate instance is constructed for every target (including a
// target re-added under an existing name), so a goroutine captured before a
// delete/rebuild can only settle against its own detached state and can
// never pollute the new target.
type flightState struct {
	cooldown time.Duration
	lastFire *sync.Map // key(string) → time.Time of last successful delivery
	mu       sync.Mutex
	inflight map[string]struct{}
}

func newFlightState(cooldown time.Duration, lastFire *sync.Map) *flightState {
	return &flightState{
		cooldown: cooldown,
		lastFire: lastFire,
		inflight: make(map[string]struct{}),
	}
}

type claimOutcome int

const (
	claimOK claimOutcome = iota
	claimCooldown
	claimInflight
)

// claim acquires exclusive delivery ownership for key. claimCooldown means
// a prior SUCCESSFUL delivery is still within the target cooldown;
// claimInflight means another attempt currently owns the key. On claimOK
// the caller must settle exactly once via commitSuccess or release.
func (f *flightState) claim(key string) claimOutcome {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.cooldown > 0 {
		if last, ok := f.lastFire.Load(key); ok {
			if t, _ := last.(time.Time); !t.IsZero() && time.Since(t) < f.cooldown {
				return claimCooldown
			}
		}
	}
	if _, ok := f.inflight[key]; ok {
		return claimInflight
	}
	f.inflight[key] = struct{}{}
	return claimOK
}

// commitSuccess settles an owned attempt as delivered: ownership is
// released and, when the target has a cooldown, the suppression timestamp
// is stored so subsequent matching events are suppressed until it expires.
func (f *flightState) commitSuccess(key string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.inflight, key)
	if f.cooldown > 0 {
		f.lastFire.Store(key, time.Now())
	}
}

// release settles an owned attempt as failed, panicked, or not enqueued:
// ownership is dropped without recording a cooldown, so the next matching
// event can claim the key and be delivered immediately.
func (f *flightState) release(key string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.inflight, key)
}

func (m *Manager) dispatch(fn func()) dispatchResult {
	m.dispatchMu.Lock()
	defer m.dispatchMu.Unlock()

	if m.closing.Load() {
		return dispatchClosed
	}

	select {
	case m.sem <- struct{}{}:
		m.wg.Add(1)
		go func() {
			defer m.wg.Done()
			defer func() { <-m.sem }()
			fn()
		}()
		return dispatchOK
	default:
		return dispatchFull
	}
}

// CloseWithContext stops accepting new alert sends and waits for in-flight
// webhook/email deliveries to finish until ctx is canceled.
func (m *Manager) CloseWithContext(ctx context.Context) error {
	m.dispatchMu.Lock()
	m.closing.Store(true)
	m.dispatchMu.Unlock()

	done := make(chan struct{})
	go func() {
		m.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		if m.httpClient != nil {
			m.httpClient.CloseIdleConnections()
		}
		return nil
	case <-ctx.Done():
		if m.httpClient != nil {
			m.httpClient.CloseIdleConnections()
		}
		return ctx.Err()
	}
}

// Close waits for in-flight alert deliveries without a timeout.
func (m *Manager) Close() error {
	return m.CloseWithContext(context.Background())
}

// deliverWebhook runs one webhook delivery and converts a panic into a
// normal error. The delivery attempt itself (m.send) records the outcome
// in sent/failed; a panic records failed here. The caller settles the
// in-flight claim based on the returned error: release on any error,
// commitSuccess only on nil.
func (m *Manager) deliverWebhook(wc *WebhookTarget, a *Alert) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("webhook goroutine panic: %v", r)
			m.failed.Add(1)
			m.log("error", err.Error())
		}
	}()
	return m.send(wc, a)
}

// deliverEmail is the SMTP equivalent of deliverWebhook: a panicking
// delivery is turned into an error (failed counted once) so the claim is
// released rather than wedged.
func (m *Manager) deliverEmail(et *EmailTarget, ev *engine.Event) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("email goroutine panic: %v", r)
			m.failed.Add(1)
			m.log("error", err.Error())
		}
	}()
	return m.SendEmail(et, ev)
}

// send delivers an alert to a webhook endpoint.
func (m *Manager) send(wc *WebhookTarget, alert *Alert) error {
	var body []byte
	var marshalErr error
	switch wc.Type {
	case "slack":
		body, marshalErr = json.Marshal(slackPayload(alert))
	case "discord":
		body, marshalErr = json.Marshal(discordPayload(alert))
	case "pagerduty":
		body, marshalErr = json.Marshal(pagerdutyPayload(alert))
	default:
		body, marshalErr = json.Marshal(alert)
	}
	if marshalErr != nil {
		m.failed.Add(1)
		return fmt.Errorf("marshal webhook payload for %s: %w", wc.Name, marshalErr)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, wc.URL, bytes.NewReader(body))
	if err != nil {
		m.failed.Add(1)
		return fmt.Errorf("build webhook request for %s: %w", wc.Name, err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "GuardianWAF-Alerting/1.0")

	// Custom headers for generic webhooks
	for k, v := range wc.Headers {
		req.Header.Set(k, v)
	}

	resp, err := m.httpClient.Do(req)
	if err != nil {
		m.failed.Add(1)
		m.log("warn", fmt.Sprintf("Webhook %s failed: %v", wc.Name, err))
		return fmt.Errorf("webhook %s delivery failed: %w", wc.Name, err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20)) // nolint:errcheck // response body drain after webhook call; error ignored

	if resp.StatusCode >= 400 {
		m.failed.Add(1)
		m.log("warn", fmt.Sprintf("Webhook %s returned %d", wc.Name, resp.StatusCode))
		return fmt.Errorf("webhook %s rejected with status %d", wc.Name, resp.StatusCode)
	}

	m.sent.Add(1)
	return nil
}

func matchesEvent(events []string, action string) bool {
	if len(events) == 0 {
		return action == "block" // default: only blocks
	}
	for _, e := range events {
		if e == action || e == "all" {
			return true
		}
	}
	return false
}

// --- Slack format ---

func slackPayload(a *Alert) map[string]any {
	color := "#ff0000"
	if a.Action == "log" {
		color = "#ffaa00"
	} else if a.Action == "challenge" {
		color = "#0066ff"
	}

	var sb strings.Builder
	for _, f := range a.Findings {
		sb.WriteString("• ")
		sb.WriteString(f)
		sb.WriteByte('\n')
	}
	findingsText := sb.String()
	if findingsText == "" {
		findingsText = "No specific findings"
	}

	return map[string]any{
		"attachments": []map[string]any{
			{
				"color": color,
				"title": fmt.Sprintf("GuardianWAF — %s", a.Action),
				"text":  fmt.Sprintf("**%s** `%s %s` from `%s` (score: %d)", a.Action, a.Method, a.Path, a.ClientIP, a.Score),
				"fields": []map[string]any{
					{"title": "IP", "value": a.ClientIP, "short": true},
					{"title": "Score", "value": fmt.Sprintf("%d", a.Score), "short": true},
					{"title": "Path", "value": fmt.Sprintf("%s %s", a.Method, a.Path), "short": false},
					{"title": "Findings", "value": findingsText, "short": false},
				},
				"footer": "GuardianWAF",
				"ts":     a.Timestamp,
			},
		},
	}
}

// --- Discord format ---

func discordPayload(a *Alert) map[string]any {
	color := 0xff0000
	if a.Action == "log" {
		color = 0xffaa00
	} else if a.Action == "challenge" {
		color = 0x0066ff
	}

	var sb strings.Builder
	for _, f := range a.Findings {
		sb.WriteString("• ")
		sb.WriteString(f)
		sb.WriteByte('\n')
	}
	findingsText := sb.String()
	if findingsText == "" {
		findingsText = "No specific findings"
	}

	return map[string]any{
		"embeds": []map[string]any{
			{
				"title":       fmt.Sprintf("GuardianWAF — %s", a.Action),
				"description": fmt.Sprintf("**%s** `%s %s` from `%s` (score: %d)", a.Action, a.Method, a.Path, a.ClientIP, a.Score),
				"color":       color,
				"fields": []map[string]any{
					{"name": "IP", "value": a.ClientIP, "inline": true},
					{"name": "Score", "value": fmt.Sprintf("%d", a.Score), "inline": true},
					{"name": "Findings", "value": findingsText, "inline": false},
				},
				"footer":    map[string]any{"text": "GuardianWAF"},
				"timestamp": a.Timestamp,
			},
		},
	}
}

// --- PagerDuty Events API v2 format ---

func pagerdutyPayload(a *Alert) map[string]any {
	// Map action to PagerDuty severity
	severity := "warning"
	switch a.Action {
	case "block":
		severity = "critical"
	case "challenge":
		severity = "warning"
	case "log":
		severity = "info"
	}

	// Create dedup key based on IP and action
	dedupKey := fmt.Sprintf("guardianwaf-%s-%s", a.ClientIP, a.Action)

	return map[string]any{
		"routing_key":  "", // Will be set via custom header or URL
		"event_action": "trigger",
		"dedup_key":    dedupKey,
		"payload": map[string]any{
			"summary":   fmt.Sprintf("GuardianWAF %s: %s %s from %s", a.Action, a.Method, a.Path, a.ClientIP),
			"severity":  severity,
			"source":    a.ClientIP,
			"timestamp": a.Timestamp,
			"component": "WAF",
			"group":     "security",
			"class":     a.Action,
			"custom_details": map[string]any{
				"event_id":   a.EventID,
				"client_ip":  a.ClientIP,
				"method":     a.Method,
				"path":       a.Path,
				"score":      a.Score,
				"action":     a.Action,
				"user_agent": a.UserAgent,
				"findings":   a.Findings,
			},
		},
	}
}

// AddWebhook adds a new webhook target at runtime.
func (m *Manager) AddWebhook(target WebhookTarget) {
	if err := ValidateWebhookURL(target.URL); err != nil {
		m.log("error", fmt.Sprintf("webhook %q rejected: %v", target.Name, err))
		return
	}
	m.mu.Lock()
	m.webhooks = append(m.webhooks, newWebhookEntry(target))
	m.mu.Unlock()
	m.log("info", fmt.Sprintf("Webhook target added: %s", target.Name))
}

// RemoveWebhook removes a webhook target by name. Returns true if found and removed.
func (m *Manager) RemoveWebhook(name string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, wh := range m.webhooks {
		if wh.config.Name == name {
			m.webhooks = append(m.webhooks[:i], m.webhooks[i+1:]...)
			m.log("info", fmt.Sprintf("Webhook target removed: %s", name))
			return true
		}
	}
	return false
}

// AddEmailTarget adds a new email target at runtime.
func (m *Manager) AddEmailTarget(cfg config.EmailConfig) {
	if cfg.SMTPHost != "" && len(cfg.To) > 0 {
		m.mu.Lock()
		m.emailTargets = append(m.emailTargets, NewEmailTarget(cfg))
		m.mu.Unlock()
		m.log("info", fmt.Sprintf("Email target added: %s", cfg.Name))
	}
}

// RemoveEmailTarget removes an email target by name. Returns true if found and removed.
func (m *Manager) RemoveEmailTarget(name string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, et := range m.emailTargets {
		if et.config.Name == name {
			m.emailTargets = append(m.emailTargets[:i], m.emailTargets[i+1:]...)
			m.log("info", fmt.Sprintf("Email target removed: %s", name))
			return true
		}
	}
	return false
}

// TestAlert sends a test alert to the specified target.
func (m *Manager) TestAlert(targetName string) error {
	testAlert := Alert{
		Timestamp: time.Now().Format(time.RFC3339),
		EventID:   "test-" + time.Now().Format("20060102150405"),
		ClientIP:  "127.0.0.1",
		Method:    "GET",
		Path:      "/test/alert",
		Action:    "block",
		Score:     75,
		Findings:  []string{"Test alert from GuardianWAF MCP"},
		UserAgent: "GuardianWAF-Test/1.0",
	}

	// Snapshot the event before locking (built from the static test alert).
	event := engine.Event{
		ID:        testAlert.EventID,
		Timestamp: time.Now(),
		ClientIP:  testAlert.ClientIP,
		Method:    testAlert.Method,
		Path:      testAlert.Path,
		Score:     testAlert.Score,
		UserAgent: testAlert.UserAgent,
	}

	// Snapshot the target under the read lock, then deliver OUTSIDE the
	// lock: a slow or dead target must not stall concurrent config writers
	// (AddWebhook/AddEmailTarget) for the whole HTTP timeout. Both branches
	// copy the config so nothing shared escapes the lock.
	m.mu.RLock()
	var webhookCfg *WebhookTarget
	var emailCfg *EmailTarget
	for i := range m.webhooks {
		if m.webhooks[i].config.Name == targetName {
			cfg := m.webhooks[i].config
			webhookCfg = &cfg
			break
		}
	}
	if webhookCfg == nil {
		for _, et := range m.emailTargets {
			if et.config.Name == targetName {
				copied := *et // value copy: no shared pointer escapes the lock
				emailCfg = &copied
				break
			}
		}
	}
	m.mu.RUnlock()

	if webhookCfg != nil {
		return m.send(webhookCfg, &testAlert)
	}
	if emailCfg != nil {
		return m.SendEmail(emailCfg, &event)
	}

	return fmt.Errorf("target %s not found", targetName)
}

// ValidateWebhookURL checks that a webhook URL uses HTTPS and does not
// point to internal/private/loopback addresses (SSRF prevention).
func ValidateWebhookURL(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("webhook URL must use HTTPS, got %q", u.Scheme)
	}
	if u.User != nil {
		return fmt.Errorf("webhook URL must not include userinfo or credentials")
	}
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("webhook URL must include a host")
	}
	return validateHostNotPrivate(host)
}

// validateHostNotPrivate checks that a hostname does not resolve to a
// private, loopback, or link-local IP address. Protects against both
// direct IP and DNS rebinding attacks.
func validateHostNotPrivate(host string) error {
	if host == "localhost" || strings.HasSuffix(host, ".internal") || strings.HasSuffix(host, ".local") {
		return fmt.Errorf("must not target localhost or internal hosts")
	}
	// Check if host is already a raw IP
	if ip := net.ParseIP(host); ip != nil {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() || ip.IsMulticast() {
			return fmt.Errorf("must not target private/loopback/link-local/multicast addresses")
		}
		return nil
	}
	// Hostname — resolve DNS and check all resulting IPs (prevents DNS rebinding)
	addrs, err := net.LookupHost(host) // #nosec G704 -- preflight DNS check is paired with webhook client's SSRF-safe DialContext and redirect validation.
	if err != nil {
		// If DNS resolution fails, allow through — will fail at connection time
		return nil
	}
	for _, addr := range addrs {
		ip := net.ParseIP(addr)
		if ip == nil {
			continue
		}
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() || ip.IsMulticast() {
			return fmt.Errorf("hostname resolves to private/loopback address %s", ip)
		}
	}
	return nil
}

// webhookSSRFDialContext returns a DialContext that validates resolved IPs at
// connection time to prevent DNS rebinding (TOCTOU) attacks on webhook targets.
// Resolves DNS, validates all IPs, then dials the validated IP directly — avoids
// a second DNS resolution by the dialer that could be rebinding-attacked.
func webhookSSRFDialContext() func(ctx context.Context, network, addr string) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		// Skip SSRF check in tests (test servers use localhost/private IPs)
		if allowWebhookPrivate.Load() {
			return dialer.DialContext(ctx, network, addr)
		}
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			host = addr
			port = ""
		}
		// Resolve DNS and validate all resulting IPs
		ips, err := net.LookupIP(host)
		if err != nil {
			return nil, fmt.Errorf("webhook SSRF: DNS lookup failed for %q: %w", host, err)
		}
		var validIP net.IP
		for _, ip := range ips {
			if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() || ip.IsMulticast() {
				continue
			}
			validIP = ip
			break
		}
		if validIP == nil {
			return nil, fmt.Errorf("webhook SSRF: no valid public IPs for %q", host)
		}
		// Dial the validated IP directly — avoids TOCTOU via DNS rebinding
		target := net.JoinHostPort(validIP.String(), port)
		return dialer.DialContext(ctx, network, target)
	}
}

// allowWebhookPrivate allows private IPs for webhook connections (testing only).
var allowWebhookPrivate atomic.Bool

// allowWebhookPrivateTargetsForTest enables private/reserved IP targets for
// package-local tests that use httptest loopback servers.
func allowWebhookPrivateTargetsForTest() {
	allowWebhookPrivate.Store(true)
}
