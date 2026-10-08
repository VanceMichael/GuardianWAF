package tenant

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// newLifecycleManager creates a store-backed manager with one seeded tenant
// owning domain "acme.test" and an API key installed via the fast legacy hash
// plus a pre-warmed verification cache. Deletion semantics do not depend on
// PBKDF2 stretching, so this keeps the tests cheap under -race; cache
// invalidation still forces the negative slow path after a real delete.
func newLifecycleManager(t *testing.T, dir string) (*Manager, *Tenant, string) {
	t.Helper()
	m := NewManagerWithStore(10, dir)
	if err := m.Init(); err != nil {
		t.Fatalf("manager init: %v", err)
	}
	t.Cleanup(m.Close)
	tnt, err := m.CreateTenant("Acme", "seed tenant", []string{"acme.test"}, nil)
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	key := "gwaf_lifecycle_" + tnt.ID
	sum := sha256.Sum256([]byte(key))
	tnt.mu.Lock()
	tnt.APIKeyHash = hex.EncodeToString(sum[:])
	tnt.mu.Unlock()
	m.cacheAPIKeyResult(fastKeyHash(key), tnt)
	return m, tnt, key
}

// seedRuntimeState populates every per-tenant runtime structure the delete
// commit is supposed to purge, plus a retained invoice.
func seedRuntimeState(t *testing.T, m *Manager, tnt *Tenant) {
	t.Helper()
	if err := m.AddTenantRule(tnt.ID, map[string]any{
		"name": "block-sqli", "priority": 10, "action": "block", "score": 80,
		"conditions": []any{map[string]any{"field": "uri", "op": "contains", "value": "OR 1=1"}},
	}); err != nil {
		t.Fatalf("add rule: %v", err)
	}
	for range 5 {
		m.RecordUsage(tnt, 128)
	}
	if m.rateLimiter.Count(tnt.ID) != 5 || m.hourLimiter.Count(tnt.ID) != 5 {
		t.Fatalf("expected seeded minute/hour counters at 5")
	}
	if a := m.alertManager.TriggerAlert(tnt.ID, AlertSecurityEvent, AlertCritical, "Attack", "detail", nil); a == nil {
		t.Fatal("first alert should fire")
	}
	if a := m.alertManager.TriggerAlert(tnt.ID, AlertSecurityEvent, AlertCritical, "Attack", "detail", nil); a != nil {
		t.Fatal("second alert must be suppressed by cooldown")
	}
	if _, err := m.BillingManager().GenerateInvoice(tnt.ID, "Acme", PlanBasic,
		time.Now().AddDate(0, -1, 0), time.Now()); err != nil {
		t.Fatalf("generate invoice: %v", err)
	}
}

func makeStoreReadOnly(t *testing.T, dir string) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory write permissions; cannot simulate a read-only store")
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatalf("chmod read-only: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
}

func readStoreIndex(t *testing.T, dir string) map[string]string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, "index.json"))
	if err != nil {
		t.Fatalf("read index.json: %v", err)
	}
	var idx map[string]string
	if err := json.Unmarshal(data, &idx); err != nil {
		t.Fatalf("parse index.json: %v", err)
	}
	return idx
}

// ---------------------------------------------------------------------------
// Store: transactional delete
// ---------------------------------------------------------------------------

func TestStore_DeleteTenant_ReadOnlyDir_LeavesStateIntactAndIsRetryable(t *testing.T) {
	dir := t.TempDir()
	s := NewStore(dir)
	if err := s.Init(); err != nil {
		t.Fatal(err)
	}
	tnt := &Tenant{
		ID: "t-one", Name: "One", Active: true, Quota: DefaultQuota(),
		Domains: []string{"one.test"}, APIKeyHash: "hash",
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	if err := s.SaveTenant(tnt); err != nil {
		t.Fatalf("save: %v", err)
	}

	makeStoreReadOnly(t, dir)

	err := s.DeleteTenant("t-one")
	if err == nil {
		t.Fatal("expected delete error on read-only store, got nil")
	}
	if _, statErr := os.Stat(filepath.Join(dir, "t-one.json")); statErr != nil {
		t.Fatalf("tenant file must remain after failed delete: %v", statErr)
	}
	// Restore permissions and confirm the operation converges on retry.
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteTenant("t-one"); err != nil {
		t.Fatalf("retry delete: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "t-one.json")); !os.IsNotExist(err) {
		t.Fatalf("tenant file should be gone after retry: %v", err)
	}
	if idx := readStoreIndex(t, dir); idx["t-one"] != "" {
		t.Fatalf("index still references deleted tenant: %v", idx)
	}
}

// Index update failure after the data file was removed must roll the file
// back from its pre-delete bytes so the tenant is present again on restart.
func TestStore_DeleteTenant_IndexWriteFailureRollsBack(t *testing.T) {
	dir := t.TempDir()
	s := NewStore(dir)
	if err := s.Init(); err != nil {
		t.Fatal(err)
	}
	original := []byte(`{"id":"t-two","name":"Two","active":true}`)
	if err := os.WriteFile(filepath.Join(dir, "t-two.json"), original, 0600); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveTenant(&Tenant{
		ID: "t-two", Name: "Two", Active: true, Quota: DefaultQuota(),
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}); err != nil {
		t.Fatalf("save: %v", err)
	}
	// Turn index.json into a directory: tmp write succeeds but rename over a
	// directory fails, forcing the rollback path.
	indexPath := filepath.Join(dir, "index.json")
	if err := os.Remove(indexPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(indexPath, 0o700); err != nil {
		t.Fatal(err)
	}

	err := s.DeleteTenant("t-two")
	if err == nil {
		t.Fatal("expected index update error, got nil")
	}

	got, readErr := os.ReadFile(filepath.Join(dir, "t-two.json"))
	if readErr != nil {
		t.Fatalf("tenant file must be restored from backup: %v", readErr)
	}
	if string(got) == "" {
		t.Fatal("restored tenant file is empty")
	}
	if got, want := s.index["t-two"], "t-two.json"; got != want {
		t.Fatalf("in-memory index rollback: %q != %q", got, want)
	}

	// The restored file must make the tenant survive a fresh load (restart).
	_ = os.RemoveAll(indexPath)
	reload := NewStore(dir)
	if err := reload.Init(); err != nil {
		t.Fatal(err)
	}
	tenants, err := reload.LoadAllTenants()
	if err != nil {
		t.Fatal(err)
	}
	if len(tenants) != 1 || tenants[0].ID != "t-two" {
		t.Fatalf("rollback tenant must reload, got %+v", tenants)
	}
}

func TestStore_DeleteTenant_SuccessRemovesFileAndIndex(t *testing.T) {
	dir := t.TempDir()
	s := NewStore(dir)
	if err := s.Init(); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveTenant(&Tenant{
		ID: "t-three", Name: "Three", Active: true, Quota: DefaultQuota(),
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}); err != nil {
		t.Fatalf("save: %v", err)
	}
	if err := s.DeleteTenant("t-three"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "t-three.json")); !os.IsNotExist(err) {
		t.Fatalf("file still present: %v", err)
	}
	if idx := readStoreIndex(t, dir); len(idx) != 0 {
		t.Fatalf("index should be empty, got %v", idx)
	}
	// Idempotent.
	if err := s.DeleteTenant("t-three"); err != nil {
		t.Fatalf("second delete should be nil, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// Manager: failed commit leaves every runtime structure untouched
// ---------------------------------------------------------------------------

func TestManager_DeleteTenant_StorageFailureKeepsRuntimeStateAndIsRetryable(t *testing.T) {
	dir := t.TempDir()
	m, tnt, key := newLifecycleManager(t, dir)
	seedRuntimeState(t, m, tnt)

	cs := &mockClusterSync{}
	m.SetClusterSync(cs)

	makeStoreReadOnly(t, dir)

	err := m.DeleteTenant(tnt.ID)
	if err == nil {
		t.Fatal("delete must return an error on persistence failure")
	}
	if errors.Is(err, ErrTenantNotFound) {
		t.Fatalf("persistence failure must not look like not-found: %v", err)
	}

	// All runtime state stays live and consistent.
	if m.GetTenant(tnt.ID) == nil {
		t.Fatal("tenant must remain resolvable after failed delete")
	}
	if got := m.GetTenantByDomain("acme.test"); got == nil || got.ID != tnt.ID {
		t.Fatal("domain resolution must still return the old tenant")
	}
	if got := m.GetTenantByAPIKey(key); got == nil || got.ID != tnt.ID {
		t.Fatal("API key resolution must still return the old tenant")
	}
	if m.GetDefaultTenantID() != tnt.ID {
		t.Fatal("default tenant must not change on failed delete")
	}
	if rules := m.GetTenantRules(tnt.ID); len(rules) != 1 {
		t.Fatalf("rules must be retained, got %d", len(rules))
	}
	if m.rateLimiter.Count(tnt.ID) != 5 || m.hourLimiter.Count(tnt.ID) != 5 {
		t.Fatal("rate trackers must be retained after failed delete")
	}
	if alerts := m.alertManager.GetAlerts(tnt.ID, true); len(alerts) != 1 {
		t.Fatalf("alerts must be retained, got %d", len(alerts))
	}
	if a := m.alertManager.TriggerAlert(tnt.ID, AlertSecurityEvent, AlertCritical, "Attack", "detail", nil); a != nil {
		t.Fatal("cooldown must be retained after failed delete")
	}
	if invoices := m.BillingManager().GetInvoices(tnt.ID); len(invoices) != 1 {
		t.Fatalf("billing history must be retained, got %d", len(invoices))
	}

	// A failed commit must not be broadcast as a deletion.
	if calls := syncCallsContaining(cs, "/delete"); len(calls) != 0 {
		t.Fatalf("failed delete must not broadcast, got %v", calls)
	}

	// Restart while storage is still intact: tenant resurrects nowhere — it
	// was never deleted.
	m2 := NewManagerWithStore(10, dir)
	if err := m2.Init(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(m2.Close)
	if m2.GetTenant(tnt.ID) == nil {
		t.Fatal("tenant must still load from disk after a failed delete")
	}

	// Restore storage and retry: commit now succeeds and broadcasts.
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := m.DeleteTenant(tnt.ID); err != nil {
		t.Fatalf("retry delete: %v", err)
	}
	if m.GetTenant(tnt.ID) != nil {
		t.Fatal("tenant must be gone after successful retry")
	}
	if !waitForSyncCall(cs, "/delete", time.Second) {
		t.Fatal("successful delete must broadcast a cluster delete event")
	}

	m3 := NewManagerWithStore(10, dir)
	if err := m3.Init(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(m3.Close)
	if len(m3.ListTenants()) != 0 {
		t.Fatal("deleted tenant must not reappear after restart")
	}
}

// ---------------------------------------------------------------------------
// Manager: successful commit purges runtime state, keeps billing history
// ---------------------------------------------------------------------------

func TestManager_DeleteTenant_SuccessPurgesRuntimeStateAndPersists(t *testing.T) {
	dir := t.TempDir()
	m, tnt, key := newLifecycleManager(t, dir)
	seedRuntimeState(t, m, tnt)

	if err := m.DeleteTenant(tnt.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}

	if m.GetTenant(tnt.ID) != nil {
		t.Fatal("tenant map entry must be gone")
	}
	if m.GetTenantByDomain("acme.test") != nil {
		t.Fatal("domain mapping must be gone")
	}
	if m.GetTenantByAPIKey(key) != nil {
		t.Fatal("old API key must not resolve")
	}
	if m.GetDefaultTenantID() != "" {
		t.Fatal("default tenant must clear when no tenants remain")
	}
	if rules := m.GetTenantRules(tnt.ID); len(rules) != 0 {
		t.Fatalf("tenant rules must be purged, got %d", len(rules))
	}
	if m.rateLimiter.Count(tnt.ID) != 0 || m.hourLimiter.Count(tnt.ID) != 0 {
		t.Fatal("rate counters must read zero after purge")
	}
	m.rateLimiter.mu.RLock()
	_, minuteTracker := m.rateLimiter.trackers[tnt.ID]
	m.rateLimiter.mu.RUnlock()
	m.hourLimiter.mu.RLock()
	_, hourTracker := m.hourLimiter.trackers[tnt.ID]
	m.hourLimiter.mu.RUnlock()
	if minuteTracker || hourTracker {
		t.Fatal("minute/hour tracker entries must be removed")
	}
	if alerts := m.alertManager.GetAlerts(tnt.ID, true); len(alerts) != 0 {
		t.Fatalf("alerts must be purged, got %d", len(alerts))
	}
	if a := m.alertManager.TriggerAlert(tnt.ID, AlertSecurityEvent, AlertCritical, "Attack", "detail", nil); a == nil {
		t.Fatal("cooldown must be purged so the same alert type can fire again")
	}
	if invoices := m.BillingManager().GetInvoices(tnt.ID); len(invoices) != 1 {
		t.Fatalf("billing history must remain queryable by old ID, got %d invoices", len(invoices))
	}
	if _, err := os.Stat(filepath.Join(dir, tnt.ID+".json")); !os.IsNotExist(err) {
		t.Fatalf("tenant JSON must be removed: %v", err)
	}
	if idx := readStoreIndex(t, dir); idx[tnt.ID] != "" {
		t.Fatalf("index entry must be removed, got %v", idx)
	}

	// Restart: the deleted tenant stays deleted.
	m2 := NewManagerWithStore(10, dir)
	if err := m2.Init(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(m2.Close)
	if len(m2.ListTenants()) != 0 {
		t.Fatal("deleted tenant must not reload after restart")
	}
}

// ---------------------------------------------------------------------------
// Same-name re-onboarding must never inherit the old identity's state
// ---------------------------------------------------------------------------

func TestManager_DeleteTenant_SameNameRecreateGetsFreshIdentity(t *testing.T) {
	dir := t.TempDir()
	m, old, oldKey := newLifecycleManager(t, dir)
	seedRuntimeState(t, m, old)
	if err := m.DeleteTenant(old.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}

	fresh, err := m.CreateTenant("Acme", "re-onboarded", []string{"acme.test"}, nil)
	if err != nil {
		t.Fatalf("same-name recreate: %v", err)
	}
	if fresh.ID == old.ID {
		t.Fatal("re-onboarded tenant must get a new ID")
	}
	if got := m.GetTenantByDomain("acme.test"); got == nil || got.ID != fresh.ID {
		t.Fatal("domain must resolve to the new tenant")
	}
	if m.GetTenantByAPIKey(oldKey) != nil {
		t.Fatal("the old tenant's API key must never resolve to the new tenant")
	}
	if rules := m.GetTenantRules(fresh.ID); len(rules) != 0 {
		t.Fatalf("new tenant must start with no rules, got %d", len(rules))
	}
	if m.rateLimiter.Count(fresh.ID) != 0 || m.hourLimiter.Count(fresh.ID) != 0 {
		t.Fatal("new tenant must start with zero quota counters")
	}
	if alerts := m.alertManager.GetAlerts(fresh.ID, true); len(alerts) != 0 {
		t.Fatalf("new tenant must start with no alerts, got %d", len(alerts))
	}
	if a := m.alertManager.TriggerAlert(fresh.ID, AlertSecurityEvent, AlertCritical, "Attack", "detail", nil); a == nil {
		t.Fatal("new tenant must not inherit the old tenant's cooldown")
	}
	if m.GetDefaultTenantID() != fresh.ID {
		t.Fatal("the re-onboarded tenant should become the new default")
	}
	if invoices := m.BillingManager().GetInvoices(old.ID); len(invoices) != 1 {
		t.Fatalf("old tenant billing history must remain queryable, got %d", len(invoices))
	}
	if invoices := m.BillingManager().GetInvoices(fresh.ID); len(invoices) != 0 {
		t.Fatalf("new tenant must not inherit billing history, got %d", len(invoices))
	}

	// Restart: only the new tenant exists on disk.
	m2 := NewManagerWithStore(10, dir)
	if err := m2.Init(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(m2.Close)
	loaded := m2.ListTenants()
	if len(loaded) != 1 || loaded[0].ID != fresh.ID {
		t.Fatalf("restart must load only the new tenant, got %+v", loaded)
	}
}

// ---------------------------------------------------------------------------
// Deterministic default-tenant reassignment
// ---------------------------------------------------------------------------

func TestManager_DeleteTenant_DeterministicDefault(t *testing.T) {
	minID := func(ids []string) string {
		cp := append([]string(nil), ids...)
		sort.Strings(cp)
		return cp[0]
	}
	// Insert tenants directly with random IDs: default reassignment is the
	// behavior under test, and CreateTenant's PBKDF2 key hashing is irrelevant
	// here (it dominates the test's CPU budget under -race).
	insertTenant := func(m *Manager, id, domain string) *Tenant {
		tn := &Tenant{
			ID: id, Name: "T", Active: true, Quota: DefaultQuota(),
			Domains: []string{domain}, CreatedAt: time.Now(), UpdatedAt: time.Now(),
		}
		m.mu.Lock()
		m.tenants[id] = tn
		m.domains[domainKey(domain)] = id
		if m.defaultTenantID == "" {
			m.defaultTenantID = id
		}
		m.mu.Unlock()
		return tn
	}
	for round := range 2 {
		m := NewManagerWithStore(10, t.TempDir())
		if err := m.Init(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(m.Close)
		var ids []string
		for i := range 3 {
			id, err := generateTenantID("T")
			if err != nil {
				t.Fatal(err)
			}
			insertTenant(m, id, fmt.Sprintf("d-%d-%d.test", round, i))
			ids = append(ids, id)
		}
		if m.GetDefaultTenantID() != ids[0] {
			t.Fatal("first inserted tenant should be default")
		}

		// Delete the default (first created); the new default must be the
		// smallest remaining ID, independent of map iteration order.
		if err := m.DeleteTenant(ids[0]); err != nil {
			t.Fatal(err)
		}
		remaining := []string{ids[1], ids[2]}
		if got := m.GetDefaultTenantID(); got != minID(remaining) {
			t.Fatalf("default after delete = %s, want deterministic %s", got, minID(remaining))
		}

		// Delete the reassigned default; the lone survivor is deterministic.
		next := minID(remaining)
		if err := m.DeleteTenant(next); err != nil {
			t.Fatal(err)
		}
		last := remaining[0]
		if remaining[0] == next {
			last = remaining[1]
		}
		if got := m.GetDefaultTenantID(); got != last {
			t.Fatalf("default after second delete = %s, want %s", got, last)
		}
		if err := m.DeleteTenant(last); err != nil {
			t.Fatal(err)
		}
		if got := m.GetDefaultTenantID(); got != "" {
			t.Fatalf("default should clear with no tenants, got %s", got)
		}
	}
}

// Concurrent deletes and same-name/domain re-creates must converge to a
// consistent identity index; run under -race.
func TestManager_DeleteTenant_ConcurrentDeleteRecreateResolve(t *testing.T) {
	dir := t.TempDir()
	m, first, _ := newLifecycleManager(t, dir)
	originalID := first.ID

	stop := make(chan struct{})
	var wg sync.WaitGroup

	// Resolvers hammer every lookup path (small sleep keeps them from
	// busy-spinning a core under -race).
	for range 3 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodGet, "http://acme.test/x", nil)
			for {
				select {
				case <-stop:
					return
				case <-time.After(time.Millisecond):
				}
				m.GetTenantByDomain("acme.test")
				m.ResolveTenant(req)
				m.ListTenants()
			}
		}()
	}

	// Mutators delete the domain owner and re-create the same name/domain.
	for g := range 3 {
		wg.Add(1)
		go func(seed int) {
			defer wg.Done()
			for range 5 {
				current := m.GetTenantByDomain("acme.test")
				if current != nil && (seed%2 == 0) {
					_ = m.DeleteTenant(current.ID)
				} else {
					_, _ = m.CreateTenant("Acme", "d", []string{"acme.test"}, nil)
				}
			}
		}(g)
	}

	// Concurrent double-delete of one ID: exactly one outcome per call, never
	// a panic, and the tenant is absent afterwards.
	wg.Add(2)
	doubleDelete := func() {
		defer wg.Done()
		_ = m.DeleteTenant(originalID)
	}
	go doubleDelete()
	go doubleDelete()

	// Give mutators a short bounded run.
	time.Sleep(60 * time.Millisecond)
	close(stop)
	wg.Wait()

	// Converge: delete every tenant holding the domain, then create once.
	for {
		current := m.GetTenantByDomain("acme.test")
		if current == nil {
			break
		}
		if err := m.DeleteTenant(current.ID); err != nil {
			t.Fatal(err)
		}
	}
	final, err := m.CreateTenant("Acme", "d", []string{"acme.test"}, nil)
	if err != nil {
		t.Fatalf("final create: %v", err)
	}

	// Full index consistency check.
	m.mu.RLock()
	defer m.mu.RUnlock()
	for did, tid := range m.domains {
		tn, ok := m.tenants[tid]
		if !ok {
			t.Fatalf("domain %s maps to missing tenant %s", did, tid)
		}
		present := false
		for _, d := range tn.Domains {
			if domainKey(d) == did {
				present = true
			}
		}
		if !present {
			t.Fatalf("domain index %s->%s has no back-reference in tenant domains", did, tid)
		}
	}
	for id, tn := range m.tenants {
		for _, d := range tn.Domains {
			if m.domains[domainKey(d)] != id {
				t.Fatalf("tenant %s domain %s resolves to %s", id, d, m.domains[domainKey(d)])
			}
		}
	}
	if m.domains[domainKey("acme.test")] != final.ID {
		t.Fatal("domain must resolve to the final tenant")
	}
}

// Not-found is a distinct, typed error so handlers can answer 404 honestly.
func TestManager_DeleteTenant_NotFoundSentinel(t *testing.T) {
	m := NewManager(10)
	t.Cleanup(m.Close)
	err := m.DeleteTenant("missing")
	if !errors.Is(err, ErrTenantNotFound) {
		t.Fatalf("expected ErrTenantNotFound, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// Internal HTTP handler: status-code honesty
// ---------------------------------------------------------------------------

func TestHandlers_DeleteTenant_StorageFailureReturns500AndKeepsTenant(t *testing.T) {
	dir := t.TempDir()
	m := NewManagerWithStore(10, dir)
	if err := m.Init(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(m.Close)
	tnt, err := m.CreateTenant("Acme", "d", []string{"acme.test"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	h := NewHandlers(m)
	h.SetAPIKey("admin-key")

	makeStoreReadOnly(t, dir)

	rr := httptest.NewRecorder()
	h.deleteTenant(rr, httptest.NewRequest(http.MethodDelete, "/api/v1/tenants/"+tnt.ID, nil), tnt.ID)
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("failed commit = %d, want 500 (body %q)", rr.Code, rr.Body.String())
	}

	getRR := httptest.NewRecorder()
	h.getTenant(getRR, httptest.NewRequest(http.MethodGet, "/", nil), tnt.ID)
	if getRR.Code != http.StatusOK {
		t.Fatalf("tenant must still be readable after failed delete, got %d", getRR.Code)
	}

	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	okRR := httptest.NewRecorder()
	h.deleteTenant(okRR, httptest.NewRequest(http.MethodDelete, "/", nil), tnt.ID)
	if okRR.Code != http.StatusNoContent {
		t.Fatalf("successful delete = %d, want 204", okRR.Code)
	}
	missingRR := httptest.NewRecorder()
	h.deleteTenant(missingRR, httptest.NewRequest(http.MethodDelete, "/", nil), tnt.ID)
	if missingRR.Code != http.StatusNotFound {
		t.Fatalf("delete again = %d, want 404", missingRR.Code)
	}
}

// ---------------------------------------------------------------------------
// Test helpers for the cluster mock defined in tenant_coverage_test.go
// ---------------------------------------------------------------------------

func syncCallsContaining(cs *mockClusterSync, fragment string) []string {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	var out []string
	for _, call := range cs.calls {
		if len(call) >= len(fragment) && call[len(call)-len(fragment):] == fragment {
			out = append(out, call)
		}
	}
	return out
}

func waitForSyncCall(cs *mockClusterSync, fragment string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if len(syncCallsContaining(cs, fragment)) > 0 {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return false
}
