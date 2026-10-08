package dashboard

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// deleteErrorManager overrides only DeleteTenant so the admin/compat handlers
// can be exercised against failed commits without a real tenant manager.
type deleteErrorManager struct {
	*mockTenantManager
	err error
}

func (m *deleteErrorManager) DeleteTenant(string) error { return m.err }

// A failed persistence commit must surface as 500 (not the previous
// unconditional 404), while a missing tenant stays 404.
func TestTenantDelete_AdminStatusHonesty(t *testing.T) {
	d := newTestDashboard(t, "global-key")
	t.Cleanup(d.Close)

	failing := NewTenantAdminHandler(d, &deleteErrorManager{
		mockTenantManager: &mockTenantManager{},
		err:               fmt.Errorf("storage is read-only"),
	})
	rr := httptest.NewRecorder()
	failing.deleteTenant(rr, httptest.NewRequest(http.MethodDelete, "/", nil), "t1")
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("persistence failure = %d, want 500 (body %s)", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), `"error"`) {
		t.Fatalf("500 must keep the JSON error envelope, got %s", rr.Body.String())
	}

	missing := NewTenantAdminHandler(d, &deleteErrorManager{
		mockTenantManager: &mockTenantManager{},
		err:               fmt.Errorf("tenant t1 not found"),
	})
	missRR := httptest.NewRecorder()
	missing.deleteTenant(missRR, httptest.NewRequest(http.MethodDelete, "/", nil), "t1")
	if missRR.Code != http.StatusNotFound {
		t.Fatalf("missing tenant = %d, want 404", missRR.Code)
	}
}

// A failed admin delete must not drop the cached tenant key: the tenant still
// exists and its key must keep authenticating until a successful commit.
func TestTenantDelete_AdminFailureKeepsCachedKey(t *testing.T) {
	d := newTestDashboard(t, "global-key")
	t.Cleanup(d.Close)
	d.SetTenantAPIKey("t1", legacyTenantKeyHash("tenant-key"))

	h := NewTenantAdminHandler(d, &deleteErrorManager{
		mockTenantManager: &mockTenantManager{},
		err:               fmt.Errorf("index update failed"),
	})
	rr := httptest.NewRecorder()
	h.deleteTenant(rr, httptest.NewRequest(http.MethodDelete, "/", nil), "t1")
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rr.Code)
	}
	if !tenantKeyAuthenticates(d, "t1", "tenant-key") {
		t.Fatal("cached tenant key must remain valid after a failed delete")
	}
}

// The compatibility REST route shares the same commit semantics: successful
// delete invalidates the dashboard key cache (previously leaked), a failed
// delete keeps it, and status codes distinguish 404 from 500.
func TestTenantDelete_CompatKeyCacheAndStatus(t *testing.T) {
	t.Run("success clears cached key", func(t *testing.T) {
		d := newTestDashboard(t, "global-key")
		t.Cleanup(d.Close)
		d.SetTenantManager(&mockTenantManager{})
		d.SetTenantAPIKey("t1", legacyTenantKeyHash("tenant-key"))

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/tenants/t1", nil)
		req.SetPathValue("id", "t1")
		rr := httptest.NewRecorder()
		d.handleTenantDeleteCompat(rr, req)
		if rr.Code != http.StatusNoContent {
			t.Fatalf("status = %d, want 204 (body %s)", rr.Code, rr.Body.String())
		}
		if tenantKeyAuthenticates(d, "t1", "tenant-key") {
			t.Fatal("deleted tenant key must not authenticate via the compat route cache")
		}
	})

	t.Run("failure keeps cached key and returns 500", func(t *testing.T) {
		d := newTestDashboard(t, "global-key")
		t.Cleanup(d.Close)
		d.SetTenantManager(&deleteErrorManager{
			mockTenantManager: &mockTenantManager{},
			err:               fmt.Errorf("removing tenant file: disk failure"),
		})
		d.SetTenantAPIKey("t1", legacyTenantKeyHash("tenant-key"))

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/tenants/t1", nil)
		req.SetPathValue("id", "t1")
		rr := httptest.NewRecorder()
		d.handleTenantDeleteCompat(rr, req)
		if rr.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d, want 500 (body %s)", rr.Code, rr.Body.String())
		}
		if !tenantKeyAuthenticates(d, "t1", "tenant-key") {
			t.Fatal("cached tenant key must remain valid after a failed compat delete")
		}
	})

	t.Run("missing tenant returns 404", func(t *testing.T) {
		d := newTestDashboard(t, "global-key")
		t.Cleanup(d.Close)
		d.SetTenantManager(&deleteErrorManager{
			mockTenantManager: &mockTenantManager{},
			err:               fmt.Errorf("tenant gone not found"),
		})

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/tenants/gone", nil)
		req.SetPathValue("id", "gone")
		rr := httptest.NewRecorder()
		d.handleTenantDeleteCompat(rr, req)
		if rr.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rr.Code)
		}
	})
}
