package dashboard

import (
	"net/http"

	"github.com/guardianwaf/guardianwaf/internal/docker"
)

// dockerWatcherInterface defines what the dashboard needs from the Docker watcher.
type dockerWatcherInterface interface {
	Services() []docker.DiscoveredService
	ServiceCount() int
	Stats() docker.WatcherStats
}

// dockerSnapshotState classifies the watcher's convergence for operators:
// "converged" — running state matches the latest complete snapshot;
// "stale" — the last sync failed but an earlier snapshot is still in use;
// "failed" — the last sync failed and no prior snapshot exists.
func dockerSnapshotState(stats docker.WatcherStats) string {
	switch {
	case stats.LastSyncOK:
		return "converged"
	case stats.ServiceCount > 0:
		return "stale"
	default:
		return "failed"
	}
}

// SetDockerWatcher injects the Docker watcher for dashboard API access.
func (d *Dashboard) SetDockerWatcher(w dockerWatcherInterface) {
	// Atomic publication: the dashboard server may already be serving when
	// this runs (setupDockerRuntime wires it after startDashboard returns).
	d.dockerWatcher.Store(&w)
}

// getDockerWatcher returns the injected Docker watcher, or nil when unset.
// Safe for concurrent use with SetDockerWatcher.
func (d *Dashboard) getDockerWatcher() dockerWatcherInterface {
	if p := d.dockerWatcher.Load(); p != nil {
		return *p
	}
	return nil
}

// handleDockerServices returns discovered Docker containers.
func (d *Dashboard) handleDockerServices(w http.ResponseWriter, r *http.Request) {
	watcher := d.getDockerWatcher()
	if watcher == nil {
		writeJSON(w, http.StatusOK, map[string]any{"enabled": false, "state": "disabled", "services": []any{}})
		return
	}
	services := watcher.Services()
	stats := watcher.Stats()
	writeJSON(w, http.StatusOK, map[string]any{
		"enabled":  true,
		"count":    len(services),
		"state":    dockerSnapshotState(stats),
		"stats":    stats,
		"services": docker.ServiceSummary(services),
	})
}

func (d *Dashboard) handleDockerContainers(w http.ResponseWriter, r *http.Request) {
	watcher := d.getDockerWatcher()
	if watcher == nil {
		writeJSON(w, http.StatusOK, map[string]any{"enabled": false, "state": "disabled", "containers": []any{}})
		return
	}
	services := docker.ServiceSummary(watcher.Services())
	stats := watcher.Stats()
	writeJSON(w, http.StatusOK, map[string]any{
		"enabled":    true,
		"count":      len(services),
		"state":      dockerSnapshotState(stats),
		"stats":      stats,
		"containers": services,
	})
}

func (d *Dashboard) handleDockerEvents(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"enabled": d.getDockerWatcher() != nil,
		"events":  []any{},
	})
}
