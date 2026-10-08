package docker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

// ============================================================================
// Convergence: every label-derived field (and network changes) must be
// reflected in the snapshot, and identical snapshots must not churn.
// ============================================================================

// makeDetail builds a single-container batch-inspect JSON response.
func makeDetail(id, name string, labels map[string]string, ip string, ports ...int) string {
	var d ContainerDetail
	d.ID = id
	d.Name = "/" + name
	d.Config.Labels = labels
	d.Config.ExposedPorts = map[string]any{}
	for _, p := range ports {
		d.Config.ExposedPorts[strconv.Itoa(p)+"/tcp"] = struct{}{}
	}
	d.NetworkSettings.Networks = map[string]NetworkInfo{"bridge": {IPAddress: ip}}
	d.State.Status = "running"
	d.State.Running = true
	b, _ := json.Marshal([]ContainerDetail{d})
	return string(b)
}

func baselineLabels() map[string]string {
	return map[string]string{
		"gwaf.enable":          "true",
		"gwaf.host":            "web.example.com",
		"gwaf.path":            "/api",
		"gwaf.port":            "8080",
		"gwaf.weight":          "2",
		"gwaf.strip_prefix":    "true",
		"gwaf.lb":              "weighted",
		"gwaf.tls":             "manual",
		"gwaf.health.path":     "/healthz",
		"gwaf.health.interval": "7s",
	}
}

// snapshotClient returns a client whose ps lists id and whose inspect returns
// the JSON held in the inspectOut pointer.
func snapshotClient(id string, inspectOut *string) *Client {
	return makeClientWithCmdFunc(func(_ context.Context, args ...string) (string, error) {
		if len(args) > 0 && args[0] == "ps" {
			return `{"ID":"` + id + `"}`, nil
		}
		return *inspectOut, nil
	})
}

func TestWatcher_ConvergesOnEveryLabelAndNetworkField(t *testing.T) {
	const id = "abc123def456"
	inspectOut := makeDetail(id, "web", baselineLabels(), "172.17.0.2", 8080)
	w := NewWatcher(snapshotClient(id, &inspectOut), "gwaf", "bridge", time.Second)
	w.SetLogger(func(_, _ string) {})

	if !w.sync() {
		t.Fatal("baseline sync must establish the snapshot")
	}
	baseline := w.Services()[0]

	cases := []struct {
		name   string
		mutate func(map[string]string)
		ip     string
		check  func(t *testing.T, got DiscoveredService)
	}{
		{
			name:   "host",
			mutate: func(l map[string]string) { l["gwaf.host"] = "other.example.com" },
			check: func(t *testing.T, got DiscoveredService) {
				if got.Host != "other.example.com" {
					t.Errorf("host not converged: %q", got.Host)
				}
			},
		},
		{
			name:   "path",
			mutate: func(l map[string]string) { l["gwaf.path"] = "/v2" },
			check: func(t *testing.T, got DiscoveredService) {
				if got.Path != "/v2" {
					t.Errorf("path not converged: %q", got.Path)
				}
			},
		},
		{
			name:   "port",
			mutate: func(l map[string]string) { l["gwaf.port"] = "9090" },
			check: func(t *testing.T, got DiscoveredService) {
				if got.Port != 9090 {
					t.Errorf("port not converged: %d", got.Port)
				}
			},
		},
		{
			name:   "weight",
			mutate: func(l map[string]string) { l["gwaf.weight"] = "5" },
			check: func(t *testing.T, got DiscoveredService) {
				if got.Weight != 5 {
					t.Errorf("weight not converged: %d", got.Weight)
				}
			},
		},
		{
			name:   "load-balancer",
			mutate: func(l map[string]string) { l["gwaf.lb"] = "ip_hash" },
			check: func(t *testing.T, got DiscoveredService) {
				if got.LBStrategy != "ip_hash" {
					t.Errorf("lb strategy not converged: %q", got.LBStrategy)
				}
			},
		},
		{
			name:   "strip-prefix-removed",
			mutate: func(l map[string]string) { delete(l, "gwaf.strip_prefix") },
			check: func(t *testing.T, got DiscoveredService) {
				if got.StripPrefix {
					t.Error("strip_prefix must converge to false")
				}
			},
		},
		{
			name:   "tls-removed",
			mutate: func(l map[string]string) { delete(l, "gwaf.tls") },
			check: func(t *testing.T, got DiscoveredService) {
				if got.TLS != "" || got.TargetURL() != "http://172.17.0.2:8080" {
					t.Errorf("tls not converged: tls=%q target=%q", got.TLS, got.TargetURL())
				}
			},
		},
		{
			name:   "health-path",
			mutate: func(l map[string]string) { l["gwaf.health.path"] = "/ready" },
			check: func(t *testing.T, got DiscoveredService) {
				if got.HealthPath != "/ready" {
					t.Errorf("health path not converged: %q", got.HealthPath)
				}
			},
		},
		{
			name:   "health-interval",
			mutate: func(l map[string]string) { l["gwaf.health.interval"] = "3s" },
			check: func(t *testing.T, got DiscoveredService) {
				if got.HealthInterval != 3*time.Second {
					t.Errorf("health interval not converged: %v", got.HealthInterval)
				}
			},
		},
		{
			name:   "network-address",
			mutate: func(l map[string]string) {},
			ip:     "172.17.0.9",
			check: func(t *testing.T, got DiscoveredService) {
				if got.IPAddress != "172.17.0.9" {
					t.Errorf("network change not converged: %q", got.IPAddress)
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			labels := baselineLabels()
			tc.mutate(labels)
			ip := "172.17.0.2"
			if tc.ip != "" {
				ip = tc.ip
			}
			inspectOut = makeDetail(id, "web", labels, ip, 8080)

			if !w.sync() {
				t.Fatalf("expected %q change to be detected", tc.name)
			}
			got := w.Services()[0]
			tc.check(t, got)

			// A repeated identical sync after the change must stay quiet.
			if w.sync() {
				t.Fatalf("repeated identical sync after %q change must not report another change", tc.name)
			}

			// Restore the baseline so the next case starts clean.
			inspectOut = makeDetail(id, "web", baselineLabels(), "172.17.0.2", 8080)
			if !w.sync() {
				t.Fatal("restore-to-baseline sync must be a change")
			}
			if w.Services()[0] != baseline {
				t.Fatal("snapshot did not restore to baseline")
			}
		})
	}
}

// ============================================================================
// Failure retention: list failures keep the previous snapshot; a later
// successful sync converges and clears the error.
// ============================================================================

func TestWatcher_FailedSyncRetainsSnapshotThenRecovers(t *testing.T) {
	const id = "abc123def456"
	baselineJSON := makeDetail(id, "web", baselineLabels(), "172.17.0.2", 8080)
	var shouldFail atomic.Bool
	var lastErr atomic.Value

	c := makeClientWithCmdFunc(func(_ context.Context, args ...string) (string, error) {
		if shouldFail.Load() {
			return "", fmt.Errorf("Cannot connect to the Docker daemon")
		}
		if len(args) > 0 && args[0] == "ps" {
			return `{"ID":"` + id + `"}`, nil
		}
		return baselineJSON, nil
	})
	w := NewWatcher(c, "gwaf", "bridge", time.Second)
	w.SetLogger(func(level, msg string) {
		if level == "warn" {
			lastErr.Store(msg)
		}
	})

	if !w.sync() {
		t.Fatal("baseline sync must succeed")
	}
	baseline := w.Services()
	successTime := w.Stats().LastSuccess

	// Two consecutive failed rounds — the snapshot must survive both.
	shouldFail.Store(true)
	for i := 1; i <= 2; i++ {
		if w.sync() {
			t.Fatalf("failed round %d must not report a change", i)
		}
		got := w.Services()
		if len(got) != len(baseline) || got[0] != baseline[0] {
			t.Fatalf("round %d mutated the retained snapshot", i)
		}
		stats := w.Stats()
		if stats.LastSyncOK || stats.Converged {
			t.Fatalf("round %d must report not converged", i)
		}
		if !stats.Stale {
			t.Fatalf("round %d must report stale (old snapshot in use)", i)
		}
		if stats.SyncFailures != int64(i) {
			t.Fatalf("round %d failures = %d", i, stats.SyncFailures)
		}
		if stats.LastError == "" {
			t.Fatalf("round %d must record the error string", i)
		}
		msg, _ := lastErr.Load().(string)
		if msg == "" || !strContains(msg, "retaining last valid snapshot") {
			t.Fatalf("round %d log must state the snapshot is retained, got %q", i, msg)
		}
	}

	// Recovery — the daemon returns the same snapshot, so no rebuild is
	// needed, but the state must flip to converged and the error must clear.
	shouldFail.Store(false)
	w.sync()
	stats := w.Stats()
	if !stats.Converged || stats.Stale {
		t.Fatal("post-recovery state must be converged")
	}
	if stats.LastError != "" {
		t.Fatal("recovery must clear the last error")
	}
	if !stats.LastSuccess.After(successTime) {
		t.Fatal("recovery must advance the last-success timestamp")
	}

	// And an actual change after recovery converges normally.
	changedJSON := makeDetail(id, "web", func() map[string]string {
		l := baselineLabels()
		l["gwaf.host"] = "new.example.com"
		return l
	}(), "172.17.0.2", 8080)
	baselineJSON = changedJSON
	if !w.sync() {
		t.Fatal("change after recovery must be applied")
	}
	if w.Services()[0].Host != "new.example.com" {
		t.Fatal("post-recovery change did not converge")
	}
}

// ============================================================================
// Incomplete snapshot: a ps'd container missing from batch inspect while
// still running must fail the whole round (ErrIncompleteSnapshot) instead of
// removing its routes.
// ============================================================================

func TestListContainers_RejectsIncompleteSnapshotWhenContainerStillRunning(t *testing.T) {
	const idA = "1111111111111111"
	const idB = "2222222222222222"

	c := makeClientWithCmdFunc(func(_ context.Context, args ...string) (string, error) {
		if len(args) > 0 && args[0] == "ps" {
			return `{"ID":"` + idA + `"}` + "\n" + `{"ID":"` + idB + `"}`, nil
		}
		// Single-container verification probe.
		if len(args) >= 3 && args[1] == "--format={{.State.Running}}" {
			return "true\n", nil
		}
		// Batch inspect: only A comes back, daemon error for B.
		labels := map[string]string{"gwaf.enable": "true", "gwaf.host": "a.example.com"}
		out := makeDetail(idA, "a", labels, "172.17.0.2", 8080)
		return out, fmt.Errorf("Error response from daemon: %s: timeout", idB)
	})

	_, err := c.ListContainers("gwaf")
	if !errors.Is(err, ErrIncompleteSnapshot) {
		t.Fatalf("expected ErrIncompleteSnapshot, got %v", err)
	}

	// The watcher must keep its prior snapshot against this error.
	w := NewWatcher(c, "gwaf", "bridge", time.Second)
	w.SetLogger(func(_, _ string) {})
	w.services[idA] = &DiscoveredService{ContainerID: idA, ContainerName: "a", IPAddress: "172.17.0.2", Port: 8080}
	w.services[idB] = &DiscoveredService{ContainerID: idB, ContainerName: "b", IPAddress: "172.17.0.3", Port: 8080}
	w.lastSyncOK.Store(true)

	if w.sync() {
		t.Fatal("incomplete snapshot must not be applied")
	}
	if w.ServiceCount() != 2 {
		t.Fatalf("incomplete snapshot clobbered the routes: %d services", w.ServiceCount())
	}
	if !w.Stats().Stale {
		t.Fatal("serving a retained snapshot after a failed round must report stale")
	}
}

// When the verification probe itself fails for an unknown reason, the round
// also fails rather than guessing the container is gone.
func TestListContainers_RejectsWhenVerificationInconclusive(t *testing.T) {
	const idA = "1111111111111111"
	const idB = "2222222222222222"

	c := makeClientWithCmdFunc(func(_ context.Context, args ...string) (string, error) {
		if len(args) > 0 && args[0] == "ps" {
			return `{"ID":"` + idA + `"}` + "\n" + `{"ID":"` + idB + `"}`, nil
		}
		if len(args) >= 3 && args[1] == "--format={{.State.Running}}" {
			return "", context.DeadlineExceeded
		}
		labels := map[string]string{"gwaf.enable": "true", "gwaf.host": "a.example.com"}
		return makeDetail(idA, "a", labels, "172.17.0.2", 8080), fmt.Errorf("partial")
	})

	_, err := c.ListContainers("gwaf")
	if err == nil || errors.Is(err, ErrIncompleteSnapshot) {
		t.Fatalf("verification failure must surface as the underlying error, got %v", err)
	}
}
