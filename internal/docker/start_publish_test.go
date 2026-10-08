package docker

import (
	"os"
	"runtime"
	"sync/atomic"
	"testing"
	"time"
)

// Regression: Watcher.Start's initial sync never published the snapshot —
// the runtime kept static-only routing until an unrelated container event
// or an event-stream failure. Start must converge the initial snapshot via
// the same refresh path events use, and must not notify when the first
// snapshot is empty.

// startFakeDocker writes a fake docker CLI. With services=true, ps/inspect
// return one labeled container; events sleeps (kept alive until Stop cancels
// the command). With services=false, ps returns nothing.
func startFakeDocker(t *testing.T, services bool) string {
	t.Helper()
	script := `#!/bin/sh
cmd="$1"
shift
case "$cmd" in
	ps)
		if [ "` + boolToken(services) + `" = "true" ]; then
			printf '%s\n' '{"ID":"abc123def4567890"}'
		fi
		;;
	inspect)
		printf '%s' '[{"Id":"abc123def4567890","Name":"/web","Config":{"Labels":{"gwaf.enable":"true","gwaf.host":"web.example.com","gwaf.port":"8080"},"ExposedPorts":{"8080/tcp":{}}},"State":{"Status":"running","Running":true},"NetworkSettings":{"Networks":{"bridge":{"IPAddress":"172.17.0.2"}}}}]'
		;;
	events)
		sleep 30
		;;
	*)
		exit 1
		;;
esac
`
	dir := writeFakeDocker(t, script)
	// Keep the real PATH so the events-branch `sleep` resolves.
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return dir
}

func boolToken(v bool) string {
	if v {
		return "true"
	}
	return "false"
}

func waitForCounter(t *testing.T, c *atomic.Int64, want int64) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if c.Load() == want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("counter = %d, want %d", c.Load(), want)
}

func TestWatcher_StartPublishesInitialSnapshot(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake docker requires a POSIX shell")
	}
	startFakeDocker(t, true)

	w := NewWatcher(NewClient(""), "gwaf", "bridge", time.Second)
	w.SetLogger(func(_, _ string) {})
	var notifications atomic.Int64
	w.SetOnChange(func() { notifications.Add(1) })

	w.Start()
	t.Cleanup(w.Stop)

	// The initial snapshot is published exactly once at startup.
	waitForCounter(t, &notifications, 1)
	if w.ServiceCount() != 1 {
		t.Fatalf("initial snapshot not stored: %d services", w.ServiceCount())
	}
	if !w.Stats().Converged {
		t.Fatal("startup must finish converged")
	}
}

func TestWatcher_StartDoesNotNotifyOnEmptySnapshot(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake docker requires a POSIX shell")
	}
	startFakeDocker(t, false)

	w := NewWatcher(NewClient(""), "gwaf", "bridge", time.Second)
	w.SetLogger(func(_, _ string) {})
	var notifications atomic.Int64
	w.SetOnChange(func() { notifications.Add(1) })

	w.Start()
	t.Cleanup(w.Stop)

	// Give the startup path a moment to run; it must stay at zero.
	time.Sleep(100 * time.Millisecond)
	if notifications.Load() != 0 {
		t.Fatalf("empty initial snapshot must not trigger a rebuild, got %d", notifications.Load())
	}
}
