package status

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestStatusOnlineDaemon(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/health" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{
				"status":  "ok",
				"version": "v0.2.0",
			})
			return
		}
		http.NotFound(w, r)
	}))
	defer ts.Close()

	// Write mock PID file with current test PID (guaranteed alive)
	tmpDir := t.TempDir()
	pidFile := filepath.Join(tmpDir, "stormcage.pid")
	if err := WritePID(pidFile, os.Getpid()); err != nil {
		t.Fatalf("failed to write pid file: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	res := CheckDaemon(ctx, ts.URL, pidFile)
	if !res.Online {
		t.Fatalf("expected daemon to be online, got error: %s", res.Error)
	}
	if res.Version != "v0.2.0" {
		t.Errorf("expected version v0.2.0, got %s", res.Version)
	}
	if res.PID == nil || *res.PID != os.Getpid() {
		t.Errorf("expected PID %d, got %v", os.Getpid(), res.PID)
	}
	if res.PIDDisplay != fmt.Sprintf("%d", os.Getpid()) {
		t.Errorf("expected PIDDisplay %d, got %s", os.Getpid(), res.PIDDisplay)
	}

	human := res.FormatHuman()
	if !strings.Contains(human, "⚡ Stormcage Context Firewall: ONLINE") {
		t.Errorf("human output missing ONLINE header: %s", human)
	}
	if !strings.Contains(human, "Status:     Active (healthy)") {
		t.Errorf("human output missing Active status: %s", human)
	}
	if !strings.Contains(human, "Version:    v0.2.0") {
		t.Errorf("human output missing version: %s", human)
	}

	jsonData, err := res.FormatJSON()
	if err != nil {
		t.Fatalf("failed to format JSON: %v", err)
	}
	var jsonMap map[string]interface{}
	if err := json.Unmarshal(jsonData, &jsonMap); err != nil {
		t.Fatalf("failed to unmarshal JSON output: %v", err)
	}
	if jsonMap["healthy"] != true {
		t.Errorf("expected json healthy=true, got %v", jsonMap["healthy"])
	}
	if jsonMap["version"] != "v0.2.0" {
		t.Errorf("expected json version=v0.2.0, got %v", jsonMap["version"])
	}
}

func TestStatusOfflineDaemon(t *testing.T) {
	// Point to an unused port
	offlineURL := "http://127.0.0.1:54321"

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	res := CheckDaemon(ctx, offlineURL, "")
	if res.Online {
		t.Fatalf("expected daemon to be offline")
	}
	if res.StatusText != "offline" {
		t.Errorf("expected status offline, got %s", res.StatusText)
	}

	human := res.FormatHuman()
	if !strings.Contains(human, "⚡ Stormcage Context Firewall: OFFLINE") {
		t.Errorf("human output missing OFFLINE header: %s", human)
	}
	if !strings.Contains(human, "stormcage daemon --port 8088") {
		t.Errorf("human output missing start instruction: %s", human)
	}

	jsonData, err := res.FormatJSON()
	if err != nil {
		t.Fatalf("failed to format JSON: %v", err)
	}
	var jsonMap map[string]interface{}
	if err := json.Unmarshal(jsonData, &jsonMap); err != nil {
		t.Fatalf("failed to unmarshal JSON output: %v", err)
	}
	if jsonMap["healthy"] != false {
		t.Errorf("expected json healthy=false, got %v", jsonMap["healthy"])
	}
}

func TestStatusDegradedDaemon(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	res := CheckDaemon(ctx, ts.URL, "")
	if res.Online {
		t.Fatalf("expected daemon to be offline/degraded")
	}
	if res.StatusText != "degraded" {
		t.Errorf("expected status degraded, got %s", res.StatusText)
	}
}

func TestPIDFileLifecycle(t *testing.T) {
	tmpDir := t.TempDir()
	pidFile := filepath.Join(tmpDir, "test.pid")

	// 1. Non-existent file
	_, alive := ReadPID(pidFile)
	if alive {
		t.Errorf("expected non-existent pid file to report not alive")
	}

	// 2. Write current process PID
	if err := WritePID(pidFile, os.Getpid()); err != nil {
		t.Fatalf("unexpected WritePID error: %v", err)
	}

	pid, alive := ReadPID(pidFile)
	if !alive || pid != os.Getpid() {
		t.Errorf("expected alive=true and pid=%d, got alive=%v, pid=%d", os.Getpid(), alive, pid)
	}

	// 3. Remove PID file
	if err := RemovePID(pidFile); err != nil {
		t.Fatalf("unexpected RemovePID error: %v", err)
	}

	_, aliveAfter := ReadPID(pidFile)
	if aliveAfter {
		t.Errorf("expected alive=false after removal")
	}

	// 4. Stale PID (e.g. 9999999)
	if err := WritePID(pidFile, 9999999); err != nil {
		t.Fatalf("unexpected WritePID error: %v", err)
	}
	stalePID, staleAlive := ReadPID(pidFile)
	if staleAlive {
		t.Errorf("expected stale pid to report not alive, got alive=true for pid=%d", stalePID)
	}
}

func TestStatusTimeout(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(500 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	res := CheckDaemon(ctx, ts.URL, "")
	if res.Online {
		t.Errorf("expected status check to fail on timeout")
	}
}
