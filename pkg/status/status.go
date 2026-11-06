package status

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	defaultHost = "127.0.0.1"
	defaultPort = "8088"
	Divider     = "─────────────────────────────────────────────────────────────────"
)

var DefaultEndpoint = "http://" + defaultHost + ":" + defaultPort

// DaemonStatus represents the health and runtime status of the Stormcage daemon.
type DaemonStatus struct {
	Online     bool     `json:"healthy"`
	StatusText string   `json:"status"`
	Endpoint   string   `json:"endpoint"`
	PID        *int     `json:"pid,omitempty"`
	PIDDisplay string   `json:"pid_display,omitempty"`
	LatencyMs  float64  `json:"latency_ms,omitempty"`
	Version    string   `json:"version,omitempty"`
	Error      string   `json:"error,omitempty"`
}

// DefaultPIDPath returns the canonical path to the Stormcage daemon PID file.
func DefaultPIDPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".stormcage", "stormcage.pid")
}

// ReadPID reads and parses the PID from the specified pidPath, verifying whether the process is alive.
func ReadPID(pidPath string) (int, bool) {
	if pidPath == "" {
		return 0, false
	}
	data, err := os.ReadFile(pidPath)
	if err != nil {
		return 0, false
	}
	pidStr := strings.TrimSpace(string(data))
	pid, err := strconv.Atoi(pidStr)
	if err != nil || pid <= 0 {
		return 0, false
	}

	// Verify process liveness using signal 0
	proc, err := os.FindProcess(pid)
	if err != nil {
		return pid, false
	}
	if err := proc.Signal(syscall.Signal(0)); err != nil {
		return pid, false
	}
	return pid, true
}

// WritePID writes the given PID to the specified pidPath with restricted permissions.
func WritePID(pidPath string, pid int) error {
	if pidPath == "" {
		return nil
	}
	dir := filepath.Dir(pidPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	return os.WriteFile(pidPath, []byte(strconv.Itoa(pid)), 0600)
}

// RemovePID removes the PID file at pidPath if it exists.
func RemovePID(pidPath string) error {
	if pidPath == "" {
		return nil
	}
	err := os.Remove(pidPath)
	if err != nil && os.IsNotExist(err) {
		return nil
	}
	return err
}

// CheckDaemon probes the Stormcage daemon health endpoint and checks the PID file.
func CheckDaemon(ctx context.Context, endpoint string, pidPath string) *DaemonStatus {
	if endpoint == "" {
		endpoint = DefaultEndpoint
	}
	probeURL := endpoint
	if !strings.HasSuffix(probeURL, "/v1/health") {
		probeURL = strings.TrimRight(probeURL, "/") + "/v1/health"
	}

	res := &DaemonStatus{
		Endpoint: endpoint,
	}

	pid, pidAlive := ReadPID(pidPath)
	if pidAlive {
		res.PID = &pid
		res.PIDDisplay = fmt.Sprintf("%d", pid)
	} else {
		res.PIDDisplay = "active"
	}

	req, err := http.NewRequestWithContext(ctx, "GET", probeURL, nil)
	if err != nil {
		res.Online = false
		res.StatusText = "offline"
		res.Error = err.Error()
		return res
	}

	client := &http.Client{
		Timeout: 1 * time.Second,
	}

	start := time.Now()
	resp, err := client.Do(req)
	latency := time.Since(start)
	res.LatencyMs = float64(latency.Nanoseconds()) / 1e6

	if err != nil {
		res.Online = false
		res.StatusText = "offline"
		res.Error = err.Error()
		return res
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		res.Online = false
		res.StatusText = "degraded"
		res.Error = fmt.Sprintf("HTTP %d", resp.StatusCode)
		return res
	}

	var healthResp struct {
		Status  string `json:"status"`
		Version string `json:"version"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&healthResp); err != nil {
		res.Online = false
		res.StatusText = "degraded"
		res.Error = "invalid JSON from health endpoint"
		return res
	}

	res.Online = true
	res.StatusText = "online"
	res.Version = healthResp.Version
	return res
}

// FormatHuman formats the status output into clean human-readable text.
func (s *DaemonStatus) FormatHuman() string {
	var b strings.Builder
	if s.Online {
		b.WriteString("⚡ Stormcage Context Firewall: ONLINE\n")
		b.WriteString(Divider + "\n")
		b.WriteString("  Status:     Active (healthy)\n")
		b.WriteString(fmt.Sprintf("  Endpoint:   %s\n", s.Endpoint))
		b.WriteString(fmt.Sprintf("  Daemon PID: %s\n", s.PIDDisplay))
		b.WriteString(fmt.Sprintf("  Latency:    %.2fms\n", s.LatencyMs))
		b.WriteString(fmt.Sprintf("  Version:    %s\n", s.Version))
		b.WriteString(Divider + "\n")
	} else {
		b.WriteString("⚡ Stormcage Context Firewall: OFFLINE\n")
		b.WriteString(Divider + "\n")
		errDesc := "connection refused"
		if s.Error != "" {
			if strings.Contains(s.Error, "connect: connection refused") {
				errDesc = "connection refused"
			} else if strings.Contains(s.Error, "deadline exceeded") || strings.Contains(s.Error, "timeout") {
				errDesc = "timeout"
			} else {
				errDesc = s.Error
			}
		}
		b.WriteString(fmt.Sprintf("  Status:     Inactive (%s)\n", errDesc))
		b.WriteString(fmt.Sprintf("  Endpoint:   %s\n", s.Endpoint))
		b.WriteString(Divider + "\n")
		b.WriteString("Daemon is offline. To start the background firewall:\n")
		b.WriteString("  stormcage daemon --port 8088\n")
	}
	return b.String()
}

// FormatJSON produces machine-readable JSON status output.
func (s *DaemonStatus) FormatJSON() ([]byte, error) {
	type jsonOutput struct {
		Status    string   `json:"status"`
		Healthy   bool     `json:"healthy"`
		Endpoint  string   `json:"endpoint"`
		PID       *int     `json:"pid,omitempty"`
		LatencyMs *float64 `json:"latency_ms,omitempty"`
		Version   string   `json:"version,omitempty"`
		Error     string   `json:"error,omitempty"`
	}

	out := jsonOutput{
		Status:   s.StatusText,
		Healthy:  s.Online,
		Endpoint: s.Endpoint,
		Version:  s.Version,
		Error:    s.Error,
	}
	if s.Online {
		out.LatencyMs = &s.LatencyMs
		out.PID = s.PID
	}
	return json.MarshalIndent(out, "", "  ")
}
