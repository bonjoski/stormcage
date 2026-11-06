package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/bonjoski/stormcage/pkg/firewall"
	"github.com/bonjoski/stormcage/pkg/schema"
	"github.com/bonjoski/stormcage/pkg/status"
	"github.com/bonjoski/stormcage/pkg/taint"
	"github.com/bonjoski/stormcage/pkg/version"
)

const (
	Banner = "Stormcage Context & Memory Firewall (bonjoski toolchain)"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	command := os.Args[1]
	args := os.Args[2:]

	switch command {
	case "status":
		runStatus(args)
	case "scan":
		runScan(args)
	case "sanitize":
		runSanitize(args)
	case "daemon":
		runDaemon(args)
	case "version", "--version", "-v":
		fmt.Printf("stormcage %s\n", version.Version)
	case "help", "--help", "-h":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", command)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Printf("%s %s\n\n", Banner, version.Version)
	fmt.Println("Usage:")
	fmt.Println("  stormcage status [--json] [--endpoint <url>]")
	fmt.Println("  stormcage scan [--input <file.json>] [--privilege HIGH|MEDIUM|LOW]")
	fmt.Println("  stormcage sanitize [--input <file>]")
	fmt.Println("  stormcage daemon [--port 8088]")
	fmt.Println("  stormcage version")
}

func readInput(inputPath string) ([]byte, error) {
	if inputPath == "" || inputPath == "-" {
		return io.ReadAll(os.Stdin)
	}
	return os.ReadFile(inputPath)
}

func runStatus(args []string) {
	code := executeStatus(args, os.Stdout, os.Stderr)
	if code != 0 {
		os.Exit(code)
	}
}

func executeStatus(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	fs.SetOutput(stderr)
	jsonOutput := fs.Bool("json", false, "Output status in JSON format")
	endpoint := fs.String("endpoint", status.DefaultEndpoint, "Daemon health endpoint")
	port := fs.Int("port", 0, "Daemon port (overrides endpoint port)")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	targetEndpoint := *endpoint
	if *port > 0 {
		targetEndpoint = fmt.Sprintf("http://%s:%d", "127.0.0.1", *port)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	pidPath := status.DefaultPIDPath()
	res := status.CheckDaemon(ctx, targetEndpoint, pidPath)

	if *jsonOutput {
		data, _ := res.FormatJSON()
		fmt.Fprintln(stdout, string(data))
	} else {
		fmt.Fprint(stdout, res.FormatHuman())
	}

	if !res.Online {
		return 1
	}
	return 0
}

func runScan(args []string) {
	code := executeScan(args, os.Stdin, os.Stdout, os.Stderr)
	if code != 0 {
		os.Exit(code)
	}
}

func executeScan(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	inputPath := fs.String("input", "", "Path to JSON memory record file (or '-' for stdin)")
	privilegeStr := fs.String("privilege", "HIGH", "Target agent privilege level (HIGH, MEDIUM, LOW)")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	privilege, err := taint.ParsePrivilegeLevel(*privilegeStr)
	if err != nil {
		fmt.Fprintf(stderr, "error parsing privilege: %v\n", err)
		return 2
	}

	var record *schema.MemoryRecord

	if *inputPath != "" {
		var data []byte
		if *inputPath == "-" {
			d, err := io.ReadAll(stdin)
			if err != nil {
				fmt.Fprintf(stderr, "error reading stdin: %v\n", err)
				return 2
			}
			data = d
		} else if fileData, err := os.ReadFile(*inputPath); err == nil {
			data = fileData
		} else {
			if errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ENAMETOOLONG) {
				if (strings.HasSuffix(*inputPath, ".json") || strings.HasSuffix(*inputPath, ".txt")) &&
					!strings.Contains(*inputPath, " ") && !strings.HasPrefix(*inputPath, "{") {
					fmt.Fprintf(stderr, "error reading input: %v\n", err)
					return 2
				}
				data = []byte(*inputPath)
			} else {
				fmt.Fprintf(stderr, "error reading input: %v\n", err)
				return 2
			}
		}

		trimmed := bytes.TrimSpace(data)
		if bytes.HasPrefix(trimmed, []byte("{")) {
			rec, err := schema.ParseStrictJSON(trimmed)
			if err != nil {
				fmt.Fprintf(stderr, "schema validation error: %v\n", err)
				return 2
			}
			record = rec
		} else {
			if len(trimmed) == 0 {
				fmt.Fprintln(stderr, "error: empty input provided")
				return 2
			}
			record = &schema.MemoryRecord{
				AgentID:    "cli-scanner",
				Taint:      taint.TAINT_EXTERNAL_USER,
				Content:    string(trimmed),
				TaskIntent: "Security scan of input content",
			}
		}
	} else {
		// --input is NOT specified
		// Check if stdin has data
		hasPipedData := false
		var pipedData []byte

		if file, ok := stdin.(*os.File); ok && file == os.Stdin {
			stat, err := os.Stdin.Stat()
			if err == nil && (stat.Mode()&os.ModeCharDevice) == 0 {
				data, err := io.ReadAll(os.Stdin)
				if err == nil && len(bytes.TrimSpace(data)) > 0 {
					hasPipedData = true
					pipedData = bytes.TrimSpace(data)
				}
			}
		} else if stdin != nil && stdin != os.Stdin {
			// In tests or non-os.Stdin readers with data
			data, err := io.ReadAll(stdin)
			if err == nil && len(bytes.TrimSpace(data)) > 0 {
				hasPipedData = true
				pipedData = bytes.TrimSpace(data)
			}
		}

		if hasPipedData {
			if bytes.HasPrefix(pipedData, []byte("{")) {
				rec, err := schema.ParseStrictJSON(pipedData)
				if err != nil {
					fmt.Fprintf(stderr, "schema validation error: %v\n", err)
					return 2
				}
				record = rec
			} else {
				record = &schema.MemoryRecord{
					AgentID:    "pipe-scanner",
					Taint:      taint.TAINT_EXTERNAL_USER,
					Content:    string(pipedData),
					TaskIntent: "Security scan of piped content",
				}
			}
		} else {
			// Stdin is a TTY / no data piped: DO NOT BLOCK.
			// Automatically capture working tree git diff
			diffCmd := exec.Command("git", "diff", "HEAD")
			diffOut, diffErr := diffCmd.Output()
			if diffErr != nil || len(bytes.TrimSpace(diffOut)) == 0 {
				if d, err := exec.Command("git", "diff").Output(); err == nil && len(bytes.TrimSpace(d)) > 0 {
					diffOut = d
					diffErr = nil
				}
			}

			if diffErr == nil && len(bytes.TrimSpace(diffOut)) > 0 {
				record = &schema.MemoryRecord{
					AgentID:    "git-diff",
					Taint:      taint.TRUST_LOCAL_WORKSPACE,
					Content:    string(diffOut),
					TaskIntent: "Scan working tree git diff for prompt injection and malicious instructions",
				}
			} else {
				// Diff is empty, check recent git commits
				logCmd := exec.Command("git", "log", "-n", "5", "--pretty=format:%B")
				logOut, logErr := logCmd.Output()
				if logErr == nil && len(bytes.TrimSpace(logOut)) > 0 {
					record = &schema.MemoryRecord{
						AgentID:    "git-commits",
						Taint:      taint.TRUST_LOCAL_WORKSPACE,
						Content:    string(logOut),
						TaskIntent: "Scan recent git commits for prompt injection and malicious instructions",
					}
				} else {
					fmt.Fprintln(stdout, "No input provided and no git working tree changes or recent commits found to scan.")
					return 0
				}
			}
		}
	}

	fw := firewall.NewFirewall()
	verdict := fw.Gate(record, privilege)

	out, _ := json.MarshalIndent(verdict, "", "  ")
	fmt.Fprintln(stdout, string(out))

	if verdict.Status == firewall.DecisionQuarantined {
		return 1
	}
	return 0
}

func runSanitize(args []string) {
	fs := flag.NewFlagSet("sanitize", flag.ExitOnError)
	inputPath := fs.String("input", "", "Path to file to sanitize (or '-' for stdin)")
	_ = fs.Parse(args)

	data, err := readInput(*inputPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading input: %v\n", err)
		os.Exit(2)
	}

	// Try parsing as JSON envelope, otherwise treat as plain text
	sanitizer := firewall.NewPreFlightSanitizer()
	var record schema.MemoryRecord
	if err := json.Unmarshal(data, &record); err == nil && record.Content != "" {
		record.Content = sanitizer.Neutralize(record.Content)
		out, _ := json.MarshalIndent(record, "", "  ")
		fmt.Println(string(out))
		return
	}

	sanitized := sanitizer.Neutralize(string(data))
	fmt.Print(sanitized)
}

func runDaemon(args []string) {
	fs := flag.NewFlagSet("daemon", flag.ExitOnError)
	port := fs.Int("port", 8088, "HTTP port for memory write interceptor")
	_ = fs.Parse(args)

	pidPath := status.DefaultPIDPath()
	if pidPath != "" {
		_ = status.WritePID(pidPath, os.Getpid())
		defer status.RemovePID(pidPath)
	}

	fw := firewall.NewFirewall()

	mux := http.NewServeMux()

	// GET /v1/health
	mux.HandleFunc("GET /v1/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"status":  "ok",
			"version": version.Version,
		})
	})

	// POST /v1/memory/write
	mux.HandleFunc("POST /v1/memory/write", func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, schema.MaxContentLength))
		if err != nil {
			http.Error(w, `{"error": "failed to read request body"}`, http.StatusBadRequest)
			return
		}
		defer r.Body.Close()

		record, err := schema.ParseStrictJSON(body)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error":   "schema_validation_failed",
				"details": err.Error(),
			})
			return
		}

		verdict := fw.Gate(record, taint.PRIVILEGE_HIGH)

		w.Header().Set("Content-Type", "application/json")
		if verdict.Status == firewall.DecisionQuarantined {
			w.WriteHeader(http.StatusUnprocessableEntity) // HTTP 422
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status":  verdict.Status,
				"reason":  verdict.Reason,
				"taint":   verdict.Taint,
				"details": verdict.Details,
			})
			return
		}

		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status":          verdict.Status,
			"reason":          verdict.Reason,
			"taint":           verdict.Taint,
			"cleaned_content": verdict.CleanedContent,
			"latency_ms":      verdict.LatencyMs,
		})
	})

	server := &http.Server{
		Addr:         fmt.Sprintf(":%d", *port),
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	go func() {
		fmt.Printf("Stormcage Context Firewall listening on :%d...\n", *port)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			fmt.Fprintf(os.Stderr, "server error: %v\n", err)
		}
	}()

	<-stop
	fmt.Println("\nShutting down Stormcage daemon...")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = server.Shutdown(ctx)
	fmt.Println("Stormcage daemon stopped.")
}
