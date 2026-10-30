package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/bonjoski/stormcage/pkg/firewall"
	"github.com/bonjoski/stormcage/pkg/schema"
	"github.com/bonjoski/stormcage/pkg/taint"
	"github.com/bonjoski/stormcage/pkg/version"
)

const (
	Banner    = "Stormcage Context & Memory Firewall (bonjoski toolchain)"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	command := os.Args[1]
	args := os.Args[2:]

	switch command {
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

func runScan(args []string) {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	inputPath := fs.String("input", "", "Path to JSON memory record file (or '-' for stdin)")
	privilegeStr := fs.String("privilege", "HIGH", "Target agent privilege level (HIGH, MEDIUM, LOW)")
	_ = fs.Parse(args)

	privilege, err := taint.ParsePrivilegeLevel(*privilegeStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error parsing privilege: %v\n", err)
		os.Exit(2)
	}

	data, err := readInput(*inputPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading input: %v\n", err)
		os.Exit(2)
	}

	record, err := schema.ParseStrictJSON(data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "schema validation error: %v\n", err)
		os.Exit(2)
	}

	fw := firewall.NewFirewall()
	verdict := fw.Gate(record, privilege)

	out, _ := json.MarshalIndent(verdict, "", "  ")
	fmt.Println(string(out))

	if verdict.Status == firewall.DecisionQuarantined {
		os.Exit(1)
	}
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
	var record schema.MemoryRecord
	if err := json.Unmarshal(data, &record); err == nil && record.Content != "" {
		sanitized := schema.SanitizeText(record.Content)
		record.Content = sanitized
		out, _ := json.MarshalIndent(record, "", "  ")
		fmt.Println(string(out))
		return
	}

	sanitized := schema.SanitizeText(string(data))
	fmt.Print(sanitized)
}

func runDaemon(args []string) {
	fs := flag.NewFlagSet("daemon", flag.ExitOnError)
	port := fs.Int("port", 8088, "HTTP port for memory write interceptor")
	_ = fs.Parse(args)

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
