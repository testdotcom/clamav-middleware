package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/testdotcom/threats-scanner/internal/observability"
	"github.com/testdotcom/threats-scanner/internal/system"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var requestQueue chan struct{}

type ScanRequest struct {
	FilePath string `json:"filePath"`
}

type ScanResponse struct {
	IsThreat   bool   `json:"isThreat"`
	ScanResult string `json:"scanResult"`
}

func sendErrorResponse(w http.ResponseWriter, message string, statusCode int) {
	observability.Logger.LogAttrs(context.Background(), slog.LevelError, message, slog.Int("statusCode", statusCode))

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	json.NewEncoder(w).Encode(map[string]string{"error": message})
}

func runThreatScanner(filePath string) (bool, string, error) {
	var isThreat bool

	start := time.Now()

	scanCmd := exec.Command("/usr/bin/clamdscan", "--no-summary", "--fdpass", filePath)
	output, err := scanCmd.CombinedOutput()
	if err != nil {
		if strings.Contains(err.Error(), "1") {
			observability.ThreatsFound.Inc()
			isThreat = true
			err = nil
		} else {
			observability.FailureCount.Inc()
			err = fmt.Errorf("clamdscan: %w: %s", err, strings.TrimSpace(string(output)))
		}
	} else {
		isThreat = false
		err = nil
	}

	end := time.Since(start)
	observability.ScanLatency.Observe(end.Seconds())

	return isThreat, strings.TrimSpace(string(output)), err
}

func scanHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		sendErrorResponse(w, "method not allowed: Use POST.", http.StatusMethodNotAllowed)
		return
	}

	var req ScanRequest

	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&req); err != nil {
		observability.FailureCount.Inc()
		sendErrorResponse(w, "malformed request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	if req.FilePath == "" {
		sendErrorResponse(w, "missing filePath member.", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), system.RequestTimeout)
	defer cancel()

	select {
	case requestQueue <- struct{}{}:
		defer func() { <-requestQueue }()

		start := time.Now()

		observability.Logger.LogAttrs(context.Background(), slog.LevelDebug, "processing scan request", slog.String("filePath", req.FilePath))

		isThreat, scanResult, err := runThreatScanner(req.FilePath)
		if err != nil {
			sendErrorResponse(w, err.Error(), http.StatusInternalServerError)
			return
		}

		observability.RequestsProcessed.Inc()
		observability.Logger.LogAttrs(context.Background(), slog.LevelInfo, "scan response",
			slog.Bool("isThreat", isThreat), slog.String("scanResult", scanResult))

		resp := ScanResponse{IsThreat: isThreat, ScanResult: scanResult}
		w.Header().Set("Content-Type", "application/json")

		encoder := json.NewEncoder(w)
		if err := encoder.Encode(resp); err != nil {
			observability.FailureCount.Inc()
			sendErrorResponse(w, "encode response failure: "+err.Error(), http.StatusInternalServerError)
			return
		}

		end := time.Since(start)
		observability.RequestLatency.Observe(end.Seconds())
	case <-ctx.Done():
		observability.TimeoutsExpired.Inc()
		sendErrorResponse(w, "request timeout. Please try again later.", http.StatusRequestTimeout)
	}
}

func init() {
	observability.InitJSONLogger(system.LogLevel)

	requestQueue = make(chan struct{}, system.MaxConcurrentRequests)
}

func main() {
	http.HandleFunc("/api/v1/scan", scanHandler)
	http.Handle("/metrics", promhttp.Handler())

	observability.Logger.LogAttrs(context.Background(), slog.LevelDebug, "serving on", slog.String("port", system.Port))

	err := http.ListenAndServe(system.Port, nil)
	if err != nil {
		observability.Logger.LogAttrs(context.Background(), slog.LevelError, "failed starting HTTP server", slog.String("error", err.Error()))
		os.Exit(1)
	}
}
