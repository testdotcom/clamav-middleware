package main_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"testing"
	"time"
)

type ScanRequest struct {
	FilePath string `json:"filePath"`
}

type ScanResponse struct {
	IsThreat   bool   `json:"isThreat"`
	ScanResult string `json:"scanResult"`
}

func TestBackPressureScanner(t *testing.T) {
	numClients := 5
	endpoint := "http://localhost:8080/api/v1/scan"

	var (
		totalRequests int
		successCount  int
		failureCount  int
		totalDuration time.Duration
		minDuration   time.Duration
		maxDuration   time.Duration
		threatsFound  int
		mutex         sync.Mutex
	)

	var wg sync.WaitGroup
	wg.Add(numClients)

	startTime := time.Now()

	for i := range numClients {
		go func(clientID int) {
			defer wg.Done()

			client := &http.Client{Timeout: 60 * time.Second}

			infectedFiles := []string{"EICAR.COM", "EICAR.COM-ZIP", "EICAR.COM2-ZIP", "EICAR.txt"}
			for _, fileName := range infectedFiles {
				scanFile := fmt.Sprintf("/mnt/webdav/%d/%s", clientID, fileName)
				t.Logf("Scan file %s", scanFile)

				reqBody := ScanRequest{FilePath: scanFile}

				jsonData, err := json.Marshal(reqBody)
				if err != nil {
					t.Log(err)
					continue
				}

				reqStart := time.Now()
				resp, err := client.Post(endpoint, "application/json", bytes.NewBuffer(jsonData))
				reqDuration := time.Since(reqStart)

				mutex.Lock()
				totalRequests++
				totalDuration += reqDuration

				if reqDuration < minDuration {
					minDuration = reqDuration
				}
				if reqDuration > maxDuration {
					maxDuration = reqDuration
				}

				if err != nil {
					failureCount++
					t.Log(err)
				} else {
					defer resp.Body.Close()

					if resp.StatusCode == http.StatusOK {
						successCount++

						var scanResp ScanResponse
						if err := json.NewDecoder(resp.Body).Decode(&scanResp); err != nil {
							t.Log(err)
						} else if scanResp.IsThreat {
							threatsFound++
						}

						t.Logf("Scan result: %s", scanResp.ScanResult)
					} else {
						failureCount++
						t.Logf("Client %d request failed with status: %d", clientID, resp.StatusCode)
					}
				}
				mutex.Unlock()

				time.Sleep(100 * time.Millisecond)
			}
		}(i)
	}

	wg.Wait()

	testDuration := time.Since(startTime)
	t.Logf("Test runtime: %v", testDuration)

	t.Logf("Sum of requests duration: %v", totalDuration)

	successRate := float64(successCount) / float64(totalRequests) * 100
	failureRate := float64(failureCount) / float64(totalRequests) * 100
	t.Logf("Number of requests processed: %d\nSuccess rate: %f\nFailure rate: %f", totalRequests, successRate, failureRate)

	t.Logf("Number of threats found: %d", threatsFound)
}
