package observability

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	ThreatsFound      prometheus.Counter
	RequestsProcessed prometheus.Counter
	FailureCount      prometheus.Counter
	TimeoutsExpired   prometheus.Counter
	RequestLatency    prometheus.Histogram
	ScanLatency       prometheus.Histogram
)

func init() {
	ThreatsFound = promauto.NewCounter(prometheus.CounterOpts{
		Name: "threats_found_total",
		Help: "The total number of threats found",
	})

	RequestsProcessed = promauto.NewCounter(prometheus.CounterOpts{
		Name: "requests_processed_total",
		Help: "The total number of requests processed",
	})

	FailureCount = promauto.NewCounter(prometheus.CounterOpts{
		Name: "failure_found_total",
		Help: "The total number of failures received",
	})

	TimeoutsExpired = promauto.NewCounter(prometheus.CounterOpts{
		Name: "timeouts_triggered_total",
		Help: "The total number of timeouts expired",
	})

	RequestLatency = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "scan_duration",
		Help:    "Duration for processing a scan",
		Buckets: prometheus.LinearBuckets(1, 120, 5), // Cover up to 10m, inside buckets of 2m
	})

	ScanLatency = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "scan_duration",
		Help:    "Duration for processing a scan",
		Buckets: prometheus.LinearBuckets(1, 120, 5), // Cover up to 10m, inside buckets of 2m
	})
}
