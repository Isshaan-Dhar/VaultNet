package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	SecretsStored = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "vaultnet_secrets_stored_total",
		Help: "Total number of active secrets currently stored",
	})

	SecretsRotated = promauto.NewCounter(prometheus.CounterOpts{
		Name: "vaultnet_secrets_rotated_total",
		Help: "Total number of secret rotation operations performed",
	})

	SecretsDeleted = promauto.NewCounter(prometheus.CounterOpts{
		Name: "vaultnet_secrets_deleted_total",
		Help: "Total number of secrets soft-deleted",
	})

	AnomaliesDetected = promauto.NewCounter(prometheus.CounterOpts{
		Name: "vaultnet_anomalies_detected_total",
		Help: "Total number of anomalies flagged by the audit analyser",
	})

	AuthFailures = promauto.NewCounter(prometheus.CounterOpts{
		Name: "vaultnet_auth_failures_total",
		Help: "Total number of failed authentication attempts",
	})

	RequestDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "vaultnet_request_duration_seconds",
		Help:    "HTTP request duration in seconds",
		Buckets: prometheus.DefBuckets,
	}, []string{"method", "route", "status"})
)
