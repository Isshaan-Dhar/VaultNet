package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/isshaan-dhar/VaultNet/metrics"
)

type InternalHandler struct{}

func NewInternalHandler() *InternalHandler {
	return &InternalHandler{}
}

type anomalyNotification struct {
	AnomalyType string `json:"anomaly_type"`
	Severity    string `json:"severity"`
}

func (h *InternalHandler) RecordAnomaly(w http.ResponseWriter, r *http.Request) {
	var n anomalyNotification
	if err := json.NewDecoder(r.Body).Decode(&n); err != nil {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}
	metrics.AnomaliesDetected.WithLabelValues(n.AnomalyType, n.Severity).Inc()
	w.WriteHeader(http.StatusNoContent)
}
