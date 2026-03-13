package handlers

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/isshaan-dhar/VaultNet/auth"
	vaultcrypto "github.com/isshaan-dhar/VaultNet/crypto"
	"github.com/isshaan-dhar/VaultNet/db"
	"github.com/isshaan-dhar/VaultNet/metrics"
	redisstore "github.com/isshaan-dhar/VaultNet/redis"
)

type SecretsHandler struct {
	store  *db.Store
	redis  *redisstore.Store
	aesKey []byte
}

func NewSecretsHandler(store *db.Store, redis *redisstore.Store, aesKey []byte) *SecretsHandler {
	return &SecretsHandler{store: store, redis: redis, aesKey: aesKey}
}

type storeSecretRequest struct {
	Name       string `json:"name"`
	Value      string `json:"value"`
	TTLSeconds *int   `json:"ttl_seconds,omitempty"`
}

type rotateSecretRequest struct {
	NewValue string `json:"new_value"`
}

type secretResponse struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	Version   int        `json:"version"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
}

type secretValueResponse struct {
	secretResponse
	Value string `json:"value"`
}

func toSecretResponse(s *db.Secret) secretResponse {
	return secretResponse{
		ID:        s.ID,
		Name:      s.Name,
		Version:   s.Version,
		ExpiresAt: s.ExpiresAt,
		CreatedAt: s.CreatedAt,
		UpdatedAt: s.UpdatedAt,
	}
}

func (h *SecretsHandler) Store(w http.ResponseWriter, r *http.Request) {
	claims := auth.GetClaims(r)

	var req storeSecretRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}

	if req.Name == "" || req.Value == "" {
		http.Error(w, `{"error":"name and value are required"}`, http.StatusBadRequest)
		return
	}

	encrypted, nonce, err := vaultcrypto.Encrypt(h.aesKey, req.Value)
	if err != nil {
		http.Error(w, `{"error":"encryption failed"}`, http.StatusInternalServerError)
		return
	}

	sec, err := h.store.CreateSecret(r.Context(), claims.UserID, req.Name, encrypted, nonce, req.TTLSeconds)
	if err != nil {
		http.Error(w, `{"error":"failed to store secret"}`, http.StatusInternalServerError)
		return
	}

	if req.TTLSeconds != nil && *req.TTLSeconds > 0 {
		h.redis.SetExpiry(r.Context(), sec.ID, time.Duration(*req.TTLSeconds)*time.Second)
	}

	metrics.SecretsStored.Inc()

	h.store.WriteAuditLog(r.Context(), db.AuditEntry{
		UserID:     &claims.UserID,
		Username:   claims.Username,
		Action:     "STORE",
		SecretName: &req.Name,
		SecretID:   &sec.ID,
		IPAddress:  ipFromRequest(r),
		UserAgent:  r.UserAgent(),
		Status:     "SUCCESS",
	})

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(toSecretResponse(sec))
}

func (h *SecretsHandler) Retrieve(w http.ResponseWriter, r *http.Request) {
	claims := auth.GetClaims(r)
	name := chi.URLParam(r, "name")

	sec, err := h.store.GetSecret(r.Context(), claims.UserID, name)
	if err != nil {
		http.Error(w, `{"error":"database error"}`, http.StatusInternalServerError)
		return
	}
	if sec == nil {
		http.Error(w, `{"error":"secret not found"}`, http.StatusNotFound)
		return
	}

	expired, err := h.redis.IsExpired(r.Context(), sec.ID)
	if err == nil && expired && sec.TTLSeconds != nil {
		http.Error(w, `{"error":"secret has expired"}`, http.StatusGone)
		return
	}

	plaintext, err := vaultcrypto.Decrypt(h.aesKey, sec.EncryptedValue, sec.Nonce)
	if err != nil {
		http.Error(w, `{"error":"decryption failed"}`, http.StatusInternalServerError)
		return
	}

	h.store.WriteAuditLog(r.Context(), db.AuditEntry{
		UserID:     &claims.UserID,
		Username:   claims.Username,
		Action:     "RETRIEVE",
		SecretName: &name,
		SecretID:   &sec.ID,
		IPAddress:  ipFromRequest(r),
		UserAgent:  r.UserAgent(),
		Status:     "SUCCESS",
	})

	resp := secretValueResponse{
		secretResponse: toSecretResponse(sec),
		Value:          plaintext,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (h *SecretsHandler) List(w http.ResponseWriter, r *http.Request) {
	claims := auth.GetClaims(r)

	secrets, err := h.store.ListSecrets(r.Context(), claims.UserID)
	if err != nil {
		http.Error(w, `{"error":"database error"}`, http.StatusInternalServerError)
		return
	}

	var result []secretResponse
	for i := range secrets {
		result = append(result, toSecretResponse(&secrets[i]))
	}

	if result == nil {
		result = []secretResponse{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func (h *SecretsHandler) Rotate(w http.ResponseWriter, r *http.Request) {
	claims := auth.GetClaims(r)
	name := chi.URLParam(r, "name")

	var req rotateSecretRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}

	if req.NewValue == "" {
		http.Error(w, `{"error":"new_value is required"}`, http.StatusBadRequest)
		return
	}

	encrypted, nonce, err := vaultcrypto.Encrypt(h.aesKey, req.NewValue)
	if err != nil {
		http.Error(w, `{"error":"encryption failed"}`, http.StatusInternalServerError)
		return
	}

	sec, err := h.store.RotateSecret(r.Context(), claims.UserID, name, encrypted, nonce)
	if err != nil {
		http.Error(w, `{"error":"database error"}`, http.StatusInternalServerError)
		return
	}
	if sec == nil {
		http.Error(w, `{"error":"secret not found"}`, http.StatusNotFound)
		return
	}

	metrics.SecretsRotated.Inc()

	h.store.WriteAuditLog(r.Context(), db.AuditEntry{
		UserID:     &claims.UserID,
		Username:   claims.Username,
		Action:     "ROTATE",
		SecretName: &name,
		SecretID:   &sec.ID,
		IPAddress:  ipFromRequest(r),
		UserAgent:  r.UserAgent(),
		Status:     "SUCCESS",
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(toSecretResponse(sec))
}

func (h *SecretsHandler) Delete(w http.ResponseWriter, r *http.Request) {
	claims := auth.GetClaims(r)
	name := chi.URLParam(r, "name")

	sec, err := h.store.GetSecret(r.Context(), claims.UserID, name)
	if err != nil {
		http.Error(w, `{"error":"database error"}`, http.StatusInternalServerError)
		return
	}
	if sec == nil {
		http.Error(w, `{"error":"secret not found"}`, http.StatusNotFound)
		return
	}

	deleted, err := h.store.DeleteSecret(r.Context(), claims.UserID, name)
	if err != nil || !deleted {
		http.Error(w, `{"error":"failed to delete secret"}`, http.StatusInternalServerError)
		return
	}

	h.redis.DeleteExpiry(r.Context(), sec.ID)
	metrics.SecretsDeleted.Inc()

	h.store.WriteAuditLog(r.Context(), db.AuditEntry{
		UserID:     &claims.UserID,
		Username:   claims.Username,
		Action:     "DELETE",
		SecretName: &name,
		SecretID:   &sec.ID,
		IPAddress:  ipFromRequest(r),
		UserAgent:  r.UserAgent(),
		Status:     "SUCCESS",
	})

	w.WriteHeader(http.StatusNoContent)
}
