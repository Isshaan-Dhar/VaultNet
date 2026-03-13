package handlers

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/isshaan-dhar/VaultNet/auth"
	"github.com/isshaan-dhar/VaultNet/db"
	"github.com/isshaan-dhar/VaultNet/metrics"
	"golang.org/x/crypto/bcrypt"
)

type AuthHandler struct {
	store   *db.Store
	manager *auth.Manager
}

func NewAuthHandler(store *db.Store, manager *auth.Manager) *AuthHandler {
	return &AuthHandler{store: store, manager: manager}
}

type registerRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type tokenResponse struct {
	Token string `json:"token"`
}

func ipFromRequest(r *http.Request) string {
	ip := r.Header.Get("X-Forwarded-For")
	if ip != "" {
		return strings.Split(ip, ",")[0]
	}
	return r.RemoteAddr
}

func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	var req registerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}

	if len(req.Username) < 3 || len(req.Password) < 8 {
		http.Error(w, `{"error":"username min 3 chars, password min 8 chars"}`, http.StatusBadRequest)
		return
	}

	existing, err := h.store.GetUserByUsername(r.Context(), req.Username)
	if err != nil {
		http.Error(w, `{"error":"database error"}`, http.StatusInternalServerError)
		return
	}
	if existing != nil {
		http.Error(w, `{"error":"username already taken"}`, http.StatusConflict)
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, `{"error":"failed to hash password"}`, http.StatusInternalServerError)
		return
	}

	user, err := h.store.CreateUser(r.Context(), req.Username, string(hash))
	if err != nil {
		http.Error(w, `{"error":"failed to create user"}`, http.StatusInternalServerError)
		return
	}

	h.store.WriteAuditLog(r.Context(), db.AuditEntry{
		UserID:    &user.ID,
		Username:  user.Username,
		Action:    "REGISTER",
		IPAddress: ipFromRequest(r),
		UserAgent: r.UserAgent(),
		Status:    "SUCCESS",
	})

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"id": user.ID, "username": user.Username})
}

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}

	user, err := h.store.GetUserByUsername(r.Context(), req.Username)
	if err != nil {
		http.Error(w, `{"error":"database error"}`, http.StatusInternalServerError)
		return
	}

	if user == nil || bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)) != nil {
		metrics.AuthFailures.Inc()
		h.store.WriteAuditLog(r.Context(), db.AuditEntry{
			Username:  req.Username,
			Action:    "LOGIN",
			IPAddress: ipFromRequest(r),
			UserAgent: r.UserAgent(),
			Status:    "FAILURE",
			Detail:    "invalid credentials",
		})
		http.Error(w, `{"error":"invalid credentials"}`, http.StatusUnauthorized)
		return
	}

	token, err := h.manager.GenerateToken(user.ID, user.Username)
	if err != nil {
		http.Error(w, `{"error":"failed to generate token"}`, http.StatusInternalServerError)
		return
	}

	h.store.UpdateLastLogin(r.Context(), user.ID)
	h.store.WriteAuditLog(r.Context(), db.AuditEntry{
		UserID:    &user.ID,
		Username:  user.Username,
		Action:    "LOGIN",
		IPAddress: ipFromRequest(r),
		UserAgent: r.UserAgent(),
		Status:    "SUCCESS",
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(tokenResponse{Token: token})
}
