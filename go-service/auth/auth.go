package auth

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	redisstore "github.com/isshaan-dhar/VaultNet/redis"
)

type Claims struct {
	UserID   string `json:"user_id"`
	Username string `json:"username"`
	TokenID  string `json:"token_id"`
	jwt.RegisteredClaims
}

type Manager struct {
	secret []byte
	redis  *redisstore.Store
}

func NewManager(secret string, redis *redisstore.Store) *Manager {
	return &Manager{secret: []byte(secret), redis: redis}
}

func (m *Manager) GenerateToken(userID, username string) (string, error) {
	tokenID := userID + ":" + username + ":" + time.Now().String()

	claims := Claims{
		UserID:   userID,
		Username: username,
		TokenID:  tokenID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(m.secret)
}

func (m *Manager) ValidateClaims(tokenStr string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &Claims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return m.secret, nil
	})
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid token")
	}

	return claims, nil
}

type contextKey string

const ClaimsKey contextKey = "claims"

func (m *Manager) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
			http.Error(w, `{"error":"missing or malformed authorization header"}`, http.StatusUnauthorized)
			return
		}

		tokenStr := strings.TrimPrefix(authHeader, "Bearer ")

		claims, err := m.ValidateClaims(tokenStr)
		if err != nil {
			http.Error(w, `{"error":"invalid token"}`, http.StatusUnauthorized)
			return
		}

		blacklisted, err := m.redis.IsTokenBlacklisted(r.Context(), claims.TokenID)
		if err != nil || blacklisted {
			http.Error(w, `{"error":"token has been revoked"}`, http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), ClaimsKey, claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func GetClaims(r *http.Request) *Claims {
	claims, _ := r.Context().Value(ClaimsKey).(*Claims)
	return claims
}
