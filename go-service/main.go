package main

import (
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/isshaan-dhar/VaultNet/auth"
	"github.com/isshaan-dhar/VaultNet/config"
	"github.com/isshaan-dhar/VaultNet/db"
	"github.com/isshaan-dhar/VaultNet/handlers"
	"github.com/isshaan-dhar/VaultNet/metrics"
	redisstore "github.com/isshaan-dhar/VaultNet/redis"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func main() {
	cfg := config.Load()

	store, err := db.New(cfg.PostgresDSN)
	if err != nil {
		log.Fatalf("failed to connect to postgres: %v", err)
	}
	defer store.Close()

	redis, err := redisstore.New(cfg.RedisAddr)
	if err != nil {
		log.Fatalf("failed to connect to redis: %v", err)
	}
	defer redis.Close()

	authManager := auth.NewManager(cfg.JWTSecret, redis)

	authHandler := handlers.NewAuthHandler(store, authManager)
	secretsHandler := handlers.NewSecretsHandler(store, redis, cfg.AESKey)

	r := chi.NewRouter()

	r.Use(chimiddleware.RequestID)
	r.Use(chimiddleware.RealIP)
	r.Use(chimiddleware.Logger)
	r.Use(chimiddleware.Recoverer)
	r.Use(chimiddleware.Timeout(30 * time.Second))
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			start := time.Now()
			ww := chimiddleware.NewWrapResponseWriter(w, req.ProtoMajor)
			next.ServeHTTP(ww, req)
			duration := time.Since(start).Seconds()
			metrics.RequestDuration.With(prometheus.Labels{
				"method": req.Method,
				"route":  req.URL.Path,
				"status": strconv.Itoa(ww.Status()),
			}).Observe(duration)
		})
	})

	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"ok"}`))
	})

	r.Handle("/metrics", promhttp.Handler())

	r.Post("/auth/register", authHandler.Register)
	r.Post("/auth/login", authHandler.Login)

	r.Group(func(r chi.Router) {
		r.Use(authManager.Middleware)
		r.Post("/secrets", secretsHandler.Store)
		r.Get("/secrets", secretsHandler.List)
		r.Get("/secrets/{name}", secretsHandler.Retrieve)
		r.Put("/secrets/{name}/rotate", secretsHandler.Rotate)
		r.Delete("/secrets/{name}", secretsHandler.Delete)
	})

	log.Printf("VaultNet running on :%s", cfg.AppPort)
	if err := http.ListenAndServe(":"+cfg.AppPort, r); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
