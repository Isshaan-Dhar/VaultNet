package redisstore

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
)

type Store struct {
	client *redis.Client
}

func New(addr string) (*Store, error) {
	client := redis.NewClient(&redis.Options{
		Addr: addr,
		DB:   0,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		return nil, err
	}

	return &Store{client: client}, nil
}

func (s *Store) Close() error {
	return s.client.Close()
}

func (s *Store) SetExpiry(ctx context.Context, secretID string, ttl time.Duration) error {
	return s.client.Set(ctx, "secret:expiry:"+secretID, "1", ttl).Err()
}

func (s *Store) IsExpired(ctx context.Context, secretID string) (bool, error) {
	val, err := s.client.Exists(ctx, "secret:expiry:"+secretID).Result()
	if err != nil {
		return false, err
	}
	return val == 0, nil
}

func (s *Store) DeleteExpiry(ctx context.Context, secretID string) error {
	return s.client.Del(ctx, "secret:expiry:"+secretID).Err()
}

func (s *Store) BlacklistToken(ctx context.Context, tokenID string, ttl time.Duration) error {
	return s.client.Set(ctx, "token:blacklist:"+tokenID, "1", ttl).Err()
}

func (s *Store) IsTokenBlacklisted(ctx context.Context, tokenID string) (bool, error) {
	val, err := s.client.Exists(ctx, "token:blacklist:"+tokenID).Result()
	if err != nil {
		return false, err
	}
	return val == 1, nil
}
