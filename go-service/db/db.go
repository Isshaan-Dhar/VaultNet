package db

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Store struct {
	pool *pgxpool.Pool
}

func New(dsn string) (*Store, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, err
	}

	if err := pool.Ping(ctx); err != nil {
		return nil, err
	}

	return &Store{pool: pool}, nil
}

func (s *Store) Close() {
	s.pool.Close()
}

type User struct {
	ID           string
	Username     string
	PasswordHash string
	CreatedAt    time.Time
	LastLogin    *time.Time
}

type Secret struct {
	ID             string
	OwnerID        string
	Name           string
	EncryptedValue string
	Nonce          string
	Version        int
	TTLSeconds     *int
	ExpiresAt      *time.Time
	CreatedAt      time.Time
	UpdatedAt      time.Time
	IsActive       bool
}

type AuditEntry struct {
	UserID     *string
	Username   string
	Action     string
	SecretName *string
	SecretID   *string
	IPAddress  string
	UserAgent  string
	Status     string
	Detail     string
}

func (s *Store) CreateUser(ctx context.Context, username, passwordHash string) (*User, error) {
	var u User
	err := s.pool.QueryRow(ctx,
		`INSERT INTO users (username, password_hash)
		 VALUES ($1, $2)
		 RETURNING id, username, password_hash, created_at`,
		username, passwordHash,
	).Scan(&u.ID, &u.Username, &u.PasswordHash, &u.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &u, nil
}

func (s *Store) GetUserByUsername(ctx context.Context, username string) (*User, error) {
	var u User
	err := s.pool.QueryRow(ctx,
		`SELECT id, username, password_hash, created_at, last_login
		 FROM users WHERE username = $1`,
		username,
	).Scan(&u.ID, &u.Username, &u.PasswordHash, &u.CreatedAt, &u.LastLogin)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return &u, nil
}

func (s *Store) UpdateLastLogin(ctx context.Context, userID string) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE users SET last_login = NOW() WHERE id = $1`,
		userID,
	)
	return err
}

func (s *Store) CreateSecret(ctx context.Context, ownerID, name, encryptedValue, nonce string, ttlSeconds *int) (*Secret, error) {
	var sec Secret
	var expiresAt *time.Time

	if ttlSeconds != nil && *ttlSeconds > 0 {
		t := time.Now().Add(time.Duration(*ttlSeconds) * time.Second)
		expiresAt = &t
	}

	err := s.pool.QueryRow(ctx,
		`INSERT INTO secrets (owner_id, name, encrypted_value, nonce, ttl_seconds, expires_at)
		 VALUES ($1, $2, $3, $4, $5, $6)
		 RETURNING id, owner_id, name, encrypted_value, nonce, version, ttl_seconds, expires_at, created_at, updated_at, is_active`,
		ownerID, name, encryptedValue, nonce, ttlSeconds, expiresAt,
	).Scan(
		&sec.ID, &sec.OwnerID, &sec.Name, &sec.EncryptedValue, &sec.Nonce,
		&sec.Version, &sec.TTLSeconds, &sec.ExpiresAt, &sec.CreatedAt, &sec.UpdatedAt, &sec.IsActive,
	)
	if err != nil {
		return nil, err
	}
	return &sec, nil
}

func (s *Store) GetSecret(ctx context.Context, ownerID, name string) (*Secret, error) {
	var sec Secret
	err := s.pool.QueryRow(ctx,
		`SELECT id, owner_id, name, encrypted_value, nonce, version, ttl_seconds, expires_at, created_at, updated_at, is_active
		 FROM secrets
		 WHERE owner_id = $1 AND name = $2 AND is_active = TRUE`,
		ownerID, name,
	).Scan(
		&sec.ID, &sec.OwnerID, &sec.Name, &sec.EncryptedValue, &sec.Nonce,
		&sec.Version, &sec.TTLSeconds, &sec.ExpiresAt, &sec.CreatedAt, &sec.UpdatedAt, &sec.IsActive,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return &sec, nil
}

func (s *Store) ListSecrets(ctx context.Context, ownerID string) ([]Secret, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, owner_id, name, encrypted_value, nonce, version, ttl_seconds, expires_at, created_at, updated_at, is_active
		 FROM secrets
		 WHERE owner_id = $1 AND is_active = TRUE
		 ORDER BY created_at DESC`,
		ownerID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var secrets []Secret
	for rows.Next() {
		var sec Secret
		if err := rows.Scan(
			&sec.ID, &sec.OwnerID, &sec.Name, &sec.EncryptedValue, &sec.Nonce,
			&sec.Version, &sec.TTLSeconds, &sec.ExpiresAt, &sec.CreatedAt, &sec.UpdatedAt, &sec.IsActive,
		); err != nil {
			return nil, err
		}
		secrets = append(secrets, sec)
	}
	return secrets, nil
}

func (s *Store) RotateSecret(ctx context.Context, ownerID, name, newEncryptedValue, newNonce string) (*Secret, error) {
	var sec Secret
	err := s.pool.QueryRow(ctx,
		`UPDATE secrets
		 SET encrypted_value = $1, nonce = $2, version = version + 1, updated_at = NOW()
		 WHERE owner_id = $3 AND name = $4 AND is_active = TRUE
		 RETURNING id, owner_id, name, encrypted_value, nonce, version, ttl_seconds, expires_at, created_at, updated_at, is_active`,
		newEncryptedValue, newNonce, ownerID, name,
	).Scan(
		&sec.ID, &sec.OwnerID, &sec.Name, &sec.EncryptedValue, &sec.Nonce,
		&sec.Version, &sec.TTLSeconds, &sec.ExpiresAt, &sec.CreatedAt, &sec.UpdatedAt, &sec.IsActive,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return &sec, nil
}

func (s *Store) DeleteSecret(ctx context.Context, ownerID, name string) (bool, error) {
	tag, err := s.pool.Exec(ctx,
		`UPDATE secrets SET is_active = FALSE, updated_at = NOW()
		 WHERE owner_id = $1 AND name = $2 AND is_active = TRUE`,
		ownerID, name,
	)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

func (s *Store) WriteAuditLog(ctx context.Context, entry AuditEntry) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO audit_log (user_id, username, action, secret_name, secret_id, ip_address, user_agent, status, detail)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		entry.UserID, entry.Username, entry.Action, entry.SecretName, entry.SecretID,
		entry.IPAddress, entry.UserAgent, entry.Status, entry.Detail,
	)
	return err
}
