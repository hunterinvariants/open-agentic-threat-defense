package store

import (
	"context"
	"fmt"
	"time"
)

const gatewayAdvisoryLockBase = 82043001

func (s *Store) AcquireGatewayLease(ctx context.Context, limit int) (func(), bool, error) {
	s.mu.RLock()
	db := s.db
	s.mu.RUnlock()
	if db == nil {
		return nil, false, nil
	}
	if limit <= 0 {
		limit = 1
	}
	conn, err := db.Conn(ctx)
	if err != nil {
		return nil, false, err
	}
	for slot := int64(1); slot <= int64(limit); slot++ {
		lockID := gatewayAdvisoryLockBase + slot
		var ok bool
		if err := conn.QueryRowContext(ctx, `SELECT pg_try_advisory_lock($1)`, lockID).Scan(&ok); err != nil {
			_ = conn.Close()
			return nil, false, err
		}
		if !ok {
			continue
		}
		release := func() {
			unlockCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_, _ = conn.ExecContext(unlockCtx, `SELECT pg_advisory_unlock($1)`, lockID)
			_ = conn.Close()
		}
		return release, true, nil
	}
	_ = conn.Close()
	return nil, false, nil
}

func (s *Store) GatewayLimitStatus() (int, string) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.db == nil {
		return 0, "memory"
	}
	return 0, fmt.Sprintf("postgres:%s", s.mode)
}
