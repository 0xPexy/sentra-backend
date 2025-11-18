package auth

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

type nonceStore struct {
	mu     sync.Mutex
	values map[string]time.Time
	ttl    time.Duration
}

func newNonceStore(ttl time.Duration) *nonceStore {
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	return &nonceStore{
		values: make(map[string]time.Time),
		ttl:    ttl,
	}
}

func (s *nonceStore) Issue() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	nonce := hex.EncodeToString(buf)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanupLocked()
	s.values[nonce] = time.Now().Add(s.ttl)
	return nonce, nil
}

func (s *nonceStore) Has(nonce string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanupLocked()
	exp, ok := s.values[nonce]
	if !ok {
		return false
	}
	if time.Now().After(exp) {
		delete(s.values, nonce)
		return false
	}
	return true
}

func (s *nonceStore) Consume(nonce string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.values, nonce)
}

func (s *nonceStore) cleanupLocked() {
	now := time.Now()
	for nonce, expiry := range s.values {
		if now.After(expiry) {
			delete(s.values, nonce)
		}
	}
}
