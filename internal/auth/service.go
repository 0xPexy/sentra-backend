package auth

import (
	"context"
	"crypto/subtle"
	"errors"
	"strings"
	"time"

	"github.com/0xPexy/sentra-backend/internal/config"
	"github.com/0xPexy/sentra-backend/internal/store"
	"github.com/golang-jwt/jwt/v5"
	"github.com/spruceid/siwe-go"
)

const devAdminID uint = 10000

var ErrInvalidCredentials = errors.New("invalid credentials")

type Claims struct {
	AdminID uint
	Address string
	jwt.RegisteredClaims
}

type Service struct {
	secret    []byte
	repo      *store.Repository
	ttl       time.Duration
	devTok    string
	devID     uint
	nonces    *nonceStore
	domain    string
	uri       string
	statement string
	chainID   uint64
	allowed   map[string]struct{}
}

func NewService(cfg config.AuthConfig, adminAddrs []string, repo *store.Repository) *Service {
	s := &Service{
		secret:    []byte(cfg.JWTSecret),
		repo:      repo,
		ttl:       cfg.JWTTTL,
		devTok:    cfg.DevToken,
		nonces:    newNonceStore(cfg.NonceTTL),
		domain:    strings.TrimSpace(cfg.SIWEDomain),
		uri:       strings.TrimSpace(cfg.SIWEURI),
		statement: strings.TrimSpace(cfg.SIWEStatement),
		chainID:   cfg.SIWEChainID,
		allowed:   make(map[string]struct{}),
	}
	if cfg.DevToken != "" {
		s.devID = devAdminID
	}
	for _, addr := range adminAddrs {
		norm := store.NormalizeAddress(addr)
		if norm == "" {
			continue
		}
		s.allowed[norm] = struct{}{}
	}
	return s
}

func (s *Service) IssueNonce() (string, error) {
	return s.nonces.Issue()
}

func (s *Service) LoginWithSIWE(ctx context.Context, message, signature string) (string, error) {
	if strings.TrimSpace(message) == "" || strings.TrimSpace(signature) == "" {
		return "", ErrInvalidCredentials
	}
	if len(s.allowed) == 0 {
		return "", ErrInvalidCredentials
	}

	parsed, err := siwe.ParseMessage(message)
	if err != nil {
		return "", ErrInvalidCredentials
	}
	nonce := parsed.GetNonce()
	if !s.nonces.Has(nonce) {
		return "", ErrInvalidCredentials
	}
	var domain *string
	if s.domain != "" {
		d := s.domain
		domain = &d
	}
	if s.uri != "" {
		uri := parsed.GetURI()
		if uri.String() != s.uri {
			return "", ErrInvalidCredentials
		}
	}
	if s.statement != "" {
		if stmt := parsed.GetStatement(); stmt == nil || strings.TrimSpace(*stmt) != s.statement {
			return "", ErrInvalidCredentials
		}
	}
	if s.chainID > 0 && parsed.GetChainID() != int(s.chainID) {
		return "", ErrInvalidCredentials
	}
	if _, err := parsed.Verify(signature, domain, &nonce, nil); err != nil {
		return "", ErrInvalidCredentials
	}
	addr := store.NormalizeAddress(parsed.GetAddress().Hex())
	if _, ok := s.allowed[addr]; !ok {
		return "", ErrInvalidCredentials
	}
	admin, err := s.repo.GetAdminByAddress(ctx, addr)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return "", ErrInvalidCredentials
		}
		return "", err
	}
	s.nonces.Consume(nonce)
	now := time.Now()
	claims := Claims{
		AdminID: admin.ID,
		Address: addr,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   addr,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(s.ttl)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(s.secret)
}

func (s *Service) Parse(tokenStr string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &Claims{}, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, ErrInvalidCredentials
		}
		return s.secret, nil
	})
	if err != nil {
		return nil, ErrInvalidCredentials
	}
	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		return claims, nil
	}
	return nil, ErrInvalidCredentials
}

func (s *Service) IsDevToken(tok string) bool {
	if s.devTok == "" {
		return false
	}
	return constantTimeEquals(s.devTok, tok)
}

func (s *Service) DevAdminID() uint {
	return s.devID
}

func (s *Service) DevAdminAddress() string {
	return "dev-token"
}

func constantTimeEquals(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
