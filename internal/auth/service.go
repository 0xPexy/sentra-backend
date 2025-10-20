package auth

import (
	"context"
	"crypto/subtle"
	"errors"
	"time"

	"github.com/0xPexy/sentra-backend/internal/store"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

const devAdminID uint = 10000

type Service struct {
	secret []byte
	repo   *store.Repository
	ttl    time.Duration
	devTok string
	devID  uint
}

func NewService(secret string, repo *store.Repository, ttl time.Duration, devToken string) *Service {
	s := &Service{secret: []byte(secret), repo: repo, ttl: ttl, devTok: devToken}
	if devToken != "" {
		s.devID = devAdminID
	}
	return s
}

var ErrInvalidCredentials = errors.New("invalid credentials")

type Claims struct {
	AdminID  uint
	Username string
	jwt.RegisteredClaims
}

func (s *Service) Login(ctx context.Context, username, password string) (string, error) {
	admin, err := s.repo.GetAdminByUsername(ctx, username)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return "", ErrInvalidCredentials
		}
		return "", err
	}
	if err := bcrypt.CompareHashAndPassword([]byte(admin.PassHash), []byte(password)); err != nil {
		return "", ErrInvalidCredentials
	}

	now := time.Now()
	claims := Claims{
		AdminID:  admin.ID,
		Username: admin.Username,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   username,
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

func DevAdminID() uint { return devAdminID }

func constantTimeEquals(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
