package auth

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

func JWTMiddleware(svc *Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		authz := c.GetHeader("Authorization")
		if authz == "" || !strings.HasPrefix(strings.ToLower(authz), "bearer ") {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing authorization"})
			return
		}
		token := strings.TrimSpace(authz[7:])
		claims, err := svc.Parse(token)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
			return
		}
		c.Set("adminID", claims.AdminID)
		c.Set("adminAddress", claims.Address)
		c.Next()
	}
}

// OptionalJWTMiddleware allows authenticated context when a valid token is provided
// but does not block requests lacking Authorization headers.
func OptionalJWTMiddleware(svc *Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		authz := c.GetHeader("Authorization")
		if authz == "" || !strings.HasPrefix(strings.ToLower(authz), "bearer ") {
			c.Next()
			return
		}
		token := strings.TrimSpace(authz[7:])
		claims, err := svc.Parse(token)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
			return
		}
		c.Set("adminID", claims.AdminID)
		c.Set("adminAddress", claims.Address)
		c.Next()
	}
}
