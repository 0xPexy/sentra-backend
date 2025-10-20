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
		if svc.IsDevToken(token) {
			c.Set("adminID", svc.DevAdminID())
			c.Set("adminUsername", "dev-token")
			c.Next()
			return
		}

		claims, err := svc.Parse(token)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
			return
		}
		c.Set("adminID", claims.AdminID)
		c.Set("adminUsername", claims.Username)
		c.Next()
	}
}
