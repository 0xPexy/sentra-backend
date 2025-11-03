package server

import (
	"time"

	"github.com/0xPexy/sentra-backend/internal/admin"
	"github.com/0xPexy/sentra-backend/internal/auth"
	"github.com/0xPexy/sentra-backend/internal/config"
	"github.com/0xPexy/sentra-backend/internal/erc7677"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
)

func NewRouter(cfg config.Config, authSvc *auth.Service, pm *erc7677.Handler, adminH *admin.Handler) *gin.Engine {
	r := gin.New()
	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"*"},
		AllowMethods:     []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"*"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))

	r.GET("/healthz", func(c *gin.Context) { c.JSON(200, gin.H{"ok": true}) })
	r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))
	addrH := newAddressHandler(cfg)
	api := r.Group("/api/v1")
	api.GET("/addresses", addrH.LookupAddress)

	r.POST("/auth/login", adminH.Login)
	guard := auth.JWTMiddleware(authSvc)
	ad := api.Group("", guard)
	{
		ad.POST("/erc7677", pm.HandleJSONRPC)
		ad.GET("/me", adminH.Me)

		ad.POST("/paymasters", adminH.CreatePaymaster)
		ad.GET("/paymasters", adminH.ListPaymasters)
		ad.GET("/paymasters/me", adminH.GetPaymaster)
		ad.PATCH("/paymasters/me", adminH.UpdatePaymaster)

		ad.POST("/paymasters/me/contracts", adminH.AddContract)
		ad.PATCH("/paymasters/me/contracts/:contractId", adminH.UpdateContract)
		ad.DELETE("/paymasters/me/contracts/:contractId", adminH.DeleteContract)
		ad.PATCH("/paymasters/me/users", adminH.ReplaceUsers)
		ad.POST("/paymasters/me/users", adminH.AddUser)
		ad.DELETE("/paymasters/me/users/:address", adminH.DeleteUser)
		ad.GET("/paymasters/me/contracts", adminH.ListContracts)
		ad.GET("/paymasters/me/users", adminH.ListUsers)

		ad.GET("/paymasters/me/operations", adminH.ListOperations)
		ad.GET("/contracts/:name", adminH.GetContractArtifact)
	}

	return r
}
