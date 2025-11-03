package config

type AdminConfig struct {
	Username string
	Password string
}

func loadAdmin() AdminConfig {
	return AdminConfig{
		Username: getenv("ADMIN_USERNAME", "admin"),
		Password: getenv("ADMIN_PASSWORD", "admin123"),
	}
}
