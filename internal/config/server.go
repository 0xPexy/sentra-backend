package config

type ServerConfig struct {
	HTTPAddr string
}

func loadServer() ServerConfig {
	return ServerConfig{
		HTTPAddr: getenv("HTTP_ADDR", ":8080"),
	}
}
