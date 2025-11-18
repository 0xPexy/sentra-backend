package config

import "strings"

type AdminConfig struct {
	Address string
}

func loadAdmin() AdminConfig {
	addr := strings.TrimSpace(strings.ToLower(getenv("ADMIN_ADDRESS", "")))
	if addr != "" && !strings.HasPrefix(addr, "0x") {
		addr = "0x" + addr
	}
	return AdminConfig{Address: addr}
}
