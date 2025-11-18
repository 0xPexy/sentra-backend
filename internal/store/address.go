package store

import "strings"

// NormalizeAddress ensures addresses are lowercase with 0x prefix.
func NormalizeAddress(addr string) string {
	s := strings.TrimSpace(strings.ToLower(addr))
	if s == "" {
		return ""
	}
	if !strings.HasPrefix(s, "0x") {
		s = "0x" + s
	}
	return s
}
