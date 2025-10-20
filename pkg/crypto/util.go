package crypto

import (
	"encoding/hex"
)

func Hex0x(b []byte) string { return "0x" + hex.EncodeToString(b) }
