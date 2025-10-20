package erc7677

import (
	"encoding/hex"
	"encoding/json"
	"math/big"
	"strings"
	"time"

	"github.com/0xPexy/sentra-backend/internal/config"
	"github.com/0xPexy/sentra-backend/internal/store"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
)

type Policy struct {
	repo   *store.Repository
	cfg    config.Config
	defDur time.Duration
}

func NewPolicy(repo *store.Repository, cfg config.Config) *Policy {
	return &Policy{repo: repo, cfg: cfg, defDur: 10 * time.Minute}
}

// utils moved here for packing
func mustABIType(t string) abi.Type {
	typ, err := abi.NewType(t, "", nil)
	if err != nil {
		panic(err)
	}
	return typ
}
func abiPack(args abi.Arguments, values ...any) []byte {
	b, err := args.Pack(values...)
	if err != nil {
		panic(err)
	}
	return b
}
func hex0x(b []byte) string { return "0x" + hex.EncodeToString(b) }
func hexUint(u uint64) string {
	return "0x" + strings.TrimLeft(hex.EncodeToString(new(big.Int).SetUint64(u).Bytes()), "0")
}
func strOr(v any, def string) string {
	if s, ok := v.(string); ok {
		return s
	}
	return def
}
func uint16Or(v any, def uint16) uint16 {
	switch x := v.(type) {
	case float64:
		if x < 0 {
			return def
		}
		if x > 65535 {
			return 65535
		}
		return uint16(x)
	case json.Number:
		i, _ := x.Int64()
		if i < 0 {
			return def
		}
		if i > 65535 {
			return 65535
		}
		return uint16(i)
	default:
		return def
	}
}

// expose helpers used by signer/handler
func mustAddr(s string) common.Address { return common.HexToAddress(s) }
