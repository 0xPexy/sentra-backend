package erc7677

import (
	"crypto/ecdsa"
	"encoding/binary"
	"encoding/hex"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

type Signer struct {
	sk *ecdsa.PrivateKey
}

func NewSigner(skHex string) *Signer {
	k, err := crypto.HexToECDSA(trim0x(skHex))
	if err != nil {
		panic(err)
	}
	return &Signer{sk: k}
}

func trim0x(s string) string {
	if len(s) >= 2 && s[:2] == "0x" {
		return s[2:]
	}
	return s
}

// Build prefix-only PMD (no signature)
func buildPMDPrefix(paymaster string, pmValGas, postOpGas uint64, now uint64, validFor time.Duration, p PolicyInput) []byte {
	validAfter := now
	validUntil := now + uint64(validFor/time.Second)
	pmAddr := mustAddr(paymaster)
	target := mustAddr(p.Target)
	sel := mustSelector(p.Selector)

	out := make([]byte, 0, 20+16+16+6+6+20+4+2)
	out = append(out, pmAddr.Bytes()...)
	out = append(out, u128(pmValGas)...)
	out = append(out, u128(postOpGas)...)

	vu := make([]byte, 6)
	va := make([]byte, 6)
	putU48(vu, validUntil)
	putU48(va, validAfter)
	out = append(out, vu...)
	out = append(out, va...)
	out = append(out, target.Bytes()...)
	out = append(out, sel[:]...)
	out = append(out, byte(p.SubsidyBps>>8), byte(p.SubsidyBps))
	return out
}

func putU48(dst []byte, v uint64) {
	dst[0] = byte(v >> 40)
	dst[1] = byte(v >> 32)
	dst[2] = byte(v >> 24)
	dst[3] = byte(v >> 16)
	dst[4] = byte(v >> 8)
	dst[5] = byte(v)
}

func u128(v uint64) []byte {
	buf := make([]byte, 16)
	binary.BigEndian.PutUint64(buf[8:], v)
	return buf
}

func mustSelector(s string) [4]byte {
	s = trim0x(s)
	b, _ := hex.DecodeString(s)
	var out [4]byte
	copy(out[:], b)
	return out
}

// tmpUserOpHash: draft extractor
func extractTmpUserOpHash(ctx map[string]any) (common.Hash, error) {
	if h, ok := ctx["userOpHash"].(string); ok && len(h) > 0 {
		return common.HexToHash(h), nil
	}
	return common.Hash{}, nil
}

// policy message hash = keccak256( abi.encode(
//
//	tmpUserOpHash, target, selector, subsidyBps, validUntil, validAfter, pmValGas, postOpGas
//
// ) ) with EIP-191 prefix
func (s *Signer) signPolicyMessage(tmpUserOpHash common.Hash, p PolicyInput, vu, va uint64, pmValGas, postOpGas uint64) ([]byte, error) {
	args := abi.Arguments{
		{Type: mustABIType("bytes32")},
		{Type: mustABIType("address")},
		{Type: mustABIType("bytes4")},
		{Type: mustABIType("uint16")},
		{Type: mustABIType("uint48")},
		{Type: mustABIType("uint48")},
		{Type: mustABIType("uint128")},
		{Type: mustABIType("uint128")},
	}
	packed := abiPack(args,
		tmpUserOpHash,
		mustAddr(p.Target),
		mustSelector(p.Selector),
		p.SubsidyBps,
		u48(vu), u48(va),
		uintToBig(pmValGas),
		uintToBig(postOpGas),
	)
	msg := crypto.Keccak256(packed)
	ethSigned := crypto.Keccak256Hash(append([]byte("\x19Ethereum Signed Message:\n32"), msg...))
	return crypto.Sign(ethSigned[:], s.sk)
}

func u48(i uint64) *bigInt { return newBig().SetUint64(i) }

// minimal big.Int wrapper to avoid importing math/big here repeatedly
type bigInt = big.Int

func newBig() *bigInt            { return new(bigInt) }
func uintToBig(u uint64) *bigInt { return newBig().SetUint64(u) }
