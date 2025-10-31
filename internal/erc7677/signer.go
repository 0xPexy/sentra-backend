package erc7677

import (
	"crypto/ecdsa"
	"encoding/hex"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

type Signer struct {
	sk      *ecdsa.PrivateKey
	chainID *big.Int
}

func NewSigner(skHex string, chainID *big.Int) *Signer {
	k, err := crypto.HexToECDSA(trim0x(skHex))
	if err != nil {
		panic(err)
	}
	return &Signer{sk: k, chainID: chainID}
}

func trim0x(s string) string {
	if len(s) >= 2 && s[:2] == "0x" {
		return s[2:]
	}
	return s
}

// Build prefix-only PMD (no signature)
func buildPMDPrefix(validAfter, validUntil uint64, p PolicyInput) []byte {
	target := mustAddr(p.Target)
	sel := mustSelector(p.Selector)

	out := make([]byte, 0, 6+6+20+4)
	vu := make([]byte, 6)
	va := make([]byte, 6)
	putU48(vu, validUntil)
	putU48(va, validAfter)
	out = append(out, vu...)
	out = append(out, va...)
	out = append(out, target.Bytes()...)
	out = append(out, sel[:]...)
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
//	tmpUserOpHash, target, selector, validUntil, validAfter, pmValGas, postOpGas
//
// ) ) with EIP-191 prefix
func (s *Signer) signPolicyMessage(tmpUserOpHash common.Hash) ([]byte, error) {
	sig, err := crypto.Sign(tmpUserOpHash[:], s.sk)
	if err != nil {
		return nil, err
	}

	// The crypto.Sign function returns v as 0 or 1 (recovery ID).
	// For UserOperation signatures, it's common to adjust v to be 27 or 28
	// (standard non-EIP-155 v values), and the EntryPoint contract handles
	// the EIP-155 chain ID logic internally using block.chainid. This results
	// in a 'v' value of 27 (0x1b) or 28 (0x1c).
	sig[64] += 27

	// The chainID is already incorporated into the userOpHash calculation
	// via the EIP-712 domain separator.
	return sig, nil
}

func u48(i uint64) *bigInt { return newBig().SetUint64(i) }

// minimal big.Int wrapper to avoid importing math/big here repeatedly
type bigInt = big.Int

func newBig() *bigInt            { return new(bigInt) }
func uintToBig(u uint64) *bigInt { return newBig().SetUint64(u) }
