package pipeline

import (
	"encoding/json"
	"math/big"
	"strings"

	"github.com/0xPexy/sentra-backend/internal/store"
	"github.com/ethereum/go-ethereum/common"
)

type PhaseGas struct {
	Phase    string `json:"phase"`
	GasUsed  string `json:"gasUsed"`
	GasLimit string `json:"gasLimit,omitempty"`
}

type phaseSummary struct {
	Phases                        []PhaseGas
	VerificationGasLimit          string
	CallGasLimit                  string
	PaymasterVerificationGasLimit string
	PaymasterPostOpGasLimit       string
	PreVerificationGas            string
	MaxFeePerGas                  string
	MaxPriorityFeePerGas          string
}

func summarizeTrace(result *TraceResult, event *store.UserOperationEvent, entryPoint common.Address) phaseSummary {
	summary := phaseSummary{}
	if result == nil || event == nil {
		return summary
	}
	userOpHash := strings.ToLower(event.UserOpHash)
	if userOpHash == "" {
		return summary
	}

	totals := map[string]*big.Int{
		"validation": big.NewInt(0),
		"execution":  big.NewInt(0),
		"postOp":     big.NewInt(0),
	}

	verificationLimit := parseBigIntString(event.VerificationGasLimit)
	callLimit := parseBigIntString(event.CallGasLimit)
	paymasterVerification := parseBigIntString(event.PaymasterVerificationGasLimit)
	paymasterPostOp := parseBigIntString(event.PaymasterPostOpGasLimit)
	preVerification := parseBigIntString(event.PreVerificationGas)
	maxFee := parseBigIntString(event.MaxFeePerGas)
	maxPriority := parseBigIntString(event.MaxPriorityFeePerGas)

	addPhase := func(phase string, frame TraceFrame) {
		used := parseNumeric(frame.GasUsed)
		if used == nil {
			return
		}
		if _, ok := totals[phase]; !ok {
			totals[phase] = new(big.Int)
		}
		totals[phase].Add(totals[phase], used)
	}

	for _, frame := range result.Trace {
		if !frameMatchesUserOp(frame, userOpHash) {
			continue
		}
		method := strings.ToLower(frame.Method)
		switch method {
		case "validateuserop", "getuserophash":
			addPhase("validation", frame)
		case "validatepaymasteruserop":
			addPhase("validation", frame)
		case "innerhandleop":
			addPhase("execution", frame)
			if info := extractInnerOpInfo(frame); info != nil {
				verificationLimit = parseBigIntString(info.VerificationGasLimit)
				callLimit = parseBigIntString(info.CallGasLimit)
				paymasterVerification = parseBigIntString(info.PaymasterVerificationGasLimit)
				paymasterPostOp = parseBigIntString(info.PaymasterPostOpGasLimit)
				preVerification = parseBigIntString(info.PreVerificationGas)
				maxFee = parseBigIntString(info.MaxFeePerGas)
				maxPriority = parseBigIntString(info.MaxPriorityFeePerGas)
			}
		case "postop", "handlepostop":
			addPhase("postOp", frame)
		}
	}

	validationLimitStr := sumBigInts(verificationLimit, paymasterVerification, preVerification)
	execLimitStr := bigToString(callLimit)
	postLimitStr := bigToString(paymasterPostOp)

	order := []struct {
		name  string
		limit string
	}{
		{"validation", validationLimitStr},
		{"execution", execLimitStr},
		{"postOp", postLimitStr},
	}

	for _, item := range order {
		total := totals[item.name]
		if total == nil {
			total = big.NewInt(0)
		}
		phase := PhaseGas{
			Phase:    item.name,
			GasUsed:  total.String(),
			GasLimit: defaultString(item.limit),
		}
		summary.Phases = append(summary.Phases, phase)
	}

	summary.VerificationGasLimit = defaultString(bigToString(verificationLimit))
	summary.CallGasLimit = defaultString(bigToString(callLimit))
	summary.PaymasterVerificationGasLimit = defaultString(bigToString(paymasterVerification))
	summary.PaymasterPostOpGasLimit = defaultString(bigToString(paymasterPostOp))
	summary.PreVerificationGas = defaultString(bigToString(preVerification))
	summary.MaxFeePerGas = defaultString(bigToString(maxFee))
	summary.MaxPriorityFeePerGas = defaultString(bigToString(maxPriority))
	return summary
}

type innerUserOp struct {
	VerificationGasLimit          string `json:"verificationGasLimit"`
	CallGasLimit                  string `json:"callGasLimit"`
	PaymasterVerificationGasLimit string `json:"paymasterVerificationGasLimit"`
	PaymasterPostOpGasLimit       string `json:"paymasterPostOpGasLimit"`
	PreVerificationGas            string `json:"preVerificationGas"`
	MaxFeePerGas                  string `json:"maxFeePerGas"`
	MaxPriorityFeePerGas          string `json:"maxPriorityFeePerGas"`
}

type innerOpInfo struct {
	MUserOp innerUserOp `json:"mUserOp"`
}

func extractInnerOpInfo(frame TraceFrame) *innerUserOp {
	for _, arg := range frame.DecodedInput {
		if strings.EqualFold(arg.Name, "opinfo") {
			var info innerOpInfo
			if err := json.Unmarshal(arg.Value, &info); err == nil {
				return &info.MUserOp
			}
		}
	}
	return nil
}

func frameMatchesUserOp(frame TraceFrame, hash string) bool {
	if hash == "" {
		return false
	}
	for _, arg := range frame.DecodedInput {
		nameLower := strings.ToLower(arg.Name)
		switch nameLower {
		case "userophash":
			if val := parseHash(arg.Value); val == hash {
				return true
			}
		case "opinfo":
			if val := extractFieldHash(arg.Value, "userOpHash"); val == hash {
				return true
			}
		}
	}
	return false
}

func parseHash(raw json.RawMessage) string {
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		s = strings.ToLower(strings.TrimSpace(s))
		if strings.HasPrefix(s, "0x") && len(s) == 66 {
			return s
		}
	}
	return ""
}

func extractFieldHash(raw json.RawMessage, key string) string {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return ""
	}
	if value, ok := obj[key]; ok {
		if hash := parseHash(value); hash != "" {
			return hash
		}
	}
	return ""
}

func hasTracePrefix(addr, prefix []int) bool {
	if len(prefix) == 0 || len(addr) < len(prefix) {
		return false
	}
	for i := range prefix {
		if addr[i] != prefix[i] {
			return false
		}
	}
	return true
}

func normalizeNumeric(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return "0"
	}
	if strings.HasPrefix(v, "0x") || strings.HasPrefix(v, "0X") {
		value := strings.TrimPrefix(strings.TrimPrefix(v, "0x"), "0X")
		if value == "" {
			return "0"
		}
		num, ok := new(big.Int).SetString(value, 16)
		if !ok {
			return "0"
		}
		return num.String()
	}
	if num, ok := new(big.Int).SetString(v, 10); ok {
		return num.String()
	}
	return v
}

func parseNumeric(v string) *big.Int {
	v = strings.TrimSpace(v)
	if v == "" {
		return nil
	}
	if strings.HasPrefix(v, "0x") || strings.HasPrefix(v, "0X") {
		value := strings.TrimPrefix(strings.TrimPrefix(v, "0x"), "0X")
		if value == "" {
			return nil
		}
		num, ok := new(big.Int).SetString(value, 16)
		if !ok {
			return nil
		}
		return num
	}
	if num, ok := new(big.Int).SetString(v, 10); ok {
		return num
	}
	return nil
}

func parseBigIntString(v string) *big.Int {
	v = strings.TrimSpace(v)
	if v == "" {
		return nil
	}
	if num, ok := new(big.Int).SetString(v, 10); ok {
		return num
	}
	return parseNumeric(v)
}

func sumBigInts(vals ...*big.Int) string {
	total := big.NewInt(0)
	hasValue := false
	for _, v := range vals {
		if v != nil {
			total.Add(total, v)
			hasValue = true
		}
	}
	if !hasValue {
		return ""
	}
	return total.String()
}

func bigToString(x *big.Int) string {
	if x == nil || x.Sign() == 0 {
		return "0"
	}
	return x.String()
}

func defaultString(v string) string {
	if strings.TrimSpace(v) == "" {
		return "0"
	}
	return v
}
