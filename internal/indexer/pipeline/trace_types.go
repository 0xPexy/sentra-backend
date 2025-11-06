package pipeline

import "encoding/json"

type TraceResult struct {
	Trace []TraceFrame `json:"trace"`
}

type TraceFrame struct {
	Type          string       `json:"type"`
	CallType      string       `json:"callType,omitempty"`
	From          string       `json:"from"`
	To            string       `json:"to"`
	Gas           string       `json:"gas"`
	GasUsed       string       `json:"gasUsed"`
	Method        string       `json:"method,omitempty"`
	TraceAddress  []int        `json:"traceAddress"`
	DecodedInput  []DecodedArg `json:"decodedInput,omitempty"`
	DecodedOutput []DecodedArg `json:"decodedOutput,omitempty"`
	Error         string       `json:"error,omitempty"`
}

type DecodedArg struct {
	Name  string          `json:"name"`
	Type  string          `json:"type"`
	Value json.RawMessage `json:"value"`
}
