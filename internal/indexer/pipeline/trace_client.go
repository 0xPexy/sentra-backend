package pipeline

import (
	"context"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rpc"
)

type TraceableEthClient struct {
	eth *ethclient.Client
	rpc *rpc.Client
}

func NewTraceableEthClient(eth *ethclient.Client, rpcClient *rpc.Client) (*TraceableEthClient, error) {
	if eth == nil {
		return nil, fmt.Errorf("eth client is nil")
	}
	if rpcClient == nil {
		return nil, fmt.Errorf("rpc client is nil")
	}
	return &TraceableEthClient{
		eth: eth,
		rpc: rpcClient,
	}, nil
}

func (c *TraceableEthClient) FilterLogs(ctx context.Context, q ethereum.FilterQuery) ([]types.Log, error) {
	return c.eth.FilterLogs(ctx, q)
}

func (c *TraceableEthClient) HeaderByNumber(ctx context.Context, number *big.Int) (*types.Header, error) {
	return c.eth.HeaderByNumber(ctx, number)
}

func (c *TraceableEthClient) TransactionByHash(ctx context.Context, hash common.Hash) (*types.Transaction, bool, error) {
	return c.eth.TransactionByHash(ctx, hash)
}

func (c *TraceableEthClient) TraceTransaction(ctx context.Context, hash common.Hash) (*TraceResult, error) {
	var result TraceResult
	if err := c.rpc.CallContext(ctx, &result, "tenderly_traceTransaction", hash.Hex()); err != nil {
		return nil, err
	}
	return &result, nil
}

func (c *TraceableEthClient) Close() {
	if c.eth != nil {
		c.eth.Close()
	}
	if c.rpc != nil {
		c.rpc.Close()
	}
}
