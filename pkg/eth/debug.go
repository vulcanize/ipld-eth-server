package eth

import (
	"context"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/vulcanize/ipld-eth-server/pkg/eth/tracer"
)

type DebugAPI struct {
	// Local db backend
	backend *Backend
}

func NewDebugAPI(b *Backend) *DebugAPI {
	return &DebugAPI{
		backend: b,
	}
}

func (api *DebugAPI) Trace(ctx context.Context, hash common.Hash) (interface{}, error) {
	tx, _, blockNum, txIndex, err := api.backend.GetTransaction(ctx, hash)
	if err != nil {
		return nil, err
	}

	signer := types.MakeSigner(api.backend.Config.ChainConfig, big.NewInt(int64(blockNum)))

	block, err := api.backend.BlockByNumber(ctx, rpc.BlockNumber(blockNum))
	if err != nil {
		return nil, err
	}

	statedb, _, err := api.backend.StateAndHeaderByNumber(ctx, rpc.BlockNumber(blockNum-1))
	if err != nil {
		return nil, err
	}

	txs := block.Transactions()
	for i, ln := uint64(0), uint64(len(txs)); i < ln && i < txIndex; i++ {
		msg, err := tx.AsMessage(signer)
		if err != nil {
			return nil, err
		}
		evm, _ := api.backend.GetEVM(ctx, msg, statedb, block.Header())
		_, _, _, err = core.ApplyMessage(evm, msg, new(core.GasPool).AddGas(math.MaxUint64))
		if err != nil {
			return nil, err
		}
	}

	msg, err := tx.AsMessage(signer)
	statedb.SetBalance(msg.From(), math.MaxBig256)
	c := core.NewEVMContext(msg, block.Header(), api.backend, nil)
	tracer := tracer.NewCallTracer()
	cfg := api.backend.Config.VmConfig
	cfg.Debug = true
	cfg.Tracer = tracer

	evm := vm.NewEVM(c, statedb, api.backend.Config.ChainConfig, cfg)
	_, _, _, err = core.ApplyMessage(evm, msg, new(core.GasPool).AddGas(math.MaxUint64))
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"error":  tracer.Error(),
		"output": tracer.Output(),
		"framse": tracer.Frames(),
	}, nil
}
