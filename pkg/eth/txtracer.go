package eth

import (
	"fmt"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/sirupsen/logrus"
)

type TxTracer struct {
	ops           map[vm.OpCode]bool
	logs          []vm.StructLog
	changedValues map[common.Address]vm.Storage
	output        []byte
	err           error
}

func NewTxTracer() *TxTracer {
	return &TxTracer{
		ops: map[vm.OpCode]bool{
			vm.CREATE:       true,
			vm.CREATE2:      true,
			vm.CALL:         true,
			vm.CALLCODE:     true,
			vm.DELEGATECALL: true,
		},
		logs:          make([]vm.StructLog, 0),
		changedValues: make(map[common.Address]vm.Storage),
	}
}

// CaptureStart implements the Tracer interface to initialize the tracing operation.
func (tracer *TxTracer) CaptureStart(from common.Address, to common.Address, create bool, input []byte, gas uint64, value *big.Int) error {
	return nil
}

// CaptureState logs a new structured log message and pushes it out to the environment
//
// CaptureState also tracks SSTORE ops to track dirty values.
func (tracer *TxTracer) CaptureState(env *vm.EVM, pc uint64, op vm.OpCode, gas, cost uint64, memory *vm.Memory, stack *vm.Stack, contract *vm.Contract, depth int, err error) error {
	if tracer.changedValues[contract.Address()] == nil {
		tracer.changedValues[contract.Address()] = make(vm.Storage)
	}

	if data := stack.Data(); op == vm.SSTORE && len(data) >= 2 {
		var (
			value   = common.BigToHash(data[len(data)-2])
			address = common.BigToHash(data[len(data)-1])
		)
		tracer.changedValues[contract.Address()][address] = value
	}

	// Copy a snapshot of the current memory state to a new buffer
	mem := make([]byte, len(memory.Data()))
	copy(mem, memory.Data())

	// Copy a snapshot of the current stack state to a new buffer
	stck := make([]*big.Int, len(stack.Data()))
	for i, item := range stack.Data() {
		stck[i] = new(big.Int).Set(item)
	}

	// Copy a snapshot of the current storage to a new container
	storage := tracer.changedValues[contract.Address()].Copy()

	// create a new snapshot of the EVM.
	log := vm.StructLog{pc, op, gas, cost, mem, memory.Len(), stck, storage, depth, env.StateDB.GetRefund(), err}
	tracer.logs = append(tracer.logs, log)

	if tracer.ops[op] {
		logrus.WithFields(logrus.Fields{
			"gas":     gas,
			"gasCost": cost,
			"mem":     fmt.Sprintf("%x", mem),
			"depth":   depth,
			"err":     err,
		}).Info(op.String())
	}
	return nil
}

// CaptureFault implements the Tracer interface to trace an execution fault
// while running an opcode.
func (tracer *TxTracer) CaptureFault(env *vm.EVM, pc uint64, op vm.OpCode, gas, cost uint64, memory *vm.Memory, stack *vm.Stack, contract *vm.Contract, depth int, err error) error {
	return nil
}

// CaptureEnd is called after the call finishes to finalize the tracing.
func (tracer *TxTracer) CaptureEnd(output []byte, gasUsed uint64, t time.Duration, err error) error {
	return nil
}

// StructLogs returns the captured log entries.
func (tracer *TxTracer) StructLogs() []vm.StructLog { return tracer.logs }

// Error returns the VM error captured by the trace.
func (tracer *TxTracer) Error() error { return tracer.err }

// Output returns the VM return value captured by the trace.
func (tracer *TxTracer) Output() []byte { return tracer.output }
