package eth

import (
	"fmt"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/sirupsen/logrus"
)

type Frame struct {
	Op     vm.OpCode      `json:"-"`
	From   common.Address `json:"from"`
	To     common.Address `json:"to"`
	Input  hexutil.Bytes  `json:"input"`
	Output hexutil.Bytes  `json:"output"`
	Gas    uint64         `json:"gas"`
	Cost   uint64         `json:"cost"`
	Value  *big.Int       `json:"value"`
}

type CallTracer struct {
	ops    map[vm.OpCode]bool
	frames []Frame
	output []byte
	err    error
}

func NewCallTracer() *CallTracer {
	return &CallTracer{
		ops: map[vm.OpCode]bool{
			vm.CREATE:       true,
			vm.CREATE2:      true,
			vm.SELFDESTRUCT: true,
			vm.CALL:         true,
			vm.CALLCODE:     true,
			vm.DELEGATECALL: true,
			vm.STATICCALL:   true,
		},
		frames: make([]Frame, 0),
	}
}

// CaptureStart implements the Tracer interface to initialize the tracing operation.
func (tracer *CallTracer) CaptureStart(from common.Address, to common.Address, create bool, input []byte, gas uint64, value *big.Int) error {
	return nil
}

func getData(stack *vm.Stack, n int) []*big.Int {
	tmp := make([]*big.Int, n)
	dat := stack.Data()
	for i, j := len(dat)-1, 0; i >= 0 && j < n; i, j = i-1, j+1 {
		tmp[j] = new(big.Int).Set(dat[i])
	}
	return tmp
}

// CaptureState logs a new structured log message and pushes it out to the environment
func (tracer *CallTracer) CaptureState(env *vm.EVM, pc uint64, op vm.OpCode, gas, cost uint64, memory *vm.Memory, stack *vm.Stack, contract *vm.Contract, depth int, err error) error {
	if !tracer.ops[op] {
		return nil
	}
	frame := Frame{
		Op:   op,
		From: contract.Address(),
		Gas:  gas,
		Cost: cost,
	}
	switch op {
	// create(v, p, n)
	//   create new contract with code mem[p…(p+n)) and send v wei and return the new address
	// create2(v, p, n, s)
	//   create new contract with code mem[p…(p+n)) at address keccak256(0xff . this . s . keccak256(mem[p…(p+n))) and
	//   send v wei and return the new address, where 0xff is a 8 byte value, this is the current contract’s address
	//   as a 20 byte value and s is a big-endian 256-bit value
	case vm.CREATE, vm.CREATE2:
		frame.Value = new(big.Int).Set(stack.Back(0))
		frame.Input = memory.GetCopy(stack.Back(1).Int64(), stack.Back(2).Int64())
	// selfdestruct(a)
	//   end execution, destroy current contract and send funds to a
	case vm.SELFDESTRUCT:
		frame.To = common.BigToAddress(stack.Back(0))
		frame.Value = env.StateDB.GetBalance(contract.Address())
	// call (g, a, v, in, insize, out, outsize)
	//   call contract at address a with input mem[in…(in+insize))
	//   providing g gas and v wei and output area mem[out…(out+outsize))
	//   returning 0 on error (eg. out of gas) and 1 on success
	// callcode (g, a, v, in, insize, out, outsize)
	//   dentical to call but only use the code from a and stay
	//   in the context of the current contract otherwise
	case vm.CALL, vm.CALLCODE:
		frame.To = common.BigToAddress(stack.Back(1))
		frame.Value = new(big.Int).Set(stack.Back(2))
		frame.Input = memory.GetCopy(stack.Back(3).Int64(), stack.Back(4).Int64())
		frame.Output = memory.GetCopy(stack.Back(5).Int64(), stack.Back(6).Int64())
	// delegatecall (g, a, in, insize, out, outsize)
	//   identical to callcode but also keep caller and callvalue
	// staticcall   (g, a, in, insize, out, outsize)
	//   identical to call(g, a, 0, in, insize, out, outsize) but do not allow state modifications
	case vm.DELEGATECALL, vm.STATICCALL:
		frame.To = common.BigToAddress(stack.Back(1))
		frame.Value = big.NewInt(0)
		frame.Input = memory.GetCopy(stack.Back(2).Int64(), stack.Back(3).Int64())
		frame.Output = memory.GetCopy(stack.Back(4).Int64(), stack.Back(5).Int64())
	}
	tracer.frames = append(tracer.frames, frame)
	return nil
}

// CaptureFault implements the Tracer interface to trace an execution fault
// while running an opcode.
func (tracer *CallTracer) CaptureFault(env *vm.EVM, pc uint64, op vm.OpCode, gas, cost uint64, memory *vm.Memory, stack *vm.Stack, contract *vm.Contract, depth int, err error) error {
	return nil
}

// CaptureEnd is called after the call finishes to finalize the tracing.
func (tracer *CallTracer) CaptureEnd(output []byte, gasUsed uint64, t time.Duration, err error) error {
	tracer.err = err
	tracer.output = output
	for _, frame := range tracer.frames {
		logrus.WithFields(logrus.Fields{
			"From":  frame.From.Hex(),
			"To":    frame.To.Hex(),
			"Input": frame.Input.String(),
			"Value": fmt.Sprintf("%#x", frame.Value),
		}).Info(frame.Op.String())
	}
	return nil
}

// Frames returns the captured call frames.
func (tracer *CallTracer) Frames() []Frame { return tracer.frames }

// Error returns the VM error captured by the trace.
func (tracer *CallTracer) Error() error { return tracer.err }

// Output returns the VM return value captured by the trace.
func (tracer *CallTracer) Output() []byte { return tracer.output }
