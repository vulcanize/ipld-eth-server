// VulcanizeDB
// Copyright © 2019 Vulcanize

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.

// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package eth_test

import (
	"bytes"
	"context"
	"io/ioutil"
	"math/big"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/ethereum/go-ethereum/statediff"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	eth2 "github.com/vulcanize/ipld-eth-indexer/pkg/eth"
	"github.com/vulcanize/ipld-eth-indexer/pkg/postgres"
	"github.com/vulcanize/ipld-eth-indexer/pkg/shared"
	"github.com/vulcanize/ipld-eth-server/pkg/eth"
	"github.com/vulcanize/ipld-eth-server/pkg/eth/test_helpers"
)

var (
	parsedABI abi.ABI
)

func init() {
	// load abi
	abiBytes, err := ioutil.ReadFile("./test_helpers/abi.json")
	if err != nil {
		panic(err)
	}
	parsedABI, err = abi.JSON(bytes.NewReader(abiBytes))
	if err != nil {
		panic(err)
	}
}

var _ = Describe("eth state reading tests", func() {
	const chainLength = 5
	var (
		blocks                  []*types.Block
		receipts                []types.Receipts
		chain                   *core.BlockChain
		db                      *postgres.DB
		api                     *eth.PublicEthAPI
		backend                 *eth.Backend
		chainConfig             = params.TestChainConfig
		mockTD                  = big.NewInt(1337)
		expectedCanonicalHeader map[string]interface{}
	)
	It("test init", func() {
		// db and type initializations
		var err error
		db, err = shared.SetupDB()
		Expect(err).ToNot(HaveOccurred())
		transformer := eth2.NewStateDiffTransformer(chainConfig, db)
		backend, err = eth.NewEthBackend(db, &eth.Config{
			ChainConfig: chainConfig,
			VmConfig:    vm.Config{},
			RPCGasCap:   big.NewInt(10000000000), // Max gas capacity for a rpc call.
		})
		Expect(err).ToNot(HaveOccurred())
		api = eth.NewPublicEthAPI(backend, nil, false)

		// make the test blockchain (and state)
		blocks, receipts, chain = test_helpers.MakeChain(chainLength, test_helpers.Genesis, test_helpers.TestChainGen)
		params := statediff.Params{
			IntermediateStateNodes:   true,
			IntermediateStorageNodes: true,
		}
		canonicalHeader := blocks[1].Header()
		expectedCanonicalHeader = map[string]interface{}{
			"number":           (*hexutil.Big)(canonicalHeader.Number),
			"hash":             canonicalHeader.Hash(),
			"parentHash":       canonicalHeader.ParentHash,
			"nonce":            canonicalHeader.Nonce,
			"mixHash":          canonicalHeader.MixDigest,
			"sha3Uncles":       canonicalHeader.UncleHash,
			"logsBloom":        canonicalHeader.Bloom,
			"stateRoot":        canonicalHeader.Root,
			"miner":            canonicalHeader.Coinbase,
			"difficulty":       (*hexutil.Big)(canonicalHeader.Difficulty),
			"extraData":        hexutil.Bytes([]byte{}),
			"size":             hexutil.Uint64(canonicalHeader.Size()),
			"gasLimit":         hexutil.Uint64(canonicalHeader.GasLimit),
			"gasUsed":          hexutil.Uint64(canonicalHeader.GasUsed),
			"timestamp":        hexutil.Uint64(canonicalHeader.Time),
			"transactionsRoot": canonicalHeader.TxHash,
			"receiptsRoot":     canonicalHeader.ReceiptHash,
			"totalDifficulty":  (*hexutil.Big)(mockTD),
		}
		// iterate over the blocks, generating statediff payloads, and transforming the data into Postgres
		builder := statediff.NewBuilder(chain.StateCache())
		for i, block := range blocks {
			var args statediff.Args
			var rcts types.Receipts
			if i == 0 {
				args = statediff.Args{
					OldStateRoot: common.Hash{},
					NewStateRoot: block.Root(),
					BlockNumber:  block.Number(),
					BlockHash:    block.Hash(),
				}
			} else {
				args = statediff.Args{
					OldStateRoot: blocks[i-1].Root(),
					NewStateRoot: block.Root(),
					BlockNumber:  block.Number(),
					BlockHash:    block.Hash(),
				}
				rcts = receipts[i-1]
			}
			diff, err := builder.BuildStateDiffObject(args, params)
			Expect(err).ToNot(HaveOccurred())
			diffRlp, err := rlp.EncodeToBytes(diff)
			Expect(err).ToNot(HaveOccurred())
			blockRlp, err := rlp.EncodeToBytes(block)
			Expect(err).ToNot(HaveOccurred())
			receiptsRlp, err := rlp.EncodeToBytes(rcts)
			Expect(err).ToNot(HaveOccurred())
			payload := statediff.Payload{
				StateObjectRlp:  diffRlp,
				BlockRlp:        blockRlp,
				ReceiptsRlp:     receiptsRlp,
				TotalDifficulty: mockTD,
			}
			_, err = transformer.Transform(0, payload)
			Expect(err).ToNot(HaveOccurred())
		}

		// Insert some non-canonical data into the database so that we test our ability to discern canonicity
		indexAndPublisher := eth2.NewIPLDPublisher(db)
		api = eth.NewPublicEthAPI(backend, nil, false)
		err = indexAndPublisher.Publish(test_helpers.MockConvertedPayload)
		Expect(err).ToNot(HaveOccurred())
		// The non-canonical header has a child
		err = indexAndPublisher.Publish(test_helpers.MockConvertedPayloadForChild)
		Expect(err).ToNot(HaveOccurred())
		err = publishCode(db, test_helpers.ContractCodeHash, test_helpers.ContractCode)
		Expect(err).ToNot(HaveOccurred())
	})
	defer It("test teardown", func() {
		eth.TearDownDB(db)
		chain.Stop()
	})

	Describe("eth_call", func() {
		It("Applies call args (tx data) on top of state, returning the result (e.g. a Getter method call)", func() {
			data, err := parsedABI.Pack("data")
			Expect(err).ToNot(HaveOccurred())
			bdata := hexutil.Bytes(data)
			callArgs := eth.CallArgs{
				To:   &test_helpers.ContractAddr,
				Data: &bdata,
			}
			// Before contract deployment, returns nil
			res, err := api.Call(context.Background(), callArgs, rpc.BlockNumberOrHashWithNumber(0), nil)
			Expect(err).ToNot(HaveOccurred())
			Expect(res).To(BeNil())

			res, err = api.Call(context.Background(), callArgs, rpc.BlockNumberOrHashWithNumber(1), nil)
			Expect(err).ToNot(HaveOccurred())
			Expect(res).To(BeNil())

			// After deployment
			res, err = api.Call(context.Background(), callArgs, rpc.BlockNumberOrHashWithNumber(2), nil)
			Expect(err).ToNot(HaveOccurred())
			expectedRes := hexutil.Bytes(common.Hex2Bytes("0000000000000000000000000000000000000000000000000000000000000001"))
			Expect(res).To(Equal(expectedRes))

			res, err = api.Call(context.Background(), callArgs, rpc.BlockNumberOrHashWithNumber(3), nil)
			Expect(err).ToNot(HaveOccurred())
			expectedRes = hexutil.Bytes(common.Hex2Bytes("0000000000000000000000000000000000000000000000000000000000000003"))
			Expect(res).To(Equal(expectedRes))

			res, err = api.Call(context.Background(), callArgs, rpc.BlockNumberOrHashWithNumber(4), nil)
			Expect(err).ToNot(HaveOccurred())
			expectedRes = hexutil.Bytes(common.Hex2Bytes("0000000000000000000000000000000000000000000000000000000000000009"))
			Expect(res).To(Equal(expectedRes))

			res, err = api.Call(context.Background(), callArgs, rpc.BlockNumberOrHashWithNumber(5), nil)
			Expect(err).ToNot(HaveOccurred())
			expectedRes = hexutil.Bytes(common.Hex2Bytes("0000000000000000000000000000000000000000000000000000000000000000"))
			Expect(res).To(Equal(expectedRes))
		})
	})

	var (
		expectedContractBalance   = (*hexutil.Big)(common.Big0)
		expectedBankBalanceBlock0 = (*hexutil.Big)(test_helpers.TestBankFunds)

		expectedAcct1BalanceBlock1 = (*hexutil.Big)(big.NewInt(10000))
		expectedBankBalanceBlock1  = (*hexutil.Big)(new(big.Int).Sub(test_helpers.TestBankFunds, big.NewInt(10000)))

		expectedAcct2BalanceBlock2 = (*hexutil.Big)(big.NewInt(1000))
		expectedBankBalanceBlock2  = (*hexutil.Big)(new(big.Int).Sub(expectedBankBalanceBlock1.ToInt(), big.NewInt(1000)))

		expectedAcct2BalanceBlock3 = (*hexutil.Big)(new(big.Int).Add(expectedAcct2BalanceBlock2.ToInt(), test_helpers.MiningReward))

		expectedAcct2BalanceBlock4 = (*hexutil.Big)(new(big.Int).Add(expectedAcct2BalanceBlock3.ToInt(), test_helpers.MiningReward))

		expectedAcct1BalanceBlock5 = (*hexutil.Big)(new(big.Int).Add(expectedAcct1BalanceBlock1.ToInt(), test_helpers.MiningReward))
	)

	Describe("eth_getBalance", func() {
		It("Retrieves the eth balance for the provided account address at the block with the provided number", func() {
			bal, err := api.GetBalance(ctx, test_helpers.TestBankAddress, rpc.BlockNumberOrHashWithNumber(0))
			Expect(err).ToNot(HaveOccurred())
			Expect(bal).To(Equal(expectedBankBalanceBlock0))

			bal, err = api.GetBalance(ctx, test_helpers.Account1Addr, rpc.BlockNumberOrHashWithNumber(1))
			Expect(err).ToNot(HaveOccurred())
			Expect(bal).To(Equal(expectedAcct1BalanceBlock1))

			bal, err = api.GetBalance(ctx, test_helpers.Account2Addr, rpc.BlockNumberOrHashWithNumber(1))
			Expect(err).ToNot(HaveOccurred())
			Expect(bal).To(Equal((*hexutil.Big)(common.Big0)))

			bal, err = api.GetBalance(ctx, test_helpers.ContractAddr, rpc.BlockNumberOrHashWithNumber(1))
			Expect(err).ToNot(HaveOccurred())
			Expect(bal).To(Equal((*hexutil.Big)(common.Big0)))

			bal, err = api.GetBalance(ctx, test_helpers.TestBankAddress, rpc.BlockNumberOrHashWithNumber(1))
			Expect(err).ToNot(HaveOccurred())
			Expect(bal).To(Equal(expectedBankBalanceBlock1))

			bal, err = api.GetBalance(ctx, test_helpers.Account1Addr, rpc.BlockNumberOrHashWithNumber(2))
			Expect(err).ToNot(HaveOccurred())
			Expect(bal).To(Equal(expectedAcct1BalanceBlock1))

			bal, err = api.GetBalance(ctx, test_helpers.Account2Addr, rpc.BlockNumberOrHashWithNumber(2))
			Expect(err).ToNot(HaveOccurred())
			Expect(bal).To(Equal(expectedAcct2BalanceBlock2))

			bal, err = api.GetBalance(ctx, test_helpers.ContractAddr, rpc.BlockNumberOrHashWithNumber(2))
			Expect(err).ToNot(HaveOccurred())
			Expect(bal).To(Equal(expectedContractBalance))

			bal, err = api.GetBalance(ctx, test_helpers.TestBankAddress, rpc.BlockNumberOrHashWithNumber(2))
			Expect(err).ToNot(HaveOccurred())
			Expect(bal).To(Equal(expectedBankBalanceBlock2))

			bal, err = api.GetBalance(ctx, test_helpers.Account1Addr, rpc.BlockNumberOrHashWithNumber(3))
			Expect(err).ToNot(HaveOccurred())
			Expect(bal).To(Equal(expectedAcct1BalanceBlock1))

			bal, err = api.GetBalance(ctx, test_helpers.Account2Addr, rpc.BlockNumberOrHashWithNumber(3))
			Expect(err).ToNot(HaveOccurred())
			Expect(bal).To(Equal(expectedAcct2BalanceBlock3))

			bal, err = api.GetBalance(ctx, test_helpers.ContractAddr, rpc.BlockNumberOrHashWithNumber(3))
			Expect(err).ToNot(HaveOccurred())
			Expect(bal).To(Equal(expectedContractBalance))

			bal, err = api.GetBalance(ctx, test_helpers.TestBankAddress, rpc.BlockNumberOrHashWithNumber(3))
			Expect(err).ToNot(HaveOccurred())
			Expect(bal).To(Equal(expectedBankBalanceBlock2))

			bal, err = api.GetBalance(ctx, test_helpers.Account1Addr, rpc.BlockNumberOrHashWithNumber(4))
			Expect(err).ToNot(HaveOccurred())
			Expect(bal).To(Equal(expectedAcct1BalanceBlock1))

			bal, err = api.GetBalance(ctx, test_helpers.Account2Addr, rpc.BlockNumberOrHashWithNumber(4))
			Expect(err).ToNot(HaveOccurred())
			Expect(bal).To(Equal(expectedAcct2BalanceBlock4))

			bal, err = api.GetBalance(ctx, test_helpers.ContractAddr, rpc.BlockNumberOrHashWithNumber(4))
			Expect(err).ToNot(HaveOccurred())
			Expect(bal).To(Equal(expectedContractBalance))

			bal, err = api.GetBalance(ctx, test_helpers.TestBankAddress, rpc.BlockNumberOrHashWithNumber(4))
			Expect(err).ToNot(HaveOccurred())
			Expect(bal).To(Equal(expectedBankBalanceBlock2))

			bal, err = api.GetBalance(ctx, test_helpers.Account1Addr, rpc.BlockNumberOrHashWithNumber(5))
			Expect(err).ToNot(HaveOccurred())
			Expect(bal).To(Equal(expectedAcct1BalanceBlock5))

			bal, err = api.GetBalance(ctx, test_helpers.Account2Addr, rpc.BlockNumberOrHashWithNumber(5))
			Expect(err).ToNot(HaveOccurred())
			Expect(bal).To(Equal(expectedAcct2BalanceBlock4))

			bal, err = api.GetBalance(ctx, test_helpers.ContractAddr, rpc.BlockNumberOrHashWithNumber(5))
			Expect(err).ToNot(HaveOccurred())
			Expect(bal).To(Equal(expectedContractBalance))

			bal, err = api.GetBalance(ctx, test_helpers.TestBankAddress, rpc.BlockNumberOrHashWithNumber(5))
			Expect(err).ToNot(HaveOccurred())
			Expect(bal).To(Equal(expectedBankBalanceBlock2))
		})
		It("Retrieves the eth balance for the provided account address at the block with the provided hash", func() {
			bal, err := api.GetBalance(ctx, test_helpers.TestBankAddress, rpc.BlockNumberOrHashWithHash(blocks[0].Hash(), true))
			Expect(err).ToNot(HaveOccurred())
			Expect(bal).To(Equal(expectedBankBalanceBlock0))

			bal, err = api.GetBalance(ctx, test_helpers.Account1Addr, rpc.BlockNumberOrHashWithHash(blocks[1].Hash(), true))
			Expect(err).ToNot(HaveOccurred())
			Expect(bal).To(Equal(expectedAcct1BalanceBlock1))

			bal, err = api.GetBalance(ctx, test_helpers.Account2Addr, rpc.BlockNumberOrHashWithHash(blocks[1].Hash(), true))
			Expect(err).ToNot(HaveOccurred())
			Expect(bal).To(Equal((*hexutil.Big)(common.Big0)))

			_, err = api.GetBalance(ctx, test_helpers.ContractAddr, rpc.BlockNumberOrHashWithHash(blocks[1].Hash(), true))
			Expect(err).ToNot(HaveOccurred())
			Expect(bal).To(Equal((*hexutil.Big)(common.Big0)))

			bal, err = api.GetBalance(ctx, test_helpers.TestBankAddress, rpc.BlockNumberOrHashWithHash(blocks[1].Hash(), true))
			Expect(err).ToNot(HaveOccurred())
			Expect(bal).To(Equal(expectedBankBalanceBlock1))

			bal, err = api.GetBalance(ctx, test_helpers.Account1Addr, rpc.BlockNumberOrHashWithHash(blocks[2].Hash(), true))
			Expect(err).ToNot(HaveOccurred())
			Expect(bal).To(Equal(expectedAcct1BalanceBlock1))

			bal, err = api.GetBalance(ctx, test_helpers.Account2Addr, rpc.BlockNumberOrHashWithHash(blocks[2].Hash(), true))
			Expect(err).ToNot(HaveOccurred())

			Expect(bal).To(Equal(expectedAcct2BalanceBlock2))
			bal, err = api.GetBalance(ctx, test_helpers.ContractAddr, rpc.BlockNumberOrHashWithHash(blocks[2].Hash(), true))
			Expect(err).ToNot(HaveOccurred())
			Expect(bal).To(Equal(expectedContractBalance))

			bal, err = api.GetBalance(ctx, test_helpers.TestBankAddress, rpc.BlockNumberOrHashWithHash(blocks[2].Hash(), true))
			Expect(err).ToNot(HaveOccurred())
			Expect(bal).To(Equal(expectedBankBalanceBlock2))

			bal, err = api.GetBalance(ctx, test_helpers.Account1Addr, rpc.BlockNumberOrHashWithHash(blocks[3].Hash(), true))
			Expect(err).ToNot(HaveOccurred())
			Expect(bal).To(Equal(expectedAcct1BalanceBlock1))

			bal, err = api.GetBalance(ctx, test_helpers.Account2Addr, rpc.BlockNumberOrHashWithHash(blocks[3].Hash(), true))
			Expect(err).ToNot(HaveOccurred())
			Expect(bal).To(Equal(expectedAcct2BalanceBlock3))

			bal, err = api.GetBalance(ctx, test_helpers.ContractAddr, rpc.BlockNumberOrHashWithHash(blocks[3].Hash(), true))
			Expect(err).ToNot(HaveOccurred())
			Expect(bal).To(Equal(expectedContractBalance))

			bal, err = api.GetBalance(ctx, test_helpers.TestBankAddress, rpc.BlockNumberOrHashWithHash(blocks[3].Hash(), true))
			Expect(err).ToNot(HaveOccurred())
			Expect(bal).To(Equal(expectedBankBalanceBlock2))

			bal, err = api.GetBalance(ctx, test_helpers.Account1Addr, rpc.BlockNumberOrHashWithHash(blocks[4].Hash(), true))
			Expect(err).ToNot(HaveOccurred())
			Expect(bal).To(Equal(expectedAcct1BalanceBlock1))

			bal, err = api.GetBalance(ctx, test_helpers.Account2Addr, rpc.BlockNumberOrHashWithHash(blocks[4].Hash(), true))
			Expect(err).ToNot(HaveOccurred())
			Expect(bal).To(Equal(expectedAcct2BalanceBlock4))

			bal, err = api.GetBalance(ctx, test_helpers.ContractAddr, rpc.BlockNumberOrHashWithHash(blocks[4].Hash(), true))
			Expect(err).ToNot(HaveOccurred())
			Expect(bal).To(Equal(expectedContractBalance))

			bal, err = api.GetBalance(ctx, test_helpers.TestBankAddress, rpc.BlockNumberOrHashWithHash(blocks[4].Hash(), true))
			Expect(err).ToNot(HaveOccurred())
			Expect(bal).To(Equal(expectedBankBalanceBlock2))

			bal, err = api.GetBalance(ctx, test_helpers.Account1Addr, rpc.BlockNumberOrHashWithHash(blocks[5].Hash(), true))
			Expect(err).ToNot(HaveOccurred())
			Expect(bal).To(Equal(expectedAcct1BalanceBlock5))

			bal, err = api.GetBalance(ctx, test_helpers.Account2Addr, rpc.BlockNumberOrHashWithHash(blocks[5].Hash(), true))
			Expect(err).ToNot(HaveOccurred())
			Expect(bal).To(Equal(expectedAcct2BalanceBlock4))

			bal, err = api.GetBalance(ctx, test_helpers.ContractAddr, rpc.BlockNumberOrHashWithHash(blocks[5].Hash(), true))
			Expect(err).ToNot(HaveOccurred())
			Expect(bal).To(Equal(expectedContractBalance))

			bal, err = api.GetBalance(ctx, test_helpers.TestBankAddress, rpc.BlockNumberOrHashWithHash(blocks[5].Hash(), true))
			Expect(err).ToNot(HaveOccurred())
			Expect(bal).To(Equal(expectedBankBalanceBlock2))
		})
		It("Returns `0` for an account it cannot find the balance for an account at the provided block number", func() {
			bal, err := api.GetBalance(ctx, test_helpers.Account1Addr, rpc.BlockNumberOrHashWithNumber(0))
			Expect(err).ToNot(HaveOccurred())
			Expect(bal).To(Equal((*hexutil.Big)(common.Big0)))

			bal, err = api.GetBalance(ctx, test_helpers.Account2Addr, rpc.BlockNumberOrHashWithNumber(0))
			Expect(err).ToNot(HaveOccurred())
			Expect(bal).To(Equal((*hexutil.Big)(common.Big0)))

			bal, err = api.GetBalance(ctx, test_helpers.ContractAddr, rpc.BlockNumberOrHashWithNumber(0))
			Expect(err).ToNot(HaveOccurred())
			Expect(bal).To(Equal((*hexutil.Big)(common.Big0)))
		})
		It("Returns `0` for an error for an account it cannot find the balance for an account at the provided block hash", func() {
			bal, err := api.GetBalance(ctx, test_helpers.Account1Addr, rpc.BlockNumberOrHashWithHash(blocks[0].Hash(), true))
			Expect(err).ToNot(HaveOccurred())
			Expect(bal).To(Equal((*hexutil.Big)(common.Big0)))

			bal, err = api.GetBalance(ctx, test_helpers.Account2Addr, rpc.BlockNumberOrHashWithHash(blocks[0].Hash(), true))
			Expect(err).ToNot(HaveOccurred())
			Expect(bal).To(Equal((*hexutil.Big)(common.Big0)))

			bal, err = api.GetBalance(ctx, test_helpers.ContractAddr, rpc.BlockNumberOrHashWithHash(blocks[0].Hash(), true))
			Expect(err).ToNot(HaveOccurred())
			Expect(bal).To(Equal((*hexutil.Big)(common.Big0)))

		})
	})

	Describe("eth_getCode", func() {
		It("Retrieves the code for the provided contract address at the block with the provided number", func() {
			code, err := api.GetCode(ctx, test_helpers.ContractAddr, rpc.BlockNumberOrHashWithNumber(3))
			Expect(err).ToNot(HaveOccurred())
			Expect(code).To(Equal((hexutil.Bytes)(test_helpers.ContractCode)))

			code, err = api.GetCode(ctx, test_helpers.ContractAddr, rpc.BlockNumberOrHashWithNumber(5))
			Expect(err).ToNot(HaveOccurred())
			Expect(code).To(Equal((hexutil.Bytes)(test_helpers.ContractCode)))
		})
		It("Retrieves the code for the provided contract address at the block with the provided hash", func() {
			code, err := api.GetCode(ctx, test_helpers.ContractAddr, rpc.BlockNumberOrHashWithHash(blocks[3].Hash(), true))
			Expect(err).ToNot(HaveOccurred())
			Expect(code).To(Equal((hexutil.Bytes)(test_helpers.ContractCode)))

			code, err = api.GetCode(ctx, test_helpers.ContractAddr, rpc.BlockNumberOrHashWithHash(blocks[5].Hash(), true))
			Expect(err).ToNot(HaveOccurred())
			Expect(code).To(Equal((hexutil.Bytes)(test_helpers.ContractCode)))
		})
		It("Returns `nil` for an account it cannot find the code for", func() {
			code, err := api.GetCode(ctx, randomAddr, rpc.BlockNumberOrHashWithHash(blocks[3].Hash(), true))
			Expect(err).ToNot(HaveOccurred())
			Expect(code).To(BeEmpty())
		})
		It("Returns `nil`  for a contract that doesn't exist at this height", func() {
			code, err := api.GetCode(ctx, test_helpers.ContractAddr, rpc.BlockNumberOrHashWithNumber(0))
			Expect(err).ToNot(HaveOccurred())
			Expect(code).To(BeEmpty())
		})
	})

	Describe("eth_getStorageAt", func() {
		It("Returns empty slice if it tries to access a contract which does not exist", func() {
			storage, err := api.GetStorageAt(ctx, test_helpers.ContractAddr, test_helpers.ContractSlotKeyHash.Hex(), rpc.BlockNumberOrHashWithNumber(0))
			Expect(err).NotTo(HaveOccurred())
			Expect(storage).To(Equal(hexutil.Bytes(make([]byte, 32))))

			storage, err = api.GetStorageAt(ctx, test_helpers.ContractAddr, test_helpers.ContractSlotKeyHash.Hex(), rpc.BlockNumberOrHashWithNumber(1))
			Expect(err).NotTo(HaveOccurred())
			Expect(storage).To(Equal(hexutil.Bytes(make([]byte, 32))))
		})
		It("Returns empty slice if it tries to access a contract slot which does not exist", func() {
			storage, err := api.GetStorageAt(ctx, test_helpers.ContractAddr, randomHash.Hex(), rpc.BlockNumberOrHashWithNumber(2))
			Expect(err).NotTo(HaveOccurred())
			Expect(storage).To(Equal(hexutil.Bytes(make([]byte, 32))))
		})
		It("Retrieves the storage value at the provided contract address and storage leaf key at the block with the provided hash or number", func() {
			// After deployment
			val, err := api.GetStorageAt(ctx, test_helpers.ContractAddr, test_helpers.IndexOne, rpc.BlockNumberOrHashWithNumber(2))
			Expect(err).ToNot(HaveOccurred())
			expectedRes := hexutil.Bytes(common.Hex2Bytes("0000000000000000000000000000000000000000000000000000000000000001"))
			Expect(val).To(Equal(expectedRes))

			val, err = api.GetStorageAt(ctx, test_helpers.ContractAddr, test_helpers.IndexOne, rpc.BlockNumberOrHashWithNumber(3))
			Expect(err).ToNot(HaveOccurred())
			expectedRes = hexutil.Bytes(common.Hex2Bytes("0000000000000000000000000000000000000000000000000000000000000003"))
			Expect(val).To(Equal(expectedRes))

			val, err = api.GetStorageAt(ctx, test_helpers.ContractAddr, test_helpers.IndexOne, rpc.BlockNumberOrHashWithNumber(4))
			Expect(err).ToNot(HaveOccurred())
			expectedRes = hexutil.Bytes(common.Hex2Bytes("0000000000000000000000000000000000000000000000000000000000000009"))
			Expect(val).To(Equal(expectedRes))

			val, err = api.GetStorageAt(ctx, test_helpers.ContractAddr, test_helpers.IndexOne, rpc.BlockNumberOrHashWithNumber(5))
			Expect(err).ToNot(HaveOccurred())
			Expect(val).To(Equal(hexutil.Bytes{}))
		})
		It("Throws an error for a non-existing block hash", func() {
			_, err := api.GetStorageAt(ctx, test_helpers.ContractAddr, test_helpers.IndexOne, rpc.BlockNumberOrHashWithHash(randomHash, true))
			Expect(err).To(HaveOccurred())
			Expect(err).To(MatchError("header for hash not found"))
		})
		It("Throws an error for a non-existing block number", func() {
			_, err := api.GetStorageAt(ctx, test_helpers.ContractAddr, test_helpers.IndexOne, rpc.BlockNumberOrHashWithNumber(chainLength+1))
			Expect(err).To(HaveOccurred())
			Expect(err).To(MatchError("header not found"))
		})
	})

	Describe("eth_getHeaderByNumber", func() {
		It("Finds the canonical header based on the header's weight relative to others at the provided height", func() {
			header, err := api.GetHeaderByNumber(ctx, number)
			Expect(err).ToNot(HaveOccurred())
			Expect(header).To(Equal(expectedCanonicalHeader))
		})
	})
})
