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
	"context"
	"math/big"
	"strconv"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/eth/filters"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/rpc"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	eth2 "github.com/vulcanize/ipld-eth-indexer/pkg/eth"
	"github.com/vulcanize/ipld-eth-indexer/pkg/postgres"
	"github.com/vulcanize/ipld-eth-indexer/pkg/shared"

	"github.com/vulcanize/ipld-eth-server/pkg/eth"
	"github.com/vulcanize/ipld-eth-server/pkg/eth/test_helpers"
)

var (
	randomAddr    = common.HexToAddress("0x1C3ab14BBaD3D99F4203bd7a11aCB94882050E6f")
	randomHash    = crypto.Keccak256Hash(randomAddr.Bytes())
	number        = rpc.BlockNumber(test_helpers.BlockNumber.Int64())
	wrongNumber   = rpc.BlockNumber(number + 1)
	blockHash     = test_helpers.MockBlock.Header().Hash()
	ctx           = context.Background()
	expectedBlock = map[string]interface{}{
		"number":           (*hexutil.Big)(test_helpers.MockBlock.Number()),
		"hash":             test_helpers.MockBlock.Hash(),
		"parentHash":       test_helpers.MockBlock.ParentHash(),
		"nonce":            test_helpers.MockBlock.Header().Nonce,
		"mixHash":          test_helpers.MockBlock.MixDigest(),
		"sha3Uncles":       test_helpers.MockBlock.UncleHash(),
		"logsBloom":        test_helpers.MockBlock.Bloom(),
		"stateRoot":        test_helpers.MockBlock.Root(),
		"miner":            test_helpers.MockBlock.Coinbase(),
		"difficulty":       (*hexutil.Big)(test_helpers.MockBlock.Difficulty()),
		"extraData":        hexutil.Bytes(test_helpers.MockBlock.Header().Extra),
		"gasLimit":         hexutil.Uint64(test_helpers.MockBlock.GasLimit()),
		"gasUsed":          hexutil.Uint64(test_helpers.MockBlock.GasUsed()),
		"timestamp":        hexutil.Uint64(test_helpers.MockBlock.Time()),
		"transactionsRoot": test_helpers.MockBlock.TxHash(),
		"receiptsRoot":     test_helpers.MockBlock.ReceiptHash(),
		"totalDifficulty":  (*hexutil.Big)(test_helpers.MockBlock.Difficulty()),
		"size":             hexutil.Uint64(test_helpers.MockBlock.Size()),
	}
	expectedHeader = map[string]interface{}{
		"number":           (*hexutil.Big)(test_helpers.MockBlock.Header().Number),
		"hash":             blockHash,
		"parentHash":       test_helpers.MockBlock.Header().ParentHash,
		"nonce":            test_helpers.MockBlock.Header().Nonce,
		"mixHash":          test_helpers.MockBlock.Header().MixDigest,
		"sha3Uncles":       test_helpers.MockBlock.Header().UncleHash,
		"logsBloom":        test_helpers.MockBlock.Header().Bloom,
		"stateRoot":        test_helpers.MockBlock.Header().Root,
		"miner":            test_helpers.MockBlock.Header().Coinbase,
		"difficulty":       (*hexutil.Big)(test_helpers.MockBlock.Header().Difficulty),
		"extraData":        hexutil.Bytes(test_helpers.MockBlock.Header().Extra),
		"size":             hexutil.Uint64(test_helpers.MockBlock.Header().Size()),
		"gasLimit":         hexutil.Uint64(test_helpers.MockBlock.Header().GasLimit),
		"gasUsed":          hexutil.Uint64(test_helpers.MockBlock.Header().GasUsed),
		"timestamp":        hexutil.Uint64(test_helpers.MockBlock.Header().Time),
		"transactionsRoot": test_helpers.MockBlock.Header().TxHash,
		"receiptsRoot":     test_helpers.MockBlock.Header().ReceiptHash,
		"totalDifficulty":  (*hexutil.Big)(test_helpers.MockBlock.Header().Difficulty),
	}
	expectedUncle1 = map[string]interface{}{
		"number":           (*hexutil.Big)(test_helpers.MockUncles[0].Number),
		"hash":             test_helpers.MockUncles[0].Hash(),
		"parentHash":       test_helpers.MockUncles[0].ParentHash,
		"nonce":            test_helpers.MockUncles[0].Nonce,
		"mixHash":          test_helpers.MockUncles[0].MixDigest,
		"sha3Uncles":       test_helpers.MockUncles[0].UncleHash,
		"logsBloom":        test_helpers.MockUncles[0].Bloom,
		"stateRoot":        test_helpers.MockUncles[0].Root,
		"miner":            test_helpers.MockUncles[0].Coinbase,
		"difficulty":       (*hexutil.Big)(test_helpers.MockUncles[0].Difficulty),
		"extraData":        hexutil.Bytes(test_helpers.MockUncles[0].Extra),
		"size":             hexutil.Uint64(types.NewBlockWithHeader(test_helpers.MockUncles[0]).Size()),
		"gasLimit":         hexutil.Uint64(test_helpers.MockUncles[0].GasLimit),
		"gasUsed":          hexutil.Uint64(test_helpers.MockUncles[0].GasUsed),
		"timestamp":        hexutil.Uint64(test_helpers.MockUncles[0].Time),
		"transactionsRoot": test_helpers.MockUncles[0].TxHash,
		"receiptsRoot":     test_helpers.MockUncles[0].ReceiptHash,
		"uncles":           []common.Hash{},
	}
	expectedUncle2 = map[string]interface{}{
		"number":           (*hexutil.Big)(test_helpers.MockUncles[1].Number),
		"hash":             test_helpers.MockUncles[1].Hash(),
		"parentHash":       test_helpers.MockUncles[1].ParentHash,
		"nonce":            test_helpers.MockUncles[1].Nonce,
		"mixHash":          test_helpers.MockUncles[1].MixDigest,
		"sha3Uncles":       test_helpers.MockUncles[1].UncleHash,
		"logsBloom":        test_helpers.MockUncles[1].Bloom,
		"stateRoot":        test_helpers.MockUncles[1].Root,
		"miner":            test_helpers.MockUncles[1].Coinbase,
		"difficulty":       (*hexutil.Big)(test_helpers.MockUncles[1].Difficulty),
		"extraData":        hexutil.Bytes(test_helpers.MockUncles[1].Extra),
		"size":             hexutil.Uint64(types.NewBlockWithHeader(test_helpers.MockUncles[1]).Size()),
		"gasLimit":         hexutil.Uint64(test_helpers.MockUncles[1].GasLimit),
		"gasUsed":          hexutil.Uint64(test_helpers.MockUncles[1].GasUsed),
		"timestamp":        hexutil.Uint64(test_helpers.MockUncles[1].Time),
		"transactionsRoot": test_helpers.MockUncles[1].TxHash,
		"receiptsRoot":     test_helpers.MockUncles[1].ReceiptHash,
		"uncles":           []common.Hash{},
	}
	expectedTransaction  = eth.NewRPCTransaction(test_helpers.MockTransactions[0], test_helpers.MockBlock.Hash(), test_helpers.MockBlock.NumberU64(), 0)
	expectedTransaction2 = eth.NewRPCTransaction(test_helpers.MockTransactions[1], test_helpers.MockBlock.Hash(), test_helpers.MockBlock.NumberU64(), 1)
	expectedTransaction3 = eth.NewRPCTransaction(test_helpers.MockTransactions[2], test_helpers.MockBlock.Hash(), test_helpers.MockBlock.NumberU64(), 2)
	expectRawTx, _       = rlp.EncodeToBytes(test_helpers.MockTransactions[0])
	expectRawTx2, _      = rlp.EncodeToBytes(test_helpers.MockTransactions[1])
	expectRawTx3, _      = rlp.EncodeToBytes(test_helpers.MockTransactions[2])
	expectedReceipt      = map[string]interface{}{
		"blockHash":         blockHash,
		"blockNumber":       hexutil.Uint64(uint64(number.Int64())),
		"transactionHash":   expectedTransaction.Hash,
		"transactionIndex":  hexutil.Uint64(0),
		"from":              expectedTransaction.From,
		"to":                expectedTransaction.To,
		"gasUsed":           hexutil.Uint64(test_helpers.MockReceipts[0].GasUsed),
		"cumulativeGasUsed": hexutil.Uint64(test_helpers.MockReceipts[0].CumulativeGasUsed),
		"contractAddress":   nil,
		"logs":              test_helpers.MockReceipts[0].Logs,
		"logsBloom":         test_helpers.MockReceipts[0].Bloom,
		"root":              hexutil.Bytes(test_helpers.MockReceipts[0].PostState),
	}
	expectedReceipt2 = map[string]interface{}{
		"blockHash":         blockHash,
		"blockNumber":       hexutil.Uint64(uint64(number.Int64())),
		"transactionHash":   expectedTransaction2.Hash,
		"transactionIndex":  hexutil.Uint64(1),
		"from":              expectedTransaction2.From,
		"to":                expectedTransaction2.To,
		"gasUsed":           hexutil.Uint64(test_helpers.MockReceipts[1].GasUsed),
		"cumulativeGasUsed": hexutil.Uint64(test_helpers.MockReceipts[1].CumulativeGasUsed),
		"contractAddress":   nil,
		"logs":              test_helpers.MockReceipts[1].Logs,
		"logsBloom":         test_helpers.MockReceipts[1].Bloom,
		"root":              hexutil.Bytes(test_helpers.MockReceipts[1].PostState),
	}
	expectedReceipt3 = map[string]interface{}{
		"blockHash":         blockHash,
		"blockNumber":       hexutil.Uint64(uint64(number.Int64())),
		"transactionHash":   expectedTransaction3.Hash,
		"transactionIndex":  hexutil.Uint64(2),
		"from":              expectedTransaction3.From,
		"to":                expectedTransaction3.To,
		"gasUsed":           hexutil.Uint64(test_helpers.MockReceipts[2].GasUsed),
		"cumulativeGasUsed": hexutil.Uint64(test_helpers.MockReceipts[2].CumulativeGasUsed),
		"contractAddress":   test_helpers.ContractAddress,
		"logs":              test_helpers.MockReceipts[2].Logs,
		"logsBloom":         test_helpers.MockReceipts[2].Bloom,
		"root":              hexutil.Bytes(test_helpers.MockReceipts[2].PostState),
	}
)

var _ = Describe("API", func() {
	var (
		db          *postgres.DB
		api         *eth.PublicEthAPI
		chainConfig = params.TestChainConfig
	)
	// Test db setup, rather than using BeforeEach we only need to setup once since the tests do not mutate the database
	// Note: if you focus one of the tests be sure to focus this and the defered It()
	It("test init", func() {
		var err error
		db, err = shared.SetupDB()
		Expect(err).ToNot(HaveOccurred())
		indexAndPublisher := eth2.NewIPLDPublisher(db)
		backend, err := eth.NewEthBackend(db, &eth.Config{
			ChainConfig: chainConfig,
			VmConfig:    vm.Config{},
			RPCGasCap:   big.NewInt(10000000000), // Max gas capacity for a rpc call.
		})
		Expect(err).ToNot(HaveOccurred())
		api = eth.NewPublicEthAPI(backend, nil, false)
		err = indexAndPublisher.Publish(test_helpers.MockConvertedPayload)
		Expect(err).ToNot(HaveOccurred())
		err = publishCode(db, test_helpers.ContractCodeHash, test_helpers.ContractCode)
		Expect(err).ToNot(HaveOccurred())
		uncles := test_helpers.MockBlock.Uncles()
		uncleHashes := make([]common.Hash, len(uncles))
		for i, uncle := range uncles {
			uncleHashes[i] = uncle.Hash()
		}
		expectedBlock["uncles"] = uncleHashes
	})
	// Single test db tear down at end of all tests
	defer It("test teardown", func() { eth.TearDownDB(db) })
	/*

	   Headers and blocks

	*/
	Describe("eth_getHeaderByNumber", func() {
		It("Retrieves a header by number", func() {
			header, err := api.GetHeaderByNumber(ctx, number)
			Expect(err).ToNot(HaveOccurred())
			Expect(header).To(Equal(expectedHeader))
		})

		It("Throws an error if a header cannot be found", func() {
			header, err := api.GetHeaderByNumber(ctx, wrongNumber)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("sql: no rows in result set"))
			Expect(header).To(BeNil())
			_, err = api.B.DB.Beginx()
			Expect(err).ToNot(HaveOccurred())
		})
	})

	Describe("eth_getHeaderByHash", func() {
		It("Retrieves a header by hash", func() {
			header := api.GetHeaderByHash(ctx, blockHash)
			Expect(header).To(Equal(expectedHeader))
		})

		It("Throws an error if a header cannot be found", func() {
			header := api.GetHeaderByHash(ctx, randomHash)
			Expect(header).To(BeNil())
		})
	})

	Describe("eth_blockNumber", func() {
		It("Retrieves the head block number", func() {
			bn := api.BlockNumber()
			ubn := (uint64)(bn)
			subn := strconv.FormatUint(ubn, 10)
			Expect(subn).To(Equal(test_helpers.BlockNumber.String()))
		})
	})

	Describe("eth_getBlockByNumber", func() {
		It("Retrieves a block by number, without full txs", func() {
			block, err := api.GetBlockByNumber(ctx, number, false)
			Expect(err).ToNot(HaveOccurred())
			transactionHashes := make([]interface{}, len(test_helpers.MockBlock.Transactions()))
			for i, trx := range test_helpers.MockBlock.Transactions() {
				transactionHashes[i] = trx.Hash()
			}
			expectedBlock["transactions"] = transactionHashes
			for key, val := range expectedBlock {
				Expect(val).To(Equal(block[key]))
			}
		})
		It("Retrieves a block by number, with full txs", func() {
			block, err := api.GetBlockByNumber(ctx, number, true)
			Expect(err).ToNot(HaveOccurred())
			transactions := make([]interface{}, len(test_helpers.MockBlock.Transactions()))
			for i, trx := range test_helpers.MockBlock.Transactions() {
				transactions[i] = eth.NewRPCTransactionFromBlockHash(test_helpers.MockBlock, trx.Hash())
			}
			expectedBlock["transactions"] = transactions
			for key, val := range expectedBlock {
				Expect(val).To(Equal(block[key]))
			}
		})
		It("Returns `nil` if a block cannot be found", func() {
			block, err := api.GetBlockByNumber(ctx, wrongNumber, false)
			Expect(err).ToNot(HaveOccurred())
			Expect(block).To(BeNil())
		})
	})

	Describe("eth_getBlockByHash", func() {
		It("Retrieves a block by hash, without full txs", func() {
			block, err := api.GetBlockByHash(ctx, test_helpers.MockBlock.Hash(), false)
			Expect(err).ToNot(HaveOccurred())
			transactionHashes := make([]interface{}, len(test_helpers.MockBlock.Transactions()))
			for i, trx := range test_helpers.MockBlock.Transactions() {
				transactionHashes[i] = trx.Hash()
			}
			expectedBlock["transactions"] = transactionHashes
			for key, val := range expectedBlock {
				Expect(val).To(Equal(block[key]))
			}
		})
		It("Retrieves a block by hash, with full txs", func() {
			block, err := api.GetBlockByHash(ctx, test_helpers.MockBlock.Hash(), true)
			Expect(err).ToNot(HaveOccurred())
			transactions := make([]interface{}, len(test_helpers.MockBlock.Transactions()))
			for i, trx := range test_helpers.MockBlock.Transactions() {
				transactions[i] = eth.NewRPCTransactionFromBlockHash(test_helpers.MockBlock, trx.Hash())
			}
			expectedBlock["transactions"] = transactions
			for key, val := range expectedBlock {
				Expect(val).To(Equal(block[key]))
			}
		})
		It("Returns `nil` if a block cannot be found", func() {
			block, err := api.GetBlockByHash(ctx, randomHash, false)
			Expect(err).ToNot(HaveOccurred())
			Expect(block).To(BeZero())
		})
	})

	/*

	   Uncles

	*/

	Describe("eth_getUncleByBlockNumberAndIndex", func() {
		It("Retrieves the uncle at the provided index in the canoncial block with the provided hash", func() {
			uncle1, err := api.GetUncleByBlockNumberAndIndex(ctx, number, 0)
			Expect(err).ToNot(HaveOccurred())
			Expect(uncle1).To(Equal(expectedUncle1))
			uncle2, err := api.GetUncleByBlockNumberAndIndex(ctx, number, 1)
			Expect(err).ToNot(HaveOccurred())
			Expect(uncle2).To(Equal(expectedUncle2))
		})
		It("Returns `nil` if an block for block number cannot be found", func() {
			block, err := api.GetUncleByBlockNumberAndIndex(ctx, wrongNumber, 0)
			Expect(err).ToNot(HaveOccurred())
			Expect(block).To(BeNil())
		})
		It("Returns `nil` if an uncle at the provided index does not exist for the block found for the provided block number", func() {
			uncle, err := api.GetUncleByBlockNumberAndIndex(ctx, number, 2)
			Expect(err).ToNot(HaveOccurred())
			Expect(uncle).To(BeNil())
		})
	})

	Describe("eth_getUncleByBlockHashAndIndex", func() {
		It("Retrieves the uncle at the provided index in the block with the provided hash", func() {
			uncle1, err := api.GetUncleByBlockHashAndIndex(ctx, blockHash, 0)
			Expect(err).ToNot(HaveOccurred())
			Expect(uncle1).To(Equal(expectedUncle1))
			uncle2, err := api.GetUncleByBlockHashAndIndex(ctx, blockHash, 1)
			Expect(err).ToNot(HaveOccurred())
			Expect(uncle2).To(Equal(expectedUncle2))
		})
		It("Returns `nil` if a block for blockhash cannot be found", func() {
			block, err := api.GetUncleByBlockHashAndIndex(ctx, randomHash, 0)
			Expect(err).ToNot(HaveOccurred())
			Expect(block).To(BeNil())
		})
		It("Returns `nil` if an uncle at the provided index does not exist for the block with the provided hash", func() {
			uncle, err := api.GetUncleByBlockHashAndIndex(ctx, blockHash, 2)
			Expect(err).ToNot(HaveOccurred())
			Expect(uncle).To(BeNil())
		})
	})

	Describe("eth_getUncleCountByBlockNumber", func() {
		It("Retrieves the number of uncles for the canonical block with the provided number", func() {
			count := api.GetUncleCountByBlockNumber(ctx, number)
			Expect(*count).NotTo(Equal(nil))
			Expect(uint64(*count)).To(Equal(uint64(2)))
		})
	})

	Describe("eth_getUncleCountByBlockHash", func() {
		It("Retrieves the number of uncles for the block with the provided hash", func() {
			count := api.GetUncleCountByBlockHash(ctx, blockHash)
			Expect(*count).NotTo(Equal(nil))
			Expect(uint64(*count)).To(Equal(uint64(2)))
		})
	})

	/*

	   Transactions

	*/

	Describe("eth_getTransactionCount", func() {
		It("Retrieves the number of transactions the given address has sent for the given block number", func() {
			count, err := api.GetTransactionCount(ctx, test_helpers.ContractAddress, rpc.BlockNumberOrHashWithNumber(number))
			Expect(err).ToNot(HaveOccurred())
			Expect(*count).To(Equal(hexutil.Uint64(1)))

			count, err = api.GetTransactionCount(ctx, test_helpers.AccountAddresss, rpc.BlockNumberOrHashWithNumber(number))
			Expect(err).ToNot(HaveOccurred())
			Expect(*count).To(Equal(hexutil.Uint64(0)))
		})
		It("Retrieves the number of transactions the given address has sent for the given block hash", func() {
			count, err := api.GetTransactionCount(ctx, test_helpers.ContractAddress, rpc.BlockNumberOrHashWithHash(blockHash, true))
			Expect(err).ToNot(HaveOccurred())
			Expect(*count).To(Equal(hexutil.Uint64(1)))

			count, err = api.GetTransactionCount(ctx, test_helpers.AccountAddresss, rpc.BlockNumberOrHashWithHash(blockHash, true))
			Expect(err).ToNot(HaveOccurred())
			Expect(*count).To(Equal(hexutil.Uint64(0)))
		})
	})

	Describe("eth_getBlockTransactionCountByNumber", func() {
		It("Retrieves the number of transactions in the canonical block with the provided number", func() {
			count := api.GetBlockTransactionCountByNumber(ctx, number)
			Expect(uint64(*count)).To(Equal(uint64(3)))
		})
	})

	Describe("eth_getBlockTransactionCountByHash", func() {
		It("Retrieves the number of transactions in the block with the provided hash ", func() {
			count := api.GetBlockTransactionCountByHash(ctx, blockHash)
			Expect(uint64(*count)).To(Equal(uint64(3)))
		})
	})

	Describe("eth_getTransactionByBlockNumberAndIndex", func() {
		It("Retrieves the tx with the provided index in the canonical block with the provided block number", func() {
			tx := api.GetTransactionByBlockNumberAndIndex(ctx, number, 0)
			Expect(tx).ToNot(BeNil())
			Expect(tx).To(Equal(expectedTransaction))

			tx = api.GetTransactionByBlockNumberAndIndex(ctx, number, 1)
			Expect(tx).ToNot(BeNil())
			Expect(tx).To(Equal(expectedTransaction2))

			tx = api.GetTransactionByBlockNumberAndIndex(ctx, number, 2)
			Expect(tx).ToNot(BeNil())
			Expect(tx).To(Equal(expectedTransaction3))
		})
	})

	Describe("eth_getTransactionByBlockHashAndIndex", func() {
		It("Retrieves the tx with the provided index in the block with the provided hash", func() {
			tx := api.GetTransactionByBlockHashAndIndex(ctx, blockHash, 0)
			Expect(tx).ToNot(BeNil())
			Expect(tx).To(Equal(expectedTransaction))

			tx = api.GetTransactionByBlockHashAndIndex(ctx, blockHash, 1)
			Expect(tx).ToNot(BeNil())
			Expect(tx).To(Equal(expectedTransaction2))

			tx = api.GetTransactionByBlockHashAndIndex(ctx, blockHash, 2)
			Expect(tx).ToNot(BeNil())
			Expect(tx).To(Equal(expectedTransaction3))
		})
	})

	Describe("eth_getRawTransactionByBlockNumberAndIndex", func() {
		It("Retrieves the raw tx with the provided index in the canonical block with the provided block number", func() {
			tx := api.GetRawTransactionByBlockNumberAndIndex(ctx, number, 0)
			Expect(tx).ToNot(BeNil())
			Expect(tx).To(Equal(hexutil.Bytes(expectRawTx)))

			tx = api.GetRawTransactionByBlockNumberAndIndex(ctx, number, 1)
			Expect(tx).ToNot(BeNil())
			Expect(tx).To(Equal(hexutil.Bytes(expectRawTx2)))

			tx = api.GetRawTransactionByBlockNumberAndIndex(ctx, number, 2)
			Expect(tx).ToNot(BeNil())
			Expect(tx).To(Equal(hexutil.Bytes(expectRawTx3)))
		})
	})

	Describe("eth_getRawTransactionByBlockHashAndIndex", func() {
		It("Retrieves the raw tx with the provided index in the block with the provided hash", func() {
			tx := api.GetRawTransactionByBlockHashAndIndex(ctx, blockHash, 0)
			Expect(tx).ToNot(BeNil())
			Expect(tx).To(Equal(hexutil.Bytes(expectRawTx)))

			tx = api.GetRawTransactionByBlockHashAndIndex(ctx, blockHash, 1)
			Expect(tx).ToNot(BeNil())
			Expect(tx).To(Equal(hexutil.Bytes(expectRawTx2)))

			tx = api.GetRawTransactionByBlockHashAndIndex(ctx, blockHash, 2)
			Expect(tx).ToNot(BeNil())
			Expect(tx).To(Equal(hexutil.Bytes(expectRawTx3)))
		})
	})

	Describe("eth_getTransactionByHash", func() {
		It("Retrieves a transaction by hash", func() {
			hash := test_helpers.MockTransactions[0].Hash()
			tx, err := api.GetTransactionByHash(ctx, hash)
			Expect(err).ToNot(HaveOccurred())
			Expect(tx).To(Equal(expectedTransaction))

			hash = test_helpers.MockTransactions[1].Hash()
			tx, err = api.GetTransactionByHash(ctx, hash)
			Expect(err).ToNot(HaveOccurred())
			Expect(tx).To(Equal(expectedTransaction2))

			hash = test_helpers.MockTransactions[2].Hash()
			tx, err = api.GetTransactionByHash(ctx, hash)
			Expect(err).ToNot(HaveOccurred())
			Expect(tx).To(Equal(expectedTransaction3))
		})
		It("Throws an error if it cannot find a tx for the provided tx hash", func() {
			_, err := api.GetTransactionByHash(ctx, randomHash)
			Expect(err).To(HaveOccurred())
		})
	})

	Describe("eth_getRawTransactionByHash", func() {
		It("Retrieves a raw transaction by hash", func() {
			hash := test_helpers.MockTransactions[0].Hash()
			tx, err := api.GetRawTransactionByHash(ctx, hash)
			Expect(err).ToNot(HaveOccurred())
			Expect(tx).To(Equal(hexutil.Bytes(expectRawTx)))

			hash = test_helpers.MockTransactions[1].Hash()
			tx, err = api.GetRawTransactionByHash(ctx, hash)
			Expect(err).ToNot(HaveOccurred())
			Expect(tx).To(Equal(hexutil.Bytes(expectRawTx2)))

			hash = test_helpers.MockTransactions[2].Hash()
			tx, err = api.GetRawTransactionByHash(ctx, hash)
			Expect(err).ToNot(HaveOccurred())
			Expect(tx).To(Equal(hexutil.Bytes(expectRawTx3)))
		})
		It("Throws an error if it cannot find a tx for the provided tx hash", func() {
			_, err := api.GetRawTransactionByHash(ctx, randomHash)
			Expect(err).To(HaveOccurred())
		})
	})

	/*

	   Receipts and logs

	*/

	Describe("eth_getTransactionReceipt", func() {
		It("Retrieves a receipt by tx hash", func() {
			hash := test_helpers.MockTransactions[0].Hash()
			rct, err := api.GetTransactionReceipt(ctx, hash)
			Expect(err).ToNot(HaveOccurred())
			Expect(rct).To(Equal(expectedReceipt))

			hash = test_helpers.MockTransactions[1].Hash()
			rct, err = api.GetTransactionReceipt(ctx, hash)
			Expect(err).ToNot(HaveOccurred())
			Expect(rct).To(Equal(expectedReceipt2))

			hash = test_helpers.MockTransactions[2].Hash()
			rct, err = api.GetTransactionReceipt(ctx, hash)
			Expect(err).ToNot(HaveOccurred())
			Expect(rct).To(Equal(expectedReceipt3))
		})
		It("Throws an error if it cannot find a receipt for the provided tx hash", func() {
			_, err := api.GetTransactionReceipt(ctx, randomHash)
			Expect(err).To(HaveOccurred())
		})
	})

	Describe("eth_getLogs", func() {
		It("Retrieves receipt logs that match the provided topics within the provided range", func() {
			crit := filters.FilterCriteria{
				Topics: [][]common.Hash{
					{
						common.HexToHash("0x04"),
					},
				},
				FromBlock: test_helpers.MockBlock.Number(),
				ToBlock:   test_helpers.MockBlock.Number(),
			}
			logs, err := api.GetLogs(ctx, crit)
			Expect(err).ToNot(HaveOccurred())
			Expect(len(logs)).To(Equal(1))
			Expect(logs).To(Equal([]*types.Log{test_helpers.MockLog1}))

			crit = filters.FilterCriteria{
				Topics: [][]common.Hash{
					{
						common.HexToHash("0x04"),
						common.HexToHash("0x05"),
					},
				},
				FromBlock: test_helpers.MockBlock.Number(),
				ToBlock:   test_helpers.MockBlock.Number(),
			}
			logs, err = api.GetLogs(ctx, crit)
			Expect(err).ToNot(HaveOccurred())
			Expect(len(logs)).To(Equal(2))
			Expect(logs).To(Equal([]*types.Log{test_helpers.MockLog1, test_helpers.MockLog2}))

			crit = filters.FilterCriteria{
				Topics: [][]common.Hash{
					{
						common.HexToHash("0x04"),
						common.HexToHash("0x06"),
					},
				},
				FromBlock: test_helpers.MockBlock.Number(),
				ToBlock:   test_helpers.MockBlock.Number(),
			}
			logs, err = api.GetLogs(ctx, crit)
			Expect(err).ToNot(HaveOccurred())
			Expect(len(logs)).To(Equal(1))
			Expect(logs).To(Equal([]*types.Log{test_helpers.MockLog1}))

			crit = filters.FilterCriteria{
				Topics: [][]common.Hash{
					{
						common.HexToHash("0x04"),
					},
					{
						common.HexToHash("0x07"),
					},
				},
				FromBlock: test_helpers.MockBlock.Number(),
				ToBlock:   test_helpers.MockBlock.Number(),
			}
			logs, err = api.GetLogs(ctx, crit)
			Expect(err).ToNot(HaveOccurred())
			Expect(len(logs)).To(Equal(0))

			crit = filters.FilterCriteria{
				Topics: [][]common.Hash{
					{
						common.HexToHash("0x04"),
					},
					{
						common.HexToHash("0x06"),
					},
				},
				FromBlock: test_helpers.MockBlock.Number(),
				ToBlock:   test_helpers.MockBlock.Number(),
			}
			logs, err = api.GetLogs(ctx, crit)
			Expect(err).ToNot(HaveOccurred())
			Expect(len(logs)).To(Equal(1))
			Expect(logs).To(Equal([]*types.Log{test_helpers.MockLog1}))

			crit = filters.FilterCriteria{
				Topics: [][]common.Hash{
					{
						common.HexToHash("0x05"),
					},
					{
						common.HexToHash("0x07"),
					},
				},
				FromBlock: test_helpers.MockBlock.Number(),
				ToBlock:   test_helpers.MockBlock.Number(),
			}
			logs, err = api.GetLogs(ctx, crit)
			Expect(err).ToNot(HaveOccurred())
			Expect(len(logs)).To(Equal(1))
			Expect(logs).To(Equal([]*types.Log{test_helpers.MockLog2}))

			crit = filters.FilterCriteria{
				Topics: [][]common.Hash{
					{
						common.HexToHash("0x05"),
					},
					{
						common.HexToHash("0x06"),
						common.HexToHash("0x07"),
					},
				},
				FromBlock: test_helpers.MockBlock.Number(),
				ToBlock:   test_helpers.MockBlock.Number(),
			}
			logs, err = api.GetLogs(ctx, crit)
			Expect(err).ToNot(HaveOccurred())
			Expect(len(logs)).To(Equal(1))
			Expect(logs).To(Equal([]*types.Log{test_helpers.MockLog2}))

			crit = filters.FilterCriteria{
				Topics: [][]common.Hash{
					{
						common.HexToHash("0x04"),
						common.HexToHash("0x05"),
					},
					{
						common.HexToHash("0x06"),
						common.HexToHash("0x07"),
					},
				},
				FromBlock: test_helpers.MockBlock.Number(),
				ToBlock:   test_helpers.MockBlock.Number(),
			}
			logs, err = api.GetLogs(ctx, crit)
			Expect(err).ToNot(HaveOccurred())
			Expect(len(logs)).To(Equal(2))
			Expect(logs).To(Equal([]*types.Log{test_helpers.MockLog1, test_helpers.MockLog2}))

			crit = filters.FilterCriteria{
				Topics: [][]common.Hash{
					{},
					{
						common.HexToHash("0x07"),
					},
				},
				FromBlock: test_helpers.MockBlock.Number(),
				ToBlock:   test_helpers.MockBlock.Number(),
			}
			logs, err = api.GetLogs(ctx, crit)
			Expect(err).ToNot(HaveOccurred())
			Expect(len(logs)).To(Equal(1))
			Expect(logs).To(Equal([]*types.Log{test_helpers.MockLog2}))

			crit = filters.FilterCriteria{
				Topics: [][]common.Hash{
					{},
					{
						common.HexToHash("0x06"),
					},
				},
				FromBlock: test_helpers.MockBlock.Number(),
				ToBlock:   test_helpers.MockBlock.Number(),
			}
			logs, err = api.GetLogs(ctx, crit)
			Expect(err).ToNot(HaveOccurred())
			Expect(len(logs)).To(Equal(1))
			Expect(logs).To(Equal([]*types.Log{test_helpers.MockLog1}))

			crit = filters.FilterCriteria{
				Topics:    [][]common.Hash{},
				FromBlock: test_helpers.MockBlock.Number(),
				ToBlock:   test_helpers.MockBlock.Number(),
			}
			logs, err = api.GetLogs(ctx, crit)
			Expect(err).ToNot(HaveOccurred())
			Expect(len(logs)).To(Equal(2))
			Expect(logs).To(Equal([]*types.Log{test_helpers.MockLog1, test_helpers.MockLog2}))
		})

		It("Uses the provided blockhash if one is provided", func() {
			hash := test_helpers.MockBlock.Hash()
			crit := filters.FilterCriteria{
				BlockHash: &hash,
				Topics: [][]common.Hash{
					{},
					{
						common.HexToHash("0x06"),
					},
				},
			}
			logs, err := api.GetLogs(ctx, crit)
			Expect(err).ToNot(HaveOccurred())
			Expect(len(logs)).To(Equal(1))
			Expect(logs).To(Equal([]*types.Log{test_helpers.MockLog1}))

			crit = filters.FilterCriteria{
				BlockHash: &hash,
				Topics: [][]common.Hash{
					{
						common.HexToHash("0x04"),
					},
					{
						common.HexToHash("0x06"),
					},
				},
			}
			logs, err = api.GetLogs(ctx, crit)
			Expect(err).ToNot(HaveOccurred())
			Expect(len(logs)).To(Equal(1))
			Expect(logs).To(Equal([]*types.Log{test_helpers.MockLog1}))

			crit = filters.FilterCriteria{
				BlockHash: &hash,
				Topics: [][]common.Hash{
					{},
					{
						common.HexToHash("0x07"),
					},
				},
			}
			logs, err = api.GetLogs(ctx, crit)
			Expect(err).ToNot(HaveOccurred())
			Expect(len(logs)).To(Equal(1))
			Expect(logs).To(Equal([]*types.Log{test_helpers.MockLog2}))

			crit = filters.FilterCriteria{
				BlockHash: &hash,
				Topics: [][]common.Hash{
					{
						common.HexToHash("0x05"),
					},
					{
						common.HexToHash("0x07"),
					},
				},
			}
			logs, err = api.GetLogs(ctx, crit)
			Expect(err).ToNot(HaveOccurred())
			Expect(len(logs)).To(Equal(1))
			Expect(logs).To(Equal([]*types.Log{test_helpers.MockLog2}))

			crit = filters.FilterCriteria{
				BlockHash: &hash,
				Topics: [][]common.Hash{
					{
						common.HexToHash("0x04"),
					},
					{
						common.HexToHash("0x07"),
					},
				},
			}
			logs, err = api.GetLogs(ctx, crit)
			Expect(err).ToNot(HaveOccurred())
			Expect(len(logs)).To(Equal(0))

			crit = filters.FilterCriteria{
				BlockHash: &hash,
				Topics: [][]common.Hash{
					{
						common.HexToHash("0x04"),
						common.HexToHash("0x05"),
					},
					{
						common.HexToHash("0x07"),
					},
				},
			}
			logs, err = api.GetLogs(ctx, crit)
			Expect(err).ToNot(HaveOccurred())
			Expect(len(logs)).To(Equal(1))
			Expect(logs).To(Equal([]*types.Log{test_helpers.MockLog2}))

			crit = filters.FilterCriteria{
				BlockHash: &hash,
				Topics: [][]common.Hash{
					{
						common.HexToHash("0x04"),
						common.HexToHash("0x05"),
					},
				},
			}
			logs, err = api.GetLogs(ctx, crit)
			Expect(err).ToNot(HaveOccurred())
			Expect(len(logs)).To(Equal(2))
			Expect(logs).To(Equal([]*types.Log{test_helpers.MockLog1, test_helpers.MockLog2}))

			crit = filters.FilterCriteria{
				BlockHash: &hash,
				Topics: [][]common.Hash{
					{
						common.HexToHash("0x04"),
						common.HexToHash("0x05"),
					},
					{
						common.HexToHash("0x06"),
						common.HexToHash("0x07"),
					},
				},
			}
			logs, err = api.GetLogs(ctx, crit)
			Expect(err).ToNot(HaveOccurred())
			Expect(len(logs)).To(Equal(2))
			Expect(logs).To(Equal([]*types.Log{test_helpers.MockLog1, test_helpers.MockLog2}))

			crit = filters.FilterCriteria{
				BlockHash: &hash,
				Topics:    [][]common.Hash{},
			}
			logs, err = api.GetLogs(ctx, crit)
			Expect(err).ToNot(HaveOccurred())
			Expect(len(logs)).To(Equal(2))
			Expect(logs).To(Equal([]*types.Log{test_helpers.MockLog1, test_helpers.MockLog2}))
		})

		It("Filters on contract address if any are provided", func() {
			hash := test_helpers.MockBlock.Hash()
			crit := filters.FilterCriteria{
				BlockHash: &hash,
				Addresses: []common.Address{
					test_helpers.Address,
				},
				Topics: [][]common.Hash{
					{
						common.HexToHash("0x04"),
						common.HexToHash("0x05"),
					},
					{
						common.HexToHash("0x06"),
						common.HexToHash("0x07"),
					},
				},
			}
			logs, err := api.GetLogs(ctx, crit)
			Expect(err).ToNot(HaveOccurred())
			Expect(len(logs)).To(Equal(1))
			Expect(logs).To(Equal([]*types.Log{test_helpers.MockLog1}))

			hash = test_helpers.MockBlock.Hash()
			crit = filters.FilterCriteria{
				BlockHash: &hash,
				Addresses: []common.Address{
					test_helpers.Address,
					test_helpers.AnotherAddress,
				},
				Topics: [][]common.Hash{
					{
						common.HexToHash("0x04"),
						common.HexToHash("0x05"),
					},
					{
						common.HexToHash("0x06"),
						common.HexToHash("0x07"),
					},
				},
			}
			logs, err = api.GetLogs(ctx, crit)
			Expect(err).ToNot(HaveOccurred())
			Expect(len(logs)).To(Equal(2))
			Expect(logs).To(Equal([]*types.Log{test_helpers.MockLog1, test_helpers.MockLog2}))

			hash = test_helpers.MockBlock.Hash()
			crit = filters.FilterCriteria{
				BlockHash: &hash,
				Addresses: []common.Address{
					test_helpers.Address,
					test_helpers.AnotherAddress,
				},
			}
			logs, err = api.GetLogs(ctx, crit)
			Expect(err).ToNot(HaveOccurred())
			Expect(len(logs)).To(Equal(2))
			Expect(logs).To(Equal([]*types.Log{test_helpers.MockLog1, test_helpers.MockLog2}))
		})
	})

	/*

	   State and storage

	*/

	Describe("eth_getBalance", func() {
		It("Retrieves the eth balance for the provided account address at the block with the provided number", func() {
			bal, err := api.GetBalance(ctx, test_helpers.AccountAddresss, rpc.BlockNumberOrHashWithNumber(number))
			Expect(err).ToNot(HaveOccurred())
			Expect(bal).To(Equal((*hexutil.Big)(test_helpers.AccountBalance)))

			bal, err = api.GetBalance(ctx, test_helpers.ContractAddress, rpc.BlockNumberOrHashWithNumber(number))
			Expect(err).ToNot(HaveOccurred())
			Expect(bal).To(Equal((*hexutil.Big)(common.Big0)))
		})
		It("Retrieves the eth balance for the provided account address at the block with the provided hash", func() {
			bal, err := api.GetBalance(ctx, test_helpers.AccountAddresss, rpc.BlockNumberOrHashWithHash(blockHash, true))
			Expect(err).ToNot(HaveOccurred())
			Expect(bal).To(Equal((*hexutil.Big)(test_helpers.AccountBalance)))

			bal, err = api.GetBalance(ctx, test_helpers.ContractAddress, rpc.BlockNumberOrHashWithHash(blockHash, true))
			Expect(err).ToNot(HaveOccurred())
			Expect(bal).To(Equal((*hexutil.Big)(common.Big0)))
		})
		It("Retrieves the eth balance for the non-existing account address at the block with the provided hash", func() {
			bal, err := api.GetBalance(ctx, randomAddr, rpc.BlockNumberOrHashWithHash(blockHash, true))
			Expect(err).ToNot(HaveOccurred())
			Expect(bal).To(Equal((*hexutil.Big)(common.Big0)))
		})
		It("Throws an error for an account of a non-existing block hash", func() {
			_, err := api.GetBalance(ctx, test_helpers.AccountAddresss, rpc.BlockNumberOrHashWithHash(randomHash, true))
			Expect(err).To(HaveOccurred())
		})
		It("Throws an error for an account of a non-existing block number", func() {
			_, err := api.GetBalance(ctx, test_helpers.AccountAddresss, rpc.BlockNumberOrHashWithNumber(wrongNumber))
			Expect(err).To(HaveOccurred())
		})
	})

	Describe("eth_getCode", func() {
		It("Retrieves the code for the provided contract address at the block with the provided number", func() {
			code, err := api.GetCode(ctx, test_helpers.ContractAddress, rpc.BlockNumberOrHashWithNumber(number))
			Expect(err).ToNot(HaveOccurred())
			Expect(code).To(Equal((hexutil.Bytes)(test_helpers.ContractCode)))
		})
		It("Retrieves the code for the provided contract address at the block with the provided hash", func() {
			code, err := api.GetCode(ctx, test_helpers.ContractAddress, rpc.BlockNumberOrHashWithHash(blockHash, true))
			Expect(err).ToNot(HaveOccurred())
			Expect(code).To(Equal((hexutil.Bytes)(test_helpers.ContractCode)))
		})
		It("Returns `nil` for an account it cannot find the code for", func() {
			code, err := api.GetCode(ctx, randomAddr, rpc.BlockNumberOrHashWithHash(blockHash, true))
			Expect(err).ToNot(HaveOccurred())
			Expect(code).To(BeEmpty())
		})
	})
})

func publishCode(db *postgres.DB, codeHash common.Hash, code []byte) error {
	tx, err := db.Beginx()
	if err != nil {
		return err
	}
	mhKey, err := shared.MultihashKeyFromKeccak256(codeHash)
	if err != nil {
		tx.Rollback()
		return err
	}
	if err := shared.PublishDirect(tx, mhKey, code); err != nil {
		tx.Rollback()
		return err
	}
	return tx.Commit()
}
