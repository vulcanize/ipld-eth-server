package integration_test

import (
	"context"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	integration "github.com/vulcanize/ipld-eth-server/test"

	"github.com/ethereum/go-ethereum/ethclient"
)

const nonExistingBlockHash = "0x111111111111111111111111111111111111111111111111111111111111111"
const nonExistingAddress = "0x1111111111111111111111111111111111111111"

var (
	randomAddr = common.HexToAddress("0x1C3ab14BBaD3D99F4203bd7a11aCB94882050E6f")
	randomHash = crypto.Keccak256Hash(randomAddr.Bytes())
)

var _ = Describe("Integration test", func() {
	gethHttpPath := "http://127.0.0.1:8545"
	gethClient, err := ethclient.Dial(gethHttpPath)
	Expect(err).ToNot(HaveOccurred())

	ipldEthHttpPath := "http://127.0.0.1:8081"
	ipldClient, err := ethclient.Dial(ipldEthHttpPath)
	Expect(err).ToNot(HaveOccurred())

	ctx := context.Background()

	var contract *integration.ContractDeployed
	var erc20TotalSupply *big.Int
	var tx *integration.Tx
	var bigIntResult bool
	var contractErr error
	var txErr error
	sleepInterval := 2 * time.Second

	Describe("get Block", func() {
		BeforeEach(func() {
			contract, contractErr = integration.DeployContract()
			time.Sleep(sleepInterval)
		})

		It("get not existing block by number", func() {
			Expect(contractErr).ToNot(HaveOccurred())

			blockNum := contract.BlockNumber + 100

			gethBlock, err := gethClient.BlockByNumber(ctx, big.NewInt(int64(blockNum)))
			Expect(err).To(MatchError(ethereum.NotFound))
			Expect(gethBlock).To(BeZero())

			ipldBlock, err := ipldClient.BlockByNumber(ctx, big.NewInt(int64(blockNum)))
			Expect(err).To(MatchError(ethereum.NotFound))
			Expect(ipldBlock).To(BeZero())
		})

		It("get not existing block by hash", func() {
			gethBlock, err := gethClient.BlockByHash(ctx, common.HexToHash(nonExistingBlockHash))
			Expect(err).To(MatchError(ethereum.NotFound))
			Expect(gethBlock).To(BeZero())

			ipldBlock, err := ipldClient.BlockByHash(ctx, common.HexToHash(nonExistingBlockHash))
			Expect(err).To(MatchError(ethereum.NotFound))
			Expect(ipldBlock).To(BeZero())
		})

		It("get block by number", func() {
			Expect(contractErr).ToNot(HaveOccurred())

			blockNum := contract.BlockNumber

			gethBlock, err := gethClient.BlockByNumber(ctx, big.NewInt(int64(blockNum)))
			Expect(err).ToNot(HaveOccurred())

			ipldBlock, err := ipldClient.BlockByNumber(ctx, big.NewInt(int64(blockNum)))
			Expect(err).ToNot(HaveOccurred())

			// check headers are equals
			Expect(gethBlock.Header()).To(Equal(ipldBlock.Header()))

			gethTxs := gethBlock.Transactions()
			ipldTxs := ipldBlock.Transactions()

			Expect(gethTxs.Len()).To(Equal(ipldTxs.Len()))
			Expect(types.TxDifference(gethTxs, ipldTxs).Len()).To(Equal(0))
		})

		It("get block by hash", func() {
			gethBlock, err := gethClient.BlockByHash(ctx, common.HexToHash(contract.BlockHash))
			Expect(err).ToNot(HaveOccurred())

			ipldBlock, err := ipldClient.BlockByHash(ctx, common.HexToHash(contract.BlockHash))
			Expect(err).ToNot(HaveOccurred())

			// check headers are equals
			compareBlocks(gethBlock, ipldBlock)

			gethTxs := gethBlock.Transactions()
			ipldTxs := ipldBlock.Transactions()

			Expect(gethTxs.Len()).To(Equal(ipldTxs.Len()))
			Expect(types.TxDifference(gethTxs, ipldTxs).Len()).To(Equal(0))
		})
	})

	Describe("Transaction", func() {
		BeforeEach(func() {
			contract, contractErr = integration.DeployContract()
			time.Sleep(sleepInterval)
		})

		It("Get tx by hash", func() {
			Expect(contractErr).ToNot(HaveOccurred())

			gethTx, _, err := gethClient.TransactionByHash(ctx, common.HexToHash(contract.TransactionHash))
			Expect(err).ToNot(HaveOccurred())

			ipldTx, _, err := ipldClient.TransactionByHash(ctx, common.HexToHash(contract.TransactionHash))
			Expect(err).ToNot(HaveOccurred())

			compareTxs(gethTx, ipldTx)

			Expect(gethTx.Hash()).To(Equal(ipldTx.Hash()))
		})

		It("Get tx by block hash and index", func() {
			gethTx, err := gethClient.TransactionInBlock(ctx, common.HexToHash(contract.BlockHash), 0)
			Expect(err).ToNot(HaveOccurred())

			ipldTx, err := ipldClient.TransactionInBlock(ctx, common.HexToHash(contract.BlockHash), 0)
			Expect(err).ToNot(HaveOccurred())

			compareTxs(gethTx, ipldTx)
		})
	})

	Describe("Receipt", func() {
		BeforeEach(func() {
			contract, contractErr = integration.DeployContract()
			time.Sleep(sleepInterval)
		})

		It("Get tx receipt", func() {
			Expect(contractErr).ToNot(HaveOccurred())

			gethReceipt, err := gethClient.TransactionReceipt(ctx, common.HexToHash(contract.TransactionHash))
			Expect(err).ToNot(HaveOccurred())

			ipldReceipt, err := ipldClient.TransactionReceipt(ctx, common.HexToHash(contract.TransactionHash))
			Expect(err).ToNot(HaveOccurred())

			Expect(gethReceipt).To(Equal(ipldReceipt))

			rlpGeth, err := rlp.EncodeToBytes(gethReceipt)
			Expect(err).ToNot(HaveOccurred())

			rlpIpld, err := rlp.EncodeToBytes(ipldReceipt)
			Expect(err).ToNot(HaveOccurred())

			Expect(rlpGeth).To(Equal(rlpIpld))
		})
	})

	Describe("FilterLogs", func() {
		BeforeEach(func() {
			contract, contractErr = integration.DeployContract()
			time.Sleep(sleepInterval)
		})

		It("with blockhash", func() {
			Expect(contractErr).ToNot(HaveOccurred())

			blockHash := common.HexToHash(contract.BlockHash)
			filterQuery := ethereum.FilterQuery{
				//Addresses: addresses,
				BlockHash: &blockHash,
				Topics:    [][]common.Hash{},
			}

			gethLogs, err := gethClient.FilterLogs(ctx, filterQuery)
			Expect(err).ToNot(HaveOccurred())

			ipldLogs, err := ipldClient.FilterLogs(ctx, filterQuery)
			Expect(err).ToNot(HaveOccurred())

			// not empty list
			Expect(gethLogs).ToNot(BeEmpty())

			Expect(len(gethLogs)).To(Equal(len(ipldLogs)))
			Expect(gethLogs).To(Equal(ipldLogs))
		})
	})

	Describe("CodeAt", func() {
		BeforeEach(func() {
			contract, contractErr = integration.DeployContract()
			time.Sleep(sleepInterval)
		})

		It("gets code at non-existing address without block number", func() {
			Expect(contractErr).ToNot(HaveOccurred())

			gethCode, err := gethClient.CodeAt(ctx, common.HexToAddress(nonExistingAddress), nil)
			Expect(err).ToNot(HaveOccurred())

			ipldCode, err := ipldClient.CodeAt(ctx, common.HexToAddress(nonExistingAddress), nil)
			Expect(err).ToNot(HaveOccurred())

			Expect(gethCode).To(BeEmpty())
			Expect(gethCode).To(Equal(ipldCode))
		})
		It("gets code of deployed contract without block number", func() {
			gethCode, err := gethClient.CodeAt(ctx, common.HexToAddress(contract.Address), nil)
			Expect(err).ToNot(HaveOccurred())

			ipldCode, err := ipldClient.CodeAt(ctx, common.HexToAddress(contract.Address), nil)
			Expect(err).ToNot(HaveOccurred())
			Expect(gethCode).To(Equal(ipldCode))
		})
		It("gets code of deployed contract with block number", func() {
			gethCode, err := gethClient.CodeAt(ctx, common.HexToAddress(contract.Address), big.NewInt(int64(contract.BlockNumber)))
			Expect(err).ToNot(HaveOccurred())

			ipldCode, err := ipldClient.CodeAt(ctx, common.HexToAddress(contract.Address), big.NewInt(int64(contract.BlockNumber)))
			Expect(err).ToNot(HaveOccurred())
			Expect(gethCode).To(Equal(ipldCode))
		})
		It("gets code of contract that doesn't exist at this height", func() {
			gethCode, err := gethClient.CodeAt(ctx, common.HexToAddress(contract.Address), big.NewInt(int64(contract.BlockNumber-1)))
			Expect(err).ToNot(HaveOccurred())

			ipldCode, err := ipldClient.CodeAt(ctx, common.HexToAddress(contract.Address), big.NewInt(int64(contract.BlockNumber-1)))
			Expect(err).ToNot(HaveOccurred())

			Expect(gethCode).To(BeEmpty())
			Expect(gethCode).To(Equal(ipldCode))
		})
	})

	Describe("Get balance", func() {
		address := "0x1111111111111111111111111111111111111112"
		BeforeEach(func() {
			tx, txErr = integration.SendEth(address, "0.01")
			time.Sleep(sleepInterval)
		})

		It("gets balance for an account with eth without block number", func() {
			Expect(txErr).ToNot(HaveOccurred())

			gethBalance, err := gethClient.BalanceAt(ctx, common.HexToAddress(address), nil)
			Expect(err).ToNot(HaveOccurred())

			ipldBalance, err := ipldClient.BalanceAt(ctx, common.HexToAddress(address), nil)
			Expect(err).ToNot(HaveOccurred())

			Expect(gethBalance).To(Equal(ipldBalance))
		})
		It("gets balance for an account with eth with block number", func() {
			Expect(txErr).ToNot(HaveOccurred())

			gethBalance, err := gethClient.BalanceAt(ctx, common.HexToAddress(address), big.NewInt(int64(tx.BlockNumber)))
			Expect(err).ToNot(HaveOccurred())

			ipldBalance, err := ipldClient.BalanceAt(ctx, common.HexToAddress(address), big.NewInt(int64(tx.BlockNumber)))
			Expect(err).ToNot(HaveOccurred())

			Expect(gethBalance).To(Equal(ipldBalance))
		})
		It("gets historical balance for an account with eth with block number", func() {
			Expect(txErr).ToNot(HaveOccurred())

			gethBalance, err := gethClient.BalanceAt(ctx, common.HexToAddress(address), big.NewInt(int64(tx.BlockNumber-1)))
			Expect(err).ToNot(HaveOccurred())

			ipldBalance, err := ipldClient.BalanceAt(ctx, common.HexToAddress(address), big.NewInt(int64(tx.BlockNumber-1)))
			Expect(err).ToNot(HaveOccurred())

			Expect(gethBalance).To(Equal(ipldBalance))
		})
		It("gets balance for a non-existing account without block number", func() {
			Expect(txErr).ToNot(HaveOccurred())

			gethBalance, err := gethClient.BalanceAt(ctx, common.HexToAddress(nonExistingAddress), nil)
			Expect(err).ToNot(HaveOccurred())

			ipldBalance, err := ipldClient.BalanceAt(ctx, common.HexToAddress(nonExistingAddress), nil)
			Expect(err).ToNot(HaveOccurred())

			Expect(gethBalance).To(Equal(ipldBalance))
		})
		It("gets balance for an non-existing block number", func() {
			Expect(txErr).ToNot(HaveOccurred())

			gethBalance, err := gethClient.BalanceAt(ctx, common.HexToAddress(address), big.NewInt(int64(tx.BlockNumber+3)))
			Expect(err).To(MatchError("header not found"))

			ipldBalance, err := ipldClient.BalanceAt(ctx, common.HexToAddress(nonExistingAddress), big.NewInt(int64(tx.BlockNumber+3)))
			Expect(err).To(MatchError("header not found"))

			Expect(gethBalance).To(Equal(ipldBalance))
		})
	})

	Describe("Get Storage", func() {
		BeforeEach(func() {
			contract, contractErr = integration.DeployContract()
			erc20TotalSupply, bigIntResult = new(big.Int).SetString("1000000000000000000000", 10)

			time.Sleep(sleepInterval)
		})

		It("gets ERC20 total supply (without block number)", func() {
			Expect(contractErr).ToNot(HaveOccurred())
			Expect(bigIntResult).To(Equal(true))

			totalSupplyIndex := "0x2"

			gethStorage, err := gethClient.StorageAt(ctx, common.HexToAddress(contract.Address), common.HexToHash(totalSupplyIndex), nil)
			Expect(err).ToNot(HaveOccurred())

			gethTotalSupply := new(big.Int).SetBytes(gethStorage)
			Expect(gethTotalSupply).To(Equal(erc20TotalSupply))

			ipldStorage, err := ipldClient.StorageAt(ctx, common.HexToAddress(contract.Address), common.HexToHash(totalSupplyIndex), nil)
			Expect(err).ToNot(HaveOccurred())

			ipldTotalSupply := new(big.Int).SetBytes(ipldStorage)
			Expect(ipldTotalSupply).To(Equal(erc20TotalSupply))

			Expect(gethStorage).To(Equal(ipldStorage))
		})

		It("gets ERC20 total supply (with block number)", func() {
			totalSupplyIndex := "0x2"

			gethStorage, err := gethClient.StorageAt(ctx, common.HexToAddress(contract.Address), common.HexToHash(totalSupplyIndex), big.NewInt(int64(contract.BlockNumber)))
			Expect(err).ToNot(HaveOccurred())

			gethTotalSupply := new(big.Int).SetBytes(gethStorage)
			Expect(gethTotalSupply).To(Equal(erc20TotalSupply))

			ipldStorage, err := ipldClient.StorageAt(ctx, common.HexToAddress(contract.Address), common.HexToHash(totalSupplyIndex), big.NewInt(int64(contract.BlockNumber)))
			Expect(err).ToNot(HaveOccurred())
			Expect(gethStorage).To(Equal(ipldStorage))
		})
		It("gets storage for non-existing account", func() {
			totalSupplyIndex := "0x2"

			gethStorage, err := gethClient.StorageAt(ctx, common.HexToAddress(nonExistingAddress), common.HexToHash(totalSupplyIndex), big.NewInt(int64(contract.BlockNumber)))
			Expect(err).ToNot(HaveOccurred())

			ipldStorage, err := ipldClient.StorageAt(ctx, common.HexToAddress(nonExistingAddress), common.HexToHash(totalSupplyIndex), big.NewInt(int64(contract.BlockNumber)))
			Expect(err).ToNot(HaveOccurred())
			Expect(gethStorage).To(Equal(ipldStorage))
		})
		It("gets storage for non-existing contract slot", func() {
			gethStorage, err := gethClient.StorageAt(ctx, common.HexToAddress(contract.Address), randomHash, big.NewInt(int64(contract.BlockNumber)))
			Expect(err).ToNot(HaveOccurred())

			ipldStorage, err := ipldClient.StorageAt(ctx, common.HexToAddress(contract.Address), randomHash, big.NewInt(int64(contract.BlockNumber)))
			Expect(err).ToNot(HaveOccurred())
			Expect(gethStorage).To(Equal(ipldStorage))
		})
		It("gets storage for non-existing contract", func() {
			totalSupplyIndex := "0x2"
			gethStorage, err := gethClient.StorageAt(ctx, common.HexToAddress(contract.Address), common.HexToHash(totalSupplyIndex), big.NewInt(0))
			Expect(err).ToNot(HaveOccurred())

			ipldStorage, err := ipldClient.StorageAt(ctx, common.HexToAddress(contract.Address), common.HexToHash(totalSupplyIndex), big.NewInt(0))
			Expect(err).ToNot(HaveOccurred())
			Expect(gethStorage).To(Equal(ipldStorage))
		})
		It("gets storage for non-existing block number", func() {
			blockNum := contract.BlockNumber + 100
			totalSupplyIndex := "0x2"

			gethStorage, err := gethClient.StorageAt(ctx, common.HexToAddress(contract.Address), common.HexToHash(totalSupplyIndex), big.NewInt(int64(blockNum)))
			Expect(err).To(MatchError("header not found"))

			ipldStorage, err := ipldClient.StorageAt(ctx, common.HexToAddress(contract.Address), common.HexToHash(totalSupplyIndex), big.NewInt(int64(blockNum)))
			Expect(err).To(MatchError("header not found"))
			Expect(gethStorage).To(Equal(ipldStorage))
		})
	})

	Describe("eth call", func() {
		BeforeEach(func() {
			contract, contractErr = integration.DeployContract()
			erc20TotalSupply, bigIntResult = new(big.Int).SetString("1000000000000000000000", 10)

			time.Sleep(sleepInterval)
		})

		It("calls totalSupply() without block number", func() {
			Expect(contractErr).ToNot(HaveOccurred())
			Expect(bigIntResult).To(Equal(true))

			contractAddress := common.HexToAddress(contract.Address)

			msg := ethereum.CallMsg{
				To:   &contractAddress,
				Data: common.Hex2Bytes("18160ddd"), // totalSupply()
			}
			gethResult, err := gethClient.CallContract(ctx, msg, nil)
			Expect(err).ToNot(HaveOccurred())

			gethTotalSupply := new(big.Int).SetBytes(gethResult)
			Expect(gethTotalSupply).To(Equal(erc20TotalSupply))

			ipldResult, err := ipldClient.CallContract(ctx, msg, nil)
			Expect(err).ToNot(HaveOccurred())

			Expect(gethResult).To(Equal(ipldResult))
		})

		It("calls totalSupply() with block number", func() {
			contractAddress := common.HexToAddress(contract.Address)

			msg := ethereum.CallMsg{
				To:   &contractAddress,
				Data: common.Hex2Bytes("18160ddd"), // totalSupply()
			}
			gethResult, err := gethClient.CallContract(ctx, msg, big.NewInt(int64(contract.BlockNumber)))
			Expect(err).ToNot(HaveOccurred())

			gethTotalSupply := new(big.Int).SetBytes(gethResult)
			Expect(gethTotalSupply).To(Equal(erc20TotalSupply))

			ipldResult, err := ipldClient.CallContract(ctx, msg, big.NewInt(int64(contract.BlockNumber)))
			Expect(err).ToNot(HaveOccurred())

			Expect(gethResult).To(Equal(ipldResult))
		})
	})

	Describe("Chain ID", func() {
		It("Check chain id", func() {
			gethChainId, err := gethClient.ChainID(ctx)
			Expect(err).ToNot(HaveOccurred())

			ipldChainId, err := ipldClient.ChainID(ctx)
			Expect(err).ToNot(HaveOccurred())

			Expect(gethChainId).To(Equal(ipldChainId))
		})
	})
})

func compareBlocks(block1 *types.Block, block2 *types.Block) {
	Expect(block1.Header()).To(Equal(block2.Header()))
	Expect(block1.Uncles()).To(Equal(block2.Uncles()))

	txs1 := block1.Transactions()
	txs2 := block2.Transactions()

	Expect(len(txs1)).To(Equal(len(txs2)))
	for i, tx := range txs1 {
		compareTxs(tx, txs2[i])
	}
}

func compareTxs(tx1 *types.Transaction, tx2 *types.Transaction) {
	Expect(tx1.Data()).To(Equal(tx2.Data()))
	Expect(tx1.Hash()).To(Equal(tx2.Hash()))
	Expect(tx1.Size()).To(Equal(tx2.Size()))

	signer := types.NewEIP155Signer(big.NewInt(4))

	gethSender, err := types.Sender(signer, tx1)
	Expect(err).ToNot(HaveOccurred())

	ipldSender, err := types.Sender(signer, tx2)
	Expect(err).ToNot(HaveOccurred())

	Expect(gethSender).To(Equal(ipldSender))
}
