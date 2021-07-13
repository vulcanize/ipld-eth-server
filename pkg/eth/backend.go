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

package eth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/bloombits"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/event"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/ethereum/go-ethereum/trie"

	ipfsethdb "github.com/vulcanize/ipfs-ethdb"
	"github.com/vulcanize/ipld-eth-indexer/pkg/ipfs"
	"github.com/vulcanize/ipld-eth-indexer/pkg/postgres"
	shared2 "github.com/vulcanize/ipld-eth-indexer/pkg/shared"

	"github.com/vulcanize/ipld-eth-server/pkg/shared"
)

var (
	errPendingBlockNumber  = errors.New("pending block number not supported")
	errNegativeBlockNumber = errors.New("negative block number not supported")
	errHeaderHashNotFound  = errors.New("header for hash not found")
	errHeaderNotFound      = errors.New("header not found")
)

const (
	RetrieveCanonicalBlockHashByNumber = `SELECT block_hash FROM eth.header_cids
									INNER JOIN public.blocks ON (header_cids.mh_key = blocks.key)
									WHERE id = (SELECT canonical_header_id($1))`
	RetrieveCanonicalHeaderByNumber = `SELECT cid, data FROM eth.header_cids
									INNER JOIN public.blocks ON (header_cids.mh_key = blocks.key)
									WHERE id = (SELECT canonical_header_id($1))`
	RetrieveTD = `SELECT td FROM eth.header_cids
			WHERE header_cids.block_hash = $1`
	RetrieveRPCTransaction = `SELECT blocks.data, block_hash, block_number, index FROM public.blocks, eth.transaction_cids, eth.header_cids
			WHERE blocks.key = transaction_cids.mh_key
			AND transaction_cids.header_id = header_cids.id
			AND transaction_cids.tx_hash = $1`
	RetrieveCodeHashByLeafKeyAndBlockHash = `SELECT code_hash FROM eth.state_accounts, eth.state_cids, eth.header_cids
											WHERE state_accounts.state_id = state_cids.id
											AND state_cids.header_id = header_cids.id
											AND state_leaf_key = $1
											AND block_number <= (SELECT block_number
																FROM eth.header_cids
																WHERE block_hash = $2)
											AND header_cids.id = (SELECT canonical_header_id(block_number))
											ORDER BY block_number DESC
											LIMIT 1`
	RetrieveCodeByMhKey = `SELECT data FROM public.blocks WHERE key = $1`
)

type Backend struct {
	// underlying postgres db
	DB *postgres.DB

	// postgres db interfaces
	Retriever     *CIDRetriever
	Fetcher       *IPLDFetcher
	IPLDRetriever *IPLDRetriever

	// ethereum interfaces
	EthDB         ethdb.Database
	StateDatabase state.Database

	Config *Config
}

type Config struct {
	ChainConfig   *params.ChainConfig
	VmConfig      vm.Config
	DefaultSender *common.Address
	RPCGasCap     *big.Int
}

func NewEthBackend(db *postgres.DB, c *Config) (*Backend, error) {
	r := NewCIDRetriever(db)
	ethDB := ipfsethdb.NewDatabase(db.DB)
	return &Backend{
		DB:            db,
		Retriever:     r,
		Fetcher:       NewIPLDFetcher(db),
		IPLDRetriever: NewIPLDRetriever(db),
		EthDB:         ethDB,
		StateDatabase: state.NewDatabase(ethDB),
		Config:        c,
	}, nil
}

// ChainDb returns the backend's underlying chain database
func (b *Backend) ChainDb() ethdb.Database {
	return b.EthDB
}

// HeaderByNumber gets the canonical header for the provided block number
func (b *Backend) HeaderByNumber(ctx context.Context, blockNumber rpc.BlockNumber) (*types.Header, error) {
	var err error
	number := blockNumber.Int64()
	if blockNumber == rpc.LatestBlockNumber {
		number, err = b.Retriever.RetrieveLastBlockNumber()
		if err != nil {
			return nil, err
		}
	}
	if blockNumber == rpc.EarliestBlockNumber {
		number, err = b.Retriever.RetrieveFirstBlockNumber()
		if err != nil {
			return nil, err
		}
	}
	if blockNumber == rpc.PendingBlockNumber {
		return nil, errPendingBlockNumber
	}
	if number < 0 {
		return nil, errNegativeBlockNumber
	}
	_, canonicalHeaderRLP, err := b.GetCanonicalHeader(uint64(number))
	if err != nil {
		return nil, err
	}

	header := new(types.Header)
	return header, rlp.DecodeBytes(canonicalHeaderRLP, header)
}

// HeaderByHash gets the header for the provided block hash
func (b *Backend) HeaderByHash(ctx context.Context, hash common.Hash) (*types.Header, error) {
	_, headerRLP, err := b.IPLDRetriever.RetrieveHeaderByHash(hash)
	if err != nil {
		return nil, err
	}
	header := new(types.Header)
	return header, rlp.DecodeBytes(headerRLP, header)
}

// HeaderByNumberOrHash gets the header for the provided block hash or number
func (b *Backend) HeaderByNumberOrHash(ctx context.Context, blockNrOrHash rpc.BlockNumberOrHash) (*types.Header, error) {
	if blockNr, ok := blockNrOrHash.Number(); ok {
		return b.HeaderByNumber(ctx, blockNr)
	}
	if hash, ok := blockNrOrHash.Hash(); ok {
		header, err := b.HeaderByHash(ctx, hash)
		if err != nil {
			return nil, err
		}
		if header == nil {
			return nil, errors.New("header for hash not found")
		}
		canonicalHash, err := b.GetCanonicalHash(header.Number.Uint64())
		if err != nil {
			return nil, err
		}
		if blockNrOrHash.RequireCanonical && canonicalHash != hash {
			return nil, errors.New("hash is not currently canonical")
		}
		return header, nil
	}
	return nil, errors.New("invalid arguments; neither block nor hash specified")
}

// GetTd gets the total difficulty at the given block hash
func (b *Backend) GetTd(blockHash common.Hash) (*big.Int, error) {
	var tdStr string
	err := b.DB.Get(&tdStr, RetrieveTD, blockHash.String())
	if err != nil {
		return nil, err
	}
	td, ok := new(big.Int).SetString(tdStr, 10)
	if !ok {
		return nil, errors.New("total difficulty retrieved from Postgres cannot be converted to an integer")
	}
	return td, nil
}

// CurrentBlock returns the current block
func (b *Backend) CurrentBlock() (*types.Block, error) {
	block, err := b.BlockByNumber(context.Background(), rpc.LatestBlockNumber)
	return block, err
}

// BlockByNumberOrHash returns block by number or hash
func (b *Backend) BlockByNumberOrHash(ctx context.Context, blockNrOrHash rpc.BlockNumberOrHash) (*types.Block, error) {
	if blockNr, ok := blockNrOrHash.Number(); ok {
		return b.BlockByNumber(ctx, blockNr)
	}
	if hash, ok := blockNrOrHash.Hash(); ok {
		header, err := b.HeaderByHash(ctx, hash)
		if err != nil {
			return nil, err
		}
		if header == nil {
			return nil, errors.New("header for hash not found")
		}
		canonicalHash, err := b.GetCanonicalHash(header.Number.Uint64())
		if err != nil {
			return nil, err
		}
		if blockNrOrHash.RequireCanonical && canonicalHash != hash {
			return nil, errors.New("hash is not currently canonical")
		}
		block, err := b.BlockByHash(ctx, hash)
		if err != nil {
			return nil, err
		}
		if block == nil {
			return nil, errors.New("header found, but block body is missing")
		}
		return block, nil
	}
	return nil, errors.New("invalid arguments; neither block nor hash specified")
}

// BlockByNumber returns the requested canonical block.
func (b *Backend) BlockByNumber(ctx context.Context, blockNumber rpc.BlockNumber) (*types.Block, error) {
	var err error
	number := blockNumber.Int64()
	if blockNumber == rpc.LatestBlockNumber {
		number, err = b.Retriever.RetrieveLastBlockNumber()
		if err != nil {
			return nil, err
		}
	}
	if blockNumber == rpc.EarliestBlockNumber {
		number, err = b.Retriever.RetrieveFirstBlockNumber()
		if err != nil {
			return nil, err
		}
	}
	if blockNumber == rpc.PendingBlockNumber {
		return nil, errPendingBlockNumber
	}
	if number < 0 {
		return nil, errNegativeBlockNumber
	}
	// Get the canonical hash
	canonicalHash, err := b.GetCanonicalHash(uint64(number))
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	// Retrieve all the CIDs for the block
	// TODO: optimize this by retrieving iplds directly rather than the cids first (this is remanent from when we fetched iplds through ipfs blockservice interface)
	headerCID, uncleCIDs, txCIDs, rctCIDs, err := b.Retriever.RetrieveBlockByHash(canonicalHash)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	// Begin tx
	tx, err := b.DB.Beginx()
	if err != nil {
		return nil, err
	}
	defer func() {
		if p := recover(); p != nil {
			shared.Rollback(tx)
			panic(p)
		} else if err != nil {
			shared.Rollback(tx)
		} else {
			err = tx.Commit()
		}
	}()

	// Fetch and decode the header IPLD
	var headerIPLD ipfs.BlockModel
	headerIPLD, err = b.Fetcher.FetchHeader(tx, headerCID)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	var header types.Header
	err = rlp.DecodeBytes(headerIPLD.Data, &header)
	if err != nil {
		return nil, err
	}
	// Fetch and decode the uncle IPLDs
	var uncleIPLDs []ipfs.BlockModel
	uncleIPLDs, err = b.Fetcher.FetchUncles(tx, uncleCIDs)
	if err != nil {
		return nil, err
	}
	var uncles []*types.Header
	for _, uncleIPLD := range uncleIPLDs {
		var uncle types.Header
		err = rlp.DecodeBytes(uncleIPLD.Data, &uncle)
		if err != nil {
			return nil, err
		}
		uncles = append(uncles, &uncle)
	}
	// Fetch and decode the transaction IPLDs
	var txIPLDs []ipfs.BlockModel
	txIPLDs, err = b.Fetcher.FetchTrxs(tx, txCIDs)
	if err != nil {
		return nil, err
	}
	var transactions []*types.Transaction
	for _, txIPLD := range txIPLDs {
		var transaction types.Transaction
		err = rlp.DecodeBytes(txIPLD.Data, &transaction)
		if err != nil {
			return nil, err
		}
		transactions = append(transactions, &transaction)
	}
	// Fetch and decode the receipt IPLDs
	var rctIPLDs []ipfs.BlockModel
	rctIPLDs, err = b.Fetcher.FetchRcts(tx, rctCIDs)
	if err != nil {
		return nil, err
	}
	var receipts []*types.Receipt
	for _, rctIPLD := range rctIPLDs {
		var receipt types.Receipt
		err = rlp.DecodeBytes(rctIPLD.Data, &receipt)
		if err != nil {
			return nil, err
		}
		receipts = append(receipts, &receipt)
	}
	// Compose everything together into a complete block
	return types.NewBlock(&header, transactions, uncles, receipts, new(trie.Trie)), err
}

// BlockByHash returns the requested block. When fullTx is true all transactions in the block are returned in full
// detail, otherwise only the transaction hash is returned.
func (b *Backend) BlockByHash(ctx context.Context, hash common.Hash) (*types.Block, error) {
	// Retrieve all the CIDs for the block
	headerCID, uncleCIDs, txCIDs, rctCIDs, err := b.Retriever.RetrieveBlockByHash(hash)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	// Begin tx
	tx, err := b.DB.Beginx()
	if err != nil {
		return nil, err
	}
	defer func() {
		if p := recover(); p != nil {
			shared.Rollback(tx)
			panic(p)
		} else if err != nil {
			shared.Rollback(tx)
		} else {
			err = tx.Commit()
		}
	}()

	// Fetch and decode the header IPLD
	var headerIPLD ipfs.BlockModel
	headerIPLD, err = b.Fetcher.FetchHeader(tx, headerCID)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	var header types.Header
	err = rlp.DecodeBytes(headerIPLD.Data, &header)
	if err != nil {
		return nil, err
	}
	// Fetch and decode the uncle IPLDs
	var uncleIPLDs []ipfs.BlockModel
	uncleIPLDs, err = b.Fetcher.FetchUncles(tx, uncleCIDs)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	var uncles []*types.Header
	for _, uncleIPLD := range uncleIPLDs {
		var uncle types.Header
		err = rlp.DecodeBytes(uncleIPLD.Data, &uncle)
		if err != nil {
			return nil, err
		}
		uncles = append(uncles, &uncle)
	}
	// Fetch and decode the transaction IPLDs
	var txIPLDs []ipfs.BlockModel
	txIPLDs, err = b.Fetcher.FetchTrxs(tx, txCIDs)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	var transactions []*types.Transaction
	for _, txIPLD := range txIPLDs {
		var transaction types.Transaction
		err = rlp.DecodeBytes(txIPLD.Data, &transaction)
		if err != nil {
			return nil, err
		}
		transactions = append(transactions, &transaction)
	}
	// Fetch and decode the receipt IPLDs
	var rctIPLDs []ipfs.BlockModel
	rctIPLDs, err = b.Fetcher.FetchRcts(tx, rctCIDs)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	var receipts []*types.Receipt
	for _, rctIPLD := range rctIPLDs {
		var receipt types.Receipt
		err = rlp.DecodeBytes(rctIPLD.Data, &receipt)
		if err != nil {
			return nil, err
		}
		receipts = append(receipts, &receipt)
	}
	// Compose everything together into a complete block
	return types.NewBlock(&header, transactions, uncles, receipts, new(trie.Trie)), err
}

// GetTransaction retrieves a tx by hash
// It also returns the blockhash, blocknumber, and tx index associated with the transaction
func (b *Backend) GetTransaction(ctx context.Context, txHash common.Hash) (*types.Transaction, common.Hash, uint64, uint64, error) {
	var tempTxStruct struct {
		Data        []byte `db:"data"`
		BlockHash   string `db:"block_hash"`
		BlockNumber uint64 `db:"block_number"`
		Index       uint64 `db:"index"`
	}
	if err := b.DB.Get(&tempTxStruct, RetrieveRPCTransaction, txHash.String()); err != nil {
		return nil, common.Hash{}, 0, 0, err
	}
	var transaction types.Transaction
	if err := rlp.DecodeBytes(tempTxStruct.Data, &transaction); err != nil {
		return nil, common.Hash{}, 0, 0, err
	}
	return &transaction, common.HexToHash(tempTxStruct.BlockHash), tempTxStruct.BlockNumber, tempTxStruct.Index, nil
}

// GetReceipts retrieves receipts for provided block hash
func (b *Backend) GetReceipts(ctx context.Context, hash common.Hash) (types.Receipts, error) {
	_, receiptBytes, txs, err := b.IPLDRetriever.RetrieveReceiptsByBlockHash(hash)
	if err != nil {
		return nil, err
	}
	rcts := make(types.Receipts, len(receiptBytes))
	for i, rctBytes := range receiptBytes {
		rct := new(types.Receipt)
		if err := rlp.DecodeBytes(rctBytes, rct); err != nil {
			return nil, err
		}
		rct.TxHash = common.HexToHash(txs[i])
		rcts[i] = rct
	}
	return rcts, nil
}

// GetLogs returns all the logs for the given block hash
func (b *Backend) GetLogs(ctx context.Context, hash common.Hash) ([][]*types.Log, error) {
	_, receiptBytes, txs, err := b.IPLDRetriever.RetrieveReceiptsByBlockHash(hash)
	if err != nil {
		return nil, err
	}
	logs := make([][]*types.Log, len(receiptBytes))
	for i, rctBytes := range receiptBytes {
		var rct types.Receipt
		if err := rlp.DecodeBytes(rctBytes, &rct); err != nil {
			return nil, err
		}

		for _, log := range rct.Logs {
			log.TxHash = common.HexToHash(txs[i])
		}

		logs[i] = rct.Logs
	}
	return logs, nil
}

// StateAndHeaderByNumberOrHash returns the statedb and header for the provided block number or hash
func (b *Backend) StateAndHeaderByNumberOrHash(ctx context.Context, blockNrOrHash rpc.BlockNumberOrHash) (*state.StateDB, *types.Header, error) {
	if blockNr, ok := blockNrOrHash.Number(); ok {
		return b.StateAndHeaderByNumber(ctx, blockNr)
	}
	if hash, ok := blockNrOrHash.Hash(); ok {
		header, err := b.HeaderByHash(ctx, hash)
		if err != nil {
			return nil, nil, err
		}
		if header == nil {
			return nil, nil, errors.New("header for hash not found")
		}
		canonicalHash, err := b.GetCanonicalHash(header.Number.Uint64())
		if err != nil {
			return nil, nil, err
		}
		if blockNrOrHash.RequireCanonical && canonicalHash != hash {
			return nil, nil, errors.New("hash is not currently canonical")
		}
		stateDb, err := state.New(header.Root, b.StateDatabase, nil)
		return stateDb, header, err
	}
	return nil, nil, errors.New("invalid arguments; neither block nor hash specified")
}

// StateAndHeaderByNumber returns the statedb and header for a provided block number
func (b *Backend) StateAndHeaderByNumber(ctx context.Context, number rpc.BlockNumber) (*state.StateDB, *types.Header, error) {
	// Pending state is only known by the miner
	if number == rpc.PendingBlockNumber {
		return nil, nil, errPendingBlockNumber
	}
	// Otherwise resolve the block number and return its state
	header, err := b.HeaderByNumber(ctx, number)
	if err != nil {
		return nil, nil, err
	}
	if header == nil {
		return nil, nil, errors.New("header not found")
	}
	stateDb, err := state.New(header.Root, b.StateDatabase, nil)
	return stateDb, header, err
}

// GetCanonicalHash gets the canonical hash for the provided number, if there is one
func (b *Backend) GetCanonicalHash(number uint64) (common.Hash, error) {
	var hashResult string
	if err := b.DB.Get(&hashResult, RetrieveCanonicalBlockHashByNumber, number); err != nil {
		return common.Hash{}, err
	}
	return common.HexToHash(hashResult), nil
}

type rowResult struct {
	CID  string
	Data []byte
}

// GetCanonicalHeader gets the canonical header for the provided number, if there is one
func (b *Backend) GetCanonicalHeader(number uint64) (string, []byte, error) {
	headerResult := new(rowResult)
	return headerResult.CID, headerResult.Data, b.DB.QueryRowx(RetrieveCanonicalHeaderByNumber, number).StructScan(headerResult)
}

// GetEVM constructs and returns a vm.EVM
func (b *Backend) GetEVM(ctx context.Context, msg core.Message, state *state.StateDB, header *types.Header) (*vm.EVM, error) {
	state.SetBalance(msg.From(), math.MaxBig256)
	vmctx := core.NewEVMBlockContext(header, b, nil)
	txContext := core.NewEVMTxContext(msg)
	return vm.NewEVM(vmctx, txContext, state, b.Config.ChainConfig, b.Config.VmConfig), nil
}

// GetAccountByNumberOrHash returns the account object for the provided address at the block corresponding to the provided number or hash
func (b *Backend) GetAccountByNumberOrHash(ctx context.Context, address common.Address, blockNrOrHash rpc.BlockNumberOrHash) (*state.Account, error) {
	if blockNr, ok := blockNrOrHash.Number(); ok {
		return b.GetAccountByNumber(ctx, address, blockNr)
	}
	if hash, ok := blockNrOrHash.Hash(); ok {
		return b.GetAccountByHash(ctx, address, hash)
	}
	return nil, errors.New("invalid arguments; neither block nor hash specified")
}

// GetAccountByNumber returns the account object for the provided address at the canonical block at the provided height
func (b *Backend) GetAccountByNumber(ctx context.Context, address common.Address, blockNumber rpc.BlockNumber) (*state.Account, error) {
	var err error
	number := blockNumber.Int64()
	if blockNumber == rpc.LatestBlockNumber {
		number, err = b.Retriever.RetrieveLastBlockNumber()
		if err != nil {
			return nil, err
		}
	}
	if blockNumber == rpc.EarliestBlockNumber {
		number, err = b.Retriever.RetrieveFirstBlockNumber()
		if err != nil {
			return nil, err
		}
	}
	if blockNumber == rpc.PendingBlockNumber {
		return nil, errPendingBlockNumber
	}
	hash, err := b.GetCanonicalHash(uint64(number))
	if err == sql.ErrNoRows {
		return nil, errHeaderNotFound
	} else if err != nil {
		return nil, err
	}

	return b.GetAccountByHash(ctx, address, hash)
}

// GetAccountByHash returns the account object for the provided address at the block with the provided hash
func (b *Backend) GetAccountByHash(ctx context.Context, address common.Address, hash common.Hash) (*state.Account, error) {
	_, err := b.HeaderByHash(context.Background(), hash)
	if err == sql.ErrNoRows {
		return nil, errHeaderHashNotFound
	} else if err != nil {
		return nil, err
	}

	_, accountRlp, err := b.IPLDRetriever.RetrieveAccountByAddressAndBlockHash(address, hash)
	if err != nil {
		return nil, err
	}

	acct := new(state.Account)
	return acct, rlp.DecodeBytes(accountRlp, acct)
}

// GetCodeByNumberOrHash returns the byte code for the contract deployed at the provided address at the block with the provided hash or block number
func (b *Backend) GetCodeByNumberOrHash(ctx context.Context, address common.Address, blockNrOrHash rpc.BlockNumberOrHash) ([]byte, error) {
	if blockNr, ok := blockNrOrHash.Number(); ok {
		return b.GetCodeByNumber(ctx, address, blockNr)
	}
	if hash, ok := blockNrOrHash.Hash(); ok {
		return b.GetCodeByHash(ctx, address, hash)
	}
	return nil, errors.New("invalid arguments; neither block nor hash specified")
}

// GetCodeByNumber returns the byte code for the contract deployed at the provided address at the canonical block with the provided block number
func (b *Backend) GetCodeByNumber(ctx context.Context, address common.Address, blockNumber rpc.BlockNumber) ([]byte, error) {
	var err error
	number := blockNumber.Int64()
	if blockNumber == rpc.LatestBlockNumber {
		number, err = b.Retriever.RetrieveLastBlockNumber()
		if err != nil {
			return nil, err
		}
	}
	if blockNumber == rpc.EarliestBlockNumber {
		number, err = b.Retriever.RetrieveFirstBlockNumber()
		if err != nil {
			return nil, err
		}
	}
	if blockNumber == rpc.PendingBlockNumber {
		return nil, errPendingBlockNumber
	}
	hash, err := b.GetCanonicalHash(uint64(number))
	if err != nil {
		return nil, err
	}
	if hash == (common.Hash{}) {
		return nil, fmt.Errorf("no canoncial block hash found for provided height (%d)", number)
	}
	return b.GetCodeByHash(ctx, address, hash)
}

// GetCodeByHash returns the byte code for the contract deployed at the provided address at the block with the provided hash
func (b *Backend) GetCodeByHash(ctx context.Context, address common.Address, hash common.Hash) ([]byte, error) {
	codeHash := make([]byte, 0)
	leafKey := crypto.Keccak256Hash(address.Bytes())
	// Begin tx
	tx, err := b.DB.Beginx()
	if err != nil {
		return nil, err
	}
	defer func() {
		if p := recover(); p != nil {
			shared.Rollback(tx)
			panic(p)
		} else if err != nil {
			shared.Rollback(tx)
		} else {
			err = tx.Commit()
		}
	}()
	err = tx.Get(&codeHash, RetrieveCodeHashByLeafKeyAndBlockHash, leafKey.Hex(), hash.Hex())
	if err != nil {
		return nil, err
	}
	var mhKey string
	mhKey, err = shared2.MultihashKeyFromKeccak256(common.BytesToHash(codeHash))
	if err != nil {
		return nil, err
	}
	code := make([]byte, 0)
	err = tx.Get(&code, RetrieveCodeByMhKey, mhKey)
	return code, err
}

// GetStorageByNumberOrHash returns the storage value for the provided contract address an storage key at the block corresponding to the provided number or hash
func (b *Backend) GetStorageByNumberOrHash(ctx context.Context, address common.Address, key common.Hash, blockNrOrHash rpc.BlockNumberOrHash) (hexutil.Bytes, error) {
	if blockNr, ok := blockNrOrHash.Number(); ok {
		return b.GetStorageByNumber(ctx, address, key, blockNr)
	}
	if hash, ok := blockNrOrHash.Hash(); ok {
		return b.GetStorageByHash(ctx, address, key, hash)
	}
	return nil, errors.New("invalid arguments; neither block nor hash specified")
}

// GetStorageByNumber returns the storage value for the provided contract address an storage key at the block corresponding to the provided number
func (b *Backend) GetStorageByNumber(ctx context.Context, address common.Address, key common.Hash, blockNumber rpc.BlockNumber) (hexutil.Bytes, error) {
	var err error
	number := blockNumber.Int64()
	if blockNumber == rpc.LatestBlockNumber {
		number, err = b.Retriever.RetrieveLastBlockNumber()
		if err != nil {
			return nil, err
		}
	}
	if blockNumber == rpc.EarliestBlockNumber {
		number, err = b.Retriever.RetrieveFirstBlockNumber()
		if err != nil {
			return nil, err
		}
	}
	if blockNumber == rpc.PendingBlockNumber {
		return nil, errPendingBlockNumber
	}
	hash, err := b.GetCanonicalHash(uint64(number))
	if err == sql.ErrNoRows {
		return nil, errHeaderNotFound
	} else if err != nil {
		return nil, err
	}

	return b.GetStorageByHash(ctx, address, key, hash)
}

// GetStorageByHash returns the storage value for the provided contract address an storage key at the block corresponding to the provided hash
func (b *Backend) GetStorageByHash(ctx context.Context, address common.Address, key, hash common.Hash) (hexutil.Bytes, error) {
	_, err := b.HeaderByHash(context.Background(), hash)
	if err == sql.ErrNoRows {
		return nil, errHeaderHashNotFound
	} else if err != nil {
		return nil, err
	}

	_, _, storageRlp, err := b.IPLDRetriever.RetrieveStorageAtByAddressAndStorageSlotAndBlockHash(address, key, hash)
	return storageRlp, err
}

// Engine satisfied the ChainContext interface
func (b *Backend) Engine() consensus.Engine {
	// TODO: we need to support more than just ethash based engines
	return ethash.NewFaker()
}

// GetHeader satisfied the ChainContext interface
func (b *Backend) GetHeader(hash common.Hash, height uint64) *types.Header {
	header, err := b.HeaderByHash(context.Background(), hash)
	if err != nil {
		return nil
	}
	return header
}

// RPCGasCap returns the configured gas cap for the rpc server
func (b *Backend) RPCGasCap() *big.Int {
	return b.Config.RPCGasCap
}

func (b *Backend) SubscribeNewTxsEvent(chan<- core.NewTxsEvent) event.Subscription {
	panic("implement me")
}

func (b *Backend) SubscribeChainEvent(ch chan<- core.ChainEvent) event.Subscription {
	panic("implement me")
}

func (b *Backend) SubscribeRemovedLogsEvent(ch chan<- core.RemovedLogsEvent) event.Subscription {
	panic("implement me")
}

func (b *Backend) SubscribeLogsEvent(ch chan<- []*types.Log) event.Subscription {
	panic("implement me")
}

func (b *Backend) SubscribePendingLogsEvent(ch chan<- []*types.Log) event.Subscription {
	panic("implement me")
}

func (b *Backend) BloomStatus() (uint64, uint64) {
	panic("implement me")
}

func (b *Backend) ServiceFilter(ctx context.Context, session *bloombits.MatcherSession) {
	panic("implement me")
}
