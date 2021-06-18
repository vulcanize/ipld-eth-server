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
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
	log "github.com/sirupsen/logrus"

	"github.com/vulcanize/ipld-eth-indexer/pkg/eth"
	"github.com/vulcanize/ipld-eth-indexer/pkg/postgres"

	"github.com/vulcanize/ipld-eth-server/pkg/shared"
)

// Retriever interface for substituting mocks in tests
type Retriever interface {
	RetrieveFirstBlockNumber() (int64, error)
	RetrieveLastBlockNumber() (int64, error)
	Retrieve(filter SubscriptionSettings, blockNumber int64) ([]CIDWrapper, bool, error)
}

// CIDRetriever satisfies the CIDRetriever interface for ethereum
type CIDRetriever struct {
	db *postgres.DB
}

// NewCIDRetriever returns a pointer to a new CIDRetriever which supports the CIDRetriever interface
func NewCIDRetriever(db *postgres.DB) *CIDRetriever {
	return &CIDRetriever{
		db: db,
	}
}

// RetrieveFirstBlockNumber is used to retrieve the first block number in the db
func (ecr *CIDRetriever) RetrieveFirstBlockNumber() (int64, error) {
	var blockNumber int64
	err := ecr.db.Get(&blockNumber, "SELECT block_number FROM eth.header_cids ORDER BY block_number ASC LIMIT 1")
	return blockNumber, err
}

// RetrieveLastBlockNumber is used to retrieve the latest block number in the db
func (ecr *CIDRetriever) RetrieveLastBlockNumber() (int64, error) {
	var blockNumber int64
	err := ecr.db.Get(&blockNumber, "SELECT block_number FROM eth.header_cids ORDER BY block_number DESC LIMIT 1 ")
	return blockNumber, err
}

// Retrieve is used to retrieve all of the CIDs which conform to the passed StreamFilters
func (ecr *CIDRetriever) Retrieve(filter SubscriptionSettings, blockNumber int64) ([]CIDWrapper, bool, error) {
	log.Debug("retrieving cids")

	// Begin new db tx
	tx, err := ecr.db.Beginx()
	if err != nil {
		return nil, true, err
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

	// Retrieve cached header CIDs at this block height
	var headers []eth.HeaderModel
	headers, err = ecr.RetrieveHeaderCIDs(tx, blockNumber)
	if err != nil {
		log.Error("header cid retrieval error")
		return nil, true, err
	}
	cws := make([]CIDWrapper, len(headers))
	empty := true
	for i, header := range headers {
		cw := new(CIDWrapper)
		cw.BlockNumber = big.NewInt(blockNumber)
		if !filter.HeaderFilter.Off {
			cw.Header = header
			empty = false
			if filter.HeaderFilter.Uncles {
				// Retrieve uncle cids for this header id
				var uncleCIDs []eth.UncleModel
				uncleCIDs, err = ecr.RetrieveUncleCIDsByHeaderID(tx, header.ID)
				if err != nil {
					log.Error("uncle cid retrieval error")
					return nil, true, err
				}
				cw.Uncles = uncleCIDs
			}
		}
		// Retrieve cached trx CIDs
		if !filter.TxFilter.Off {
			cw.Transactions, err = ecr.RetrieveTxCIDs(tx, filter.TxFilter, header.ID)
			if err != nil {
				log.Error("transaction cid retrieval error")
				return nil, true, err
			}
			if len(cw.Transactions) > 0 {
				empty = false
			}
		}
		trxIds := make([]int64, len(cw.Transactions))
		for j, tx := range cw.Transactions {
			trxIds[j] = tx.ID
		}
		// Retrieve cached receipt CIDs
		if !filter.ReceiptFilter.Off {
			cw.Receipts, err = ecr.RetrieveRctCIDsByHeaderID(tx, filter.ReceiptFilter, header.ID, trxIds)
			if err != nil {
				log.Error("receipt cid retrieval error")
				return nil, true, err
			}
			if len(cw.Receipts) > 0 {
				empty = false
			}
		}
		// Retrieve cached state CIDs
		if !filter.StateFilter.Off {
			cw.StateNodes, err = ecr.RetrieveStateCIDs(tx, filter.StateFilter, header.ID)
			if err != nil {
				log.Error("state cid retrieval error")
				return nil, true, err
			}
			if len(cw.StateNodes) > 0 {
				empty = false
			}
		}
		// Retrieve cached storage CIDs
		if !filter.StorageFilter.Off {
			cw.StorageNodes, err = ecr.RetrieveStorageCIDs(tx, filter.StorageFilter, header.ID)
			if err != nil {
				log.Error("storage cid retrieval error")
				return nil, true, err
			}
			if len(cw.StorageNodes) > 0 {
				empty = false
			}
		}
		cws[i] = *cw
	}

	return cws, empty, err
}

// RetrieveHeaderCIDs retrieves and returns all of the header cids at the provided blockheight
func (ecr *CIDRetriever) RetrieveHeaderCIDs(tx *sqlx.Tx, blockNumber int64) ([]eth.HeaderModel, error) {
	log.Debug("retrieving header cids for block ", blockNumber)
	headers := make([]eth.HeaderModel, 0)
	pgStr := `SELECT * FROM eth.header_cids
				WHERE block_number = $1`
	return headers, tx.Select(&headers, pgStr, blockNumber)
}

// RetrieveUncleCIDsByHeaderID retrieves and returns all of the uncle cids for the provided header
func (ecr *CIDRetriever) RetrieveUncleCIDsByHeaderID(tx *sqlx.Tx, headerID int64) ([]eth.UncleModel, error) {
	log.Debug("retrieving uncle cids for block id ", headerID)
	headers := make([]eth.UncleModel, 0)
	pgStr := `SELECT * FROM eth.uncle_cids
				WHERE header_id = $1`
	return headers, tx.Select(&headers, pgStr, headerID)
}

// RetrieveTxCIDs retrieves and returns all of the trx cids at the provided blockheight that conform to the provided filter parameters
// also returns the ids for the returned transaction cids
func (ecr *CIDRetriever) RetrieveTxCIDs(tx *sqlx.Tx, txFilter TxFilter, headerID int64) ([]eth.TxModel, error) {
	log.Debug("retrieving transaction cids for header id ", headerID)
	args := make([]interface{}, 0, 3)
	results := make([]eth.TxModel, 0)
	id := 1
	pgStr := fmt.Sprintf(`SELECT transaction_cids.id, transaction_cids.header_id,
 			transaction_cids.tx_hash, transaction_cids.cid, transaction_cids.mh_key,
 			transaction_cids.dst, transaction_cids.src, transaction_cids.index, transaction_cids.tx_data
 			FROM eth.transaction_cids INNER JOIN eth.header_cids ON (transaction_cids.header_id = header_cids.id)
			WHERE header_cids.id = $%d`, id)
	args = append(args, headerID)
	id++
	if len(txFilter.Dst) > 0 {
		pgStr += fmt.Sprintf(` AND transaction_cids.dst = ANY($%d::VARCHAR(66)[])`, id)
		args = append(args, pq.Array(txFilter.Dst))
		id++
	}
	if len(txFilter.Src) > 0 {
		pgStr += fmt.Sprintf(` AND transaction_cids.src = ANY($%d::VARCHAR(66)[])`, id)
		args = append(args, pq.Array(txFilter.Src))
	}
	pgStr += ` ORDER BY transaction_cids.index`
	return results, tx.Select(&results, pgStr, args...)
}

// RetrieveRctCIDsByHeaderID retrieves and returns all of the rct cids at the provided header ID that conform to the provided
// filter parameters and correspond to the provided tx ids
func (ecr *CIDRetriever) RetrieveRctCIDsByHeaderID(tx *sqlx.Tx, rctFilter ReceiptFilter, headerID int64, trxIds []int64) ([]eth.ReceiptModel, error) {
	log.Debug("retrieving receipt cids for header id ", headerID)
	args := make([]interface{}, 0, 4)
	pgStr := `SELECT receipt_cids.id, receipt_cids.tx_id, receipt_cids.cid, receipt_cids.mh_key,
 			receipt_cids.contract, receipt_cids.contract_hash, receipt_cids.topic0s, receipt_cids.topic1s,
			receipt_cids.topic2s, receipt_cids.topic3s, receipt_cids.log_contracts
 			FROM eth.receipt_cids, eth.transaction_cids, eth.header_cids
			WHERE receipt_cids.tx_id = transaction_cids.id 
			AND transaction_cids.header_id = header_cids.id
			AND header_cids.id = $1`
	id := 2
	args = append(args, headerID)
	if len(rctFilter.LogAddresses) > 0 {
		// Filter on log contract addresses if there are any
		pgStr += fmt.Sprintf(` AND ((receipt_cids.log_contracts && $%d::VARCHAR(66)[]`, id)
		args = append(args, pq.Array(rctFilter.LogAddresses))
		id++
		// Filter on topics if there are any
		if hasTopics(rctFilter.Topics) {
			pgStr += " AND ("
			first := true
			for i, topicSet := range rctFilter.Topics {
				if i < 4 && len(topicSet) > 0 {
					if first {
						pgStr += fmt.Sprintf(`receipt_cids.topic%ds && $%d::VARCHAR(66)[]`, i, id)
						first = false
					} else {
						pgStr += fmt.Sprintf(` AND receipt_cids.topic%ds && $%d::VARCHAR(66)[]`, i, id)
					}
					args = append(args, pq.Array(topicSet))
					id++
				}
			}
			pgStr += ")"
		}
		pgStr += ")"
		// Filter on txIDs if there are any and we are matching txs
		if rctFilter.MatchTxs && len(trxIds) > 0 {
			pgStr += fmt.Sprintf(` OR receipt_cids.tx_id = ANY($%d::INTEGER[])`, id)
			args = append(args, pq.Array(trxIds))
		}
		pgStr += ")"
	} else { // If there are no contract addresses to filter on
		// Filter on topics if there are any
		if hasTopics(rctFilter.Topics) {
			pgStr += " AND (("
			first := true
			for i, topicSet := range rctFilter.Topics {
				if i < 4 && len(topicSet) > 0 {
					if first {
						pgStr += fmt.Sprintf(`receipt_cids.topic%ds && $%d::VARCHAR(66)[]`, i, id)
						first = false
					} else {
						pgStr += fmt.Sprintf(` AND receipt_cids.topic%ds && $%d::VARCHAR(66)[]`, i, id)
					}
					args = append(args, pq.Array(topicSet))
					id++
				}
			}
			pgStr += ")"
			// Filter on txIDs if there are any and we are matching txs
			if rctFilter.MatchTxs && len(trxIds) > 0 {
				pgStr += fmt.Sprintf(` OR receipt_cids.tx_id = ANY($%d::INTEGER[])`, id)
				args = append(args, pq.Array(trxIds))
			}
			pgStr += ")"
		} else if rctFilter.MatchTxs && len(trxIds) > 0 {
			// If there are no contract addresses or topics to filter on,
			// Filter on txIDs if there are any and we are matching txs
			pgStr += fmt.Sprintf(` AND receipt_cids.tx_id = ANY($%d::INTEGER[])`, id)
			args = append(args, pq.Array(trxIds))
		}
	}
	pgStr += ` ORDER BY transaction_cids.index`
	receiptCids := make([]eth.ReceiptModel, 0)
	return receiptCids, tx.Select(&receiptCids, pgStr, args...)
}

// RetrieveRctCIDs retrieves and returns all of the rct cids at the provided blockheight or block hash that conform to the provided
// filter parameters and correspond to the provided tx ids
func (ecr *CIDRetriever) RetrieveRctCIDs(tx *sqlx.Tx, rctFilter ReceiptFilter, blockNumber int64, blockHash *common.Hash, trxIds []int64) ([]eth.ReceiptModel, error) {
	log.Debug("retrieving receipt cids for block ", blockNumber)
	args := make([]interface{}, 0, 5)
	pgStr := `SELECT receipt_cids.id, receipt_cids.tx_id, receipt_cids.cid, receipt_cids.mh_key,
 			receipt_cids.contract, receipt_cids.contract_hash, receipt_cids.topic0s, receipt_cids.topic1s,
			receipt_cids.topic2s, receipt_cids.topic3s, receipt_cids.log_contracts
 			FROM eth.receipt_cids, eth.transaction_cids, eth.header_cids
			WHERE receipt_cids.tx_id = transaction_cids.id 
			AND transaction_cids.header_id = header_cids.id`
	id := 1
	if blockNumber > 0 {
		pgStr += fmt.Sprintf(` AND header_cids.block_number = $%d`, id)
		args = append(args, blockNumber)
		id++
	}
	if blockHash != nil {
		pgStr += fmt.Sprintf(` AND header_cids.block_hash = $%d`, id)
		args = append(args, blockHash.String())
		id++
	}

	// TODO: Add the below filters when we have log index in DB.
	if true {
		pgStr += ` ORDER BY transaction_cids.index`
		receiptCids := make([]eth.ReceiptModel, 0)
		return receiptCids, tx.Select(&receiptCids, pgStr, args...)
	}

	if len(rctFilter.LogAddresses) > 0 {
		// Filter on log contract addresses if there are any
		pgStr += fmt.Sprintf(` AND ((receipt_cids.log_contracts && $%d::VARCHAR(66)[]`, id)
		args = append(args, pq.Array(rctFilter.LogAddresses))
		id++
		// Filter on topics if there are any
		if hasTopics(rctFilter.Topics) {
			pgStr += " AND ("
			first := true
			for i, topicSet := range rctFilter.Topics {
				if i < 4 && len(topicSet) > 0 {
					if first {
						pgStr += fmt.Sprintf(`receipt_cids.topic%ds && $%d::VARCHAR(66)[]`, i, id)
						first = false
					} else {
						pgStr += fmt.Sprintf(` AND receipt_cids.topic%ds && $%d::VARCHAR(66)[]`, i, id)
					}
					args = append(args, pq.Array(topicSet))
					id++
				}
			}
			pgStr += ")"
		}
		pgStr += ")"
		// Filter on txIDs if there are any and we are matching txs
		if rctFilter.MatchTxs && len(trxIds) > 0 {
			pgStr += fmt.Sprintf(` OR receipt_cids.tx_id = ANY($%d::INTEGER[])`, id)
			args = append(args, pq.Array(trxIds))
		}
		pgStr += ")"
	} else { // If there are no contract addresses to filter on
		// Filter on topics if there are any
		if hasTopics(rctFilter.Topics) {
			pgStr += " AND (("
			first := true
			for i, topicSet := range rctFilter.Topics {
				if i < 4 && len(topicSet) > 0 {
					if first {
						pgStr += fmt.Sprintf(`receipt_cids.topic%ds && $%d::VARCHAR(66)[]`, i, id)
						first = false
					} else {
						pgStr += fmt.Sprintf(` AND receipt_cids.topic%ds && $%d::VARCHAR(66)[]`, i, id)
					}
					args = append(args, pq.Array(topicSet))
					id++
				}
			}
			pgStr += ")"
			// Filter on txIDs if there are any and we are matching txs
			if rctFilter.MatchTxs && len(trxIds) > 0 {
				pgStr += fmt.Sprintf(` OR receipt_cids.tx_id = ANY($%d::INTEGER[])`, id)
				args = append(args, pq.Array(trxIds))
			}
			pgStr += ")"
		} else if rctFilter.MatchTxs && len(trxIds) > 0 {
			// If there are no contract addresses or topics to filter on,
			// Filter on txIDs if there are any and we are matching txs
			pgStr += fmt.Sprintf(` AND receipt_cids.tx_id = ANY($%d::INTEGER[])`, id)
			args = append(args, pq.Array(trxIds))
		}
	}

	pgStr += ` ORDER BY transaction_cids.index`
	receiptCids := make([]eth.ReceiptModel, 0)
	return receiptCids, tx.Select(&receiptCids, pgStr, args...)
}

func hasTopics(topics [][]string) bool {
	for _, topicSet := range topics {
		if len(topicSet) > 0 {
			return true
		}
	}
	return false
}

// RetrieveStateCIDs retrieves and returns all of the state node cids at the provided header ID that conform to the provided filter parameters
func (ecr *CIDRetriever) RetrieveStateCIDs(tx *sqlx.Tx, stateFilter StateFilter, headerID int64) ([]eth.StateNodeModel, error) {
	log.Debug("retrieving state cids for header id ", headerID)
	args := make([]interface{}, 0, 2)
	pgStr := `SELECT state_cids.id, state_cids.header_id,
			state_cids.state_leaf_key, state_cids.node_type, state_cids.cid, state_cids.mh_key, state_cids.state_path
			FROM eth.state_cids INNER JOIN eth.header_cids ON (state_cids.header_id = header_cids.id)
			WHERE header_cids.id = $1`
	args = append(args, headerID)
	addrLen := len(stateFilter.Addresses)
	if addrLen > 0 {
		keys := make([]string, addrLen)
		for i, addr := range stateFilter.Addresses {
			keys[i] = crypto.Keccak256Hash(common.HexToAddress(addr).Bytes()).String()
		}
		pgStr += ` AND state_cids.state_leaf_key = ANY($2::VARCHAR(66)[])`
		args = append(args, pq.Array(keys))
	}
	if !stateFilter.IntermediateNodes {
		pgStr += ` AND state_cids.node_type = 2`
	}
	stateNodeCIDs := make([]eth.StateNodeModel, 0)
	return stateNodeCIDs, tx.Select(&stateNodeCIDs, pgStr, args...)
}

// RetrieveStorageCIDs retrieves and returns all of the storage node cids at the provided header id that conform to the provided filter parameters
func (ecr *CIDRetriever) RetrieveStorageCIDs(tx *sqlx.Tx, storageFilter StorageFilter, headerID int64) ([]eth.StorageNodeWithStateKeyModel, error) {
	log.Debug("retrieving storage cids for header id ", headerID)
	args := make([]interface{}, 0, 3)
	pgStr := `SELECT storage_cids.id, storage_cids.state_id, storage_cids.storage_leaf_key, storage_cids.node_type,
 			storage_cids.cid, storage_cids.mh_key, storage_cids.storage_path, state_cids.state_leaf_key
 			FROM eth.storage_cids, eth.state_cids, eth.header_cids
			WHERE storage_cids.state_id = state_cids.id 
			AND state_cids.header_id = header_cids.id
			AND header_cids.id = $1`
	args = append(args, headerID)
	id := 2
	addrLen := len(storageFilter.Addresses)
	if addrLen > 0 {
		keys := make([]string, addrLen)
		for i, addr := range storageFilter.Addresses {
			keys[i] = crypto.Keccak256Hash(common.HexToAddress(addr).Bytes()).String()
		}
		pgStr += fmt.Sprintf(` AND state_cids.state_leaf_key = ANY($%d::VARCHAR(66)[])`, id)
		args = append(args, pq.Array(keys))
		id++
	}
	if len(storageFilter.StorageKeys) > 0 {
		pgStr += fmt.Sprintf(` AND storage_cids.storage_leaf_key = ANY($%d::VARCHAR(66)[])`, id)
		args = append(args, pq.Array(storageFilter.StorageKeys))
	}
	if !storageFilter.IntermediateNodes {
		pgStr += ` AND storage_cids.node_type = 2`
	}
	storageNodeCIDs := make([]eth.StorageNodeWithStateKeyModel, 0)
	return storageNodeCIDs, tx.Select(&storageNodeCIDs, pgStr, args...)
}

// RetrieveBlockByHash returns all of the CIDs needed to compose an entire block, for a given block hash
func (ecr *CIDRetriever) RetrieveBlockByHash(blockHash common.Hash) (eth.HeaderModel, []eth.UncleModel, []eth.TxModel, []eth.ReceiptModel, error) {
	log.Debug("retrieving block cids for block hash ", blockHash.String())

	// Begin new db tx
	tx, err := ecr.db.Beginx()
	if err != nil {
		return eth.HeaderModel{}, nil, nil, nil, err
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

	var headerCID eth.HeaderModel
	headerCID, err = ecr.RetrieveHeaderCIDByHash(tx, blockHash)
	if err != nil {
		log.Error("header cid retrieval error")
		return eth.HeaderModel{}, nil, nil, nil, err
	}
	var uncleCIDs []eth.UncleModel
	uncleCIDs, err = ecr.RetrieveUncleCIDsByHeaderID(tx, headerCID.ID)
	if err != nil {
		log.Error("uncle cid retrieval error")
		return eth.HeaderModel{}, nil, nil, nil, err
	}
	var txCIDs []eth.TxModel
	txCIDs, err = ecr.RetrieveTxCIDsByHeaderID(tx, headerCID.ID)
	if err != nil {
		log.Error("tx cid retrieval error")
		return eth.HeaderModel{}, nil, nil, nil, err
	}
	txIDs := make([]int64, len(txCIDs))
	for i, txCID := range txCIDs {
		txIDs[i] = txCID.ID
	}
	var rctCIDs []eth.ReceiptModel
	rctCIDs, err = ecr.RetrieveReceiptCIDsByTxIDs(tx, txIDs)
	if err != nil {
		log.Error("rct cid retrieval error")
	}
	return headerCID, uncleCIDs, txCIDs, rctCIDs, err
}

// RetrieveBlockByNumber returns all of the CIDs needed to compose an entire block, for a given block number
func (ecr *CIDRetriever) RetrieveBlockByNumber(blockNumber int64) (eth.HeaderModel, []eth.UncleModel, []eth.TxModel, []eth.ReceiptModel, error) {
	log.Debug("retrieving block cids for block number ", blockNumber)

	// Begin new db tx
	tx, err := ecr.db.Beginx()
	if err != nil {
		return eth.HeaderModel{}, nil, nil, nil, err
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

	var headerCID []eth.HeaderModel
	headerCID, err = ecr.RetrieveHeaderCIDs(tx, blockNumber)
	if err != nil {
		log.Error("header cid retrieval error")
		return eth.HeaderModel{}, nil, nil, nil, err
	}
	if len(headerCID) < 1 {
		return eth.HeaderModel{}, nil, nil, nil, fmt.Errorf("header cid retrieval error, no header CIDs found at block %d", blockNumber)
	}
	var uncleCIDs []eth.UncleModel
	uncleCIDs, err = ecr.RetrieveUncleCIDsByHeaderID(tx, headerCID[0].ID)
	if err != nil {
		log.Error("uncle cid retrieval error")
		return eth.HeaderModel{}, nil, nil, nil, err
	}
	var txCIDs []eth.TxModel
	txCIDs, err = ecr.RetrieveTxCIDsByHeaderID(tx, headerCID[0].ID)
	if err != nil {
		log.Error("tx cid retrieval error")
		return eth.HeaderModel{}, nil, nil, nil, err
	}
	txIDs := make([]int64, len(txCIDs))
	for i, txCID := range txCIDs {
		txIDs[i] = txCID.ID
	}
	var rctCIDs []eth.ReceiptModel
	rctCIDs, err = ecr.RetrieveReceiptCIDsByTxIDs(tx, txIDs)
	if err != nil {
		log.Error("rct cid retrieval error")
	}
	return headerCID[0], uncleCIDs, txCIDs, rctCIDs, err
}

// RetrieveHeaderCIDByHash returns the header for the given block hash
func (ecr *CIDRetriever) RetrieveHeaderCIDByHash(tx *sqlx.Tx, blockHash common.Hash) (eth.HeaderModel, error) {
	log.Debug("retrieving header cids for block hash ", blockHash.String())
	pgStr := `SELECT * FROM eth.header_cids
			WHERE block_hash = $1`
	var headerCID eth.HeaderModel
	return headerCID, tx.Get(&headerCID, pgStr, blockHash.String())
}

// RetrieveTxCIDsByHeaderID retrieves all tx CIDs for the given header id
func (ecr *CIDRetriever) RetrieveTxCIDsByHeaderID(tx *sqlx.Tx, headerID int64) ([]eth.TxModel, error) {
	log.Debug("retrieving tx cids for block id ", headerID)
	pgStr := `SELECT * FROM eth.transaction_cids
			WHERE header_id = $1
			ORDER BY index`
	var txCIDs []eth.TxModel
	return txCIDs, tx.Select(&txCIDs, pgStr, headerID)
}

// RetrieveReceiptCIDsByTxIDs retrieves receipt CIDs by their associated tx IDs
func (ecr *CIDRetriever) RetrieveReceiptCIDsByTxIDs(tx *sqlx.Tx, txIDs []int64) ([]eth.ReceiptModel, error) {
	log.Debugf("retrieving receipt cids for tx ids %v", txIDs)
	pgStr := `SELECT receipt_cids.id, receipt_cids.tx_id, receipt_cids.cid, receipt_cids.mh_key,
 			receipt_cids.contract, receipt_cids.contract_hash, receipt_cids.topic0s, receipt_cids.topic1s,
			receipt_cids.topic2s, receipt_cids.topic3s, receipt_cids.log_contracts
			FROM eth.receipt_cids, eth.transaction_cids
			WHERE tx_id = ANY($1::INTEGER[])
			AND receipt_cids.tx_id = transaction_cids.id
			ORDER BY transaction_cids.index`
	var rctCIDs []eth.ReceiptModel
	return rctCIDs, tx.Select(&rctCIDs, pgStr, pq.Array(txIDs))
}
