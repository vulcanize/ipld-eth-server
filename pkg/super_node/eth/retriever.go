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

	"github.com/vulcanize/vulcanizedb/pkg/postgres"
	"github.com/vulcanize/vulcanizedb/pkg/super_node/shared"
)

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
func (ecr *CIDRetriever) Retrieve(filter shared.SubscriptionSettings, blockNumber int64) (shared.CIDsForFetching, bool, error) {
	streamFilter, ok := filter.(*SubscriptionSettings)
	if !ok {
		return nil, true, fmt.Errorf("eth retriever expected filter type %T got %T", &SubscriptionSettings{}, filter)
	}
	log.Debug("retrieving cids")
	tx, err := ecr.db.Beginx()
	if err != nil {
		return nil, true, err
	}

	cw := new(CIDWrapper)
	cw.BlockNumber = big.NewInt(blockNumber)
	// Retrieve cached header CIDs
	if !streamFilter.HeaderFilter.Off {
		cw.Headers, err = ecr.RetrieveHeaderCIDs(tx, blockNumber)
		if err != nil {
			if err := tx.Rollback(); err != nil {
				log.Error(err)
			}
			log.Error("header cid retrieval error")
			return nil, true, err
		}
		if streamFilter.HeaderFilter.Uncles {
			for _, headerCID := range cw.Headers {
				uncleCIDs, err := ecr.RetrieveUncleCIDsByHeaderID(tx, headerCID.ID)
				if err != nil {
					if err := tx.Rollback(); err != nil {
						log.Error(err)
					}
					log.Error("uncle cid retrieval error")
					return nil, true, err
				}
				cw.Uncles = append(cw.Uncles, uncleCIDs...)
			}
		}
	}
	// Retrieve cached trx CIDs
	if !streamFilter.TxFilter.Off {
		cw.Transactions, err = ecr.RetrieveTxCIDs(tx, streamFilter.TxFilter, blockNumber)
		if err != nil {
			if err := tx.Rollback(); err != nil {
				log.Error(err)
			}
			log.Error("transaction cid retrieval error")
			return nil, true, err
		}
	}
	trxIds := make([]int64, 0, len(cw.Transactions))
	for _, tx := range cw.Transactions {
		trxIds = append(trxIds, tx.ID)
	}
	// Retrieve cached receipt CIDs
	if !streamFilter.ReceiptFilter.Off {
		cw.Receipts, err = ecr.RetrieveRctCIDs(tx, streamFilter.ReceiptFilter, blockNumber, nil, trxIds)
		if err != nil {
			if err := tx.Rollback(); err != nil {
				log.Error(err)
			}
			log.Error("receipt cid retrieval error")
			return nil, true, err
		}
	}
	// Retrieve cached state CIDs
	if !streamFilter.StateFilter.Off {
		cw.StateNodes, err = ecr.RetrieveStateCIDs(tx, streamFilter.StateFilter, blockNumber)
		if err != nil {
			if err := tx.Rollback(); err != nil {
				log.Error(err)
			}
			log.Error("state cid retrieval error")
			return nil, true, err
		}
	}
	// Retrieve cached storage CIDs
	if !streamFilter.StorageFilter.Off {
		cw.StorageNodes, err = ecr.RetrieveStorageCIDs(tx, streamFilter.StorageFilter, blockNumber)
		if err != nil {
			if err := tx.Rollback(); err != nil {
				log.Error(err)
			}
			log.Error("storage cid retrieval error")
			return nil, true, err
		}
	}
	return cw, empty(cw), tx.Commit()
}

func empty(cidWrapper *CIDWrapper) bool {
	if len(cidWrapper.Transactions) > 0 || len(cidWrapper.Headers) > 0 || len(cidWrapper.Uncles) > 0 || len(cidWrapper.Receipts) > 0 || len(cidWrapper.StateNodes) > 0 || len(cidWrapper.StorageNodes) > 0 {
		return false
	}
	return true
}

// RetrieveHeaderCIDs retrieves and returns all of the header cids at the provided blockheight
func (ecr *CIDRetriever) RetrieveHeaderCIDs(tx *sqlx.Tx, blockNumber int64) ([]HeaderModel, error) {
	log.Debug("retrieving header cids for block ", blockNumber)
	headers := make([]HeaderModel, 0)
	pgStr := `SELECT * FROM eth.header_cids
				WHERE block_number = $1`
	return headers, tx.Select(&headers, pgStr, blockNumber)
}

// RetrieveUncleCIDsByHeaderID retrieves and returns all of the uncle cids for the provided header
func (ecr *CIDRetriever) RetrieveUncleCIDsByHeaderID(tx *sqlx.Tx, headerID int64) ([]UncleModel, error) {
	log.Debug("retrieving uncle cids for block id ", headerID)
	headers := make([]UncleModel, 0)
	pgStr := `SELECT * FROM eth.uncle_cids
				WHERE header_id = $1`
	return headers, tx.Select(&headers, pgStr, headerID)
}

// RetrieveTxCIDs retrieves and returns all of the trx cids at the provided blockheight that conform to the provided filter parameters
// also returns the ids for the returned transaction cids
func (ecr *CIDRetriever) RetrieveTxCIDs(tx *sqlx.Tx, txFilter TxFilter, blockNumber int64) ([]TxModel, error) {
	log.Debug("retrieving transaction cids for block ", blockNumber)
	args := make([]interface{}, 0, 3)
	results := make([]TxModel, 0)
	id := 1
	pgStr := fmt.Sprintf(`SELECT transaction_cids.id, transaction_cids.header_id,
 			transaction_cids.tx_hash, transaction_cids.cid,
 			transaction_cids.dst, transaction_cids.src, transaction_cids.index
 			FROM eth.transaction_cids INNER JOIN eth.header_cids ON (transaction_cids.header_id = header_cids.id)
			WHERE header_cids.block_number = $%d`, id)
	args = append(args, blockNumber)
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
	return results, tx.Select(&results, pgStr, args...)
}

// RetrieveRctCIDs retrieves and returns all of the rct cids at the provided blockheight that conform to the provided
// filter parameters and correspond to the provided tx ids
func (ecr *CIDRetriever) RetrieveRctCIDs(tx *sqlx.Tx, rctFilter ReceiptFilter, blockNumber int64, blockHash *common.Hash, trxIds []int64) ([]ReceiptModel, error) {
	log.Debug("retrieving receipt cids for block ", blockNumber)
	id := 1
	args := make([]interface{}, 0, 4)
	pgStr := `SELECT receipt_cids.id, receipt_cids.tx_id, receipt_cids.cid,
 			receipt_cids.contract, receipt_cids.topic0s, receipt_cids.topic1s,
			receipt_cids.topic2s, receipt_cids.topic3s
 			FROM eth.receipt_cids, eth.transaction_cids, eth.header_cids
			WHERE receipt_cids.tx_id = transaction_cids.id 
			AND transaction_cids.header_id = header_cids.id`
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
	if len(rctFilter.Contracts) > 0 {
		// Filter on contract addresses if there are any
		pgStr += fmt.Sprintf(` AND ((receipt_cids.contract = ANY($%d::VARCHAR(66)[])`, id)
		args = append(args, pq.Array(rctFilter.Contracts))
		id++
		// Filter on topics if there are any
		if len(rctFilter.Topics) > 0 {
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
		if len(rctFilter.Topics) > 0 {
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
	receiptCids := make([]ReceiptModel, 0)
	return receiptCids, tx.Select(&receiptCids, pgStr, args...)
}

// RetrieveStateCIDs retrieves and returns all of the state node cids at the provided blockheight that conform to the provided filter parameters
func (ecr *CIDRetriever) RetrieveStateCIDs(tx *sqlx.Tx, stateFilter StateFilter, blockNumber int64) ([]StateNodeModel, error) {
	log.Debug("retrieving state cids for block ", blockNumber)
	args := make([]interface{}, 0, 2)
	pgStr := `SELECT state_cids.id, state_cids.header_id,
			state_cids.state_key, state_cids.leaf, state_cids.cid
			FROM eth.state_cids INNER JOIN eth.header_cids ON (state_cids.header_id = header_cids.id)
			WHERE header_cids.block_number = $1`
	args = append(args, blockNumber)
	addrLen := len(stateFilter.Addresses)
	if addrLen > 0 {
		keys := make([]string, addrLen)
		for i, addr := range stateFilter.Addresses {
			keys[i] = crypto.Keccak256Hash(common.HexToAddress(addr).Bytes()).String()
		}
		pgStr += ` AND state_cids.state_key = ANY($2::VARCHAR(66)[])`
		args = append(args, pq.Array(keys))
	}
	if !stateFilter.IntermediateNodes {
		pgStr += ` AND state_cids.leaf = TRUE`
	}
	stateNodeCIDs := make([]StateNodeModel, 0)
	return stateNodeCIDs, tx.Select(&stateNodeCIDs, pgStr, args...)
}

// RetrieveStorageCIDs retrieves and returns all of the storage node cids at the provided blockheight that conform to the provided filter parameters
func (ecr *CIDRetriever) RetrieveStorageCIDs(tx *sqlx.Tx, storageFilter StorageFilter, blockNumber int64) ([]StorageNodeWithStateKeyModel, error) {
	log.Debug("retrieving storage cids for block ", blockNumber)
	args := make([]interface{}, 0, 3)
	id := 1
	pgStr := fmt.Sprintf(`SELECT storage_cids.id, storage_cids.state_id, storage_cids.storage_key,
 			storage_cids.leaf, storage_cids.cid, state_cids.state_key FROM eth.storage_cids, eth.state_cids, eth.header_cids
			WHERE storage_cids.state_id = state_cids.id 
			AND state_cids.header_id = header_cids.id
			AND header_cids.block_number = $%d`, id)
	args = append(args, blockNumber)
	id++
	addrLen := len(storageFilter.Addresses)
	if addrLen > 0 {
		keys := make([]string, addrLen)
		for i, addr := range storageFilter.Addresses {
			keys[i] = crypto.Keccak256Hash(common.HexToAddress(addr).Bytes()).String()
		}
		pgStr += fmt.Sprintf(` AND state_cids.state_key = ANY($%d::VARCHAR(66)[])`, id)
		args = append(args, pq.Array(keys))
		id++
	}
	if len(storageFilter.StorageKeys) > 0 {
		pgStr += fmt.Sprintf(` AND storage_cids.storage_key = ANY($%d::VARCHAR(66)[])`, id)
		args = append(args, pq.Array(storageFilter.StorageKeys))
	}
	if !storageFilter.IntermediateNodes {
		pgStr += ` AND storage_cids.leaf = TRUE`
	}
	storageNodeCIDs := make([]StorageNodeWithStateKeyModel, 0)
	return storageNodeCIDs, tx.Select(&storageNodeCIDs, pgStr, args...)
}

// RetrieveGapsInData is used to find the the block numbers at which we are missing data in the db
func (ecr *CIDRetriever) RetrieveGapsInData() ([]shared.Gap, error) {
	pgStr := `SELECT header_cids.block_number + 1 AS start, min(fr.block_number) - 1 AS stop FROM eth.header_cids
				LEFT JOIN eth.header_cids r on eth.header_cids.block_number = r.block_number - 1
				LEFT JOIN eth.header_cids fr on eth.header_cids.block_number < fr.block_number
				WHERE r.block_number is NULL and fr.block_number IS NOT NULL
				GROUP BY header_cids.block_number, r.block_number`
	results := make([]struct {
		Start uint64 `db:"start"`
		Stop  uint64 `db:"stop"`
	}, 0)
	err := ecr.db.Select(&results, pgStr)
	if err != nil {
		return nil, err
	}
	gaps := make([]shared.Gap, len(results))
	for i, res := range results {
		gaps[i] = shared.Gap{
			Start: res.Start,
			Stop:  res.Stop,
		}
	}
	return gaps, nil
}

// RetrieveBlockByHash returns all of the CIDs needed to compose an entire block, for a given block hash
func (ecr *CIDRetriever) RetrieveBlockByHash(blockHash common.Hash) (HeaderModel, []UncleModel, []TxModel, []ReceiptModel, error) {
	log.Debug("retrieving block cids for block hash ", blockHash.String())
	tx, err := ecr.db.Beginx()
	if err != nil {
		return HeaderModel{}, nil, nil, nil, err
	}
	headerCID, err := ecr.RetrieveHeaderCIDByHash(tx, blockHash)
	if err != nil {
		if err := tx.Rollback(); err != nil {
			log.Error(err)
		}
		log.Error("header cid retrieval error")
		return HeaderModel{}, nil, nil, nil, err
	}
	uncleCIDs, err := ecr.RetrieveUncleCIDsByHeaderID(tx, headerCID.ID)
	if err != nil {
		if err := tx.Rollback(); err != nil {
			log.Error(err)
		}
		log.Error("uncle cid retrieval error")
		return HeaderModel{}, nil, nil, nil, err
	}
	txCIDs, err := ecr.RetrieveTxCIDsByHeaderID(tx, headerCID.ID)
	if err != nil {
		if err := tx.Rollback(); err != nil {
			log.Error(err)
		}
		log.Error("tx cid retrieval error")
		return HeaderModel{}, nil, nil, nil, err
	}
	txIDs := make([]int64, len(txCIDs))
	for i, txCID := range txCIDs {
		txIDs[i] = txCID.ID
	}
	rctCIDs, err := ecr.RetrieveReceiptCIDsByTxIDs(tx, txIDs)
	if err != nil {
		if err := tx.Rollback(); err != nil {
			log.Error(err)
		}
		log.Error("rct cid retrieval error")
		return HeaderModel{}, nil, nil, nil, err
	}
	return headerCID, uncleCIDs, txCIDs, rctCIDs, tx.Commit()
}

// RetrieveBlockByNumber returns all of the CIDs needed to compose an entire block, for a given block number
func (ecr *CIDRetriever) RetrieveBlockByNumber(blockNumber int64) (HeaderModel, []UncleModel, []TxModel, []ReceiptModel, error) {
	log.Debug("retrieving block cids for block number ", blockNumber)
	tx, err := ecr.db.Beginx()
	if err != nil {
		return HeaderModel{}, nil, nil, nil, err
	}
	headerCID, err := ecr.RetrieveHeaderCIDs(tx, blockNumber)
	if err != nil {
		if err := tx.Rollback(); err != nil {
			log.Error(err)
		}
		log.Error("header cid retrieval error")
		return HeaderModel{}, nil, nil, nil, err
	}
	if len(headerCID) < 1 {
		return HeaderModel{}, nil, nil, nil, fmt.Errorf("header cid retrieval error, no header CIDs found at block %d", blockNumber)
	}
	uncleCIDs, err := ecr.RetrieveUncleCIDsByHeaderID(tx, headerCID[0].ID)
	if err != nil {
		if err := tx.Rollback(); err != nil {
			log.Error(err)
		}
		log.Error("uncle cid retrieval error")
		return HeaderModel{}, nil, nil, nil, err
	}
	txCIDs, err := ecr.RetrieveTxCIDsByHeaderID(tx, headerCID[0].ID)
	if err != nil {
		if err := tx.Rollback(); err != nil {
			log.Error(err)
		}
		log.Error("tx cid retrieval error")
		return HeaderModel{}, nil, nil, nil, err
	}
	txIDs := make([]int64, len(txCIDs))
	for i, txCID := range txCIDs {
		txIDs[i] = txCID.ID
	}
	rctCIDs, err := ecr.RetrieveReceiptCIDsByTxIDs(tx, txIDs)
	if err != nil {
		if err := tx.Rollback(); err != nil {
			log.Error(err)
		}
		log.Error("rct cid retrieval error")
		return HeaderModel{}, nil, nil, nil, err
	}
	return headerCID[0], uncleCIDs, txCIDs, rctCIDs, tx.Commit()
}

// RetrieveHeaderCIDByHash returns the header for the given block hash
func (ecr *CIDRetriever) RetrieveHeaderCIDByHash(tx *sqlx.Tx, blockHash common.Hash) (HeaderModel, error) {
	log.Debug("retrieving header cids for block hash ", blockHash.String())
	pgStr := `SELECT * FROM eth.header_cids
			WHERE block_hash = $1`
	var headerCID HeaderModel
	return headerCID, tx.Get(&headerCID, pgStr, blockHash.String())
}

// RetrieveTxCIDsByHeaderID retrieves all tx CIDs for the given header id
func (ecr *CIDRetriever) RetrieveTxCIDsByHeaderID(tx *sqlx.Tx, headerID int64) ([]TxModel, error) {
	log.Debug("retrieving tx cids for block id ", headerID)
	pgStr := `SELECT * FROM eth.transaction_cids
			WHERE header_id = $1`
	var txCIDs []TxModel
	return txCIDs, tx.Select(&txCIDs, pgStr, headerID)
}

// RetrieveReceiptCIDsByTxIDs retrieves receipt CIDs by their associated tx IDs
func (ecr *CIDRetriever) RetrieveReceiptCIDsByTxIDs(tx *sqlx.Tx, txIDs []int64) ([]ReceiptModel, error) {
	log.Debugf("retrieving receipt cids for tx ids %v", txIDs)
	pgStr := `SELECT * FROM eth.receipt_cids
			WHERE tx_id = ANY($1::INTEGER[])`
	var rctCIDs []ReceiptModel
	return rctCIDs, tx.Select(&rctCIDs, pgStr, pq.Array(txIDs))
}
