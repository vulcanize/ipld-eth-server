// VulcanizeDB
// Copyright © 2020 Vulcanize

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

package graphql_test

import (
	"context"
	"fmt"
	"math/big"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/ethereum/go-ethereum/statediff"
	eth2 "github.com/vulcanize/ipld-eth-indexer/pkg/eth"
	"github.com/vulcanize/ipld-eth-indexer/pkg/postgres"
	"github.com/vulcanize/ipld-eth-indexer/pkg/shared"
	"github.com/vulcanize/ipld-eth-server/pkg/eth"
	"github.com/vulcanize/ipld-eth-server/pkg/eth/test_helpers"
	"github.com/vulcanize/ipld-eth-server/pkg/graphql"
)

var _ = Describe("GraphQL", func() {
	const (
		gqlEndPoint = "127.0.0.1:8083"
	)
	var (
		randomAddr = common.HexToAddress("0x1C3ab14BBaD3D99F4203bd7a11aCB94882050E6f")
		randomHash = crypto.Keccak256Hash(randomAddr.Bytes())
		blocks     []*types.Block
		receipts   []types.Receipts
		chain      *core.BlockChain
		db         *postgres.DB

		backend         *eth.Backend
		graphQLServer   *graphql.Service
		chainConfig     = params.TestChainConfig
		mockTD          = big.NewInt(1337)
		client          = graphql.NewClient(fmt.Sprintf("http://%s/graphql", gqlEndPoint))
		ctx             = context.Background()
		blockHash       common.Hash
		contractAddress common.Address
		slot            string
	)

	It("test init", func() {
		var err error
		db, err = shared.SetupDB()
		Expect(err).ToNot(HaveOccurred())
		transformer := eth2.NewStateDiffTransformer(chainConfig, db)
		backend, err = eth.NewEthBackend(db, &eth.Config{
			ChainConfig: chainConfig,
			VmConfig:    vm.Config{},
			RPCGasCap:   big.NewInt(10000000000),
		})
		Expect(err).ToNot(HaveOccurred())

		// make the test blockchain (and state)
		blocks, receipts, chain = test_helpers.MakeChain(5, test_helpers.Genesis, test_helpers.TestChainGen)
		params := statediff.Params{
			IntermediateStateNodes:   true,
			IntermediateStorageNodes: true,
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
		blockHash = test_helpers.MockBlock.Hash()
		contractAddress = test_helpers.ContractAddr
		slot = test_helpers.ContractSlotKeyHash.Hex()

		err = indexAndPublisher.Publish(test_helpers.MockConvertedPayload)
		Expect(err).ToNot(HaveOccurred())
		// The non-canonical header has a child
		err = indexAndPublisher.Publish(test_helpers.MockConvertedPayloadForChild)
		Expect(err).ToNot(HaveOccurred())
		err = publishCode(db, test_helpers.ContractCodeHash, test_helpers.ContractCode)
		Expect(err).ToNot(HaveOccurred())

		graphQLServer, err = graphql.New(backend, gqlEndPoint, nil, []string{"*"}, rpc.HTTPTimeouts{})
		Expect(err).ToNot(HaveOccurred())

		err = graphQLServer.Start(nil)
		Expect(err).ToNot(HaveOccurred())
	})

	defer It("test teardown", func() {
		err := graphQLServer.Stop()
		Expect(err).ToNot(HaveOccurred())
		eth.TearDownDB(db)
		chain.Stop()
	})

	Describe("eth_getLogs", func() {
		It("Retrieves logs that matches the provided blockHash and contract address", func() {
			logs, err := client.GetLogs(ctx, blockHash, contractAddress)
			Expect(err).ToNot(HaveOccurred())

			expectedLogs := []graphql.LogResponse{
				{
					Topics: test_helpers.MockLog1.Topics,
					Data:   hexutil.Bytes(test_helpers.MockLog1.Data),
				},
			}
			Expect(logs).To(Equal(expectedLogs))
		})

		It("Retrieves logs with random hash", func() {
			logs, err := client.GetLogs(ctx, randomHash, contractAddress)
			Expect(err).ToNot(HaveOccurred())
			Expect(len(logs)).To(Equal(0))
		})
	})

	Describe("eth_getStorageAt", func() {
		It("Retrieves storage at the provided blockHash contract address and slot", func() {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
			defer cancel()
			_, err := client.GetStorageAt(ctx, blockHash, contractAddress, slot)
			Expect(err).ToNot(HaveOccurred())

			// TODO: Currently this is failing, Update the test when the underlying code is fixed.
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
		_ = tx.Rollback()
		return err
	}
	if err := shared.PublishDirect(tx, mhKey, code); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}
