// Copyright © 2020 Vulcanize, Inc
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <http://www.gnu.org/licenses/>.

package cmd

import (
	"sync"

	"github.com/vulcanize/vulcanizedb/pkg/super_node/shared"

	"github.com/ethereum/go-ethereum/rpc"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/vulcanize/vulcanizedb/pkg/super_node"
	"github.com/vulcanize/vulcanizedb/pkg/super_node/config"
)

// superNodeCmd represents the superNode command
var superNodeCmd = &cobra.Command{
	Use:   "superNode",
	Short: "VulcanizeDB SuperNode",
	Long: `This command configures a VulcanizeDB SuperNode.

The Sync process streams all chain data from the appropriate chain, processes this data into IPLD objects
and publishes them to IPFS. It then indexes the CIDs against useful data fields/metadata in Postgres. 

The Serve process creates and exposes a rpc subscription server over ws and ipc. Transformers can subscribe to
these endpoints to stream

The BackFill process spins up a background process which periodically probes the Postgres database to identify
and fill in gaps in the data
`,
	Run: func(cmd *cobra.Command, args []string) {
		subCommand = cmd.CalledAs()
		logWithCommand = *log.WithField("SubCommand", subCommand)
		superNode()
	},
}

func init() {
	rootCmd.AddCommand(superNodeCmd)
}

func superNode() {
	superNode, superNodeConfig, err := newSuperNode()
	if err != nil {
		logWithCommand.Fatal(err)
	}
	wg := &sync.WaitGroup{}
	var forwardQuitChan chan bool
	var forwardPayloadChan chan shared.StreamedIPLDs
	if superNodeConfig.Serve {
		forwardQuitChan = make(chan bool)
		forwardPayloadChan = make(chan shared.StreamedIPLDs, super_node.PayloadChanBufferSize)
		superNode.ScreenAndServe(wg, forwardPayloadChan, forwardQuitChan)
		if err := startServers(superNode, superNodeConfig); err != nil {
			logWithCommand.Fatal(err)
		}
	}
	if superNodeConfig.Sync {
		if err := superNode.SyncAndPublish(wg, forwardPayloadChan, forwardQuitChan); err != nil {
			logWithCommand.Fatal(err)
		}
	}
	if superNodeConfig.BackFill {
		backFiller, err := super_node.NewBackFillService(superNodeConfig)
		if err != nil {
			logWithCommand.Fatal(err)
		}
		backFiller.FillGaps(wg, nil)
	}
	wg.Wait()
}

func newSuperNode() (super_node.SuperNode, *config.SuperNode, error) {
	superNodeConfig, err := config.NewSuperNodeConfig()
	if err != nil {
		return nil, nil, err
	}
	sn, err := super_node.NewSuperNode(superNodeConfig)
	if err != nil {
		return nil, nil, err
	}
	return sn, superNodeConfig, nil
}

func startServers(superNode super_node.SuperNode, settings *config.SuperNode) error {
	_, _, err := rpc.StartIPCEndpoint(settings.IPCEndpoint, superNode.APIs())
	if err != nil {
		return err
	}
	_, _, err = rpc.StartWSEndpoint(settings.WSEndpoint, superNode.APIs(), []string{"vdb"}, nil, true)
	if err != nil {
		return err
	}
	_, _, err = rpc.StartHTTPEndpoint(settings.HTTPEndpoint, superNode.APIs(), []string{"eth"}, nil, nil, rpc.HTTPTimeouts{})
	return err
}
