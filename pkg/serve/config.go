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

package serve

import (
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"

	"github.com/ethereum/go-ethereum/rpc"
	"github.com/vulcanize/ipld-eth-indexer/pkg/shared"

	"github.com/ethereum/go-ethereum/common"

	"github.com/ethereum/go-ethereum/params"
	"github.com/spf13/viper"
	"github.com/vulcanize/ipld-eth-indexer/pkg/postgres"
	"github.com/vulcanize/ipld-eth-indexer/utils"
	"github.com/vulcanize/ipld-eth-server/pkg/prom"

	"github.com/vulcanize/ipld-eth-server/pkg/eth"
)

// Env variables
const (
	SERVER_WS_PATH   = "SERVER_WS_PATH"
	SERVER_IPC_PATH  = "SERVER_IPC_PATH"
	SERVER_HTTP_PATH = "SERVER_HTTP_PATH"

	SERVER_MAX_IDLE_CONNECTIONS = "SERVER_MAX_IDLE_CONNECTIONS"
	SERVER_MAX_OPEN_CONNECTIONS = "SERVER_MAX_OPEN_CONNECTIONS"
	SERVER_MAX_CONN_LIFETIME    = "SERVER_MAX_CONN_LIFETIME"

	ETH_DEFAULT_SENDER_ADDR = "ETH_DEFAULT_SENDER_ADDR"
	ETH_RPC_GAS_CAP         = "ETH_RPC_GAS_CAP"
	ETH_CHAIN_CONFIG        = "ETH_CHAIN_CONFIG"
	ETH_SUPPORTS_STATEDIFF  = "ETH_SUPPORTS_STATEDIFF"
)

// Config struct
type Config struct {
	DB       *postgres.DB
	DBConfig postgres.Config

	WSEnabled  bool
	WSEndpoint string

	HTTPEnabled  bool
	HTTPEndpoint string

	IPCEnabled  bool
	IPCEndpoint string

	EthGraphqlEnabled  bool
	EthGraphqlEndpoint string

	IpldGraphqlEnabled          bool
	IpldGraphqlEndpoint         string
	IpldPostgraphileEndpoint    string
	TracingHttpEndpoint         string
	TracingPostgraphileEndpoint string

	ChainConfig      *params.ChainConfig
	DefaultSender    *common.Address
	RPCGasCap        *big.Int
	EthHttpEndpoint  string
	Client           *rpc.Client
	SupportStateDiff bool
}

// NewConfig is used to initialize a watcher config from a .toml file
// Separate chain watcher instances need to be ran with separate ipfs path in order to avoid lock contention on the ipfs repository lockfile
func NewConfig() (*Config, error) {
	c := new(Config)

	viper.BindEnv("ethereum.httpPath", shared.ETH_HTTP_PATH)
	viper.BindEnv("ethereum.defaultSender", ETH_DEFAULT_SENDER_ADDR)
	viper.BindEnv("ethereum.rpcGasCap", ETH_RPC_GAS_CAP)
	viper.BindEnv("ethereum.chainConfig", ETH_CHAIN_CONFIG)
	viper.BindEnv("ethereum.supportsStateDiff", ETH_SUPPORTS_STATEDIFF)

	c.DBConfig.Init()

	ethHTTP := viper.GetString("ethereum.httpPath")
	ethHTTPEndpoint := fmt.Sprintf("http://%s", ethHTTP)
	nodeInfo, cli, err := shared.GetEthNodeAndClient(ethHTTPEndpoint)
	if err != nil {
		return nil, err
	}
	c.Client = cli
	c.SupportStateDiff = viper.GetBool("ethereum.supportsStateDiff")
	c.EthHttpEndpoint = ethHTTPEndpoint

	// websocket server
	wsEnabled := viper.GetBool("eth.server.ws")
	if wsEnabled {
		wsPath := viper.GetString("eth.server.wsPath")
		if wsPath == "" {
			wsPath = "127.0.0.1:8080"
		}
		c.WSEndpoint = wsPath
	}
	c.WSEnabled = wsEnabled

	// ipc server
	ipcEnabled := viper.GetBool("eth.server.ipc")
	if ipcEnabled {
		ipcPath := viper.GetString("eth.server.ipcPath")
		if ipcPath == "" {
			home, err := os.UserHomeDir()
			if err != nil {
				return nil, err
			}
			ipcPath = filepath.Join(home, ".vulcanize/vulcanize.ipc")
		}
		c.IPCEndpoint = ipcPath
	}
	c.IPCEnabled = ipcEnabled

	// http server
	httpEnabled := viper.GetBool("eth.server.http")
	if httpEnabled {
		httpPath := viper.GetString("eth.server.httpPath")
		if httpPath == "" {
			httpPath = "127.0.0.1:8081"
		}
		c.HTTPEndpoint = httpPath
	}
	c.HTTPEnabled = httpEnabled

	// eth graphql endpoint
	ethGraphqlEnabled := viper.GetBool("eth.server.graphql")
	if ethGraphqlEnabled {
		ethGraphqlPath := viper.GetString("eth.server.graphqlPath")
		if ethGraphqlPath == "" {
			ethGraphqlPath = "127.0.0.1:8082"
		}
		c.EthGraphqlEndpoint = ethGraphqlPath
	}
	c.EthGraphqlEnabled = ethGraphqlEnabled

	// ipld graphql endpoint
	ipldGraphqlEnabled := viper.GetBool("ipld.server.graphql")
	if ipldGraphqlEnabled {
		ipldGraphqlPath := viper.GetString("ipld.server.graphqlPath")
		if ipldGraphqlPath == "" {
			ipldGraphqlPath = "127.0.0.1:8083"
		}
		c.IpldGraphqlEndpoint = ipldGraphqlPath

		ipldPostgraphilePath := viper.GetString("ipld.postgraphilePath")
		if ipldPostgraphilePath == "" {
			return nil, errors.New("ipld-postgraphile-path parameter is empty")
		}
		c.IpldPostgraphileEndpoint = ipldPostgraphilePath

		tracingHttpEndpoint := viper.GetString("tracing.httpPath")
		tracingPostgraphilePath := viper.GetString("tracing.postgraphilePath")

		// these two parameters either can be both empty or both set
		if (tracingHttpEndpoint == "" && tracingPostgraphilePath != "") || (tracingHttpEndpoint != "" && tracingPostgraphilePath == "") {
			return nil, errors.New("tracing.httpPath and tracing.postgraphilePath parameters either can be both empty or both set")
		}

		c.TracingHttpEndpoint = tracingHttpEndpoint
		c.TracingPostgraphileEndpoint = tracingPostgraphilePath
	}
	c.IpldGraphqlEnabled = ipldGraphqlEnabled

	overrideDBConnConfig(&c.DBConfig)
	serveDB := utils.LoadPostgres(c.DBConfig, nodeInfo, false)
	prom.RegisterDBCollector(c.DBConfig.Name, serveDB.DB)
	c.DB = &serveDB

	defaultSenderStr := viper.GetString("ethereum.defaultSender")
	if defaultSenderStr != "" {
		sender := common.HexToAddress(defaultSenderStr)
		c.DefaultSender = &sender
	}
	rpcGasCapStr := viper.GetString("ethereum.rpcGasCap")
	if rpcGasCapStr != "" {
		if rpcGasCap, ok := new(big.Int).SetString(rpcGasCapStr, 10); ok {
			c.RPCGasCap = rpcGasCap
		}
	}
	chainConfigPath := viper.GetString("ethereum.chainConfig")
	if chainConfigPath != "" {
		c.ChainConfig, err = eth.LoadConfig(chainConfigPath)
	} else {
		c.ChainConfig, err = eth.ChainConfig(nodeInfo.ChainID)
	}
	return c, err
}

func overrideDBConnConfig(con *postgres.Config) {
	viper.BindEnv("database.server.maxIdle", SERVER_MAX_IDLE_CONNECTIONS)
	viper.BindEnv("database.server.maxOpen", SERVER_MAX_OPEN_CONNECTIONS)
	viper.BindEnv("database.server.maxLifetime", SERVER_MAX_CONN_LIFETIME)
	con.MaxIdle = viper.GetInt("database.server.maxIdle")
	con.MaxOpen = viper.GetInt("database.server.maxOpen")
	con.MaxLifetime = viper.GetInt("database.server.maxLifetime")
}
