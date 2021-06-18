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
	"errors"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"

	"github.com/ethereum/go-ethereum/rpc"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/vulcanize/gap-filler/pkg/mux"
	"github.com/vulcanize/ipld-eth-indexer/pkg/eth"
	"github.com/vulcanize/ipld-eth-server/pkg/graphql"
	srpc "github.com/vulcanize/ipld-eth-server/pkg/rpc"
	s "github.com/vulcanize/ipld-eth-server/pkg/serve"
	v "github.com/vulcanize/ipld-eth-server/version"
)

var ErrNoRpcEndpoints = errors.New("no rpc endpoints is available")

// serveCmd represents the serve command
var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "serve chain data from PG-IPFS",
	Long: `This command configures a VulcanizeDB ipld-eth-server.

`,
	Run: func(cmd *cobra.Command, args []string) {
		subCommand = cmd.CalledAs()
		logWithCommand = *log.WithField("SubCommand", subCommand)
		serve()
	},
}

func serve() {
	logWithCommand.Infof("running ipld-eth-server version: %s", v.VersionWithMeta)

	var forwardPayloadChan chan eth.ConvertedPayload
	wg := new(sync.WaitGroup)
	logWithCommand.Debug("loading server configuration variables")
	serverConfig, err := s.NewConfig()
	if err != nil {
		logWithCommand.Fatal(err)
	}
	logWithCommand.Infof("server config: %+v", serverConfig)
	logWithCommand.Debug("initializing new server service")
	server, err := s.NewServer(serverConfig)
	if err != nil {
		logWithCommand.Fatal(err)
	}

	logWithCommand.Info("starting up server servers")
	forwardPayloadChan = make(chan eth.ConvertedPayload, s.PayloadChanBufferSize)
	server.Serve(wg, forwardPayloadChan)
	if err := startServers(server, serverConfig); err != nil {
		logWithCommand.Fatal(err)
	}
	graphQL, err := startEthGraphQL(server, serverConfig)
	if err != nil {
		logWithCommand.Fatal(err)
	}

	err = startIpldGraphQL(serverConfig)
	if err != nil {
		logWithCommand.Fatal(err)
	}

	shutdown := make(chan os.Signal)
	signal.Notify(shutdown, os.Interrupt)
	<-shutdown
	if graphQL != nil {
		graphQL.Stop()
	}
	server.Stop()
	wg.Wait()
}

func startServers(server s.Server, settings *s.Config) error {
	if settings.IPCEnabled {
		logWithCommand.Info("starting up IPC server")
		_, _, err := srpc.StartIPCEndpoint(settings.IPCEndpoint, server.APIs())
		if err != nil {
			return err
		}
	} else {
		logWithCommand.Info("IPC server is disabled")
	}

	if settings.WSEnabled {
		logWithCommand.Info("starting up WS server")
		_, _, err := srpc.StartWSEndpoint(settings.WSEndpoint, server.APIs(), []string{"vdb", "net"}, nil, true)
		if err != nil {
			return err
		}
	} else {
		logWithCommand.Info("WS server is disabled")
	}

	if settings.HTTPEnabled {
		logWithCommand.Info("starting up HTTP server")
		_, err := srpc.StartHTTPEndpoint(settings.HTTPEndpoint, server.APIs(), []string{"eth", "net"}, nil, []string{"*"}, rpc.HTTPTimeouts{})
		if err != nil {
			return err
		}
	} else {
		logWithCommand.Info("HTTP server is disabled")
	}

	return nil
}

func startEthGraphQL(server s.Server, settings *s.Config) (graphQLServer *graphql.Service, err error) {
	if settings.EthGraphqlEnabled {
		logWithCommand.Info("starting up ETH GraphQL server")
		endPoint := settings.EthGraphqlEndpoint
		if endPoint != "" {
			graphQLServer, err = graphql.New(server.Backend(), endPoint, nil, []string{"*"}, rpc.HTTPTimeouts{})
			if err != nil {
				return
			}
			err = graphQLServer.Start(nil)
		}
	} else {
		logWithCommand.Info("ETH GraphQL server is disabled")
	}

	return
}

func startIpldGraphQL(settings *s.Config) error {
	if settings.IpldGraphqlEnabled {
		logWithCommand.Info("starting up IPLD GraphQL server")

		gqlIpldAddr, err := url.Parse(settings.IpldPostgraphileEndpoint)
		if err != nil {
			return err
		}

		gqlTracingAPIAddr, err := url.Parse(settings.TracingPostgraphileEndpoint)
		if err != nil {
			return err
		}

		ethClients, err := parseRpcAddresses(settings.EthHttpEndpoint)
		if err != nil {
			return err
		}

		var tracingClients []*rpc.Client
		tracingEndpoint := viper.GetString("tracing.httpPath")
		if tracingEndpoint != "" {
			tracingClients, err = parseRpcAddresses(tracingEndpoint)
			if err != nil {
				return err
			}
		}

		router, err := mux.NewServeMux(&mux.Options{
			BasePath:       "/",
			EnableGraphiQL: true,
			Postgraphile: mux.PostgraphileOptions{
				Default:    gqlIpldAddr,
				TracingAPI: gqlTracingAPIAddr,
			},
			RPC: mux.RPCOptions{
				DefaultClients: ethClients,
				TracingClients: tracingClients,
			},
		})
		if err != nil {
			return err
		}

		go http.ListenAndServe(settings.IpldGraphqlEndpoint, router)
	} else {
		logWithCommand.Info("IPLD GraphQL server is disabled")
	}

	return nil
}

func parseRpcAddresses(value string) ([]*rpc.Client, error) {
	rpcAddresses := strings.Split(value, ",")
	rpcClients := make([]*rpc.Client, 0, len(rpcAddresses))
	for _, address := range rpcAddresses {
		rpcClient, err := rpc.Dial(address)
		if err != nil {
			logWithCommand.Errorf("couldn't connect to %s. Error: %s", address, err)
			continue
		}

		rpcClients = append(rpcClients, rpcClient)
	}

	if len(rpcClients) == 0 {
		logWithCommand.Error(ErrNoRpcEndpoints)
		return nil, ErrNoRpcEndpoints
	}

	return rpcClients, nil
}

func init() {
	rootCmd.AddCommand(serveCmd)

	// database credentials
	serveCmd.PersistentFlags().String("database-name", "vulcanize_public", "database name")
	serveCmd.PersistentFlags().Int("database-port", 5432, "database port")
	serveCmd.PersistentFlags().String("database-hostname", "localhost", "database hostname")
	serveCmd.PersistentFlags().String("database-user", "", "database user")
	serveCmd.PersistentFlags().String("database-password", "", "database password")

	// flags for all config variables
	// eth graphql and json-rpc parameters
	serveCmd.PersistentFlags().Bool("eth-server-graphql", false, "turn on the eth graphql server")
	serveCmd.PersistentFlags().String("eth-server-graphql-path", "", "endpoint url for eth graphql server (host:port)")
	serveCmd.PersistentFlags().Bool("eth-server-http", true, "turn on the eth http json-rpc server")
	serveCmd.PersistentFlags().String("eth-server-http-path", "", "endpoint url for eth http json-rpc server (host:port)")
	serveCmd.PersistentFlags().Bool("eth-server-ws", false, "turn on the eth websocket json-rpc server")
	serveCmd.PersistentFlags().String("eth-server-ws-path", "", "endpoint url for eth websocket json-rpc server (host:port)")
	serveCmd.PersistentFlags().Bool("eth-server-ipc", false, "turn on the eth ipc json-rpc server")
	serveCmd.PersistentFlags().String("eth-server-ipc-path", "", "path for eth ipc json-rpc server")

	// ipld and tracing graphql parameters
	serveCmd.PersistentFlags().Bool("ipld-server-graphql", false, "turn on the ipld graphql server")
	serveCmd.PersistentFlags().String("ipld-server-graphql-path", "", "endpoint url for ipld graphql server (host:port)")
	serveCmd.PersistentFlags().String("ipld-postgraphile-path", "", "http url to postgraphile on top of ipld database")
	serveCmd.PersistentFlags().String("tracing-http-path", "", "http url to tracing service")
	serveCmd.PersistentFlags().String("tracing-postgraphile-path", "", "http url to postgraphile on top of tracing db")

	serveCmd.PersistentFlags().String("eth-http-path", "", "http url for ethereum node")
	serveCmd.PersistentFlags().String("eth-node-id", "", "eth node id")
	serveCmd.PersistentFlags().String("eth-client-name", "Geth", "eth client name")
	serveCmd.PersistentFlags().String("eth-genesis-block", "0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3", "eth genesis block hash")
	serveCmd.PersistentFlags().String("eth-network-id", "1", "eth network id")
	serveCmd.PersistentFlags().String("eth-chain-id", "1", "eth chain id")
	serveCmd.PersistentFlags().String("eth-default-sender", "", "default sender address")
	serveCmd.PersistentFlags().String("eth-rpc-gas-cap", "", "rpc gas cap (for eth_Call execution)")
	serveCmd.PersistentFlags().String("eth-chain-config", "", "json chain config file location")
	serveCmd.PersistentFlags().Bool("eth-supports-state-diff", false, "whether or not the proxy ethereum client supports statediffing endpoints")

	// and their bindings
	// database
	viper.BindPFlag("database.name", serveCmd.PersistentFlags().Lookup("database-name"))
	viper.BindPFlag("database.port", serveCmd.PersistentFlags().Lookup("database-port"))
	viper.BindPFlag("database.hostname", serveCmd.PersistentFlags().Lookup("database-hostname"))
	viper.BindPFlag("database.user", serveCmd.PersistentFlags().Lookup("database-user"))
	viper.BindPFlag("database.password", serveCmd.PersistentFlags().Lookup("database-password"))

	// eth graphql server
	viper.BindPFlag("eth.server.graphql", serveCmd.PersistentFlags().Lookup("eth-server-graphql"))
	viper.BindPFlag("eth.server.graphqlPath", serveCmd.PersistentFlags().Lookup("eth-server-graphql-path"))

	// eth http json-rpc server
	viper.BindPFlag("eth.server.http", serveCmd.PersistentFlags().Lookup("eth-server-http"))
	viper.BindPFlag("eth.server.httpPath", serveCmd.PersistentFlags().Lookup("eth-server-http-path"))

	// eth websocket json-rpc server
	viper.BindPFlag("eth.server.ws", serveCmd.PersistentFlags().Lookup("eth-server-ws"))
	viper.BindPFlag("eth.server.wsPath", serveCmd.PersistentFlags().Lookup("eth-server-ws-path"))

	// eth ipc json-rpc server
	viper.BindPFlag("eth.server.ipc", serveCmd.PersistentFlags().Lookup("eth-server-ipc"))
	viper.BindPFlag("eth.server.ipcPath", serveCmd.PersistentFlags().Lookup("eth-server-ipc-path"))

	// ipld and tracing graphql parameters
	viper.BindPFlag("ipld.server.graphql", serveCmd.PersistentFlags().Lookup("ipld-server-graphql"))
	viper.BindPFlag("ipld.server.graphqlPath", serveCmd.PersistentFlags().Lookup("ipld-server-graphql-path"))
	viper.BindPFlag("ipld.postgraphilePath", serveCmd.PersistentFlags().Lookup("ipld-postgraphile-path"))
	viper.BindPFlag("tracing.httpPath", serveCmd.PersistentFlags().Lookup("tracing-http-path"))
	viper.BindPFlag("tracing.postgraphilePath", serveCmd.PersistentFlags().Lookup("tracing-postgraphile-path"))

	viper.BindPFlag("ethereum.httpPath", serveCmd.PersistentFlags().Lookup("eth-http-path"))
	viper.BindPFlag("ethereum.nodeID", serveCmd.PersistentFlags().Lookup("eth-node-id"))
	viper.BindPFlag("ethereum.clientName", serveCmd.PersistentFlags().Lookup("eth-client-name"))
	viper.BindPFlag("ethereum.genesisBlock", serveCmd.PersistentFlags().Lookup("eth-genesis-block"))
	viper.BindPFlag("ethereum.networkID", serveCmd.PersistentFlags().Lookup("eth-network-id"))
	viper.BindPFlag("ethereum.chainID", serveCmd.PersistentFlags().Lookup("eth-chain-id"))
	viper.BindPFlag("ethereum.defaultSender", serveCmd.PersistentFlags().Lookup("eth-default-sender"))
	viper.BindPFlag("ethereum.rpcGasCap", serveCmd.PersistentFlags().Lookup("eth-rpc-gas-cap"))
	viper.BindPFlag("ethereum.chainConfig", serveCmd.PersistentFlags().Lookup("eth-chain-config"))
	viper.BindPFlag("ethereum.supportsStateDiff", serveCmd.PersistentFlags().Lookup("eth-supports-state-diff"))
}
