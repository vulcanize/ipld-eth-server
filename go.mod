module github.com/vulcanize/ipld-eth-server

go 1.13

require (
	github.com/ethereum/go-ethereum v1.9.25
	github.com/go-sql-driver/mysql v1.6.0 // indirect
	github.com/graph-gophers/graphql-go v0.0.0-20201003130358-c5bdf3b1108e
	github.com/ipfs/go-block-format v0.0.2
	github.com/ipfs/go-cid v0.0.7
	github.com/ipfs/go-ipfs-blockstore v1.0.1
	github.com/ipfs/go-ipfs-ds-help v1.0.0
	github.com/ipfs/go-ipld-format v0.2.0
	github.com/jmoiron/sqlx v1.2.0
	github.com/lib/pq v1.10.2
	github.com/machinebox/graphql v0.2.2
	github.com/matryer/is v1.4.0 // indirect
	github.com/mattn/go-sqlite3 v1.14.7 // indirect
	github.com/multiformats/go-multihash v0.0.14
	github.com/onsi/ginkgo v1.16.4
	github.com/onsi/gomega v1.10.1
	github.com/pkg/errors v0.9.1 // indirect
	github.com/prometheus/client_golang v1.5.1
	github.com/sirupsen/logrus v1.7.0
	github.com/spf13/cobra v1.1.1
	github.com/spf13/viper v1.7.0
	github.com/vulcanize/gap-filler v0.3.1
	github.com/vulcanize/ipfs-ethdb v0.0.2
	github.com/vulcanize/ipld-eth-indexer v0.7.1-alpha
	golang.org/x/crypto v0.0.0-20210513164829-c07d793c2f9a // indirect
	golang.org/x/net v0.0.0-20210610132358-84b48f89b13b // indirect
	golang.org/x/sys v0.0.0-20210608053332-aa57babbf139 // indirect
	golang.org/x/tools v0.1.3 // indirect
)

replace github.com/ethereum/go-ethereum v1.9.25 => github.com/vulcanize/go-ethereum v1.9.25-statediff-0.0.15
