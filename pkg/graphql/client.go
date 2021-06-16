package graphql

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	gqlclient "github.com/machinebox/graphql"
)

type StorageResponse struct {
	Cid       string        `json:"cid"`
	IpldBlock hexutil.Bytes `json:"ipldBlock"`
	Value     common.Hash   `json:"value"`
}

type GetStorageAt struct {
	Response StorageResponse `json:"getStorageAt"`
}

type LogResponse struct {
	Topics []common.Hash `json:"topics"`
	Data   hexutil.Bytes `json:"data"`
}

type GetLogs struct {
	Responses []LogResponse `json:"getLogs"`
}

type Client struct {
	client *gqlclient.Client
}

func NewClient(endpoint string) *Client {
	client := gqlclient.NewClient(endpoint)
	return &Client{client: client}
}

func (c *Client) GetLogs(ctx context.Context, hash common.Hash, address common.Address) ([]LogResponse, error) {
	getLogsQuery := fmt.Sprintf(`
		query{
			getLogs(blockHash: "%s", contract: "%s") {
				data
				topics
			}
		}
	`, hash.String(), address.String())

	req := gqlclient.NewRequest(getLogsQuery)
	req.Header.Set("Cache-Control", "no-cache")

	var respData map[string]interface{}
	err := c.client.Run(ctx, req, &respData)
	if err != nil {
		return nil, err
	}

	jsonStr, err := json.Marshal(respData)
	if err != nil {
		return nil, err
	}

	var logs GetLogs
	err = json.Unmarshal(jsonStr, &logs)
	if err != nil {
		return nil, err
	}
	return logs.Responses, nil
}

func (c *Client) GetStorageAt(ctx context.Context, hash common.Hash, address common.Address, slot string) (*StorageResponse, error) {
	getLogsQuery := fmt.Sprintf(`
		query{
			getStorageAt(blockHash: "%s", contract: "%s",slot: "%s") {
				cid
				value
				ipldBlock
			}
		}
	`, hash.String(), address.String(), slot)

	req := gqlclient.NewRequest(getLogsQuery)
	req.Header.Set("Cache-Control", "no-cache")

	var respData map[string]interface{}
	err := c.client.Run(ctx, req, &respData)
	if err != nil {
		return nil, err
	}

	jsonStr, err := json.Marshal(respData)
	if err != nil {
		return nil, err
	}

	var storageAt GetStorageAt
	err = json.Unmarshal(jsonStr, &storageAt)
	if err != nil {
		return nil, err
	}
	return &storageAt.Response, nil
}
