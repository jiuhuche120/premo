package bxh_tester

import (
	"fmt"

	rpcx "github.com/meshplus/go-bitxhub-client"
)

func (suite *Snake) Test_IPFS() {
	pk, _, _, _ := suite.prepare()
	client, err := rpcx.New(
		// rpcx.WithNodesInfo(&rpcx.NodeInfo{Addr: cfg.addrs[0]}),
		rpcx.WithLogger(cfg.logger),
		rpcx.WithPrivateKey(pk),
		rpcx.WithIPFSInfo([]string{"http://localhost:15001", "http://localhost:25001", "http://localhost:35001", "http://localhost:45001"}),
	)
	suite.Require().Nil(err)

	res, err := client.IPFSPutFromLocal("./testdata/ipfs.json")
	suite.Require().Nil(err)
	fmt.Println(string(res.Data))

	_, err = client.IPFSGet("/ipfs/" + string(res.Data))
	suite.Require().Nil(err)

	_, err = client.IPFSGetToLocal("/ipfs/"+string(res.Data), "./testdata/ipfs-get.json")
	suite.Require().Nil(err)
}
