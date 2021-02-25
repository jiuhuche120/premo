package bxh_tester

import (
	"crypto/sha256"
	"fmt"
	"io/ioutil"
	"os"
	"time"

	"github.com/bitxhub/bitxid"
	"github.com/meshplus/bitxhub-model/constant"
	"github.com/meshplus/bitxhub-model/pb"
	rpcx "github.com/meshplus/go-bitxhub-client"
	"github.com/sirupsen/logrus"
)

var cfg2 = &config{
	addrs: []string{
		"localhost:60111",
	},
	logger: logrus.New(),
}

func (suite *Snake) estAAAA_InterRelay_Init_Relay2() {
	kA, _, from, _ := suite.prepare()
	node0 := &rpcx.NodeInfo{Addr: cfg2.addrs[0]}
	client, err := rpcx.New(
		rpcx.WithNodesInfo(node0),
		rpcx.WithLogger(cfg2.logger),
		rpcx.WithPrivateKey(kA),
	)
	suite.Require().Nil(err)
	/****************************************************/
	Relay1 := "0x703b22368195d5063C5B5C26019301Cf2EbC83e2"
	ruleFile := "./testdata/simple_rule.wasm"
	bytes, err := ioutil.ReadFile(ruleFile)
	suite.Require().Nil(err)
	addr, err := client.DeployContract(bytes, nil)
	suite.Require().Nil(err)
	res, err := client.InvokeBVMContract(
		constant.RuleManagerContractAddr.Address(),
		"RegisterRule",
		nil,
		pb.String(Relay1),
		pb.String(addr.String()))
	suite.Require().Nil(err)
	suite.Require().True(res.IsSuccess())

	/****************************************************/
	client.SetPrivateKey(kA)
	adminAddrStr := fmt.Sprint(from)
	adminDID := "did:bitxhub:appchain001:" + adminAddrStr
	res, err = client.InvokeBVMContract(constant.MethodRegistryContractAddr.Address(), "Init", nil, pb.String(adminDID))
	suite.Require().Nil(err)
	if res.Ret != nil {
		fmt.Println("Init res.Ret: ", string(res.Ret))
	}

}

func (suite *Snake) estAAAA_InterRelay_Init_Relay1() {
	Relay1 := "0x454e2569dD093D09E5E8B4aB764692780D795C9a"
	ruleFile := "./testdata/simple_rule.wasm"
	bytes, err := ioutil.ReadFile(ruleFile)
	suite.Require().Nil(err)
	addr, err := suite.client.DeployContract(bytes, nil)
	suite.Require().Nil(err)
	res, err := suite.client.InvokeBVMContract(
		constant.RuleManagerContractAddr.Address(),
		"RegisterRule",
		nil,
		pb.String(Relay1),
		pb.String(addr.String()))
	suite.Require().Nil(err)
	suite.Require().True(res.IsSuccess())
}

func (suite *Snake) estAAA_InterRelay_HandleIBTP1() {
	Relay1 := "0x454e2569dD093D09E5E8B4aB764692780D795C9a"
	Relay2 := "0x703b22368195d5063C5B5C26019301Cf2EbC83e2"
	proof := "test"
	proofHash := sha256.Sum256([]byte(proof))

	item := &bitxid.MethodItem{
		BasicItem: bitxid.BasicItem{
			ID:      bitxid.DID("did:bitxhub:appchain001:."),
			DocAddr: "/ipfs/1/...",
			DocHash: []byte{1},
			Status:  bitxid.Normal,
		},
	}
	itemBytes, err := bitxid.Struct2Bytes(item)

	content := pb.Content{
		SrcContractId: constant.MethodRegistryContractAddr.String(),
		DstContractId: constant.MethodRegistryContractAddr.String(),
		Func:          "Synchronize",
		Args:          [][]byte{[]byte("did:bitxhub:relayroot:."), []byte(itemBytes)},
		Callback:      "",
	}
	contentBytes, err := content.Marshal()
	suite.Require().Nil(err)

	payload := pb.Payload{
		Encrypted: false,
		Content:   contentBytes,
	}
	payloadBytes, err := payload.Marshal()
	suite.Require().Nil(err)

	ib := &pb.IBTP{
		From:      Relay1,
		To:        Relay2,
		Payload:   payloadBytes,
		Index:     1,
		Timestamp: time.Now().UnixNano(),
		Proof:     proofHash[:],
	}

	tx, _ := suite.client.GenerateIBTPTx(ib)
	tx.Extra = []byte(proof)
	res, err := suite.client.SendTransactionWithReceipt(tx, &rpcx.TransactOpts{
		From:      fmt.Sprintf("%s-%s-%d", ib.From, ib.To, ib.Category()),
		IBTPNonce: ib.Index,
	})
	suite.Require().Nil(err)
	fmt.Println("res.Ret:", res.Ret)
	fmt.Println("tx.IBTP sent:", tx.IBTP)
}

func (suite *Snake) estAAA_InterRelay_HandleIBTP_2() {
	Relay1 := "0x454e2569dD093D09E5E8B4aB764692780D795C9a"
	Relay2 := "0x703b22368195d5063C5B5C26019301Cf2EbC83e2"
	proof := "test"
	proofHash := sha256.Sum256([]byte(proof))

	item := &bitxid.MethodItem{
		BasicItem: bitxid.BasicItem{
			ID:      bitxid.DID("did:bitxhub:appchain002:."),
			DocAddr: "/ipfs/2/...",
			DocHash: []byte{1},
			Status:  bitxid.Normal,
		},
	}
	itemBytes, err := bitxid.Struct2Bytes(item)

	content := pb.Content{
		SrcContractId: constant.MethodRegistryContractAddr.String(),
		DstContractId: constant.MethodRegistryContractAddr.String(),
		Func:          "Synchronize",
		Args:          [][]byte{[]byte("did:bitxhub:relayroot:."), []byte(itemBytes)},
		Callback:      "",
	}
	contentBytes, err := content.Marshal()
	suite.Require().Nil(err)

	payload := pb.Payload{
		Encrypted: false,
		Content:   contentBytes,
	}
	payloadBytes, err := payload.Marshal()
	suite.Require().Nil(err)

	ib := &pb.IBTP{
		From:      Relay1,
		To:        Relay2,
		Payload:   payloadBytes,
		Index:     2,
		Timestamp: time.Now().UnixNano(),
		Proof:     proofHash[:],
	}

	tx, _ := suite.client.GenerateIBTPTx(ib)
	tx.Extra = []byte(proof)
	res, err := suite.client.SendTransactionWithReceipt(tx, &rpcx.TransactOpts{
		From:      fmt.Sprintf("%s-%s-%d", ib.From, ib.To, ib.Category()),
		IBTPNonce: ib.Index,
	})
	suite.Require().Nil(err)
	fmt.Println("res.Ret:", res.Ret)
	fmt.Println("tx.IBTP sent:", tx.IBTP)
}

func (suite *Snake) estAAA_InterRelay_HandleIBTP_3() {
	Relay1 := "0x454e2569dD093D09E5E8B4aB764692780D795C9a"
	Relay2 := "0x703b22368195d5063C5B5C26019301Cf2EbC83e2"
	proof := "test"
	proofHash := sha256.Sum256([]byte(proof))

	item := &bitxid.MethodItem{
		BasicItem: bitxid.BasicItem{
			ID:      bitxid.DID("did:bitxhub:appchain003:."),
			DocAddr: "/ipfs/3/...",
			DocHash: []byte{1},
			Status:  bitxid.Normal,
		},
	}
	itemBytes, err := bitxid.Struct2Bytes(item)

	content := pb.Content{
		SrcContractId: constant.MethodRegistryContractAddr.String(),
		DstContractId: constant.MethodRegistryContractAddr.String(),
		Func:          "Synchronize",
		Args:          [][]byte{[]byte("did:bitxhub:relayroot:."), []byte(itemBytes)},
		Callback:      "",
	}
	contentBytes, err := content.Marshal()
	suite.Require().Nil(err)

	payload := pb.Payload{
		Encrypted: false,
		Content:   contentBytes,
	}
	payloadBytes, err := payload.Marshal()
	suite.Require().Nil(err)

	ib := &pb.IBTP{
		From:      Relay1,
		To:        Relay2,
		Payload:   payloadBytes,
		Index:     3,
		Timestamp: time.Now().UnixNano(),
		Proof:     proofHash[:],
	}

	tx, _ := suite.client.GenerateIBTPTx(ib)
	tx.Extra = []byte(proof)
	res, err := suite.client.SendTransactionWithReceipt(tx, &rpcx.TransactOpts{
		From:      fmt.Sprintf("%s-%s-%d", ib.From, ib.To, ib.Category()),
		IBTPNonce: ib.Index,
	})
	suite.Require().Nil(err)
	fmt.Println("res.Ret:", res.Ret)
	fmt.Println("tx.IBTP sent:", tx.IBTP)
}

// index++
func (suite *Snake) estAAA_InterRelay_HandleIBTP_4_5() {
	for i := 4; i <= 5; i++ {
		ib := suite.newTestIBTP(uint64(i))
		tx, _ := suite.client.GenerateIBTPTx(ib)
		tx.Extra = []byte(ib.Proof)
		res, err := suite.client.SendTransactionWithReceipt(tx, &rpcx.TransactOpts{
			From:      fmt.Sprintf("%s-%s-%d", ib.From, ib.To, ib.Category()),
			IBTPNonce: ib.Index,
		})
		suite.Require().Nil(err)
		fmt.Println("res.Ret:", res.Ret)
		fmt.Println("tx.IBTP sent:", tx.IBTP)
	}
}

func (suite *Snake) TestAA_End() {
	fmt.Println("..............end..................")
	os.Exit(0)
}

func (suite *Snake) newTestIBTP(i uint64) *pb.IBTP {
	Relay1 := "0x454e2569dD093D09E5E8B4aB764692780D795C9a"
	Relay2 := "0x703b22368195d5063C5B5C26019301Cf2EbC83e2"
	proof := "test"
	proofHash := sha256.Sum256([]byte(proof))

	item := &bitxid.MethodItem{
		BasicItem: bitxid.BasicItem{
			ID:      bitxid.DID("did:bitxhub:appchain00" + fmt.Sprint(i) + ":."),
			DocAddr: "/ipfs/" + fmt.Sprint(i) + "/...",
		},
	}
	itemBytes, err := bitxid.Struct2Bytes(item)

	content := pb.Content{
		SrcContractId: constant.MethodRegistryContractAddr.String(),
		DstContractId: constant.MethodRegistryContractAddr.String(),
		Func:          "Synchronize",
		Args:          [][]byte{[]byte("did:bitxhub:relayroot:."), []byte(itemBytes)},
		Callback:      "",
	}
	contentBytes, err := content.Marshal()
	suite.Require().Nil(err)

	payload := pb.Payload{
		Encrypted: false,
		Content:   contentBytes,
	}
	payloadBytes, err := payload.Marshal()
	suite.Require().Nil(err)

	fmt.Println(i)

	return &pb.IBTP{
		From:      Relay1,
		To:        Relay2,
		Payload:   payloadBytes,
		Index:     i,
		Timestamp: time.Now().UnixNano(),
		Proof:     proofHash[:],
	}
}
