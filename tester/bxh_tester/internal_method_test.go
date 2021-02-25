package bxh_tester

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/bitxhub/bitxid"
	"github.com/meshplus/bitxhub-kit/crypto"
	"github.com/meshplus/bitxhub-model/constant"
	"github.com/meshplus/bitxhub-model/pb"
	rpcx "github.com/meshplus/go-bitxhub-client"
)

func (suite *Snake) TestMethodCrossInvoke() {
	testMethod := "did:bitxhub:appchain001:."
	testDID := "did:bitxhub:appchain001:0xc7F999b83Af6DF9e67d0a37Ee7e900bF38b3D013"
	adminDID := "did:bitxhub:relayroot:0x00000001"

	rootMethod := "did:bitxhub:relayroot:."
	childMethod := "did:bitxhub:relaychain001:."

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	kA, _, _, _ := suite.prepare() // from, to, kB
	// relayID2 := suite.RegisterAppchainWithReturn(kB, "relaychain001")
	relayID2 := "0x32a07E5dC7715Fc40A54e58DE0CE5303561517ad"
	relayroot := suite.RegisterAppchainWithReturn(kA, "relayroot")

	// ch1, err := suite.client.Subscribe(ctx, pb.SubscriptionRequest_INTERCHAIN_TX_WRAPPER, []byte(relayID2))
	chUnion, err := suite.client.Subscribe(ctx, pb.SubscriptionRequest_UNION_INTERCHAIN_TX_WRAPPER, []byte(relayID2))
	chEvent, err := suite.client.Subscribe(ctx, pb.SubscriptionRequest_EVENT, []byte("lalala"))

	fmt.Println("relayroot:", relayroot)
	fmt.Println("relayID2:", relayID2)
	suite.Require().Nil(err)

	go func() {
		args := []*pb.Arg{
			rpcx.String(adminDID),
		}
		res, err := suite.client.InvokeBVMContract(constant.MethodRegistryContractAddr.Address(), "Init", nil, args...)
		suite.Require().Nil(err)
		if res.Ret != nil {
			fmt.Println("Init res.Ret: ", string(res.Ret))
		}
		// fmt.Println("res.Status: ", res.Status)
		// fmt.Println("res.TxHash: ", res.TxHash)

		args = []*pb.Arg{
			rpcx.String(testDID),
			rpcx.String(testMethod),
			rpcx.Bytes([]byte{1, 2, 3}),
		}
		res, err = suite.client.InvokeBVMContract(constant.MethodRegistryContractAddr.Address(), "Apply", nil, args...)
		suite.Require().Nil(err)
		if res.Ret != nil {
			fmt.Println("Apply res.Ret: ", string(res.Ret))
		}

		args = []*pb.Arg{
			rpcx.String(rootMethod),
			rpcx.String(relayroot),
		}
		res, err = suite.client.InvokeBVMContract(constant.MethodRegistryContractAddr.Address(), "SetConvertMap", nil, args...)
		suite.Require().Nil(err)
		if res.Ret != nil {
			fmt.Println("SetConvertMap res.Ret: ", string(res.Ret))
		}

		args = []*pb.Arg{
			rpcx.String(childMethod), // relaychain001
		}
		res, err = suite.client.InvokeBVMContract(constant.MethodRegistryContractAddr.Address(), "AddChild", nil, args...)
		suite.Require().Nil(err)
		if res.Ret != nil {
			fmt.Println("AddChild res.Ret: ", string(res.Ret))
		}

		args = []*pb.Arg{
			rpcx.String(childMethod),
			rpcx.String(relayID2), // whatever
		}
		res, err = suite.client.InvokeBVMContract(constant.MethodRegistryContractAddr.Address(), "SetConvertMap", nil, args...)
		suite.Require().Nil(err)
		if res.Ret != nil {
			fmt.Println("SetConvertMap res.Ret: ", string(res.Ret))
		}

		args = []*pb.Arg{
			rpcx.String(adminDID), // admin
			rpcx.String(testMethod),
			rpcx.Int32(1), // rpcx.Bool(true),
			rpcx.Bytes([]byte{1, 2, 3}),
		}
		res, err = suite.client.InvokeBVMContract(constant.MethodRegistryContractAddr.Address(), "AuditApply", nil, args...)
		suite.Require().Nil(err)
		if res.Ret != nil {
			fmt.Println("AuditApply res.Ret: ", string(res.Ret))
		}

		doc := getMethodDoc(1)
		docb, err := bitxid.Struct2Bytes(doc)
		suite.Require().Nil(err)
		args = []*pb.Arg{
			rpcx.String(testDID),
			rpcx.String(testMethod),
			rpcx.Bytes(docb),
			rpcx.Bytes([]byte{1, 2, 3}),
		}
		res, err = suite.client.InvokeBVMContract(constant.MethodRegistryContractAddr.Address(), "Register", nil, args...)
		suite.Require().Nil(err)
		if res.Ret != nil {
			fmt.Println("Register res.Ret: ", string(res.Ret))
		}
		fmt.Println("res.Events:", res.Events)

		// args = []*pb.Arg{
		// 	rpcx.String("did:bitxhub:relaychain001:0xc7F999b83Af6DF9e67d0a37Ee7e900bF38b3D013"),
		// 	rpcx.String("did:bitxhub:appchain002:."),
		// 	rpcx.Bytes([]byte{1, 2, 3}),
		// }
		// res, err = suite.client.InvokeBVMContract(constant.MethodRegistryContractAddr.Address(), "Resolve", nil, args...)
		// suite.Require().Nil(err)
		// fmt.Println("Resolve res.Ret: ", string(res.Ret))
	}()

	go func() {
		for {
			select {
			case eventData, ok := <-chEvent:
				suite.Require().Equal(true, ok)
				suite.Require().NotNil(eventData)
				data := eventData.(*pb.Receipts)
				fmt.Printf("==> event data: %v\n", data)
				for _, r := range data.Receipts {
					for i, e := range r.Events {
						fmt.Printf("==> No.%d e.Data:", i)
						m := make(map[string]uint64)
						err := json.Unmarshal(e.Data, &m)
						if err != nil {
							fmt.Println(err)
						}
						fmt.Println(m) // ATN
					}
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	for {
		select {
		case eventData, ok := <-chUnion:
			suite.Require().Equal(true, ok)
			suite.Require().NotNil(eventData)
			data := eventData.(*pb.InterchainTxWrappers)
			// fmt.Printf("==> UNION event txwrappers: %v\n", data)
			for _, v := range data.InterchainTxWrappers {
				for i, j := range v.Transactions {
					fmt.Printf("==> No.%d tx.", i)
					fmt.Printf("IBTP: %v\n", j.IBTP)
					td := &pb.TransactionData{}
					err := td.Unmarshal(j.Payload)
					if err != nil {
						fmt.Println(err)
						break
					}
					pl := &pb.InvokePayload{}
					err = pl.Unmarshal(td.Payload)
					if err != nil {
						fmt.Println(err)
						break
					}
					fmt.Printf("IBTP.Payload: %v\n", pl)
				}
			}
		case <-ctx.Done():
			return
		}
	}

}

func (suite *Snake) RegisterAppchainWithReturn(pk crypto.PrivateKey, chainType string) string {
	pubBytes, err := pk.PublicKey().Bytes()
	suite.Require().Nil(err)

	suite.client.SetPrivateKey(pk)
	var pubKeyStr = hex.EncodeToString(pubBytes)
	args := []*pb.Arg{
		rpcx.String(""),                 //validators
		rpcx.Int32(0),                   //consensus_type
		rpcx.String(chainType),          //chain_type
		rpcx.String("AppChain"),         //name
		rpcx.String("Appchain for tax"), //desc
		rpcx.String("1.8"),              //version
		rpcx.String(pubKeyStr),          //public key
	}
	res, err := suite.client.InvokeBVMContract(constant.AppchainMgrContractAddr.Address(), "Register", nil, args...)
	suite.Require().Nil(err)
	appChain := &rpcx.Appchain{}
	err = json.Unmarshal(res.Ret, appChain)
	suite.Require().Nil(err)
	suite.Require().NotNil(appChain.ID)
	return appChain.ID
}

func getMethodDoc(ran int) bitxid.MethodDoc {
	docE := bitxid.MethodDoc{}
	docE.ID = bitxid.DID("did:bitxhub:appchain001:.")
	docE.Type = "method"
	pk1 := bitxid.PubKey{
		ID:           "KEY#1",
		Type:         "Ed25519",
		PublicKeyPem: "H3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV",
	}
	pk2 := bitxid.PubKey{
		ID:           "KEY#1",
		Type:         "Secp256k1",
		PublicKeyPem: "02b97c30de767f084ce3080168ee293053ba33b235d7116a3263d29f1450936b71",
	}
	if ran == 0 {
		docE.ID = bitxid.DID("did:bitxhub:relaychain001:.")
	} else if ran == 1 {
		docE.PublicKey = []bitxid.PubKey{pk1}
	} else {
		docE.PublicKey = []bitxid.PubKey{pk2}
	}
	auth := bitxid.Auth{
		PublicKey: []string{"KEY#1"},
	}
	docE.Authentication = []bitxid.Auth{auth}
	return docE
}
