package bxh_tester

import (
	"fmt"
	"time"

	"github.com/meshplus/bitxhub-kit/crypto"
	"github.com/meshplus/bitxhub-model/constant"
	"github.com/meshplus/bitxhub-model/pb"
	rpcx "github.com/meshplus/go-bitxhub-client"
)

func (suite *Snake) Test_ExternalDID() {
	kA, kB, from, to := suite.prepare() // from, to, kB
	adminAddrStr := fmt.Sprint(from)
	testAddrStr := fmt.Sprint(to)

	// ctx, cancel := context.WithCancel(context.Background())
	// defer cancel()

	adminDID := "did:bitxhub:appchain001:" + adminAddrStr
	testDID := "did:bitxhub:appchain001:" + testAddrStr

	docAddr := "/ipfs/QmQVxzUqN2Yv2UHUQXYwH8dSNkM8ReJ9qPqwJsf8zzoNUi"
	docHash := []byte("QmQVxzUqN2Yv2UHUQXYwH8dSNkM8ReJ9qPqwJsf8zzoNUi")

	// testMethod := "did:bitxhub:appchain001:."
	suite.client.SetPrivateKey(kA)
	suite.didInitTests(adminDID)

	suite.didRegisterTests(kB, testDID, docAddr, docHash, []byte{1, 2, 3})

	time.Sleep(5 * time.Second)
}

func (suite *Snake) didInitTests(adminDID string) {
	args := []*pb.Arg{
		rpcx.String(adminDID),
	}
	res, err := suite.client.InvokeBVMContract(constant.DIDRegistryContractAddr.Address(), "Init", nil, args...)
	suite.Require().Nil(err)
	if res.Ret != nil {
		fmt.Println("Init res.Ret: ", string(res.Ret))
	}

	args = []*pb.Arg{}
	res, err = suite.client.InvokeBVMContract(constant.DIDRegistryContractAddr.Address(), "GetMethodID", nil, args...)
	suite.Require().Nil(err)
	if res.Ret != nil {
		fmt.Println("GetMethodID res.Ret: ", string(res.Ret))
	}

	args = []*pb.Arg{}
	res, err = suite.client.InvokeBVMContract(constant.DIDRegistryContractAddr.Address(), "GetAdmins", nil, args...)
	suite.Require().Nil(err)
	if res.Ret != nil {
		fmt.Println("GetAdmins res.Ret: ", string(res.Ret))
	}
}

func (suite *Snake) didRegisterTests(kB crypto.PrivateKey, testDID string, docAddr string, docHash []byte, sig []byte) {
	// register fail:
	args := []*pb.Arg{
		rpcx.String(testDID),
		rpcx.String(docAddr),
		rpcx.Bytes(docHash),
		rpcx.Bytes(sig),
	}
	res, err := suite.client.InvokeBVMContract(constant.DIDRegistryContractAddr.Address(), "Register", nil, args...)
	suite.Require().Nil(err)
	if res.Ret != nil {
		fmt.Println("Shoud Register failed res.Ret: ", string(res.Ret))
	}

	// register succeed:
	suite.client.SetPrivateKey(kB)
	args = []*pb.Arg{
		rpcx.String(testDID),
		rpcx.String(docAddr),
		rpcx.Bytes(docHash),
		rpcx.Bytes(sig),
	}
	res, err = suite.client.InvokeBVMContract(constant.DIDRegistryContractAddr.Address(), "Register", nil, args...)
	suite.Require().Nil(err)
	if res.Ret != nil {
		fmt.Println("Register res.Ret: ", string(res.Ret))
	}

	// register succeed:
	suite.client.SetPrivateKey(kB)
	args = []*pb.Arg{
		rpcx.String(testDID),
		rpcx.String(docAddr),
		rpcx.Bytes(docHash),
		rpcx.Bytes(sig),
	}
	res, err = suite.client.InvokeBVMContract(constant.DIDRegistryContractAddr.Address(), "Update", nil, args...)
	suite.Require().Nil(err)
	if res.Ret != nil {
		fmt.Println("Update res.Ret: ", string(res.Ret))
	}

	args = []*pb.Arg{
		rpcx.String(testDID),
	}
	res, err = suite.client.InvokeBVMContract(constant.DIDRegistryContractAddr.Address(), "Resolve", nil, args...)
	suite.Require().Nil(err)
	mi := &MethodInfo{}
	Bytes2Struct(res.Ret, mi)
	fmt.Println("Resolve res.Ret: ", mi)
}

type DIDInfo struct {
	DID     string // did name
	DocAddr string // address where the doc file stored
	DocHash []byte // hash of the doc file
	Status  string // status of did
}
