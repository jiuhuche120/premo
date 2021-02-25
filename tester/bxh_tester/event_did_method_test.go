package bxh_tester

import (
	"fmt"

	"github.com/meshplus/bitxhub-model/constant"
	"github.com/meshplus/bitxhub-model/pb"
	rpcx "github.com/meshplus/go-bitxhub-client"
)

func (suite *Snake) TestMethodInit() {

	kA, _, _, _ := suite.prepare()
	relayroot := suite.RegisterAppchainWithReturn(kA, "relayroot")

	args := []*pb.Arg{
		rpcx.String("did:bitxhub:relayroot:" + relayroot),
	}
	res, err := suite.client.InvokeBVMContract(constant.MethodRegistryContractAddr.Address(), "Init", nil, args...)
	suite.Require().Nil(err)
	suite.Require().Contains(string(res.Ret), "init success")
	fmt.Println("Init res.Ret: ", string(res.Ret))
}

func (suite *Snake) TestMethodApply() {

	kA, _, _, _ := suite.prepare()
	relayroot := suite.RegisterAppchainWithReturn(kA, "relayroot")

	args := []*pb.Arg{
		rpcx.String("did:bitxhub:relayroot:" + relayroot),
		rpcx.String("did:bitxhub:relayroot:."),
		rpcx.Bytes([]byte{1, 2, 3}),
	}
	res, err := suite.client.InvokeBVMContract(constant.MethodRegistryContractAddr.Address(), "Apply", nil, args...)
	suite.Require().Nil(err)
	suite.True(res.Status == pb.Receipt_SUCCESS)
	fmt.Println("Apply res.Ret: ", string(res.Ret))
}

func (suite *Snake) TestMethodApplyWithCallerIsError() {
	args := []*pb.Arg{
		rpcx.String("did:bitxhub:relayroot:" + "12345"),
		rpcx.String("did:bitxhub:relayroot:."),
		rpcx.Bytes([]byte{1, 2, 3}),
	}
	res, err := suite.client.InvokeBVMContract(constant.MethodRegistryContractAddr.Address(), "Apply", nil, args...)
	suite.Require().Nil(err)
	suite.True(res.Status == pb.Receipt_FAILED)
	suite.Require().Contains(string(res.Ret), "not the same")
}

func (suite *Snake) TestMethodApplyWithFormatIsError() {
	kA, _, _, _ := suite.prepare()
	relayroot := suite.RegisterAppchainWithReturn(kA, "relayroot")
	args := []*pb.Arg{
		rpcx.String("did:bitxhub:relayroot:" + relayroot),
		rpcx.String("did/bitxhub/relayroot/."),
		rpcx.Bytes([]byte{1, 2, 3}),
	}
	res, err := suite.client.InvokeBVMContract(constant.MethodRegistryContractAddr.Address(), "Apply", nil, args...)
	suite.Require().Nil(err)
	suite.Require().True(res.Status == pb.Receipt_FAILED)
	suite.Require().Contains(string(res.Ret), "not valid method format")
}

func (suite *Snake) TestMethodAuditApply() {
	args := []*pb.Arg{
		rpcx.String("did:bitxhub:relayroot:0xc7F999b83Af6DF9e67d0a37Ee7e900bF38b3D013"), // admin
		rpcx.String("did:bitxhub:relayroot:."),
		// rpcx.Bool(true),
		rpcx.Int32(1),
		rpcx.Bytes([]byte{1, 2, 3}),
	}
	res, err := suite.client.InvokeBVMContract(constant.MethodRegistryContractAddr.Address(), "AuditApply", nil, args...)
	suite.Require().Nil(err)
	fmt.Println("AuditApply res.Ret: ", string(res.Ret))
}
