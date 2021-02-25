package bxh_tester

import (
	"bytes"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"os"

	"github.com/meshplus/bitxhub-kit/crypto"
	"github.com/meshplus/bitxhub-model/constant"
	"github.com/meshplus/bitxhub-model/pb"
	rpcx "github.com/meshplus/go-bitxhub-client"
)

func (suite *Snake) TestA_ExternalMethod() {
	kA, kB, from, to := suite.prepare() // from, to, kB
	adminAddrStr := fmt.Sprint(from)
	testAddrStr := fmt.Sprint(to)
	// ctx, cancel := context.WithCancel(context.Background())
	// defer cancel()

	adminDID := "did:bitxhub:relayroot:" + adminAddrStr
	testDID := "did:bitxhub:appchain001:" + testAddrStr

	docAddr := "/ipfs/QmQVxzUqN2Yv2UHUQXYwH8dSNkM8ReJ9qPqwJsf8zzoNUi"
	docHash := []byte("QmQVxzUqN2Yv2UHUQXYwH8dSNkM8ReJ9qPqwJsf8zzoNUi")

	testMethod := "did:bitxhub:appchain001:."
	rootMethod := "did:bitxhub:relayroot:."
	childMethod := "did:bitxhub:relaychain001:."

	// relayID2 := suite.RegisterAppchainWithReturn(kB, "relaychain001")
	relayAppID2 := "0x32a07E5dC7715Fc40A54e58DE0CE5303561517ad"
	relayrootID := suite.RegisterAppchainWithReturn(kA, "relayroot")
	suite.client.SetPrivateKey(kA)
	suite.methodInitTests(adminDID, rootMethod, childMethod, relayrootID, relayAppID2)

	suite.applyMethodTests(kA, kB, adminDID, testDID, testMethod, []byte{1, 2, 3})

	suite.client.SetPrivateKey(kB)
	suite.registerMethodTests(testDID, testMethod, docAddr, docHash, []byte{1, 2, 3})

	// suite.synchronizeTest("did:bitxhub:appchain001:.", []byte{0})
	suite.client.SetPrivateKey(kA)
	suite.methodAddAdmin(adminDID, "did:bitxhub:appchain001:"+suite.from.String())
	suite.methodRemoveAdmin(adminDID, "did:bitxhub:appchain001:"+suite.from.String())
	// suite.methodRemoveAdmin(adminDID, "did:bitxhub:appchain002:"+suite.from.String()) //should fail

	suite.client.SetPrivateKey(kB)
	suite.methodDelete(testDID, testMethod)

	os.Exit(0)
}

func (suite *Snake) methodInitTests(adminDID string, rootMethod string, childMethod string, relayrootID string, relayAppID2 string) {
	args := []*pb.Arg{
		rpcx.String(adminDID),
	}
	res, err := suite.client.InvokeBVMContract(constant.MethodRegistryContractAddr.Address(), "Init", nil, args...)
	suite.Require().Nil(err)
	if res.Ret != nil {
		fmt.Println("Init res.Ret: ", string(res.Ret))
	}

	args = []*pb.Arg{
		rpcx.String(adminDID),
		rpcx.String(rootMethod),
		rpcx.String(relayrootID),
	}
	res, err = suite.client.InvokeBVMContract(constant.MethodRegistryContractAddr.Address(), "SetConvertMap", nil, args...)
	suite.Require().Nil(err)
	if res.Ret != nil {
		fmt.Println("SetConvertMap res.Ret: ", string(res.Ret))
	}

	args = []*pb.Arg{
		rpcx.String(adminDID),
		rpcx.String(childMethod), // relaychain001
	}
	res, err = suite.client.InvokeBVMContract(constant.MethodRegistryContractAddr.Address(), "AddChild", nil, args...)
	suite.Require().Nil(err)
	if res.Ret != nil {
		fmt.Println("AddChild res.Ret: ", string(res.Ret))
	}

	args = []*pb.Arg{
		rpcx.String(adminDID),
		rpcx.String(childMethod),
		rpcx.String(relayAppID2), // whatever
	}
	res, err = suite.client.InvokeBVMContract(constant.MethodRegistryContractAddr.Address(), "SetConvertMap", nil, args...)
	suite.Require().Nil(err)
	if res.Ret != nil {
		fmt.Println("SetConvertMap res.Ret: ", string(res.Ret))
	}
}

func (suite *Snake) applyMethodTests(kA crypto.PrivateKey, kB crypto.PrivateKey, adminDID string, testDID string, testMethod string, sig []byte) {
	suite.client.SetPrivateKey(kB)

	args := []*pb.Arg{
		rpcx.String(testDID),
		rpcx.String(testMethod),
		rpcx.Bytes(sig),
	}
	res, err := suite.client.InvokeBVMContract(constant.MethodRegistryContractAddr.Address(), "Apply", nil, args...)
	suite.Require().Nil(err)
	if res.Ret != nil {
		fmt.Println("Apply res.Ret: ", string(res.Ret))
	}

	suite.client.SetPrivateKey(kA)
	args = []*pb.Arg{
		rpcx.String(adminDID), // admin
		rpcx.String(testMethod),
		rpcx.Int32(1), // rpcx.Bool(true),
		rpcx.Bytes(sig),
	}
	res, err = suite.client.InvokeBVMContract(constant.MethodRegistryContractAddr.Address(), "AuditApply", nil, args...)
	suite.Require().Nil(err)
	if res.Ret != nil {
		fmt.Println("AuditApply res.Ret: ", string(res.Ret))
	}
}

func (suite *Snake) registerMethodTests(testDID string, testMethod string, docAddr string, docHash []byte, sig []byte) {
	args := []*pb.Arg{
		rpcx.String(testDID),
		rpcx.String(testMethod),
		rpcx.String(docAddr),
		rpcx.Bytes(docHash),
		rpcx.Bytes(sig),
	}
	res, err := suite.client.InvokeBVMContract(constant.MethodRegistryContractAddr.Address(), "Register", nil, args...)
	suite.Require().Nil(err)
	if res.Ret != nil {
		fmt.Println("Register res.Ret: ", string(res.Ret))
	}
	ibtps := &pb.IBTPs{}
	err = ibtps.Unmarshal(res.Ret)
	suite.Require().Nil(err)
	fmt.Println("IBTPs:", ibtps.Ibtps)

	args = []*pb.Arg{
		rpcx.String(testMethod),
	}
	res, err = suite.client.InvokeBVMContract(constant.MethodRegistryContractAddr.Address(), "Resolve", nil, args...)
	suite.Require().Nil(err)
	mi := &MethodInfo{}
	Bytes2Struct(res.Ret, mi)
	fmt.Println("Resolve res.Ret: ", mi)
}

func (suite *Snake) synchronizeTest(from string, itemb []byte) {
	args := []*pb.Arg{
		rpcx.String(from),
		rpcx.Bytes(itemb),
	}
	res, err := suite.client.InvokeBVMContract(constant.MethodRegistryContractAddr.Address(), "Synchronize", nil, args...)
	suite.Require().Nil(err)
	if res.Ret != nil {
		fmt.Println("Synchronize res.Ret: ", string(res.Ret))
	}
}

func (suite *Snake) getMethodAdmins() ([]string, error) {
	res, err := suite.client.InvokeBVMContract(constant.MethodRegistryContractAddr.Address(), "GetAdmins", nil)
	if err != nil {
		return nil, err
	}
	var admins []string
	err = json.Unmarshal(res.Ret, &admins)
	if err != nil {
		return nil, err
	}
	return admins, nil
}

func (suite *Snake) methodAddAdmin(suAdminDID, adminToRm string) {
	admins, err := suite.getMethodAdmins()
	suite.Require().Nil(err)
	num1 := len(admins)
	fmt.Println("methodAddAdmin admins:", admins)
	args := []*pb.Arg{
		rpcx.String(suAdminDID),
		rpcx.String(adminToRm),
	}
	res, err := suite.client.InvokeBVMContract(constant.MethodRegistryContractAddr.Address(), "AddAdmin", nil, args...)
	suite.Require().Nil(err)
	fmt.Println("methodAddAdmin AddAdmin res.Ret:", string(res.Ret))
	suite.Require().Equal(pb.Receipt_SUCCESS, res.Status) //

	admins, err = suite.getMethodAdmins()
	suite.Require().Nil(err)
	num2 := len(admins)
	fmt.Println("methodAddAdmin admins:", admins)
	suite.Require().Equal(num1+1, num2)
}

//tc：超管正确删除管理员
func (suite *Snake) methodRemoveAdmin(suAdminDID, adminToRm string) {
	admins, err := suite.getMethodAdmins()
	suite.Require().Nil(err)
	num1 := len(admins)
	fmt.Println("methodRemoveAdmin admins:", admins)
	args := []*pb.Arg{
		rpcx.String(suAdminDID),
		rpcx.String(adminToRm),
	}
	res, err := suite.client.InvokeBVMContract(constant.MethodRegistryContractAddr.Address(), "RemoveAdmin", nil, args...)
	suite.Require().Nil(err)
	fmt.Println("methodRemoveAdmin RemoveAdmin res.Ret:", string(res.Ret))
	suite.Require().Equal(pb.Receipt_SUCCESS, res.Status)

	admins, err = suite.getMethodAdmins()
	suite.Require().Nil(err)
	num2 := len(admins)
	fmt.Println("methodRemoveAdmin admins:", admins)
	suite.Require().Equal(num1-1, num2)
}

//tc：正确删除Method
func (suite *Snake) methodDelete(suAdminDID, methodToDelete string) {
	args := []*pb.Arg{
		rpcx.String(suAdminDID), //admin
		rpcx.String(methodToDelete),
		rpcx.Bytes([]byte{1, 2, 3}),
	}
	res, err := suite.client.InvokeBVMContract(constant.MethodRegistryContractAddr.Address(), "Delete", nil, args...)
	suite.Require().Nil(err)
	fmt.Println("methodDelete Delete:", string(res.Ret))
	suite.Require().Equal(pb.Receipt_SUCCESS, res.Status)

	//resolve
	args = []*pb.Arg{
		rpcx.String(methodToDelete),
	}
	res, err = suite.client.InvokeBVMContract(constant.MethodRegistryContractAddr.Address(), "Resolve", nil, args...)
	suite.Require().Nil(err)
	suite.Require().Equal(pb.Receipt_SUCCESS, res.Status)
	mi := &MethodInfo{}
	err = Bytes2Struct(res.Ret, mi)
	suite.Require().Nil(err)
	fmt.Println("methodDelete Resolve res.Ret: ", mi)
	fmt.Println("methodDelete DocHash:", string(mi.DocHash))
}

type MethodInfo struct {
	Method  string // method name
	Owner   string // owner of the method, is a did
	DocAddr string // address where the doc file stored
	DocHash []byte // hash of the doc file
	Status  string // status of method
}

// Bytes2Struct .
func Bytes2Struct(b []byte, s interface{}) error {
	buf := bytes.NewBuffer(b)
	err := gob.NewDecoder(buf).Decode(s)
	if err != nil {
		return fmt.Errorf("gob decode err: %w", err)
	}
	return nil
}
