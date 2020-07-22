package bxh_tester

import (
	"encoding/hex"
	"encoding/json"

	"github.com/tidwall/gjson"

	"github.com/meshplus/bitxhub-model/pb"
	rpcx "github.com/meshplus/go-bitxhub-client"
)

func (suite *Snake) TestRegisterAppchain() {
	pubBytes, err := suite.pk.PublicKey().Bytes()
	suite.Nil(err)

	var pubKeyStr = hex.EncodeToString(pubBytes)
	args := []*pb.Arg{
		rpcx.String(""),                 //validators
		rpcx.Int32(0),                   //consensus_type
		rpcx.String("hyperchain"),       //chain_type
		rpcx.String("AppChain1"),        //name
		rpcx.String("Appchain for tax"), //desc
		rpcx.String("1.8"),              //version
		rpcx.String(pubKeyStr),          //public key
	}
	res, err := suite.client.InvokeBVMContract(rpcx.AppchainMgrContractAddr, "Register", args...)
	suite.Nil(err)
	appChain := &rpcx.Appchain{}
	err = json.Unmarshal(res.Ret, appChain)
	suite.Nil(err)
	suite.NotNil(appChain.ID)
}

func (suite *Snake) TestRegisterAppchainLoseFields() {
	args := []*pb.Arg{
		rpcx.String(""),    //validators
		rpcx.Int32(0),      //consensus_type
		rpcx.String("1.8"), //version
	}
	res, err := suite.client.InvokeBVMContract(rpcx.AppchainMgrContractAddr, "Register", args...)
	suite.Nil(err)
	suite.True(res.Status == pb.Receipt_FAILED)
}

func (suite *Snake) TestRegisterReplicaAppchain() {
	pubBytes, err := suite.pk.PublicKey().Bytes()
	suite.Nil(err)

	var pubKeyStr = hex.EncodeToString(pubBytes)
	args := []*pb.Arg{
		rpcx.String(""),                 //validators
		rpcx.Int32(0),                   //consensus_type
		rpcx.String("hyperchain"),       //chain_type
		rpcx.String("AppChain1"),        //name
		rpcx.String("Appchain for tax"), //desc
		rpcx.String("1.8"),              //version
		rpcx.String(pubKeyStr),          //public key
	}
	res, err := suite.client.InvokeBVMContract(rpcx.AppchainMgrContractAddr, "Register", args...)
	suite.Nil(err)
	appchainID := gjson.Get(string(res.Ret), "appchainID").String()

	res1, err := suite.client.InvokeBVMContract(rpcx.AppchainMgrContractAddr, "Register", args...)
	suite.Nil(err)

	appchainID1 := gjson.Get(string(res1.Ret), "appchainID").String()
	suite.True(appchainID == appchainID1)
}

func (suite *Snake) TestUpdateAppchain() {
	pubBytes, err := suite.pk.PublicKey().Bytes()
	suite.Nil(err)

	pubKeyStr := hex.EncodeToString(pubBytes)
	args := []*pb.Arg{
		rpcx.String(""), //validators
		rpcx.Int32(0),   //consensus_type
		rpcx.String("hyperchain1111111111111111111111111"), //chain_type
		rpcx.String("AppChain1"),                           //name
		rpcx.String("Appchain for tax"),                    //desc
		rpcx.String("1.8"),                                 //version
		rpcx.String(pubKeyStr),                             //public key
	}
	res, err := suite.client.InvokeBVMContract(rpcx.AppchainMgrContractAddr, "UpdateAppchain", args...)
	suite.Nil(err)
	suite.True(res.Status == pb.Receipt_SUCCESS)
}

func (suite *Snake) TestUpdateAppchainLoseFields() {
	pubBytes, err := suite.pk.PublicKey().Bytes()
	suite.Nil(err)

	pubKeyStr := hex.EncodeToString(pubBytes)
	args := []*pb.Arg{
		rpcx.String(""),                 //validators
		rpcx.Int32(0),                   //consensus_type
		rpcx.String("Appchain for tax"), //desc
		rpcx.String("1.8"),              //version
		rpcx.String(pubKeyStr),          //public key
	}
	res, err := suite.client.InvokeBVMContract(rpcx.AppchainMgrContractAddr, "UpdateAppchain", args...)
	suite.Nil(err)
	suite.True(res.Status == pb.Receipt_FAILED)
}

func (suite *Snake) TestAuditAppchain() {
	pubBytes, err := suite.pk.PublicKey().Bytes()
	suite.Nil(err)

	var pubKeyStr = hex.EncodeToString(pubBytes)
	args := []*pb.Arg{
		rpcx.String(""),                 //validators
		rpcx.Int32(0),                   //consensus_type
		rpcx.String("hyperchain"),       //chain_type
		rpcx.String("AppChain1"),        //name
		rpcx.String("Appchain for tax"), //desc
		rpcx.String("1.8"),              //version
		rpcx.String(pubKeyStr),          //public key
	}
	_, err = suite.client.InvokeBVMContract(rpcx.AppchainMgrContractAddr, "Register", args...)
	suite.Nil(err)

	args1 := []*pb.Arg{
		rpcx.String(suite.from.String()),
		rpcx.Int32(1),               //audit approve
		rpcx.String("Audit passed"), //desc
	}
	res, err := suite.client.InvokeBVMContract(rpcx.AppchainMgrContractAddr, "Audit", args1...)
	suite.Nil(err)
	suite.True(res.Status == pb.Receipt_SUCCESS)
}

func (suite *Snake) TestRepeatAuditAppchain() {
	args := []*pb.Arg{
		rpcx.String(suite.from.String()),
		rpcx.Int32(0),                 //audit approve
		rpcx.String("Audit rejected"), //desc
	}
	res, err := suite.client.InvokeBVMContract(rpcx.AppchainMgrContractAddr, "Audit", args...)
	suite.Nil(err)
	suite.True(res.Status == pb.Receipt_SUCCESS)

	args1 := []*pb.Arg{
		rpcx.String(suite.from.String()),
		rpcx.Int32(1),               //audit approve
		rpcx.String("Audit passed"), //desc
	}
	res1, err := suite.client.InvokeBVMContract(rpcx.AppchainMgrContractAddr, "Audit", args1...)
	suite.Nil(err)
	suite.True(res1.Status == pb.Receipt_SUCCESS)
}

func (suite *Snake) TestFetchAuditRecord() {
	args := []*pb.Arg{
		rpcx.String(suite.from.String()),
	}
	res, err := suite.client.InvokeBVMContract(rpcx.AppchainMgrContractAddr, "FetchAuditRecords", args...)
	suite.Nil(err)
	suite.True(res.Status == pb.Receipt_SUCCESS)
}

func (suite *Snake) TestGetAppchain() {
	args := []*pb.Arg{}
	res, err := suite.client.InvokeBVMContract(rpcx.AppchainMgrContractAddr, "Appchain", args...)
	suite.Nil(err)
	suite.True(res.Status == pb.Receipt_SUCCESS)
}

func (suite *Snake) TestGetAppchainByID() {
	args := []*pb.Arg{
		rpcx.String(suite.from.String()),
	}
	res, err := suite.client.InvokeBVMContract(rpcx.AppchainMgrContractAddr, "GetAppchain", args...)
	suite.Nil(err)
	suite.True(res.Status == pb.Receipt_SUCCESS)
}
