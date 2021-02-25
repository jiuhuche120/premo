package bitxhub

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/meshplus/bitxhub-kit/crypto"
	"github.com/meshplus/bitxhub-kit/crypto/asym"
	"github.com/meshplus/bitxhub-kit/types"
	"github.com/meshplus/bitxhub-model/constant"
	"github.com/meshplus/bitxhub-model/pb"
	rpcx "github.com/meshplus/go-bitxhub-client"
	"github.com/wonderivan/logger"
)

var didcounter int64
var counter int64
var sender int64
var delayer int64
var ibtppd []byte
var proofHash [32]byte
var lock sync.Mutex

type bee struct {
	adminPrivKey  crypto.PrivateKey
	adminFrom     *types.Address
	normalPrivKey crypto.PrivateKey
	normalFrom    *types.Address
	client        rpcx.Client
	tps           int
	count         uint64
	adminSeqNo    uint64
	norMalSeqNo   uint64
	ibtpSeqNo     uint64
	ctx           context.Context
	config        *Config
}

func NewBee(tps int, adminPk crypto.PrivateKey, adminFrom *types.Address, expectedNonce uint64, config *Config, ctx context.Context) (*bee, error) {
	normalPk, err := asym.GenerateKeyPair(crypto.Secp256k1)
	if err != nil {
		return nil, err
	}
	normalFrom, err := normalPk.PublicKey().Address()
	if err != nil {
		return nil, err
	}

	node0 := &rpcx.NodeInfo{Addr: config.BitxhubAddr[0]}
	client, err := rpcx.New(
		rpcx.WithNodesInfo(node0),
		rpcx.WithLogger(cfg.logger),
		rpcx.WithPrivateKey(normalPk),
	)
	if err != nil {
		return nil, err
	}

	// query ibtp nonce for init in case ibtp has been sent to bitxhub before
	ibtp := mockIBTP(1, normalFrom.String(), normalFrom.String(), config.Proof)
	ibtpAccount := fmt.Sprintf("%s-%s-%d", normalFrom.String(), normalFrom.String(), ibtp.Category())
	ibtpNonce, err := client.GetPendingNonceByAccount(ibtpAccount)
	if err != nil {
		return nil, err
	}

	return &bee{
		client:        client,
		adminPrivKey:  adminPk,
		adminFrom:     adminFrom,
		normalPrivKey: normalPk,
		normalFrom:    normalFrom,
		tps:           tps,
		ctx:           ctx,
		config:        config,
		adminSeqNo:    expectedNonce,
		ibtpSeqNo:     ibtpNonce,
		norMalSeqNo:   1,
	}, nil
}

func (bee *bee) start(typ string) error {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-bee.ctx.Done():
			return nil
		case <-ticker.C:
			for i := 0; i < bee.tps; i++ {
				bee.count++
				var (
					ibtpNo   uint64
					normalNo uint64
				)
				if typ == "interchain" {
					ibtpNo = atomic.LoadUint64(&bee.ibtpSeqNo)
					atomic.AddUint64(&bee.ibtpSeqNo, 1)
				} else {
					normalNo = atomic.LoadUint64(&bee.norMalSeqNo)
					atomic.AddUint64(&bee.norMalSeqNo, 1)
				}
				go func(count, ibtpNo, normalNo uint64) {
					select {
					case <-bee.ctx.Done():
						return
					default:
						err := bee.sendTx(typ, count, ibtpNo, normalNo)
						if err != nil {
							logger.Error(err)
						}
					}
				}(bee.count, ibtpNo, normalNo)
			}
		}
	}
}

func (bee *bee) sendTx(typ string, count, ibtpNo, normalNo uint64) error {
	switch typ {
	case "interchain":
		if err := bee.sendInterchainTx(count, ibtpNo); err != nil {
			return err
		}
	case "data":
		if err := bee.sendBVMTx(normalNo); err != nil {
			return err
		}
	case "did":
		if err := bee.sendMethodTx("Apply", normalNo); err != nil {
			return err
		}
	case "transfer":
		fallthrough
	default:
		privkey, err := asym.GenerateKeyPair(crypto.Secp256k1)
		if err != nil {
			return err
		}

		to, err := privkey.PublicKey().Address()
		if err != nil {
			return err
		}

		if err := bee.sendTransferTx(to, normalNo); err != nil {
			return err
		}
	}
	return nil
}

func (bee *bee) stop() {
	bee.client.Stop()
	return
}

func (bee *bee) sendBVMTx(normalNo uint64) error {
	atomic.AddInt64(&sender, 1)
	args := make([]*pb.Arg, 0)
	args = append(args, rpcx.String("a"), rpcx.String("10"))

	pl := &pb.InvokePayload{
		Method: "Set",
		Args:   args,
	}

	data, err := pl.Marshal()
	if err != nil {
		return err
	}

	td := &pb.TransactionData{
		Type:    pb.TransactionData_INVOKE,
		VmType:  pb.TransactionData_BVM,
		Payload: data,
	}
	payload, err := td.Marshal()
	if err != nil {
		return err
	}

	tx := &pb.Transaction{
		From:      bee.normalFrom,
		To:        constant.StoreContractAddr.Address(),
		Payload:   payload,
		Timestamp: time.Now().UnixNano(),
		Nonce:     normalNo,
	}

	txHash, err := bee.client.SendTransaction(tx, &rpcx.TransactOpts{
		NormalNonce: normalNo,
	})
	if err != nil {
		return err
	}
	tx.TransactionHash = types.NewHashByStr(txHash)

	go bee.counterReceipt(tx)
	return nil
}

func (bee *bee) prepareChain(chainType, name, validators, version, desc string, contract []byte) error {
	bee.client.SetPrivateKey(bee.normalPrivKey)
	// register chain
	pubKey, _ := bee.normalPrivKey.PublicKey().Bytes()
	receipt, err := bee.invokeContract(bee.normalFrom, constant.AppchainMgrContractAddr.Address(), atomic.LoadUint64(&bee.norMalSeqNo),
		"Register", rpcx.String(validators), rpcx.Int32(1), rpcx.String(chainType),
		rpcx.String(name), rpcx.String(desc), rpcx.String(version), rpcx.String(string(pubKey)))
	if err != nil {
		return fmt.Errorf("register appchain error: %w", err)
	}

	atomic.AddUint64(&bee.norMalSeqNo, 1)

	appchain := &rpcx.Appchain{}
	if err := json.Unmarshal(receipt.Ret, appchain); err != nil {
		return err
	}
	ID := appchain.ID

	// Audit chain and set adminPrivateKey for auditing
	bee.client.SetPrivateKey(bee.adminPrivKey)
	receipt, err = bee.invokeContract(bee.adminFrom, constant.AppchainMgrContractAddr.Address(), bee.adminSeqNo,
		"Audit", rpcx.String(ID), rpcx.Int32(1), rpcx.String("Audit passed"))
	if err != nil {
		return fmt.Errorf("audit appchain error:%w", err)
	}

	ruleAddr := "0x00000000000000000000000000000000000000a1"
	// deploy rule
	bee.client.SetPrivateKey(bee.normalPrivKey)
	if chainType == "hyperchain" {
		contractAddr, err := bee.client.DeployContract(contract, nil)
		if err != nil {
			return fmt.Errorf("deploy contract error:%w", err)
		}
		atomic.AddUint64(&bee.norMalSeqNo, 1)
		ruleAddr = contractAddr.String()
	} else if chainType == "fabric:complex" {
		ruleAddr = "0x00000000000000000000000000000000000000a0"
	}

	_, err = bee.invokeContract(bee.normalFrom, ValidationContractAddr, atomic.LoadUint64(&bee.norMalSeqNo),
		"RegisterRule", rpcx.String(ID), rpcx.String(ruleAddr))
	if err != nil {
		return fmt.Errorf("register rule error:%w", err)
	}
	atomic.AddUint64(&bee.norMalSeqNo, 1)

	prepareInterchainTx(bee.config.Proof)

	return nil
}

func (bee *bee) prepareDID(chainType, validators string) error {
	adminDID := "did:bitxhub:relayroot:" + fmt.Sprint(bee.adminFrom)
	// normalDID := "did:bitxhub:appchain001:" + fmt.Sprint(bee.normalFrom)

	// docAddr := "/ipfs/QmQVxzUqN2Yv2UHUQXYwH8dSNkM8ReJ9qPqwJsf8zzoNUi"
	// docHash := []byte("QmQVxzUqN2Yv2UHUQXYwH8dSNkM8ReJ9qPqwJsf8zzoNUi")

	// normalMethod := "did:bitxhub:appchain001:."
	rootMethod := "did:bitxhub:relayroot:."
	childMethod := "did:bitxhub:relaychain001:."

	// relayrootID := bee.RegisterAppchainWithReturn(bee.adminPrivKey, "relayroot", validators)
	relayrootID := ""
	relayAppID := "0x32a07E5dC7715Fc40A54e58DE0CE5303561517ad"
	_ = relayrootID
	_ = adminDID
	_ = rootMethod
	_ = childMethod
	_ = relayAppID

	// pubBytes, _ := bee.adminPrivKey.PublicKey().Bytes()
	bee.client.SetPrivateKey(bee.adminPrivKey)

	// var pubKeyStr = hex.EncodeToString(pubBytes)
	// args := []*pb.Arg{
	// 	rpcx.String(""),                  //validators
	// 	rpcx.Int32(0),                    //consensus_type
	// 	rpcx.String(chainType),           //chain_type
	// 	rpcx.String("AppChain"),          //name
	// 	rpcx.String("Appchain for test"), //desc
	// 	rpcx.String("1.8"),               //version
	// 	rpcx.String(pubKeyStr),           //public key
	// }
	// receipt, err := bee.client.InvokeBVMContract(constant.AppchainMgrContractAddr.Address(), "Register", nil, args...)
	// // res, err := bee.invokeContract(bee.adminFrom, constant.AppchainMgrContractAddr.Address(), atomic.LoadUint64(&bee.norMalSeqNo),
	// // 	"Register", args...)

	// // receipt, err := bee.invokeContract(bee.adminFrom, constant.AppchainMgrContractAddr.Address(), atomic.LoadUint64(&bee.adminSeqNo),
	// // 	"Register", rpcx.String(validators), rpcx.Int32(1), rpcx.String(chainType),
	// // 	rpcx.String("AppChain"), rpcx.String("desc"), rpcx.String("1.8"), rpcx.String(pubKeyStr))
	// if err != nil {
	// 	logger.Error("register appchain err: ", err)
	// 	return err
	// }
	// // atomic.AddUint64(&bee.adminSeqNo, 1)

	// appChain := &rpcx.Appchain{}
	// err = json.Unmarshal(receipt.Ret, appChain)
	// if err != nil {
	// 	logger.Error("Unmarshal err: ", err)
	// 	return err
	// }
	// // return appChain.ID
	// relayrootID = appChain.ID
	// if relayrootID == "" {
	// 	return fmt.Errorf("nil relayrootID")
	// }

	args := []*pb.Arg{
		rpcx.String(adminDID),
	}
	// res, err := bee.client.InvokeBVMContract(constant.MethodRegistryContractAddr.Address(), "Init", nil, args...)
	bee.client.SetPrivateKey(bee.adminPrivKey)
	res, err := bee.invokeContract(bee.adminFrom, constant.MethodRegistryContractAddr.Address(), atomic.LoadUint64(&bee.adminSeqNo),
		"Init", args...)
	if err != nil {
		logger.Error("Init err: ", err)
		return err
	}
	if res.Ret != nil {
		fmt.Println("Init res.Ret: ", string(res.Ret))
		return fmt.Errorf("Init res err: %s", string(res.Ret))
	}

	// args = []*pb.Arg{
	// 	rpcx.String(adminDID),
	// 	rpcx.String(rootMethod),
	// 	rpcx.String(relayrootID),
	// }
	// // res, err = bee.client.InvokeBVMContract(constant.MethodRegistryContractAddr.Address(), "SetConvertMap", nil, args...)
	// res, err = bee.invokeContract(bee.adminFrom, constant.MethodRegistryContractAddr.Address(), atomic.LoadUint64(&bee.adminSeqNo),
	// 	"SetConvertMap", args...)
	// if err != nil {
	// 	return err
	// }
	// if res.Ret != nil {
	// 	return fmt.Errorf("SetConvertMap with %s", string(res.Ret))
	// }

	// args = []*pb.Arg{
	// 	rpcx.String(adminDID),
	// 	rpcx.String(childMethod),
	// }
	// // res, err = bee.client.InvokeBVMContract(constant.MethodRegistryContractAddr.Address(), "AddChild", nil, args...)
	// res, err = bee.invokeContract(bee.adminFrom, constant.MethodRegistryContractAddr.Address(), atomic.LoadUint64(&bee.adminSeqNo),
	// 	"AddChild", args...)
	// if err != nil {
	// 	return err
	// }
	// if res.Ret != nil {
	// 	return fmt.Errorf("AddChild res.Ret: %s", string(res.Ret))
	// }

	// args = []*pb.Arg{
	// 	rpcx.String(adminDID),
	// 	rpcx.String(childMethod),
	// 	rpcx.String(relayAppID),
	// }
	// // res, err = bee.client.InvokeBVMContract(constant.MethodRegistryContractAddr.Address(), "SetConvertMap", nil, args...)
	// res, err = bee.invokeContract(bee.adminFrom, constant.MethodRegistryContractAddr.Address(), atomic.LoadUint64(&bee.adminSeqNo),
	// 	"SetConvertMap", args...)
	// if err != nil {
	// 	return err
	// }
	// if res.Ret != nil {
	// 	return fmt.Errorf("SetConvertMap res.Ret: %s", string(res.Ret))
	// }
	return nil
}

func (bee *bee) invokeContract(from, to *types.Address, nonce uint64, method string, args ...*pb.Arg) (*pb.Receipt, error) {
	pl := &pb.InvokePayload{
		Method: method,
		Args:   args[:],
	}

	data, err := pl.Marshal()
	if err != nil {
		return nil, err
	}

	td := &pb.TransactionData{
		Type:    pb.TransactionData_INVOKE,
		VmType:  pb.TransactionData_BVM,
		Payload: data,
	}
	payload, err := td.Marshal()

	tx := &pb.Transaction{
		From:      from,
		To:        to,
		Payload:   payload,
		Timestamp: time.Now().UnixNano(),
	}

	return bee.client.SendTransactionWithReceipt(tx,
		&rpcx.TransactOpts{
			From:        from.String(),
			NormalNonce: nonce,
		})
}

func (bee *bee) sendTransferTx(to *types.Address, normalNo uint64) error {
	atomic.AddInt64(&sender, 1)

	data := &pb.TransactionData{
		Type:   pb.TransactionData_NORMAL,
		VmType: pb.TransactionData_XVM,
		Amount: 0,
	}
	payload, err := data.Marshal()
	if err != nil {
		return err
	}
	tx := &pb.Transaction{
		From:      bee.normalFrom,
		To:        to,
		Timestamp: time.Now().UnixNano(),
		Payload:   payload,
	}

	txHash, err := bee.client.SendTransaction(tx, &rpcx.TransactOpts{
		From:        bee.normalFrom.String(),
		NormalNonce: normalNo,
	})
	if err != nil {
		return err
	}
	tx.TransactionHash = types.NewHashByStr(txHash)
	go bee.counterReceipt(tx)

	return nil
}

func (bee *bee) sendInterchainTx(i uint64, ibtpNo uint64) error {
	atomic.AddInt64(&sender, 1)
	ibtp := mockIBTP(i, bee.normalFrom.String(), bee.normalFrom.String(), bee.config.Proof)

	tx := &pb.Transaction{
		From:      bee.normalFrom,
		To:        constant.InterchainContractAddr.Address(),
		Timestamp: time.Now().UnixNano(),
		Extra:     bee.config.Proof,
		IBTP:      ibtp,
	}

	txHash, err := bee.client.SendTransaction(tx, &rpcx.TransactOpts{
		From:      fmt.Sprintf("%s-%s-%d", ibtp.From, ibtp.To, ibtp.Category()),
		IBTPNonce: ibtpNo,
	})
	if err != nil {
		return err
	}
	tx.TransactionHash = types.NewHashByStr(txHash)
	go bee.counterReceipt(tx)

	return nil
}

func (bee *bee) sendMethodTx(operation string, normalNo uint64) error {
	atomic.AddInt64(&sender, 1)

	atomic.AddInt64(&didcounter, 1)

	// normalDID := "did:bitxhub:appchain001:" + fmt.Sprint(bee.normalFrom)

	docAddr := "/ipfs/QmQVxzUqN2Yv2UHUQXYwH8dSNkM8ReJ9qPqwJsf8zzoNUi"
	docHash := []byte("QmQVxzUqN2Yv2UHUQXYwH8dSNkM8ReJ9qPqwJsf8zzoNUi")

	// relayrootID := bee.RegisterAppchainWithReturn(bee.adminPrivKey, "relayroot", validators)
	// relayrootID := ""
	// relayAppID := "0x32a07E5dC7715Fc40A54e58DE0CE5303561517ad"
	normalMethod := "did:bitxhub:appchain" + fmt.Sprint(didcounter) + ":."
	normalDID := "did:bitxhub:appchain" + fmt.Sprint(didcounter) + ":" + fmt.Sprint(bee.normalFrom)
	adminDID := "did:bitxhub:relayroot:" + fmt.Sprint(bee.adminFrom)
	from := bee.adminFrom

	sig := []byte{0}
	args := []*pb.Arg{}

	switch operation {
	case "Apply":
		args = []*pb.Arg{
			rpcx.String(normalDID),
			rpcx.String(normalMethod),
			rpcx.Bytes(sig),
		}
		from = bee.normalFrom
		bee.client.SetPrivateKey(bee.normalPrivKey)
	case "AuditApply":
		args = []*pb.Arg{
			rpcx.String(adminDID), // admin
			rpcx.String(normalMethod),
			rpcx.Int32(1), // rpcx.Bool(true),
			rpcx.Bytes(sig),
		}
		from = bee.adminFrom
		bee.client.SetPrivateKey(bee.adminPrivKey)
	case "Register":
		args = []*pb.Arg{
			rpcx.String(normalDID),
			rpcx.String(normalMethod),
			rpcx.String(docAddr),
			rpcx.Bytes(docHash),
			rpcx.Bytes(sig),
		}
		from = bee.normalFrom
		bee.client.SetPrivateKey(bee.normalPrivKey)
	case "Update":
		args = []*pb.Arg{
			rpcx.String(normalDID),
			rpcx.String(normalMethod),
			rpcx.String(docAddr),
			rpcx.Bytes(docHash),
			rpcx.Bytes(sig),
		}
		from = bee.normalFrom
		bee.client.SetPrivateKey(bee.normalPrivKey)
	case "Resolve":
		args = []*pb.Arg{
			rpcx.String(normalMethod),
		}
		from = bee.normalFrom
		bee.client.SetPrivateKey(bee.normalPrivKey)
	case "Freeze":
		args = []*pb.Arg{
			rpcx.String(adminDID),
			rpcx.String(normalMethod),
			rpcx.Bytes(sig),
		}
		from = bee.adminFrom
		bee.client.SetPrivateKey(bee.adminPrivKey)
	case "UnFreeze":
		args = []*pb.Arg{
			rpcx.String(adminDID),
			rpcx.String(normalMethod),
			rpcx.Bytes(sig),
		}
		from = bee.adminFrom
		bee.client.SetPrivateKey(bee.adminPrivKey)
	case "Delete":
		args = []*pb.Arg{
			rpcx.String(adminDID),
			rpcx.String(normalMethod),
			rpcx.Bytes(sig),
		}
		from = bee.adminFrom
		bee.client.SetPrivateKey(bee.adminPrivKey)

	}

	pl := &pb.InvokePayload{
		Method: operation,
		Args:   args,
	}

	data, err := pl.Marshal()
	if err != nil {
		return err
	}

	td := &pb.TransactionData{
		Type:    pb.TransactionData_INVOKE,
		VmType:  pb.TransactionData_BVM,
		Payload: data,
	}
	payload, err := td.Marshal()
	if err != nil {
		return err
	}

	tx := &pb.Transaction{
		From:      from, // from
		To:        constant.MethodRegistryContractAddr.Address(),
		Payload:   payload,
		Timestamp: time.Now().UnixNano(),
		Nonce:     normalNo,
	}

	txHash, err := bee.client.SendTransaction(tx, // nil)
		&rpcx.TransactOpts{
			NormalNonce: normalNo,
		})
	if err != nil {
		return err
	}
	tx.TransactionHash = types.NewHashByStr(txHash)

	go bee.counterReceipt(tx)
	return nil
}

func prepareInterchainTx(proof []byte) {
	if ibtppd != nil {
		return
	}

	content := &pb.Content{
		SrcContractId: "mychannel&transfer",
		DstContractId: "mychannel&transfer",
		Func:          "interchainCharge",
		Args:          [][]byte{[]byte("Alice"), []byte("Alice"), []byte("1")},
		Callback:      "interchainConfirm",
	}

	bytes, _ := content.Marshal()

	payload := &pb.Payload{
		Encrypted: false,
		Content:   bytes,
	}

	ibtppd, _ = payload.Marshal()
	proofHash = sha256.Sum256(proof)
}

func mockIBTP(index uint64, from, to string, proof []byte) *pb.IBTP {
	return &pb.IBTP{
		From:      from,
		To:        to,
		Payload:   ibtppd,
		Index:     index,
		Type:      pb.IBTP_INTERCHAIN,
		Timestamp: time.Now().UnixNano(),
		Proof:     proofHash[:],
	}
}

func (bee *bee) counterReceipt(tx *pb.Transaction) {
	for {
		receipt, err := bee.client.GetReceipt(tx.Hash().String())
		if err != nil {
			if strings.Contains(err.Error(), "not found in DB") {
				continue
			}
			logger.Error(err)
			return
		}
		_ = receipt
		if !receipt.IsSuccess() {
			logger.Error("receipt for tx %s is failed, error msg: %s", tx.TransactionHash.String(), string(receipt.Ret))
			return
		}
		break
	}
	atomic.AddInt64(&delayer, time.Now().UnixNano()-tx.Timestamp)
	atomic.AddInt64(&counter, 1)
}

func (bee *bee) constructTX(from, to *types.Address, method string, args ...*pb.Arg) (*pb.Transaction, error) {
	pl := &pb.InvokePayload{
		Method: method,
		Args:   args[:],
	}

	data, err := pl.Marshal()
	if err != nil {
		return nil, err
	}

	td := &pb.TransactionData{
		Type:    pb.TransactionData_INVOKE,
		VmType:  pb.TransactionData_BVM,
		Payload: data,
	}
	payload, err := td.Marshal()

	tx := &pb.Transaction{
		From:      from,
		To:        to,
		Payload:   payload,
		Timestamp: time.Now().UnixNano(),
	}

	return tx, nil
}

func (bee *bee) sendMethodTxOld(operation string, normalNo uint64) error {
	atomic.AddInt64(&sender, 1)
	normalDID := "did:bitxhub:appchain001:" + fmt.Sprint(bee.normalFrom)
	normalMethod := "did:bitxhub:appchain001:."
	tx := &pb.Transaction{}
	switch operation {
	case "register":
		args := []*pb.Arg{
			rpcx.String(normalDID),
			rpcx.String(normalMethod),
			rpcx.Bytes([]byte{0}),
		}
		tx, err := bee.constructTX(bee.normalFrom, constant.MethodRegistryContractAddr.Address(), "Apply", args...)
		if err != nil {
			return err
		}
		bee.client.SetPrivateKey(bee.normalPrivKey)
		txHash, err := bee.client.SendTransaction(tx, &rpcx.TransactOpts{
			// From:        bee.normalFrom.String(),
			NormalNonce: normalNo,
		})
		if err != nil {
			return err
		}
		tx.TransactionHash = types.NewHashByStr(txHash)
	}
	go bee.counterReceipt(tx)
	return nil
}
