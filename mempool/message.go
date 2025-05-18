package mempool

import (
	"bft/mvba/core"
	"bft/mvba/crypto"
	"bft/mvba/pool"
	"bytes"
	"encoding/gob"
	"reflect"
	"strconv"
)

type Block struct {
	Proposer  core.NodeID
	Batch     pool.Batch
	Signature crypto.Signature
}

func NewBlock(proposer core.NodeID, Batch pool.Batch, sigService *crypto.SigService) (*Block, error) {
	block := &Block{
		Proposer: proposer,
		Batch:    Batch,
	}
	sig, err := sigService.RequestSignature(block.Hash())
	if err != nil {
		return nil, err
	}
	block.Signature = sig
	return block, nil
}

func (b *Block) Encode() ([]byte, error) {
	buf := bytes.NewBuffer(nil)
	if err := gob.NewEncoder(buf).Encode(b); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (b *Block) Decode(data []byte) error {
	buf := bytes.NewBuffer(data)
	if err := gob.NewDecoder(buf).Decode(b); err != nil {
		return err
	}
	return nil
}

func (b *Block) Hash() crypto.Digest {
	hasher := crypto.NewHasher()
	hasher.Add(strconv.AppendInt(nil, int64(b.Proposer), 2))
	hasher.Add(strconv.AppendInt(nil, int64(b.Batch.ID), 2))
	for _, tx := range b.Batch.Txs {
		hasher.Add(tx)
	}
	return hasher.Sum256(nil)
}

func (msg *Block) Verify(committee core.Committee) bool {
	return msg.Signature.Verify(committee.Name(msg.Proposer), msg.Hash())
}

type OwnBlockMsg struct {
	Block *Block
}

func (own *OwnBlockMsg) MsgType() int {
	return OwnBlockType
}

func (own *OwnBlockMsg) Module() string {
	return "mempool"
}

type OtherBlockMsg struct {
	Block *Block
}

func (o *OtherBlockMsg) MsgType() int {
	return OtherBlockType
}

func (o *OtherBlockMsg) Module() string {
	return "mempool"
}

type RequestBlockMsg struct {
	Type    uint8 //0代表方案处理请求，1代表commit处理请求
	Digests []crypto.Digest
	Author  core.NodeID
}

func (r *RequestBlockMsg) MsgType() int {
	return RequestBlockType
}

func (r *RequestBlockMsg) Module() string {
	return "mempool"
}

type MakeConsensusBlockMsg struct {
	MaxBlockSize uint64 //一个共识区块包含的最大微小区块的数量
	Blocks       chan []crypto.Digest
}

func (r *MakeConsensusBlockMsg) MsgType() int {
	return MakeBlockType
}

func (r *MakeConsensusBlockMsg) Module() string {
	return "connect"
}

type VerifyStatus int

const (
	OK VerifyStatus = iota
	Wait
	Reject
)

type VerifyBlockMsg struct { //这个的作用是验证共识区块是否已经被收到
	//B      *consensus.Block
	Proposer           core.NodeID
	Epoch              int64
	Payloads           []crypto.Digest
	ConsensusBlockHash crypto.Digest
	Sender             chan VerifyStatus // 0:ok 1:wait 2:reject
}

func (*VerifyBlockMsg) MsgType() int {
	return VerifyBlockType
}
func (*VerifyBlockMsg) Module() string {
	return "connect"
}

type CleanBlockMsg struct {
	Digests []crypto.Digest
	Epoch   int64 //清除掉第k轮共识块引用的所有微区块
}

func (l *CleanBlockMsg) MsgType() int {
	return CleanBlockType
}

func (l *CleanBlockMsg) Module() string {
	return "connect"
}

type SyncBlockMsg struct {
	Missing []crypto.Digest //consensus中缺少的块
	Author  core.NodeID     //consensublock的作者
	//Block       *consensus.Block //这个是和大家同步某个区块，但是感觉也不能放到这里
	Epoch              int64
	ConsensusBlockHash crypto.Digest
}

func (s *SyncBlockMsg) MsgType() int {
	return SyncBlockType
}
func (s *SyncBlockMsg) Module() string {
	return "mempool"
}

type SyncCleanUpBlockMsg struct {
	Epoch uint64
}

func (s *SyncCleanUpBlockMsg) MsgType() int {
	return SyncCleanUpBlockType
}

func (s *SyncCleanUpBlockMsg) Module() string {
	return "mempool"
}

type MempoolValidator interface {
	Verify(core.Committee) bool
}

type LoopBackMsg struct {
	BlockHash crypto.Digest
}

func (msg *LoopBackMsg) Hash() crypto.Digest {
	return crypto.NewHasher().Sum256(msg.BlockHash[:])
}

func (msg *LoopBackMsg) MsgType() int {
	return LoopBackType
}

func (msg *LoopBackMsg) Module() string {
	return "consensus"
}

const (
	OwnBlockType int = iota + 12
	OtherBlockType
	RequestBlockType
	MakeBlockType
	VerifyBlockType
	CleanBlockType
	SyncBlockType
	SyncCleanUpBlockType
	LoopBackType
)

var DefaultMessageTypeMap = map[int]reflect.Type{
	OwnBlockType:         reflect.TypeOf(OwnBlockMsg{}),
	OtherBlockType:       reflect.TypeOf(OtherBlockMsg{}),
	RequestBlockType:     reflect.TypeOf(RequestBlockMsg{}),
	MakeBlockType:        reflect.TypeOf(MakeConsensusBlockMsg{}),
	VerifyBlockType:      reflect.TypeOf(VerifyBlockMsg{}),
	CleanBlockType:       reflect.TypeOf(CleanBlockMsg{}),
	SyncBlockType:        reflect.TypeOf(SyncBlockMsg{}),
	SyncCleanUpBlockType: reflect.TypeOf(SyncCleanUpBlockMsg{}),
	LoopBackType:         reflect.TypeOf(LoopBackMsg{}),
}
