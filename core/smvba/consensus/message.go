package consensus

import (
	"bft/mvba/core"
	"bft/mvba/crypto"
	"bft/mvba/pool"
	"bytes"
	"encoding/binary"
	"encoding/gob"
	"reflect"
	"strconv"
)

const MAXCOUNT int64 = 500
const (
	SPB_ONE_PHASE int8 = iota
	SPB_TWO_PHASE
)

const (
	VOTE_FLAG_YES int8 = iota
	VOTE_FLAG_NO
)

const (
	FLAG_YES uint8 = 1
	FLAG_NO  uint8 = 0
)

const (
	Prepare_HightThreshold uint8 = 1
	Prepare_FullThreshold  uint8 = 2
)

type Validator interface {
	Verify(core.Committee) bool
}

type ConsensusBlock struct {
	Proposer core.NodeID
	PayLoads []crypto.Digest
	Epoch    int64
}

func NewConsensusBlock(proposer core.NodeID, payloads []crypto.Digest, Epoch int64) *ConsensusBlock {
	return &ConsensusBlock{
		Proposer: proposer,
		PayLoads: payloads,
		Epoch:    Epoch,
	}
}

func (b *ConsensusBlock) Encode() ([]byte, error) {
	buf := bytes.NewBuffer(nil)
	if err := gob.NewEncoder(buf).Encode(b); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (b *ConsensusBlock) Decode(data []byte) error {
	buf := bytes.NewBuffer(data)
	if err := gob.NewDecoder(buf).Decode(b); err != nil {
		return err
	}
	return nil
}

func (b *ConsensusBlock) Hash() crypto.Digest {
	hasher := crypto.NewHasher()
	hasher.Add(strconv.AppendInt(nil, int64(b.Proposer), 2))
	for _, d := range b.PayLoads {
		hasher.Add(d[:])
	}
	hasher.Add(strconv.AppendInt(nil, b.Epoch, 2))
	return hasher.Sum256(nil)
}

type Block struct {
	Proposer core.NodeID
	Batch    pool.Batch
	Epoch    int64
}

// func NewBlock(proposer core.NodeID, Batch pool.Batch, Epoch int64) *Block {
// 	return &Block{
// 		Proposer: proposer,
// 		Batch:    Batch,
// 		Epoch:    Epoch,
// 	}
// }

// func (b *Block) Encode() ([]byte, error) {
// 	buf := bytes.NewBuffer(nil)
// 	if err := gob.NewEncoder(buf).Encode(b); err != nil {
// 		return nil, err
// 	}
// 	return buf.Bytes(), nil
// }

// func (b *Block) Decode(data []byte) error {
// 	buf := bytes.NewBuffer(data)
// 	if err := gob.NewDecoder(buf).Decode(b); err != nil {
// 		return err
// 	}
// 	return nil
// }

// func (b *Block) Hash() crypto.Digest {
// 	hasher := crypto.NewHasher()
// 	hasher.Add(strconv.AppendInt(nil, int64(b.Proposer), 2))
// 	hasher.Add(strconv.AppendInt(nil, b.Epoch, 2))
// 	hasher.Add(strconv.AppendInt(nil, int64(b.Batch.ID), 2))
// 	return hasher.Sum256(nil)
// }

type SPBProposal struct {
	Author    core.NodeID
	B         *ConsensusBlock
	Epoch     int64
	Phase     int8
	VoteQC    []byte
	Signature crypto.Signature
}

func NewSPBProposal(Author core.NodeID, B *ConsensusBlock, Epoch int64, Phase int8, VoteQC []byte, sigService *crypto.SigService) (*SPBProposal, error) {
	proposal := &SPBProposal{
		Author: Author,
		B:      B,
		Epoch:  Epoch,
		Phase:  Phase,
		VoteQC: VoteQC,
	}
	sig, err := sigService.RequestSignature(proposal.Hash())
	if err != nil {
		return nil, err
	}
	proposal.Signature = sig
	return proposal, nil
}

func (p *SPBProposal) Verify(committee core.Committee) bool {
	pub := committee.Name(p.Author)
	return p.Signature.Verify(pub, p.Hash())
}

func (p *SPBProposal) Hash() crypto.Digest {
	hasher := crypto.NewHasher()
	hasher.Add(strconv.AppendInt(nil, int64(p.Author), 2))
	hasher.Add(strconv.AppendInt(nil, p.Epoch, 2))
	hasher.Add(strconv.AppendInt(nil, int64(p.Phase), 2))
	if p.B != nil {
		d := p.B.Hash()
		hasher.Add(d[:])
	}
	return hasher.Sum256(nil)
}

func (*SPBProposal) MsgType() int {
	return SPBProposalType
}

func (*SPBProposal) Module() string {
	return "consensus"
}

type SPBVote struct {
	Author    core.NodeID
	Proposer  core.NodeID
	BlockHash crypto.Digest
	Epoch     int64
	Phase     int8
	Signature crypto.SignatureShare
}

func NewSPBVote(Author, Proposer core.NodeID, BlockHash crypto.Digest, Epoch int64, Phase int8, sigService *crypto.SigService) (*SPBVote, error) {
	vote := &SPBVote{
		Author:    Author,
		Proposer:  Proposer,
		BlockHash: BlockHash,
		Epoch:     Epoch,
		//Round:     Round,
		Phase: Phase,
	}
	//sig, err := sigService.RequestSignature(vote.Hash())
	sig, err := sigService.RequestTsSugnature(vote.Hash())
	if err != nil {
		return nil, err
	}
	vote.Signature = sig
	return vote, nil
}

func (v *SPBVote) Verify(committee core.Committee) bool {
	// pub := committee.Name(v.Author)
	// return v.Signature.Verify(pub, v.Hash())
	return v.Signature.Verify(v.Hash())
}

func (v *SPBVote) Hash() crypto.Digest {
	hasher := crypto.NewHasher()
	hasher.Add(strconv.AppendInt(nil, int64(v.Proposer), 2))
	hasher.Add(strconv.AppendInt(nil, v.Epoch, 2))
	hasher.Add(strconv.AppendInt(nil, int64(v.Phase), 2))
	hasher.Add(v.BlockHash[:])
	return hasher.Sum256(nil)
}

func (*SPBVote) MsgType() int {
	return SPBVoteType
}

func (*SPBVote) Module() string {
	return "consensus"
}

type Finish struct {
	Author    core.NodeID
	BlockHash crypto.Digest
	Epoch     int64
	Signature crypto.Signature
}

func NewFinish(Author core.NodeID, BlockHash crypto.Digest, Epoch int64, sigService *crypto.SigService) (*Finish, error) {
	finish := &Finish{
		Author:    Author,
		BlockHash: BlockHash,
		Epoch:     Epoch,
		//Round:     Round,
	}
	sig, err := sigService.RequestSignature(finish.Hash())
	if err != nil {
		return nil, err
	}
	finish.Signature = sig
	return finish, nil
}

func (f *Finish) Verify(committee core.Committee) bool {
	pub := committee.Name(f.Author)
	return f.Signature.Verify(pub, f.Hash())
}

func (f *Finish) Hash() crypto.Digest {
	hasher := crypto.NewHasher()
	hasher.Add(f.BlockHash[:])
	hasher.Add(strconv.AppendInt(nil, int64(f.Author), 2))
	hasher.Add(strconv.AppendInt(nil, f.Epoch, 2))
	//hasher.Add(strconv.AppendInt(nil, f.Round, 2))
	return hasher.Sum256(nil)
}

func (*Finish) MsgType() int {
	return FinishType
}

func (*Finish) Module() string {
	return "consensus"
}

type Prepare struct {
	Author    core.NodeID
	Leader    core.NodeID
	Index     int64
	Epoch     int64
	Flag      uint8
	Signature crypto.Signature
}

func NewPrepare(Author, Leader core.NodeID, Index int64, epoch int64, flag uint8, sigService *crypto.SigService) (*Prepare, error) {
	prepare := &Prepare{
		Author: Author,
		Leader: Leader,
		Index:  Index,
		Epoch:  epoch,
		Flag:   flag,
	}
	sig, err := sigService.RequestSignature(prepare.Hash())
	if err != nil {
		return nil, err
	}
	prepare.Signature = sig
	return prepare, err
}

func (p *Prepare) Verify(committee core.Committee) bool {
	pub := committee.Name(p.Author)
	return p.Signature.Verify(pub, p.Hash())
}

func (p *Prepare) Hash() crypto.Digest {
	hasher := crypto.NewHasher()
	hasher.Add(strconv.AppendInt(nil, int64(p.Author), 2))
	hasher.Add(strconv.AppendInt(nil, int64(p.Leader), 2))
	hasher.Add(strconv.AppendInt(nil, p.Index, 2))
	hasher.Add(strconv.AppendInt(nil, p.Epoch, 2))
	hasher.Add(strconv.AppendInt(nil, int64(p.Flag), 2))

	return hasher.Sum256(nil)
}

func (*Prepare) MsgType() int {
	return PrepareType
}

func (*Prepare) Module() string {
	return "consensus"
}

type ElectShare struct {
	Author        core.NodeID
	Epoch         int64
	Noproposalset map[core.NodeID]struct{}
	Lockset       map[core.NodeID]struct{}
	SigShare      crypto.SignatureShare
}

func NewElectShare(Author core.NodeID, epoch int64, no map[core.NodeID]struct{}, lock map[core.NodeID]struct{}, sigService *crypto.SigService) (*ElectShare, error) {
	elect := &ElectShare{
		Author:        Author,
		Epoch:         epoch,
		Noproposalset: no,
		Lockset:       lock,
	}
	sig, err := sigService.RequestTsSugnature(elect.Hash())
	if err != nil {
		return nil, err
	}
	elect.SigShare = sig
	return elect, nil
}

func (e *ElectShare) Verify(committee core.Committee) bool {
	_ = committee.Name(e.Author)
	return e.SigShare.Verify(e.Hash())
}

func (e *ElectShare) Hash() crypto.Digest {
	hasher := crypto.NewHasher()
	hasher.Add(strconv.AppendInt(nil, e.Epoch, 2))
	return hasher.Sum256(nil)
}

func (*ElectShare) MsgType() int {
	return ElectShareType
}

func (*ElectShare) Module() string {
	return "consensus"
}

type HelpSkip struct {
	Author core.NodeID
	Epoch  int64
	Index  int
	Leader core.NodeID
	//NoVoteSet map[int64]map[int64]core.NodeID //2f+1个节点没有投票的证明   n-f set node
	Signature crypto.Signature
}

func NewHelpSkip(Author, Leader core.NodeID, Epoch int64, index int, sigService *crypto.SigService) (*HelpSkip, error) { //novoteset map[int64]map[int64]core.NodeID,
	help := &HelpSkip{
		Author: Author,
		Leader: Leader,
		Epoch:  Epoch,
		Index:  index,
		//NoVoteSet: novoteset,
	}
	sig, err := sigService.RequestSignature(help.Hash())
	if err != nil {
		return nil, err
	}
	help.Signature = sig
	return help, nil
}

func (help *HelpSkip) Verify(committee core.Committee) bool {
	pub := committee.Name(help.Author)
	return help.Signature.Verify(pub, help.Hash())
}

func (help *HelpSkip) Hash() crypto.Digest {
	hasher := crypto.NewHasher()
	hasher.Add(strconv.AppendInt(nil, int64(help.Author), 2))
	hasher.Add(strconv.AppendInt(nil, help.Epoch, 2))
	hasher.Add(strconv.AppendInt(nil, int64(help.Leader), 2))
	hasher.Add(strconv.AppendInt(nil, int64(help.Index), 2))
	//我在思考是用hash值还是用什么值？真的有必要把所有的set传下去吗
	return hasher.Sum256(nil)
}
func (*HelpSkip) MsgType() int {
	return HelpSkipType
}
func (*HelpSkip) Module() string {
	return "consensus"
}

type HelpCommit struct {
	Author    core.NodeID
	Epoch     int64
	Leader    core.NodeID
	B         *ConsensusBlock //2f+1个节点没有投票的证明   n-f set node
	Signature crypto.Signature
}

func NewHelpCommit(Author, Leader core.NodeID, Epoch int64, B *ConsensusBlock, sigService *crypto.SigService) (*HelpCommit, error) {
	help := &HelpCommit{
		Author: Author,
		Leader: Leader,
		Epoch:  Epoch,
		B:      B,
	}
	sig, err := sigService.RequestSignature(help.Hash())
	if err != nil {
		return nil, err
	}
	help.Signature = sig
	return help, nil
}

func (help *HelpCommit) Verify(committee core.Committee) bool {
	pub := committee.Name(help.Author)
	return help.Signature.Verify(pub, help.Hash())
}

func (help *HelpCommit) Hash() crypto.Digest {
	hasher := crypto.NewHasher()
	hasher.Add(strconv.AppendInt(nil, int64(help.Author), 2))
	hasher.Add(strconv.AppendInt(nil, help.Epoch, 2))
	hasher.Add(strconv.AppendInt(nil, int64(help.Leader), 2))
	d := help.B.Hash()
	hasher.Add(d[:])
	return hasher.Sum256(nil)
}
func (*HelpCommit) MsgType() int {
	return HelpCommitType
}

func (*HelpCommit) Module() string {
	return "consensus"
}

type Halt struct {
	Author    core.NodeID
	Epoch     int64
	Leader    core.NodeID
	BlockHash crypto.Digest
	Signature crypto.Signature
}

func NewHalt(Author, Leader core.NodeID, BlockHash crypto.Digest, Epoch int64, sigService *crypto.SigService) (*Halt, error) {
	h := &Halt{
		Author:    Author,
		Epoch:     Epoch,
		Leader:    Leader,
		BlockHash: BlockHash,
	}
	sig, err := sigService.RequestSignature(h.Hash())
	if err != nil {
		return nil, err
	}
	h.Signature = sig
	return h, nil
}

func (h *Halt) Verify(committee core.Committee) bool {
	pub := committee.Name(h.Author)
	return h.Signature.Verify(pub, h.Hash())
}

func (h *Halt) Hash() crypto.Digest {
	hasher := crypto.NewHasher()
	hasher.Add(strconv.AppendInt(nil, int64(h.Author), 2))
	hasher.Add(strconv.AppendInt(nil, h.Epoch, 2))
	hasher.Add(strconv.AppendInt(nil, int64(h.Leader), 2))
	hasher.Add(h.BlockHash[:])
	return hasher.Sum256(nil)
}

func (*Halt) MsgType() int {
	return HaltType
}

func (*Halt) Module() string {
	return "consensus"
}

type ABAVal struct {
	Author    core.NodeID
	Leader    core.NodeID
	Epoch     int64
	Round     int64
	InRound   int64
	Flag      uint8
	Signature crypto.Signature
}

func NewABAVal(Author, Leader core.NodeID, Epoch, Round, InRound int64, Flag uint8, sigService *crypto.SigService) (*ABAVal, error) {
	val := &ABAVal{
		Author:  Author,
		Leader:  Leader,
		Epoch:   Epoch,
		Round:   Round,
		InRound: InRound,
		Flag:    Flag,
	}
	sig, err := sigService.RequestSignature(val.Hash())
	if err != nil {
		return nil, err
	}
	val.Signature = sig
	return val, nil
}

func (v *ABAVal) Verify(committee core.Committee) bool {
	pub := committee.Name(v.Author)
	return v.Signature.Verify(pub, v.Hash())
}

func (v *ABAVal) Hash() crypto.Digest {
	hasher := crypto.NewHasher()
	hasher.Add(binary.BigEndian.AppendUint64(nil, uint64(v.Author)))
	hasher.Add(binary.BigEndian.AppendUint64(nil, uint64(v.Leader)))
	hasher.Add(binary.BigEndian.AppendUint64(nil, uint64(v.Epoch)))
	hasher.Add([]byte{v.Flag})
	return hasher.Sum256(nil)
}

func (v *ABAVal) MsgType() int {
	return ABAValType
}

func (*ABAVal) Module() string {
	return "consensus"
}

type ABAMux struct {
	Author    core.NodeID
	Leader    core.NodeID
	Epoch     int64
	Round     int64
	InRound   int64
	Flag      uint8
	Signature crypto.Signature
}

func NewABAMux(Author, Leader core.NodeID, Epoch, Round, InRound int64, Flag uint8, sigService *crypto.SigService) (*ABAMux, error) {
	val := &ABAMux{
		Author:  Author,
		Leader:  Leader,
		Epoch:   Epoch,
		Round:   Round,
		InRound: InRound,
		Flag:    Flag,
	}
	sig, err := sigService.RequestSignature(val.Hash())
	if err != nil {
		return nil, err
	}
	val.Signature = sig
	return val, nil
}

func (v *ABAMux) Verify(committee core.Committee) bool {
	pub := committee.Name(v.Author)
	return v.Signature.Verify(pub, v.Hash())
}

func (v *ABAMux) Hash() crypto.Digest {
	hasher := crypto.NewHasher()
	hasher.Add(binary.BigEndian.AppendUint64(nil, uint64(v.Author)))
	hasher.Add(binary.BigEndian.AppendUint64(nil, uint64(v.Leader)))
	hasher.Add(binary.BigEndian.AppendUint64(nil, uint64(v.Epoch)))
	hasher.Add([]byte{v.Flag})
	return hasher.Sum256(nil)
}

func (v *ABAMux) MsgType() int {
	return ABAMuxType
}

func (*ABAMux) Module() string {
	return "consensus"
}

type CoinShare struct {
	Author  core.NodeID
	Leader  core.NodeID
	Epoch   int64
	Round   int64
	InRound int64
	Share   crypto.SignatureShare
}

func NewCoinShare(Author, Leader core.NodeID, Epoch, Round, InRound int64, sigService *crypto.SigService) (*CoinShare, error) {
	coin := &CoinShare{
		Author:  Author,
		Leader:  Leader,
		Epoch:   Epoch,
		Round:   Round,
		InRound: InRound,
	}
	sig, err := sigService.RequestTsSugnature(coin.Hash())
	if err != nil {
		return nil, err
	}
	coin.Share = sig
	return coin, nil
}

func (c *CoinShare) Verify(committee core.Committee) bool {
	_ = committee.Name(c.Author)
	return c.Share.Verify(c.Hash())
}

func (c *CoinShare) Hash() crypto.Digest {
	hasher := crypto.NewHasher()
	hasher.Add(binary.BigEndian.AppendUint64(nil, uint64(c.Leader)))
	hasher.Add(binary.BigEndian.AppendUint64(nil, uint64(c.Epoch)))
	hasher.Add(binary.BigEndian.AppendUint64(nil, uint64(c.InRound)))
	return hasher.Sum256(nil)
}

func (c *CoinShare) MsgType() int {
	return CoinShareType
}

func (*CoinShare) Module() string {
	return "consensus"
}

type ABAHalt struct {
	Author    core.NodeID
	Leader    core.NodeID
	Epoch     int64
	Round     int64
	InRound   int64
	Flag      uint8
	Signature crypto.Signature
}

func NewABAHalt(Author, Leader core.NodeID, Epoch, Round, InRound int64, Flag uint8, sigService *crypto.SigService) (*ABAHalt, error) {
	h := &ABAHalt{
		Author:  Author,
		Leader:  Leader,
		Epoch:   Epoch,
		Round:   Round,
		InRound: InRound,
		Flag:    Flag,
	}
	sig, err := sigService.RequestSignature(h.Hash())
	if err != nil {
		return nil, err
	}
	h.Signature = sig
	return h, nil
}

func (h *ABAHalt) Verify(committee core.Committee) bool {
	pub := committee.Name(h.Author)
	return h.Signature.Verify(pub, h.Hash())
}

func (h *ABAHalt) Hash() crypto.Digest {
	hasher := crypto.NewHasher()
	hasher.Add(binary.BigEndian.AppendUint64(nil, uint64(h.Author)))
	hasher.Add(binary.BigEndian.AppendUint64(nil, uint64(h.Leader)))
	hasher.Add(binary.BigEndian.AppendUint64(nil, uint64(h.Epoch)))
	hasher.Add([]byte{h.Flag})
	return hasher.Sum256(nil)
}

func (h *ABAHalt) MsgType() int {
	return ABAHaltType
}

func (*ABAHalt) Module() string {
	return "consensus"
}

const (
	SPBProposalType int = iota
	SPBVoteType
	FinishType
	ElectShareType
	HaltType
	HelpSkipType
	HelpCommitType
	PrepareType
	ABAValType
	ABAMuxType
	CoinShareType
	ABAHaltType
)

var DefaultMessageTypeMap = map[int]reflect.Type{
	SPBProposalType: reflect.TypeOf(SPBProposal{}),
	SPBVoteType:     reflect.TypeOf(SPBVote{}),
	FinishType:      reflect.TypeOf(Finish{}),
	ElectShareType:  reflect.TypeOf(ElectShare{}),
	HaltType:        reflect.TypeOf(Halt{}),
	HelpSkipType:    reflect.TypeOf(HelpSkip{}),
	PrepareType:     reflect.TypeOf(Prepare{}),
	ABAValType:      reflect.TypeOf(ABAVal{}),
	ABAMuxType:      reflect.TypeOf(ABAMux{}),
	CoinShareType:   reflect.TypeOf(CoinShare{}),
	ABAHaltType:     reflect.TypeOf(ABAHalt{}),
	HelpCommitType:  reflect.TypeOf(HelpCommit{}),
}
