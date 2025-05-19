package consensus

import (
	"bft/mvba/core"
	"bft/mvba/crypto"
	"bft/mvba/logger"
	"bft/mvba/mempool"
	"bft/mvba/pool"
	"bft/mvba/store"
	"sync"
)

type Core struct {
	Name            core.NodeID
	Committee       core.Committee
	Parameters      core.Parameters
	SigService      *crypto.SigService
	Store           *store.Store
	TxPool          *pool.Pool
	Transimtor      *core.Transmitor
	Aggreator       *Aggreator
	Elector         *Elector
	Commitor        *Committor
	MemPool         *mempool.Mempool
	loopBackChannel chan crypto.Digest //从mempool部分获取到区块

	FinishFlags   map[int64]map[core.NodeID]crypto.Digest // finish? map[epoch][node] = blockHash 完成了spb的两阶段的证明
	SPbInstances  map[int64]map[core.NodeID]*SPB          // map[epoch][node]
	abaInstances  map[int64]map[int64]*ABA                //map[epoch]map[index] index可以计算出leader
	LockSetMap    map[int64]map[core.NodeID]bool          //epoch -node lock 是否已经收到了lock
	LockFlag      map[int64]map[core.NodeID]struct{}      //SPB里面的第一轮投票需要停掉
	Lockmu        sync.RWMutex
	FinishFlag    map[int64]map[core.NodeID]struct{} //SPB里面的第二轮投票需要停掉
	Finishmu      sync.RWMutex
	SkipFlag      map[int64]map[core.NodeID]struct{} //这个leader已经被跳过了，如果需要抉择下一个leader必须等前面所有的leader都完成
	Skipmu        sync.RWMutex
	abaInvokeFlag map[int64]map[int64]map[int64]map[uint8]struct{} //aba invoke flag
	Epoch         int64
	//LeaderIndex      map[int64]int           //epoch index epoch+index可以用来选leader
	ParallelABAResult map[int64]map[int]uint8 //epoch - index -ABA结果
	ParallelABAIndex  int                     //最后一个并行序列
	abaCallBack       chan *ABABack
}

func NewCore(
	Name core.NodeID,
	Committee core.Committee,
	Parameters core.Parameters,
	SigService *crypto.SigService,
	Store *store.Store,
	TxPool *pool.Pool,
	Transimtor *core.Transmitor,
	callBack chan<- struct{},
) *Core {
	loopBackchannel := make(chan crypto.Digest)
	Sync := mempool.NewSynchronizer(Name, Transimtor, loopBackchannel, Store)
	pool := mempool.NewMempool(Name, Committee, Parameters, SigService, Store, TxPool, Transimtor, Sync)
	c := &Core{
		Name:       Name,
		Committee:  Committee,
		Parameters: Parameters,
		SigService: SigService,
		Store:      Store,
		TxPool:     TxPool,
		Transimtor: Transimtor,
		Epoch:      0,
		//LeaderIndex:       make(map[int64]int),
		Aggreator:         NewAggreator(Committee, SigService),
		Elector:           NewElector(SigService, Committee),
		Commitor:          NewCommittor(callBack, pool),
		MemPool:           pool,
		loopBackChannel:   loopBackchannel,
		FinishFlags:       make(map[int64]map[core.NodeID]crypto.Digest),
		SPbInstances:      make(map[int64]map[core.NodeID]*SPB),
		abaInstances:      make(map[int64]map[int64]*ABA), //针对index序列的ABA
		LockFlag:          make(map[int64]map[core.NodeID]struct{}),
		FinishFlag:        make(map[int64]map[core.NodeID]struct{}),
		SkipFlag:          make(map[int64]map[core.NodeID]struct{}),
		LockSetMap:        make(map[int64]map[core.NodeID]bool),
		abaInvokeFlag:     make(map[int64]map[int64]map[int64]map[uint8]struct{}),
		ParallelABAResult: make(map[int64]map[int]uint8),
		ParallelABAIndex:  0,
		abaCallBack:       make(chan *ABABack, 1000),
	}

	return c
}

func (c *Core) initParallelABAResult(epoch int64) {
	if _, ok := c.ParallelABAResult[epoch]; !ok {
		c.ParallelABAResult[epoch] = make(map[int]uint8)
	}
	for i := 0; i < c.Committee.Size(); i++ {
		c.ParallelABAResult[epoch][i] = uint8(2)
	}
}

func (c *Core) messageFilter(epoch int64) bool {
	return epoch < c.Epoch
}

func (c *Core) storeConsensusBlock(block *ConsensusBlock) error {
	key := block.Hash()
	value, err := block.Encode()
	if err != nil {
		return err
	}
	return c.Store.Write(key[:], value)
}

func (c *Core) getConsensusBlock(digest crypto.Digest) (*ConsensusBlock, error) {
	value, err := c.Store.Read(digest[:])

	if err == store.ErrNotFoundKey {
		return nil, nil
	}

	if err != nil {
		return nil, err
	}

	b := &ConsensusBlock{}
	if err := b.Decode(value); err != nil {
		return nil, err
	}
	return b, err
}

func (c *Core) getSpbInstance(epoch int64, node core.NodeID) *SPB {
	rItems, ok := c.SPbInstances[epoch]
	if !ok {
		rItems = make(map[core.NodeID]*SPB)
		c.SPbInstances[epoch] = rItems
	}
	instance, ok := rItems[node]
	if !ok {
		instance = NewSPB(c, epoch, node)
		rItems[node] = instance
	}
	return instance
}

func (c *Core) getABAInstance(epoch, index int64) *ABA {
	items, ok := c.abaInstances[epoch]
	if !ok {
		items = make(map[int64]*ABA)
		c.abaInstances[epoch] = items
	}
	instance, ok := items[index]
	if !ok {
		instance = NewABA(c, epoch, index, c.abaCallBack)
		items[index] = instance
	}
	return instance
}

func (c *Core) VisitLockFlag(epoch int64, node core.NodeID) bool {
	c.Lockmu.RLock()
	if _, oks := c.LockFlag[epoch]; oks {
		if _, ok := c.LockFlag[epoch][node]; ok {
			c.Lockmu.RUnlock()
			return true
		}
	}
	c.Lockmu.RUnlock()
	return false
}

func (c *Core) VisitFinishFlag(epoch int64, node core.NodeID) bool {
	c.Finishmu.RLock()
	if _, oks := c.FinishFlag[epoch]; oks {
		if _, ok := c.FinishFlag[epoch][node]; ok {
			c.Finishmu.RUnlock()
			return true
		}
	}
	c.Finishmu.RUnlock()
	return false

}

func (c *Core) VisitSkipFlag(epoch int64, node core.NodeID) bool {
	c.Skipmu.RLock()
	if _, oks := c.SkipFlag[epoch]; oks {
		if _, ok := c.SkipFlag[epoch][node]; ok {
			c.Skipmu.RUnlock()
			return true
		}
	}
	c.Skipmu.RUnlock()
	return false

}

// 是否已经完成finish
func (c *Core) hasFinish(epoch int64, node core.NodeID) (bool, crypto.Digest) {
	if items, ok := c.FinishFlags[epoch]; !ok {
		return false, crypto.Digest{}
	} else {
		d, ok := items[node]
		return ok, d
	}
}

// 获取并行ABA的最后一个ABA即按照优先级序列处理里面第一个完成finish的节点的前一个序列节点
func (c *Core) getABAStopInstance(epoch int64) (int, core.NodeID) {
	for i := 0; i < c.Committee.Size(); i++ {
		leader := c.Elector.GetLeader(epoch, i)
		if check, _ := c.hasFinish(epoch, leader); check {
			if i == 0 {
				return -1, leader
			} else {
				leader = c.Elector.GetLeader(epoch, i-1)
				return i - 1, leader
			}
		}
	}
	return -1, core.NONE
}

func (c *Core) generatorBlock(epoch int64) *ConsensusBlock {
	referencechan := make(chan []crypto.Digest)
	msg := &mempool.MakeConsensusBlockMsg{
		MaxBlockSize: uint64(MAXCOUNT), Blocks: referencechan,
	}
	c.Transimtor.ConnectRecvChannel() <- msg
	payloads := <-referencechan
	consensusblock := NewConsensusBlock(c.Name, payloads, epoch)
	logger.Info.Printf("create ConsensusBlock epoch %d node %d\n", consensusblock.Epoch, consensusblock.Proposer)
	return consensusblock
}

// 检查当前区块的所有payload是否都已经收到
func (c *Core) verifyConsensusBlock(block *ConsensusBlock) bool {
	verifychan := make(chan mempool.VerifyStatus)
	msg := &mempool.VerifyBlockMsg{
		Proposer:           block.Proposer, //提块的人
		Epoch:              block.Epoch,
		Payloads:           block.PayLoads,
		ConsensusBlockHash: block.Hash(),
		Sender:             verifychan,
	}
	c.Transimtor.ConnectRecvChannel() <- msg
	//获取当前区块的状态
	verifystatus := <-verifychan
	if verifystatus == mempool.OK {
		return true
	} else {
		return false
	}
}

/*********************************** Protocol Start***************************************/
func (c *Core) handleSpbProposal(p *SPBProposal) error {
	logger.Debug.Printf("Processing SPBProposal proposer %d epoch %d phase %d\n", p.Author, p.Epoch, p.Phase)
	if c.messageFilter(p.Epoch) {
		return nil
	}
	//Store Block at first time
	if p.Phase == SPB_ONE_PHASE {
		if err := c.storeConsensusBlock(p.B); err != nil {
			logger.Error.Printf("Store Block error: %v\n", err)
			return err
		}
		//如果是第一次收到区块先检查payloads,会有小部分人没有收到相关区块
		if ok := c.verifyConsensusBlock(p.B); !ok {
			logger.Debug.Printf("checkreferrence error and try to retriver Author %d Epoch %d lenof Reference %d\n", p.Author, p.Epoch, len(p.B.PayLoads))
			//向mempool要所有的微区块
			message := &mempool.RequestBlockMsg{
				Type:    0,
				Digests: p.B.PayLoads,
				Author:  c.Name,
			}
			c.Transimtor.ConnectRecvChannel() <- message
			return nil
		}
	}

	if p.Phase == SPB_ONE_PHASE {
		if c.VisitLockFlag(p.Epoch, p.Author) { //暂停第一轮的投票聚合
			logger.Debug.Printf("already send message as lock ,can not continue to vote for finish epoch %d author %d\n", p.Epoch, p.Author)
			return nil
		}
	}
	if p.Phase == SPB_TWO_PHASE {
		if c.VisitFinishFlag(p.Epoch, p.Author) { //暂停第二轮的投票聚合
			logger.Debug.Printf("already send message as Finish ,can not continue to vote for finish epoch %d author %d\n", p.Epoch, p.Author)
			return nil
		}
	}

	spb := c.getSpbInstance(p.Epoch, p.Author)
	go spb.processProposal(p)

	return nil
}

func (c *Core) handleSpbVote(v *SPBVote) error {

	//discard message
	if c.messageFilter(v.Epoch) {
		return nil
	}
	logger.Debug.Printf("Processing SPBVote author %d proposer %d epoch %d phase %d\n", v.Author, v.Proposer, v.Epoch, v.Phase)
	spb := c.getSpbInstance(v.Epoch, v.Proposer)
	go spb.processVote(v)

	return nil
}

func (c *Core) handleFinish(f *Finish) error {

	//discard message
	if c.messageFilter(f.Epoch) {
		return nil
	}
	logger.Debug.Printf("Processing Finish epoch %d Author %d \n", f.Epoch, f.Author)

	if flag, err := c.Aggreator.AddFinishVote(f); err != nil {
		return err
	} else {
		rF, ok := c.FinishFlags[f.Epoch]
		if !ok {
			rF = make(map[core.NodeID]crypto.Digest)
			c.FinishFlags[f.Epoch] = rF
		}
		rF[f.Author] = f.BlockHash
		if flag { //2f+1 finish?
			return c.invokeReadyandShare(f.Epoch)
		}
	}
	return nil
}

func (c *Core) generateNoProposalSet(epoch int64) map[core.NodeID]struct{} {
	ID := make(map[core.NodeID]struct{})

	for i := 0; i < c.Committee.Size(); i++ {
		item := c.getSpbInstance(epoch, core.NodeID(i))
		if item.BlockHash.Load() == nil {
			ID[core.NodeID(i)] = struct{}{}
			c.Lockmu.Lock()
			_, ok := c.LockFlag[epoch]
			if !ok {
				c.LockFlag[epoch] = make(map[core.NodeID]struct{})
			}
			c.LockFlag[epoch][core.NodeID(i)] = struct{}{} //更新不能投票了
			c.Lockmu.Unlock()
		}
	}

	return ID
}

func (c *Core) generateLockSet(epoch int64) map[core.NodeID]struct{} {
	ID := make(map[core.NodeID]struct{})

	for i := 0; i < c.Committee.Size(); i++ {
		item := c.getSpbInstance(epoch, core.NodeID(i))
		if item.IsLock() {
			ID[core.NodeID(i)] = struct{}{}
			c.Finishmu.Lock()
			_, ok := c.FinishFlag[epoch]
			if !ok {
				c.FinishFlag[epoch] = make(map[core.NodeID]struct{})
			}
			c.FinishFlag[epoch][core.NodeID(i)] = struct{}{} //更新不能投票了
			c.Finishmu.Unlock()
		}
	}

	return ID
}

func (c *Core) invokeReadyandShare(epoch int64) error {
	logger.Debug.Printf("Processing invoke Ready and Share epoch %d\n", epoch)
	ID := c.generateNoProposalSet(epoch)
	LockID := c.generateLockSet(epoch)
	//广播electshare消息
	share, _ := NewElectShare(c.Name, epoch, ID, LockID, c.SigService)
	c.Transimtor.Send(c.Name, core.NONE, share)
	c.Transimtor.RecvChannel() <- share
	return nil
}

func (c *Core) handleElectShare(share *ElectShare) error {
	//discard message
	if c.messageFilter(share.Epoch) {
		return nil
	}
	logger.Debug.Printf("Processing ElectShare author %d epoch %d\n", share.Author, share.Epoch)
	if leader, valid, err := c.Elector.AddShareVote(share); err != nil {
		return err
	} else if valid { //处理locksetMap
		if _, ok := c.LockSetMap[share.Epoch]; !ok {
			c.LockSetMap[share.Epoch] = make(map[core.NodeID]bool)
		}
		for i := range share.Lockset {
			if ok := c.LockSetMap[share.Epoch][i]; !ok {
				c.LockSetMap[share.Epoch][i] = true
			}
		}
		if leader[0] != core.NodeID(-1) { //收集到了2f+1个elect消息
			logger.Debug.Printf("leader[0] is what?%d\n", leader[0])
			c.processLeader(share.Epoch)
		}
	}
	return nil
}

func (c *Core) processLeader(epoch int64) error {
	if epoch < c.Epoch {
		logger.Debug.Printf("Processing Leader error for epoch is less than c.Epoch\n")
		return nil
	}
	//并行ABA预备工作
	index, leaderid := c.getABAStopInstance(epoch)
	//处理可以直接commit的部分
	if index == -1 && leaderid != core.NONE {
		if check, value := c.hasFinish(epoch, leaderid); check {
			logger.Debug.Printf("Processing Leader for epoch %d and leader %d has finish and can commit\n", epoch, leaderid)
			if b, err := c.getConsensusBlock(value); err != nil {
				return err
			} else if b != nil {
				c.Commitor.Commit(b) //如果这个值获得了finish那么直接commit并且帮助别人commit  要不要加一个commitflag呢？
				logger.Debug.Printf("help commit message leader %d epoch %d \n", leaderid, epoch)
				help, _ := NewHelpCommit(c.Name, leaderid, epoch, b, c.SigService)
				c.Transimtor.Send(c.Name, core.NONE, help)
				c.Transimtor.RecvChannel() <- help //不用发给自己
				//进入下一个epoch
				c.advanceNextEpoch(epoch + 1)
			} else {
				logger.Debug.Printf("Processing retriever epoch %d \n", epoch) //这个部分真的实现了吗
			}
		}
		return nil
	}

	logger.Debug.Printf("ParallelABA Processing Leader for epoch %d and index id  %d \n", epoch, index)
	//处理并行ABA的部分
	c.ParallelABAIndex = index
	for i := 0; i <= c.ParallelABAIndex; i++ {
		abaleader := c.Elector.GetLeader(epoch, i)
		if c.Elector.judgeSkip(epoch, abaleader) {
			//发送helpskip的消息，并且置这个位置的ABA的结果为0
			_, ok := c.SkipFlag[epoch]
			if !ok {
				c.SkipFlag[epoch] = make(map[core.NodeID]struct{})
			}
			c.SkipFlag[epoch][abaleader] = struct{}{}

			c.ParallelABAResult[epoch][i] = uint8(0)
			//帮助所有人skip
			skip, _ := NewHelpSkip(c.Name, abaleader, epoch, int(i), c.SigService)
			c.Transimtor.Send(c.Name, core.NONE, skip)
			c.Transimtor.RecvChannel() <- skip
		} else {
			if c.LockSetMap[epoch][abaleader] {
				//以1调用prepareABA
				prepare, _ := NewPrepare(c.Name, abaleader, int64(i), epoch, uint8(1), c.SigService)
				c.Transimtor.Send(c.Name, core.NONE, prepare)
				c.Transimtor.RecvChannel() <- prepare

			} else {
				//以0调用prepareABA
				prepare, _ := NewPrepare(c.Name, abaleader, int64(i), epoch, uint8(0), c.SigService)
				c.Transimtor.Send(c.Name, core.NONE, prepare)
				c.Transimtor.RecvChannel() <- prepare
			}
		}
	}
	logger.Debug.Printf("Processing Leader epoch %d index %d Leader %d\n", epoch, index, c.Elector.GetLeader(epoch, index))
	return nil
}

func (c *Core) handlePrepare(p *Prepare) error {
	logger.Debug.Printf("handle prepare message epoch %d leader%d author %d value %d\n", p.Epoch, p.Leader, p.Author, p.Flag)
	flag, value, err := c.Aggreator.AddPrepare(p)
	if flag == Prepare_FullThreshold {
		//直接结束ABA，发送ABAHalt
		c.ParallelABAResult[p.Epoch][int(p.Index)] = uint8(p.Flag)

		temp, _ := NewABAHalt(c.Name, p.Leader, p.Epoch, p.Index, 0, p.Flag, c.SigService)
		c.Transimtor.Send(c.Name, core.NONE, temp)
		c.Transimtor.RecvChannel() <- temp

	} else if flag == Prepare_HightThreshold {
		//以value调用ABA
		//logger.Debug.Printf("the start time is %d %d 1 the time first create the aba val is:\n", c.Name, epoch, time.Now())
		abaVal, _ := NewABAVal(c.Name, p.Leader, p.Epoch, p.Index, 0, value, c.SigService)
		c.Transimtor.Send(c.Name, core.NONE, abaVal)
		c.Transimtor.RecvChannel() <- abaVal
	}
	return err
}

func (c *Core) handleOutput(epoch int64, blockHash crypto.Digest) error {
	logger.Debug.Printf("Processing Ouput epoch %d \n", epoch)
	if c.messageFilter(epoch) {
		return nil
	}
	if b, err := c.getConsensusBlock(blockHash); err != nil {
		return err
	} else if b != nil {
		c.Commitor.Commit(b)
	} else {
		logger.Debug.Printf("Processing retriever epoch %d \n", epoch)
	}
	c.advanceNextEpoch(epoch + 1)
	return nil
}

func (c *Core) handleABAVal(val *ABAVal) error {
	if c.messageFilter(val.Epoch) {
		return nil
	}
	logger.Debug.Printf("Processing aba val leader %d epoch %d round %d in-round %d val %d\n", val.Leader, val.Epoch, val.Round, val.InRound, val.Flag)

	//判断是否已经skip  收到ABA的时候
	if _, oks := c.SkipFlag[val.Epoch]; oks {
		if _, ok := c.SkipFlag[val.Epoch][val.Leader]; ok { //可以skip掉
			logger.Debug.Printf("help skip message leader %d epoch %d index %d\n", val.Leader, val.Epoch, int(val.Round))
			skip, _ := NewHelpSkip(c.Name, val.Leader, val.Epoch, int(val.Round), c.SigService)
			c.Transimtor.Send(c.Name, val.Author, skip)
			c.Transimtor.RecvChannel() <- skip
			return nil
		}
	}

	go c.getABAInstance(val.Epoch, val.Round).ProcessABAVal(val)

	return nil
}

func (c *Core) handleABAMux(mux *ABAMux) error {
	if c.messageFilter(mux.Epoch) {
		return nil
	}
	logger.Debug.Printf("Processing aba mux leader %d epoch %d round %d in-round %d val %d\n", mux.Leader, mux.Epoch, mux.Round, mux.InRound, mux.Flag)

	if _, oks := c.SkipFlag[mux.Epoch]; oks {
		if _, ok := c.SkipFlag[mux.Epoch][mux.Leader]; ok { //可以skip掉
			skip, _ := NewHelpSkip(c.Name, mux.Leader, mux.Epoch, int(mux.Round), c.SigService)
			c.Transimtor.Send(c.Name, mux.Author, skip)
			c.Transimtor.RecvChannel() <- skip
			return nil
		}
	}

	go c.getABAInstance(mux.Epoch, mux.Round).ProcessABAMux(mux)

	return nil
}

func (c *Core) handleCoinShare(share *CoinShare) error {
	if c.messageFilter(share.Epoch) {
		return nil
	}
	logger.Debug.Printf("Processing coin share epoch %d round %d in-round %d", share.Epoch, share.Round, share.InRound)

	if ok, coin, err := c.Aggreator.addCoinShare(share); err != nil {
		return err
	} else if ok {
		logger.Debug.Printf("ABA epoch %d ex-round %d in-round %d coin %d\n", share.Epoch, share.Round, share.InRound, coin)
		go c.getABAInstance(share.Epoch, share.Round).ProcessCoin(share.InRound, coin, share.Leader)
	}

	return nil
}

func (c *Core) handleABAHalt(halt *ABAHalt) error {
	if c.messageFilter(halt.Epoch) {
		return nil
	}
	logger.Debug.Printf("Processing aba halt leader %d epoch %d in-round %d value %d\n", halt.Leader, halt.Epoch, halt.InRound, halt.Flag)
	go c.getABAInstance(halt.Epoch, halt.Round).ProcessHalt(halt)
	return nil
}
func (c *Core) isInvokeABA(epoch, round, inRound int64, tag uint8) bool {
	flags, ok := c.abaInvokeFlag[epoch]
	if !ok {
		return false
	}
	flag, ok := flags[round]
	if !ok {
		return false
	}
	item, ok := flag[inRound]
	if !ok {
		return false
	}
	_, ok = item[tag]
	return ok
}

func (c *Core) invokeABAVal(leader core.NodeID, epoch, round, inRound int64, flag uint8) error {
	logger.Debug.Printf("Invoke ABA epoch %d ex_round %d in_round %d val %d\n", epoch, round, inRound, flag)
	if c.isInvokeABA(epoch, round, inRound, flag) {
		return nil
	}
	flags, ok := c.abaInvokeFlag[epoch]
	if !ok {
		flags = make(map[int64]map[int64]map[uint8]struct{})
		c.abaInvokeFlag[epoch] = flags
	}
	items, ok := flags[round]
	if !ok {
		items = make(map[int64]map[uint8]struct{})
		flags[round] = items
	}
	item, ok := items[inRound]
	if !ok {
		item = make(map[uint8]struct{})
		items[inRound] = item
	}
	item[flag] = struct{}{}
	abaVal, _ := NewABAVal(c.Name, leader, epoch, round, inRound, flag, c.SigService)
	c.Transimtor.Send(c.Name, core.NONE, abaVal)
	c.Transimtor.RecvChannel() <- abaVal

	return nil
}

// 判断是否可以提交当前块 前面所有的ABA的输出是0，这个块是最新的ABA输出值1的块
func (c *Core) judgeCommit(epoch int64, index int) bool {
	for i := 0; i < index; i++ {
		if c.ParallelABAResult[epoch][i] != uint8(0) {
			return false
		}
	}
	return true
}

func (c *Core) processABABack(back *ABABack) error {
	if back.ExRound > int64(c.ParallelABAIndex) {
		logger.Debug.Printf("the aba halt index is lager than the core.Parallel index\n")
		return nil
	}
	if back.Typ == ABA_INVOKE {
		return c.invokeABAVal(back.Leader, back.Epoch, back.ExRound, back.InRound, back.Flag)
	} else if back.Typ == ABA_HALT {
		if back.Flag == FLAG_NO { //next leader 选择下一个leader去判断
			c.ParallelABAResult[back.Epoch][int(back.ExRound)] = uint8(0)
			if c.judgeCommit(back.Epoch, c.ParallelABAIndex+1) {
				leader := c.Elector.GetLeader(back.Epoch, c.ParallelABAIndex+1)
				instance := c.getSpbInstance(back.Epoch, leader)
				var blockhash crypto.Digest = instance.GetBlockHash().(crypto.Digest)
				return c.handleOutput(back.Epoch, blockhash)
			}
			//return c.invokeNextLeader(back.Epoch, back.ExRound)
		} else if back.Flag == FLAG_YES { //如果可以提交直接提交，//nextepoch
			c.ParallelABAResult[back.Epoch][int(back.ExRound)] = uint8(1)
			if c.judgeCommit(back.Epoch, int(back.ExRound)) {
				instance := c.getSpbInstance(back.Epoch, back.Leader)
				var blockhash crypto.Digest = instance.GetBlockHash().(crypto.Digest)
				return c.handleOutput(back.Epoch, blockhash)
			}
		}
	}
	return nil
}

func (c *Core) handleHelpSkip(skip *HelpSkip) error {
	if c.messageFilter(skip.Epoch) {
		return nil
	}
	if skip.Index > c.ParallelABAIndex { //如果收到的helpskip的index值大于本地，向发送helpskip的人发送abahalt但是其实好像不会出现这种情况skip和finish不会同时出现
		return nil
	}
	logger.Debug.Printf("handleHelpSkip from %d epoch %d round %d\n", skip.Author, skip.Epoch, skip.Index)

	c.ParallelABAResult[skip.Epoch][skip.Index] = uint8(0)
	//检查前面所有的值
	if c.judgeCommit(skip.Epoch, c.ParallelABAIndex+1) {
		leader := c.Elector.GetLeader(skip.Epoch, c.ParallelABAIndex+1)
		instance := c.getSpbInstance(skip.Epoch, leader)
		//ERROR 可能获取不到对应的区块，这里会有问题，需要修改，如果没有获取到会怎么办?至少需要找人去拿到这个块或者这个块的哈希
		var blockhash crypto.Digest = instance.GetBlockHash().(crypto.Digest) //这个地方可能逻辑处理有问题，遇到一些情况，这个blockhash可能获取不到
		return c.handleOutput(skip.Epoch, blockhash)
	}
	return nil
}

func (c *Core) handleHelpCommit(help *HelpCommit) error {
	if c.messageFilter(help.Epoch) { //如果已经进入下一轮了
		return nil
	}
	logger.Debug.Printf("handle help commit message epoch %d\n", help.Epoch)
	c.Commitor.Commit(help.B)
	c.advanceNextEpoch(help.Epoch + 1)
	return nil
}

func (c *Core) handleLoopBack(blockhash crypto.Digest) error {
	if block, err := c.getConsensusBlock(blockhash); err != nil {
		logger.Error.Printf("loopback error\n")
		return err
	} else {
		logger.Debug.Printf("procesing block loop back round %d node %d \n", block.Epoch, block.Proposer)
		proposal, _ := NewSPBProposal(block.Proposer, block, block.Epoch, SPB_ONE_PHASE, nil, c.SigService)
		go c.getSpbInstance(proposal.Epoch, proposal.Author).processProposal(proposal)
	}
	return nil
}

/*********************************** Protocol End***************************************/
func (c *Core) advanceNextEpoch(epoch int64) {
	if epoch <= c.Epoch {
		return
	}
	c.initParallelABAResult(epoch)
	logger.Debug.Printf("advance next epoch %d\n", epoch)
	logger.Info.Printf("advance next epoch %d\n", epoch)
	//Clear Something
	c.Epoch = epoch
	block := c.generatorBlock(epoch)
	proposal, _ := NewSPBProposal(c.Name, block, epoch, SPB_ONE_PHASE, nil, c.SigService)
	c.Transimtor.Send(c.Name, core.NONE, proposal)
	c.Transimtor.RecvChannel() <- proposal
}

func (c *Core) Run() {
	if c.Name < core.NodeID(c.Parameters.Faults) {
		logger.Debug.Printf("Node %d is faulty\n", c.Name)
		return
	}
	//启动mempool
	go c.MemPool.Run()
	//first proposal
	c.initParallelABAResult(c.Epoch)
	block := c.generatorBlock(c.Epoch)
	proposal, _ := NewSPBProposal(c.Name, block, c.Epoch, SPB_ONE_PHASE, nil, c.SigService)
	if err := c.Transimtor.Send(c.Name, core.NONE, proposal); err != nil {
		panic(err)
	}
	c.Transimtor.RecvChannel() <- proposal

	recvChannal := c.Transimtor.RecvChannel()
	for {
		var err error
		select {
		case msg := <-recvChannal:
			{
				if validator, ok := msg.(Validator); ok {
					if !validator.Verify(c.Committee) {
						err = core.ErrSignature(msg.MsgType())
						break
					}
				}

				switch msg.MsgType() {

				case SPBProposalType:
					err = c.handleSpbProposal(msg.(*SPBProposal))
				case SPBVoteType:
					err = c.handleSpbVote(msg.(*SPBVote))
				case FinishType:
					err = c.handleFinish(msg.(*Finish))
				case ElectShareType:
					err = c.handleElectShare(msg.(*ElectShare))
				case HelpSkipType:
					err = c.handleHelpSkip(msg.(*HelpSkip))
				case HelpCommitType:
					err = c.handleHelpCommit(msg.(*HelpCommit))
				case PrepareType:
					err = c.handlePrepare(msg.(*Prepare))
				case ABAValType:
					err = c.handleABAVal(msg.(*ABAVal))
				case ABAMuxType:
					err = c.handleABAMux(msg.(*ABAMux))
				case CoinShareType:
					err = c.handleCoinShare(msg.(*CoinShare))
				case ABAHaltType:
					err = c.handleABAHalt(msg.(*ABAHalt))

				}
			}
		case block := <-c.loopBackChannel:
			{
				err = c.handleLoopBack(block)
			}
		case abaBack := <-c.abaCallBack:
			err = c.processABABack(abaBack)
		default:
		}
		if err != nil {
			logger.Warn.Println(err)
		}
	}
}
