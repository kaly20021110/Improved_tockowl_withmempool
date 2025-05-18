package consensus

import (
	"bft/mvba/core"
	"bft/mvba/crypto"
	"bft/mvba/logger"
	"sync"
	"sync/atomic"
)

type SPB struct {
	c         *Core
	Proposer  core.NodeID
	Epoch     int64
	BlockHash atomic.Value

	vm    sync.Mutex
	Votes map[int8]int

	uvm              sync.Mutex
	unHandleVote     []*SPBVote
	unHandleProposal []*SPBProposal

	LockFlag atomic.Bool
}

func NewSPB(c *Core, epoch int64, proposer core.NodeID) *SPB {
	return &SPB{
		c:     c,
		Epoch: epoch,
		// Round:        round,
		Proposer:     proposer,
		unHandleVote: make([]*SPBVote, 0),
		Votes:        make(map[int8]int),
	}
}

func (s *SPB) processProposal(p *SPBProposal) {
	if p.Phase == SPB_ONE_PHASE {
		// already recieve
		if s.BlockHash.Load() != nil || s.Proposer != p.B.Proposer {
			return
		}
		blockHash := p.B.Hash()
		s.BlockHash.Store(blockHash)
		// if s.c.VisitLockFlag(p.Epoch, p.Author) { //停止投票
		// 	logger.Debug.Printf("already send no proposal message can not vote:epoch %d Author%d\n", p.Epoch, p.Author)
		// 	return
		// }
		if vote, err := NewSPBVote(s.c.Name, p.Author, blockHash, s.Epoch, p.Phase, s.c.SigService); err != nil {
			logger.Error.Printf("create spb vote message error:%v \n", err)
		} else {
			if s.c.Name != s.Proposer {
				s.c.Transimtor.Send(s.c.Name, s.Proposer, vote)
			} else {
				s.c.Transimtor.RecvChannel() <- vote
			}
		}

		s.uvm.Lock()
		for _, proposal := range s.unHandleProposal {
			go s.processProposal(proposal)
		}
		for _, vote := range s.unHandleVote {
			go s.processVote(vote)
		}
		s.unHandleProposal = nil
		s.unHandleVote = nil
		s.uvm.Unlock()

	} else if p.Phase == SPB_TWO_PHASE {
		if s.BlockHash.Load() == nil {
			s.uvm.Lock()
			defer s.uvm.Unlock()
			s.unHandleProposal = append(s.unHandleProposal, p)
			return
		}
		//if lock ensure SPB_ONE_PHASE has received
		s.LockFlag.Store(true)
		// if s.c.VisitFinishFlag(p.Epoch, p.Author) {
		// 	logger.Debug.Printf("already send message as Finish ,can not continue to vote for finish epoch %d author %d\n", p.Epoch, p.Author)
		// 	return
		// }
		if vote, err := NewSPBVote(s.c.Name, p.Author, crypto.Digest{}, s.Epoch, p.Phase, s.c.SigService); err != nil {
			logger.Error.Printf("create spb vote message error:%v \n", err)
		} else {
			if s.c.Name != s.Proposer {
				s.c.Transimtor.Send(s.c.Name, s.Proposer, vote)
			} else {
				s.c.Transimtor.RecvChannel() <- vote
			}
		}
	}
}

func (s *SPB) processVote(p *SPBVote) {
	if s.BlockHash.Load() == nil {
		s.uvm.Lock()
		s.unHandleVote = append(s.unHandleVote, p)
		s.uvm.Unlock()
		return
	}
	s.vm.Lock()
	//s.Votes[p.Phase]++
	//num := s.Votes[p.Phase]
	finish, qcvalue, _ := s.c.Aggreator.addVote(p)
	s.vm.Unlock()
	// 2f+1?
	if finish {
		if p.Phase == SPB_ONE_PHASE {
			// if s.c.VisitLockFlag(p.Epoch, p.Author) { //暂停第一轮的投票聚合
			// 	logger.Debug.Printf("already send message as lock ,can not continue to vote for finish epoch %d author %d\n", p.Epoch, p.Author)
			// 	return
			// }
			if proposal, err := NewSPBProposal(
				s.c.Name,
				NewConsensusBlock(s.Proposer, []crypto.Digest{}, -1),
				s.Epoch,
				SPB_TWO_PHASE,
				qcvalue,
				s.c.SigService,
			); err != nil {
				logger.Error.Printf("create spb proposal message error:%v \n", err)
			} else {
				s.c.Transimtor.Send(s.c.Name, core.NONE, proposal)
				s.c.Transimtor.RecvChannel() <- proposal
			}
		} else if p.Phase == SPB_TWO_PHASE {
			// if s.c.VisitFinishFlag(p.Epoch, p.Author) { //暂停第二轮的投票聚合
			// 	logger.Debug.Printf("already send message as Finish ,can not continue to vote for finish epoch %d author %d\n", p.Epoch, p.Author)
			// 	return
			// }
			blockHash := s.BlockHash.Load().(crypto.Digest)
			if finish, err := NewFinish(s.c.Name, blockHash, s.Epoch, s.c.SigService); err != nil {
				logger.Error.Printf("create finish message error:%v \n", err)
			} else {
				logger.Debug.Printf("create finish message author:%d epoch %d\n", s.c.Name, finish.Epoch)
				s.c.Transimtor.Send(s.c.Name, core.NONE, finish)
				s.c.Transimtor.RecvChannel() <- finish
			}
		}
	}
	// if num == s.c.Committee.HightThreshold() {
	// 	if p.Phase == SPB_ONE_PHASE {
	// 		if s.c.VisitLockFlag(p.Epoch, p.Author) { //暂停第一轮的投票聚合
	// 			logger.Debug.Printf("already send message as lock ,can not continue to vote for finish epoch %d author %d\n", p.Epoch, p.Author)
	// 			return
	// 		}
	// 		if proposal, err := NewSPBProposal(
	// 			s.c.Name,
	// 			NewBlock(s.Proposer, pool.Batch{}, -1),
	// 			s.Epoch,
	// 			SPB_TWO_PHASE,
	// 			s.c.SigService,
	// 		); err != nil {
	// 			logger.Error.Printf("create spb proposal message error:%v \n", err)
	// 		} else {
	// 			s.c.Transimtor.Send(s.c.Name, core.NONE, proposal)
	// 			s.c.Transimtor.RecvChannel() <- proposal
	// 		}
	// 	} else if p.Phase == SPB_TWO_PHASE {
	// 		if s.c.VisitFinishFlag(p.Epoch, p.Author) { //暂停第二轮的投票聚合
	// 			logger.Debug.Printf("already send message as Finish ,can not continue to vote for finish epoch %d author %d\n", p.Epoch, p.Author)
	// 			return
	// 		}
	// 		blockHash := s.BlockHash.Load().(crypto.Digest)
	// 		if finish, err := NewFinish(s.c.Name, blockHash, s.Epoch, s.c.SigService); err != nil {
	// 			logger.Error.Printf("create finish message error:%v \n", err)
	// 		} else {
	// 			logger.Debug.Printf("create finish message author:%d epoch %d\n", s.c.Name, finish.Epoch)
	// 			s.c.Transimtor.Send(s.c.Name, core.NONE, finish)
	// 			s.c.Transimtor.RecvChannel() <- finish
	// 		}
	// 	}
	// }
}

func (s *SPB) IsLock() bool {
	return s.LockFlag.Load()
}

func (s *SPB) GetBlockHash() any {
	return s.BlockHash.Load()
}
