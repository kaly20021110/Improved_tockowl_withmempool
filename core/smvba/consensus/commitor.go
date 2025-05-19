package consensus

import (
	"bft/mvba/logger"
	"bft/mvba/mempool"
)

type Committor struct {
	Mempool  *mempool.Mempool
	Index    int64
	Blocks   map[int64]*mempool.Block
	commitCh chan *mempool.Block
	callBack chan<- struct{}
}

func NewCommittor(callBack chan<- struct{}, pool *mempool.Mempool) *Committor {
	c := &Committor{
		Mempool:  pool,
		Index:    0,
		Blocks:   map[int64]*mempool.Block{},
		commitCh: make(chan *mempool.Block),
		callBack: callBack,
	}
	go c.run()
	return c
}

func (c *Committor) Commit(block *ConsensusBlock) {
	logger.Info.Printf("commit ConsensusBlock epoch %d node %d the length of the payload is %d\n", block.Epoch, block.Proposer, len(block.PayLoads))
	for _, b := range block.PayLoads {
		if smallblock, err := c.Mempool.GetBlock(b); err == nil {
			c.commitCh <- smallblock

		}
	}
	logger.Info.Printf("commit ConsensusBlock epoch %d node %d\n", block.Epoch, block.Proposer)

	// if block.Epoch < c.Index {
	// 	return
	// }
	// c.Blocks[block.Epoch] = block
	// for {
	// 	if b, ok := c.Blocks[c.Index]; ok {
	// 		c.commitCh <- b
	// 		delete(c.Blocks, c.Index)
	// 		c.Index++
	// 	} else {
	// 		break
	// 	}
	// }
}

func (c *Committor) run() {
	for block := range c.commitCh {
		if block.Batch.ID != -1 {
			logger.Info.Printf("commit Block node %d batch_id %d\n", block.Proposer, block.Batch.ID)
		} else {
			logger.Error.Printf("commit null Block node %d batch_id %d\n", block.Proposer, block.Batch.ID)
		}
		c.callBack <- struct{}{}
	}
}
