package mempool

import (
	"bft/mvba/core"
	"bft/mvba/crypto"
	"bft/mvba/logger"
	"bft/mvba/pool"
	"bft/mvba/store"
	"time"
)

type Mempool struct {
	Name       core.NodeID
	Committee  core.Committee
	Parameters core.Parameters
	SigService *crypto.SigService
	Store      *store.Store
	TxPool     *pool.Pool
	Transimtor *core.Transmitor
	Queue      map[crypto.Digest]struct{} //整个mempool的最大容量
	Sync       *Synchronizer
	//ConsensusMempoolCoreChan <-chan core.Messgae
}

func NewMempool(
	Name core.NodeID,
	Committee core.Committee,
	Parameters core.Parameters,
	SigService *crypto.SigService,
	Store *store.Store,
	TxPool *pool.Pool,
	Transimtor *core.Transmitor,
	Sync *Synchronizer,
	//consensusMempoolCoreChan <-chan core.Messgae,
) *Mempool {
	m := &Mempool{
		Name:       Name,
		Committee:  Committee,
		Parameters: Parameters,
		SigService: SigService,
		Store:      Store,
		TxPool:     TxPool,
		Transimtor: Transimtor,
		Queue:      make(map[crypto.Digest]struct{}),
		Sync:       Sync,
		//ConsensusMempoolCoreChan: consensusMempoolCoreChan,
	}
	return m
}

func (c *Mempool) StoreBlock(block *Block) error {
	key := block.Hash()
	value, err := block.Encode()
	if err != nil {
		return err
	}
	return c.Store.Write(key[:], value)
}

func (c *Mempool) GetBlock(digest crypto.Digest) (*Block, error) {
	value, err := c.Store.Read(digest[:])

	if err == store.ErrNotFoundKey {
		return nil, nil
	}

	if err != nil {
		return nil, err
	}

	b := &Block{}
	if err := b.Decode(value); err != nil {
		return nil, err
	}
	return b, err
}

func (m *Mempool) payloadProcess(block *Block) error {

	if uint64(len(m.Queue)) >= m.Parameters.MaxMempoolQueenSize {
		return core.ErrFullMemory(m.Name)
	}
	//本地存储
	if err := m.StoreBlock(block); err != nil {
		return err
	}
	//转发给其他人
	message := &OtherBlockMsg{
		Block: block,
	}
	m.Transimtor.Send(m.Name, core.NONE, message)
	return nil
}

func (m *Mempool) HandleOwnBlock(block *OwnBlockMsg) error {
	//logger.Debug.Printf("handle mempool OwnBlockMsg\n")  自己的值先不加入自己的内存池队列，给一个缓冲的时间，尽量减少去要payload的时间
	if uint64(len(m.Queue)) >= m.Parameters.MaxMempoolQueenSize {
		return core.ErrFullMemory(m.Name)
	}
	digest := block.Block.Hash()
	if err := m.payloadProcess(block.Block); err != nil {
		return err
	}
	m.Queue[digest] = struct{}{}
	return nil
}

func (m *Mempool) HandleOthorBlock(block *OtherBlockMsg) error {
	//m.generateBlocks()
	//logger.Debug.Printf("handle mempool otherBlockMsg\n")
	if uint64(len(m.Queue)) >= m.Parameters.MaxMempoolQueenSize {
		logger.Error.Printf("ErrFullMemory\n")
		return core.ErrFullMemory(m.Name)
	}

	digest := block.Block.Hash()
	// Verify that the payload is correctly signed.
	if flag := block.Block.Verify(m.Committee); !flag {
		logger.Error.Printf("Block sign error\n")
		return nil
	}
	//如果已经存储了就舍弃
	if _, err := m.GetBlock(block.Block.Hash()); err == nil {
		return nil
	}
	if err := m.StoreBlock(block.Block); err != nil {
		return err
	}
	m.Queue[digest] = struct{}{}
	return nil
}

func (m *Mempool) HandleRequestBlock(request *RequestBlockMsg) error {
	logger.Debug.Printf("handle mempool RequestBlockMsg from %d\n", request.Author)
	for _, digest := range request.Digests {
		if b, err := m.GetBlock(digest); err != nil {
			return err
		} else {
			message := &OtherBlockMsg{
				Block: b,
			}
			//m.Transimtor.Send(m.Name, request.Author, message) //只发给向自己要的人
			m.Transimtor.Send(m.Name, core.NONE, message) //发给所有人
		}
	}
	return nil
}

// 获取共识区块所引用的微区块
func (m *Mempool) HandleMakeBlockMsg(makemsg *MakeConsensusBlockMsg) ([]crypto.Digest, error) {
	//nums := makemsg.MaxBlockSize / uint64(len(crypto.Digest{}))

	nums := makemsg.MaxBlockSize
	ret := make([]crypto.Digest, 0)
	if len(m.Queue) == 0 {
		logger.Debug.Printf("HandleMakeBlockMsg and len(m.Queue) == 0\n")
		block, _ := NewBlock(m.Name, m.TxPool.GetBatch(), m.SigService)
		if block.Batch.ID != -1 {
			logger.Info.Printf("create Block node %d batch_id %d \n", block.Proposer, block.Batch.ID)
		}
		digest := block.Hash()
		if err := m.payloadProcess(block); err != nil {
			return nil, err
		}
		ret = append(ret, digest)
	} else {
		logger.Debug.Printf("HandleMakeBlockMsg and len(m.Queue) %d\n", len(m.Queue))
		for key := range m.Queue {
			ret = append(ret, key)
			nums--
			if nums == 0 {
				break
			}
		}
		//移除
		for _, key := range ret {
			delete(m.Queue, key)
		}
	}
	return ret, nil
}

func (m *Mempool) HandleCleanBlock(msg *CleanBlockMsg) error {
	//本地清理删除payload
	for _, digest := range msg.Digests {
		delete(m.Queue, digest)
	}
	//同步清楚某个epoch之前的所有请求
	m.Sync.Cleanup(uint64(msg.Epoch))
	return nil
}

func (m *Mempool) HandleVerifyMsg(msg *VerifyBlockMsg) VerifyStatus {
	return m.Sync.Verify(msg.Proposer, msg.Epoch, msg.Payloads, msg.ConsensusBlockHash)
}

func (m *Mempool) generateBlocks() error {
	block, _ := NewBlock(m.Name, m.TxPool.GetBatch(), m.SigService)
	if block.Batch.ID != -1 {
		logger.Info.Printf("create Block node %d batch_id %d \n", block.Proposer, block.Batch.ID)
		ownmessage := &OwnBlockMsg{
			Block: block,
		}
		m.Transimtor.MempololRecvChannel() <- ownmessage
	}
	return nil
}

func (m *Mempool) Run() {
	//一直广播微区块
	ticker := time.NewTicker(1000 * time.Microsecond)
	defer ticker.Stop()
	m.generateBlocks()

	go m.Sync.Run()

	//监听mempool的消息通道
	mempoolrecvChannal := m.Transimtor.MempololRecvChannel()
	connectrecvChannal := m.Transimtor.ConnectRecvChannel()
	for {
		var err error
		select {
		case <-ticker.C:
			logger.Debug.Printf("ticker triggered at %s", time.Now().Format(time.RFC3339Nano))
			err = m.generateBlocks()
		case msg := <-connectrecvChannal:
			{
				switch msg.MsgType() {
				case MakeBlockType:
					{
						req, _ := msg.(*MakeConsensusBlockMsg)
						data, errors := m.HandleMakeBlockMsg(req)
						req.Blocks <- data //把引用传进去了，具体使用的时候要注意,这一步要传递到哪里去？
						logger.Debug.Printf("send data to consensus\n")
						err = errors
					}
				case VerifyBlockType:
					{
						req, _ := msg.(*VerifyBlockMsg)
						req.Sender <- m.HandleVerifyMsg(req)
					}
				case CleanBlockType:
					{
						err = m.HandleCleanBlock(msg.(*CleanBlockMsg))
					}
				}
			}
		case msg := <-mempoolrecvChannal:
			{
				switch msg.MsgType() {
				case OwnBlockType:
					{
						err = m.HandleOwnBlock(msg.(*OwnBlockMsg))
					}
				case OtherBlockType:
					{
						err = m.HandleOthorBlock(msg.(*OtherBlockMsg))
					}
				case RequestBlockType:
					{
						err = m.HandleRequestBlock(msg.(*RequestBlockMsg))
					}
				}
			}
		default:
		}
		if err != nil {
			switch err.(type) {
			default:
				logger.Error.Printf("Mempool Core: %s\n", err.Error())
			}
		}
	}
}
