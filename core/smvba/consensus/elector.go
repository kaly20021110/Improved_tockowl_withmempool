package consensus

import (
	"bft/mvba/core"
	"bft/mvba/crypto"
)

type Elector struct {
	nodePriority    map[int64]map[int]core.NodeID //epoch - node队列
	electAggreators map[int64]*ElectAggreator
	sigService      *crypto.SigService
	committee       core.Committee
}

func NewElector(sigService *crypto.SigService, committee core.Committee) *Elector {
	return &Elector{
		nodePriority:    make(map[int64]map[int]core.NodeID),
		electAggreators: make(map[int64]*ElectAggreator),
		sigService:      sigService,
		committee:       committee,
	}
}

func (e *Elector) SetPriority(epoch int64, leader map[int]core.NodeID) {
	_, ok := e.nodePriority[epoch]
	if !ok {
		e.nodePriority[epoch] = make(map[int]core.NodeID)
	}
	e.nodePriority[epoch] = leader
	//items = leader
}

// 获取当前应该执行ABA的节点
func (e *Elector) GetLeader(epoch int64, priority int) core.NodeID {
	items, ok := e.nodePriority[epoch]
	if !ok {
		items = make(map[int]core.NodeID)
		e.nodePriority[epoch] = items
	}
	item, oks := items[priority]
	if !oks {
		return core.NONE
	} else {
		return item
	}
}

// 获得了prioritymap
func (e *Elector) AddShareVote(share *ElectShare) (map[int]core.NodeID, bool, error) {
	items, ok := e.electAggreators[share.Epoch]
	if !ok {
		items = NewElectAggreator()
		e.electAggreators[share.Epoch] = items
	}
	node, valid, err := items.Append(e.committee, e.sigService, share) //valid为true代表这个electshare有用被接受进去了
	if err != nil {
		return map[int]core.NodeID{0: core.NodeID(-1)}, valid, nil
	}

	if node[0] != -1 {
		e.SetPriority(share.Epoch, node)
	}
	return node, valid, nil
}

func (e *Elector) judgeSkip(epoch int64, leader core.NodeID) bool {
	return e.electAggreators[epoch].NoCount[leader] >= e.committee.HightThreshold()
}
