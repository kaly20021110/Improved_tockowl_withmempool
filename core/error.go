package core

import "fmt"

var (
	ErrSignature = func(msgTyp int) error {
		return fmt.Errorf("[type-%d] message signature verify error", msgTyp)
	}

	ErrReference = func(msgTyp, round, node int) error {
		return fmt.Errorf("[type-%d-round-%d-node-%d] not receive all block reference ", msgTyp, round, node)
	}

	ErrOneMoreMessage = func(msgTyp int, epoch int64, author NodeID) error {
		return fmt.Errorf("[type-%d-epoch-%d] receive one more message from %d ", msgTyp, epoch, author)
	}

	ErrFullMemory = func(author NodeID) error {
		return fmt.Errorf("author %d Mempool memory is full", author)
	}

	ErrStoreNotExist = func() error {
		return fmt.Errorf("storeNotExist")
	}
)
