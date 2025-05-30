package network

import (
	"bft/mvba/logger"
	"encoding/gob"
	"io"
	"reflect"
)

type Messgae interface {
	MsgType() int
	Module() string // 返回 "mempool" 或 "consensus"
}

type Codec struct {
	types   map[int]reflect.Type
	encoder *gob.Encoder
	decoder *gob.Decoder
}

func NewCodec(Consensustypes map[int]reflect.Type, Mempooltypes map[int]reflect.Type) *Codec {
	var DefaultMessageTypeMap = make(map[int]reflect.Type)
	for k, v := range Consensustypes {
		DefaultMessageTypeMap[k] = v
	}
	for k1, v1 := range Mempooltypes {
		DefaultMessageTypeMap[k1] = v1
	}
	return &Codec{
		types: DefaultMessageTypeMap,
	}
}

// BindConn: only bind once
func (cc *Codec) Bind(conn io.ReadWriter) *Codec {
	return &Codec{
		types:   cc.types,
		encoder: gob.NewEncoder(conn),
		decoder: gob.NewDecoder(conn),
	}
}

func (cc *Codec) Write(msg Messgae) error {
	typeId := msg.MsgType()

	if err := cc.encoder.Encode(typeId); err != nil {
		logger.Error.Printf("Codec encode typeId  %d error: %v \n", typeId, err)
		return err
	}
	if err := cc.encoder.Encode(msg); err != nil {
		logger.Error.Printf("Codec encode msg module %s error: %v \n", msg.Module(), err)
		return err
	}
	return nil
}

func (cc *Codec) Read() (Messgae, error) {
	var typeId int
	if err := cc.decoder.Decode(&typeId); err != nil {
		return nil, err
	}
	msg := reflect.New(cc.types[typeId]).Interface()
	if err := cc.decoder.Decode(msg); err != nil {
		return nil, err
	}
	return msg.(Messgae), nil
}
