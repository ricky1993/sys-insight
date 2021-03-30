package module

type BPFModule interface {
	Init() error
	Start() error
	Stop() error
	Name() string
	GetDataChannel() <-chan []byte
	SetSinkChannel(sc chan<- interface{}) error
	ProcessEvent([]byte) (interface{}, error)
}

type BasicData struct {
	Name  string
	Value float64
}
