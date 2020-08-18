package evmfuzz

import (
	fuzz "github.com/google/gofuzz"
	"github.com/holiman/goevmlab/fuzzing"
	"github.com/holiman/goevmlab/ops"
	"github.com/holiman/goevmlab/program"
)

func CallECRecover(p *program.Program, fuzz *fuzz.Fuzzer, memOffset uint32) {
	data := randomECRecoverArgs(p, fuzz)
	p.Mstore(data, memOffset)

	callType := randCallType(fuzz)
	callOps := FuncCall{
		addr:         9,
		memInOffset:  memOffset,
		memInSize:    213,
		memOutOffset: 0,
		memOutSize:   64,
		callType:     callType,
		gas:          fuzzing.GasRandomizer(),   //TODO (MariusVanDerWijden) change to smarter algo
		val:          fuzzing.ValueRandomizer(), // change
	}
	RandCall(p, callOps)
	// pop the ret value
	p.Op(ops.POP)
	// Store the output in some slot, to make sure the stateroot changes
	p.MemToStorage(0, 64, 0)
}

func randomECRecoverArgs(p *program.Program, fuzz *fuzz.Fuzzer) []byte {
	/*
		key, err := crypto.GenerateKey()
		if err != nil {
			panic(err)
		}
		key.Sign()*/
	return []byte{}
}
