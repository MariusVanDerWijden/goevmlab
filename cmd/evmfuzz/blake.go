package evmfuzz

import (
	"encoding/binary"
	"math"
	"math/rand"

	fuzz "github.com/google/gofuzz"
	"github.com/holiman/goevmlab/fuzzing"
	"github.com/holiman/goevmlab/ops"
	"github.com/holiman/goevmlab/program"
)

func CallBlake(p *program.Program, fuzz *fuzz.Fuzzer, memOffset uint32) {
	data := randomBlakeArgs(p, fuzz)
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

func randomBlakeArgs(p *program.Program, fuzz *fuzz.Fuzzer) []byte {
	data := make([]byte, 214)
	fuzz.Fuzz(&data)
	var rounds uint16
	fuzz.Fuzz(&rounds)
	rounds = uint16(math.Abs(1024 * rand.ExpFloat64()))
	binary.BigEndian.PutUint32(data, uint32(rounds))
	x := data[213]
	switch {
	case x == 0:
		// Leave f as is in 1/256th of the tests
	case x < 0x80:
		// set to zero
		data[212] = 0
	default:
		data[212] = 1
	}
	return data[0:213]
}
