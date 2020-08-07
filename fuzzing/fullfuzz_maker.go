// Copyright 2019 Martin Holst Swende
// This file is part of the goevmlab library.
//
// The library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the goevmlab library. If not, see <http://www.gnu.org/licenses/>.

package fuzzing

import (
	"encoding/binary"
	"math"
	"math/big"
	"math/rand"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/holiman/goevmlab/ops"
	"github.com/holiman/goevmlab/program"
)

func GenerateFullFuzz(data []byte) *GstMaker {
	gst := basicStateTest("Istanbul")
	// Add a contract which calls blake
	dest := common.HexToAddress("0x0000ca1100b1a7e")
	gst.AddAccount(dest, GenesisAccount{
		Code:    MakeRandProgram(data),
		Balance: new(big.Int),
		Storage: make(map[common.Hash]common.Hash),
	})
	// The transaction
	{
		tx := &stTransaction{
			// 8M gaslimit
			GasLimit:   []uint64{8000000},
			Nonce:      0,
			Value:      []string{randHex(4)},
			Data:       []string{randHex(100)},
			GasPrice:   big.NewInt(0x01),
			To:         dest.Hex(),
			PrivateKey: hexutil.MustDecode("0x45a915e4d060149eb4365960e6a7a45f334393093061116b197e3240065ff2d8"),
		}
		gst.SetTx(tx)
	}
	return gst
}

// GenerateFullTest generates a random test
func GenerateFullTest(name string) *GeneralStateTest {
	gst := GenerateFullFuzz()
	return gst.ToGeneralStateTest(name)
}

func MakeRandProgram(data []byte) []byte {
	// fill the memory
	p := program.NewProgram()
	dataCopy := data
	var jumpDest uint64
	for true {
		rnd := 0
		switch rnd {
		case 0:
			op := dataCopy[0]
			p.Op(ops.OpCode(op))
			dataCopy = dataCopy[:1]
		case 1:
			jumpDest = p.Jumpdest()
		case 2:
			jumpDest = p.Label()
		case 3:
			p.Jump(jumpDest)
		case 4:
			p.Push(jumpDest)
		case 5:
			var condition bool
			p.JumpIf(jumpDest, condition)
		case 6:
			var start, size, slot int
			p.MemToStorage(start, size, slot)
		case 7:
			var data []byte
			var memStart uint32
			p.Mstore(data, memStart)
		case 8:
			var data []byte
			p.Push(data)
		case 9:
			var slot interface{}
			var value interface{}
			p.Sstore(slot, value)
		case 10:
			var data []byte
			p.ReturnData(data)
		case 11:
			var offset uint32
			var length uint32
			p.Return(offset, length)
		case 12:
			var code []byte
			var isCreate2 bool
			var callOp ops.OpCode
			p.CreateAndCall(code, isCreate2, callOp)
		case 13:
			var gas *big.Int
			var address interface{}
			var value interface{}
			var inOffset interface{}
			var inSize interface{}
			var outOffset interface{}
			var outSize interface{}
			p.Call(gas, address, value, inOffset, inSize, outOffset, outSize)
		case 14:
			// Call precompile
			CallPrecompile(p, dataCopy)
		case 15:
			// Set up jumpDest from Data
		case 16:
		}
	}
	return p.Bytecode()
}

func CallPrecompile(p *program.Program, dataCopy []byte) {
	data := randomArgs()
	p.Mstore(data, 0)
	memInFn := func() (offset, size interface{}) {
		// todo:make mem generator which mostly outputs 0:213
		offset, size = 0, 213
		return
	}
	// blake outputs 64 bytes
	memOutFn := func() (offset, size interface{}) {
		offset, size = 0, 64
		return
	}
	addrGen := func() interface{} {
		return 9
	}
	p2 := RandCall(GasRandomizer(), addrGen, ValueRandomizer(), memInFn, memOutFn)
	p.AddAll(p2)
	// pop the ret value
	p.Op(ops.POP)
	// Store the output in some slot, to make sure the stateroot changes
	p.MemToStorage(0, 64, 0)
}

func randomArgs() []byte {
	//params are
	var rounds uint32
	data := make([]byte, 214)
	rand.Read(data)
	// Now, modify the rounds, and the 'f'
	// rounds should be below 1024 for the most part
	rounds = uint32(math.Abs(1024 * rand.ExpFloat64()))
	binary.BigEndian.PutUint32(data, rounds)
	x := data[213]
	switch {
	case x == 0:
		// Leave f as is in 1/256th of the tests
	case x < 0x80:
		// set to zer0
		data[212] = 0

	default:
		data[212] = 1
	}
	return data[0:213]
}
