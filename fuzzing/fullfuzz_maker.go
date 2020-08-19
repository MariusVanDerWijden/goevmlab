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

// +build gofuzz
package fuzzing

import (
	"encoding/binary"
	"math"
	"math/big"
	"math/rand"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	fuzz "github.com/google/gofuzz"
	"github.com/holiman/goevmlab/ops"
	"github.com/holiman/goevmlab/program"
)

func GenerateFullFuzz(data []byte) *GstMaker {
	gst := basicStateTest("Istanbul")
	f := fuzz.NewFromGoFuzz(data)
	// Add a contract which calls blake
	dest := common.HexToAddress("0x0000ca1100b1a7e")
	gst.AddAccount(dest, GenesisAccount{
		Code:    MakeRandProgram(f),
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

func MakeRandProgram(fuzz *fuzz.Fuzzer) []byte {
	// fill the memory
	p := program.NewProgram()
	var jumpDest uint64
	fuzz.Fuzz(&jumpDest)
	var loopCounter byte
	fuzz.Fuzz(&loopCounter)
	for i := byte(0); i < loopCounter; i++ {
		var rnd byte
		fuzz.Fuzz(&rnd)
		switch rnd % 20 {
		case 0:
			var op byte
			fuzz.Fuzz(&op)
			if ops.OpCode(op) == ops.BLOCKHASH {
				op = 0x01
			}
			p.Op(ops.OpCode(op))
		case 1:
			jumpDest = p.Jumpdest()
		case 2:
			jumpDest = p.Label()
		case 3:
			//p.Jump(jumpDest)
		case 4:
			p.Push(jumpDest)
		case 5:
			/*
				var condition bool
				fuzz.Fuzz(&condition)
				p.JumpIf(jumpDest, condition)
			*/
		case 6:
			var start, size, slot int
			fuzz.Fuzz(&start)
			fuzz.Fuzz(&size)
			size = size % 255
			fuzz.Fuzz(&slot)
			p.MemToStorage(start, size, slot)
		case 7:
			var data []byte
			var memStart uint32
			fuzz.Fuzz(&data)
			fuzz.Fuzz(&memStart)
			p.Mstore(data, memStart)
		case 8:
			var data []byte
			fuzz.Fuzz(&data)
			p.Push(data)
		case 9:
			/*
				var slot interface{}
				var value interface{}
				fuzz.Fuzz(&slot)
				fuzz.Fuzz(&value)
				p.Sstore(slot, value)
			*/
		case 10:
			var data []byte
			fuzz.Fuzz(&data)
			p.ReturnData(data)
		case 11:
			var offset uint32
			var length uint32
			fuzz.Fuzz(&offset)
			fuzz.Fuzz(&length)
			p.Return(offset, length)
		case 12:
			var code []byte
			var isCreate2 bool
			var callOp ops.OpCode
			fuzz.Fuzz(&code)
			fuzz.Fuzz(&isCreate2)
			fuzz.Fuzz(&callOp)
			p.CreateAndCall(code, isCreate2, callOp)
		case 13:
			callRandomPrecompile(p, fuzz)
		case 14:
			callSpecificPrecompile(p, fuzz)
		case 15:
			// Set up jumpDest from Data
			fuzz.Fuzz(&jumpDest)
		case 16:
		}
	}
	return p.Bytecode()
}

func CallBLSPrecompile(p *program.Program, dataCopy []byte) {
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

func callRandomPrecompile(p *program.Program, fuzz *fuzz.Fuzzer) {
	var gas *big.Int
	var address byte // Only call the first 256 precompiles
	var value *big.Int
	var inOffset uint32
	var inSize uint32
	var outOffset uint32
	var outSize uint32
	fuzz.Fuzz(&gas)
	fuzz.Fuzz(&address)
	fuzz.Fuzz(&value)
	fuzz.Fuzz(&inOffset)
	fuzz.Fuzz(&inSize)
	fuzz.Fuzz(&outOffset)
	fuzz.Fuzz(&outSize)
	p.Call(gas, address, value, inOffset, inSize, outOffset, outSize)
}

func callSpecificPrecompile(p *program.Program, fuzz *fuzz.Fuzzer) {
	var val byte
	fuzz.Fuzz(&val)
	//var offset uint32
	switch val % 18 {
	case 1:
		// Call ECRecover
	case 2:
		// Call sha256hash
	case 3:
		// Call ripemd160hash
	case 4:
		// Call dataCopy
	case 5:
		// Call bigModExp
	case 6:
		// Call bn256AddIstanbul
	case 7:
		// Call bn256ScalarMulIstanbul
	case 8:
		// Call bn256PairingIstanbul
	case 9:
		// Call blake2f
		//evmfuzz.CallBlake(p, fuzz, offset)

	// BLS tests
	case 10:
		// Call blsG1Add
	case 11:
		// Call blsG1Mul
	case 12:
		// Call blsG1MultiExp
	case 13:
		// Call blsG2Add
	case 14:
		// Call blsG2Mul
	case 15:
		// Call blsG2MultiExp
	case 16:
		// Call blsPairing
	case 17:
		// Call blsMapG1
	case 18:
		// Call blsMapG2
	}
}
