// Copyright 2019 Martin Holst Swende, Marius van der Wijden
// This file is part of the go-evmlab library.
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

package evmfuzz

import (
	fuzz "github.com/google/gofuzz"
	"github.com/holiman/goevmlab/ops"
	"github.com/holiman/goevmlab/program"
)

var callTypes = []ops.OpCode{ops.CALL, ops.CALLCODE, ops.DELEGATECALL, ops.STATICCALL}

func randCallType(fuzz *fuzz.Fuzzer) ops.OpCode {
	var callType byte
	fuzz.Fuzz(&callType)
	return callTypes[int(callType)%len(callTypes)]
}

type FuncCall struct {
	gas          interface{}
	addr         interface{}
	val          interface{}
	memInOffset  interface{}
	memInSize    interface{}
	memOutOffset interface{}
	memOutSize   interface{}
	callType     ops.OpCode
}

func RandCall(p *program.Program, call FuncCall) {
	if call.memOutSize != nil {
		p.Push(call.memOutSize)   //mem out size
		p.Push(call.memOutOffset) // mem out start
	} else {
		p.Push(0)
		p.Push(call.memOutOffset)
	}
	if call.memInSize != nil {
		p.Push(call.memInSize)   //mem in size
		p.Push(call.memInOffset) // mem in start
	} else {
		p.Push(0)
		p.Push(call.memInOffset)
	}
	op := call.callType
	if op == ops.CALL || op == ops.CALLCODE {
		if call.val != nil {
			p.Push(call.val) //value
		} else {
			p.Push(0)
		}
	}
	p.Push(call.addr)
	if call.gas != nil {
		p.Push(call.gas)
	} else {
		p.Op(ops.GAS)
	}
	p.Op(op)
}
