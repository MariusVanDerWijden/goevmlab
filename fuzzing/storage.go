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
	"github.com/ethereum/go-ethereum/common"
	"github.com/holiman/goevmlab/ops"
	"github.com/holiman/goevmlab/program"
	"math/rand"
)

// RandStorage sets some slots
func RandStorage(maxSlots, maxVal int) map[common.Hash]common.Hash {
	storage := make(map[common.Hash]common.Hash)
	numSlots := rand.Intn(maxSlots)
	for i := 0; i < numSlots; i++ {
		v, slot := byte(rand.Intn(maxVal)), byte(rand.Intn(numSlots))
		storage[common.BytesToHash([]byte{slot})] = common.BytesToHash([]byte{v})
	}
	return storage
}

func RandStorageOps() *program.Program {
	p := program.NewProgram()
	for {
		r := rand.Intn(100)
		switch {
		case r < 40:
			slot, val := rand.Intn(5), rand.Intn(3)
			p.Sstore(slot, val)
		case r < 80:
			slot := rand.Intn(10)
			p.Push(slot)
			p.Op(ops.SLOAD)
			p.Op(ops.POP)
		default:
			return p
		}
	}
}

// RandCall2200 constructs code which contains some storage ops and potentially some
// calls/creates. If depth is deemed 'too high', it won't do further calls/creates
func RandCall2200(addresses []common.Address, depth int) []byte {
	addrGen := addressRandomizer(addresses)

	// 30% sstore,
	// 30% sload,
	// 20% call of some type
	// 5% create, 5% create2,
	// 5% return, 5% revert

	// if we've reached depth too deep, we shouldn't continue
	// calling/creating -- it bloats the code too much

	chanceOfSstore := 30
	chanceOfSload := 30
	chanceOfCreate := 10 - depth*depth
	chanceOfCall := 20 - depth*depth

	p := program.NewProgram()
	for {
		r := rand.Intn(100)
		switch {
		case r < chanceOfSstore:
			p.Sstore(rand.Intn(5), rand.Intn(3))
		case r < chanceOfSstore+chanceOfSload:
			slot := rand.Intn(5)
			p.Push(slot)
			p.Op(ops.SLOAD)
			p.Op(ops.POP)
		case r < chanceOfSstore+chanceOfSload+chanceOfCreate:
			ctor := RandStorageOps()
			runtimeCode := RandCall2200(addresses, depth+1)
			ctor.ReturnData(runtimeCode)
			p.CreateAndCall(ctor.Bytecode(), r%2 == 0, randCallType(), 0)
		case r < chanceOfSstore+chanceOfSload+chanceOfCreate+chanceOfCall:
			// zero value call with no data
			var gas valFunc
			if r%2 == 0 {
				gas = func() interface{}{
					return 0
				}
			}
			p2 := RandCall(gas, addrGen, nil, nil, nil)
			p.AddAll(p2)
			// pop the ret value
			p.Op(ops.POP)
		default:
			// return/revert
			p.Push(0)
			p.Push(0)
			if r%2 == 0 {
				p.Op(ops.RETURN)
			} else {
				p.Op(ops.REVERT)
			}
			return p.Bytecode()
		}
		if len(p.Bytecode()) > 1024 {
			return p.Bytecode()
		}
	}
}
