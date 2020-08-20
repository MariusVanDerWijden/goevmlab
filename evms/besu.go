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

package evms

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/vm"
)

// BesuVM is s Evm-interface wrapper around the `evmtool` binary, based on Besu.
type BesuVM struct {
	path string
}

func NewBesuVM(path string) *BesuVM {
	return &BesuVM{
		path: path,
	}
}

// RunStateTest implements the Evm interface
func (evm *BesuVM) RunStateTest(path string, out io.Writer, speedTest bool) (string, error) {
	var (
		stdout io.ReadCloser
		err    error
		cmd    *exec.Cmd
	)
	if speedTest {
		cmd = exec.Command(evm.path, "--nomemory", "state-test", path)
	} else {
		// evm --nomemory --json state-test blaketest.json
		cmd = exec.Command(evm.path, "--nomemory", "--json", "state-test", path) // exclude memory
	}

	if stdout, err = cmd.StdoutPipe(); err != nil {
		return cmd.String(), err
	}
	if err = cmd.Start(); err != nil {
		return cmd.String(), err
	}
	// copy everything to the given writer
	evm.Copy(out, stdout)
	// release resources, handle error but ignore non-zero exit codes
	return cmd.String(), cmd.Wait()
}

func (evm *BesuVM) Name() string {
	return "besu"
}

func (vm *BesuVM) Close() {
}

type besuStructLog struct {
	Pc            uint64                      `json:"pc"`
	Op            string                      `json:"op"`
	Gas           string                      `json:"gas"`
	GasCost       string                      `json:"gasCost"`
	Memory        []byte                      `json:"memory"`
	MemorySize    int                         `json:"memSize"`
	Stack         []string                    `json:"stack"`
	ReturnStack   []uint32                    `json:"returnStack"`
	ReturnData    []byte                      `json:"returnData"`
	Storage       map[common.Hash]common.Hash `json:"-"`
	Depth         int                         `json:"depth"`
	RefundCounter uint64                      `json:"refund"`
	Err           error                       `json:"-"`
}

// feed reads from the reader, does some geth-specific filtering and
// outputs items onto the channel
func (evm *BesuVM) Copy(out io.Writer, input io.Reader) {
	var stateRoot stateRoot
	scanner := bufio.NewScanner(input)
	for scanner.Scan() {
		data := scanner.Bytes()
		var elem2 besuStructLog
		err := json.Unmarshal(data, &elem2)
		if err != nil {
			fmt.Printf("besu err: %v, line\n\t%v\n", err, string(data))
			continue
		}

		op, _ := strconv.ParseInt(strings.Replace(elem2.Op, "0x", "", -1), 16, 16)
		gas, _ := strconv.ParseInt(strings.Replace(elem2.Gas, "0x", "", -1), 16, 64)
		gasCost, _ := strconv.ParseInt(strings.Replace(elem2.GasCost, "0x", "", -1), 16, 64)
		var stack []*big.Int
		for _, ele := range elem2.Stack {
			el, _ := big.NewInt(0).SetString(strings.Replace(ele, "0x", "", 1), 16)
			// Besu prints out the stack in reverse order
			stack = append([]*big.Int{el}, stack...)
		}
		elem := vm.StructLog{
			Gas:           uint64(gas),
			Depth:         elem2.Depth,
			Err:           elem2.Err,
			GasCost:       uint64(gasCost),
			Memory:        elem2.Memory,
			MemorySize:    elem2.MemorySize,
			Op:            vm.OpCode(op),
			Pc:            elem2.Pc,
			RefundCounter: elem2.RefundCounter,
			ReturnData:    elem2.ReturnData,
			ReturnStack:   elem2.ReturnStack,
			Stack:         stack,
			Storage:       elem2.Storage,
		}
		// If the output cannot be marshalled, all fields will be blanks.
		// We can detect that through 'depth', which should never be less than 1
		// for any actual opcode
		if elem.Depth == 0 {
			if stateRoot.StateRoot == "" {
				if err := json.Unmarshal(data, &stateRoot); err == nil {
					// geth doesn't 0x-prefix stateroot
					if r := stateRoot.StateRoot; len(r) > 0 {
						stateRoot.StateRoot = fmt.Sprintf("0x%v", r)
					}
				}
			}
			//fmt.Printf("%v\n", string(data))
			// For now, just ignore these
			continue
		}
		if elem.ReturnStack == nil {
			elem.ReturnStack = make([]uint32, 0)
		}
		if elem.Stack == nil {
			elem.Stack = make([]*big.Int, 0)
		}
		// When geth encounters end of code, it continues anyway, on a 'virtual' STOP.
		// In order to handle that, we need to drop all STOP opcodes.
		if elem.Op == 0x0 {
			continue
		}
		// Parity is missing gasCost, memSize and refund
		elem.GasCost = 0
		elem.MemorySize = 0
		elem.RefundCounter = 0
		jsondata, _ := json.Marshal(elem)
		if _, err := out.Write(append(jsondata, '\n')); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing to out: %v\n", err)
			return
		}
	}
	root, _ := json.Marshal(stateRoot)
	if _, err := out.Write(append(root, '\n')); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing to out: %v\n", err)
		return
	}
}
