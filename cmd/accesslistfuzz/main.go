// Copyright 2020 Martin Holst Swende, Marius van der Wijden
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

package main

import (
	"context"
	"fmt"
	"math/big"
	"math/rand"
	"os"
	"path/filepath"

	"gopkg.in/urfave/cli.v1"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/eth"
	"github.com/ethereum/go-ethereum/node"
	"github.com/ethereum/go-ethereum/params"
	evmlabcommon "github.com/holiman/goevmlab/common"
	"github.com/holiman/goevmlab/fuzzing"
)

func initApp() *cli.App {
	app := cli.NewApp()
	app.Name = filepath.Base(os.Args[0])
	app.Author = "Martin Holst Swende"
	app.Usage = "Generator for access list (state-)tests"
	app.Flags = []cli.Flag{
		evmlabcommon.GethFlag,
		evmlabcommon.ParityFlag,
		evmlabcommon.NethermindFlag,
		evmlabcommon.BesuFlag,
		evmlabcommon.AlethFlag,
		evmlabcommon.ThreadFlag,
		evmlabcommon.LocationFlag,
	}
	app.Action = startFuzzer
	return app
}

var app = initApp()

func main() {
	if err := app.Run(os.Args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func startFuzzer(c *cli.Context) error {
	generator := func() *fuzzing.GstMaker {
		base, code := generateCode()
		target := base.GetDestination()
		base.SetCode(target, code)
		return base
	}
	return evmlabcommon.ExecuteFuzzer(c, generator, "blstest")
}

func generateCode() (*fuzzing.GstMaker, []byte) {
	gst := fuzzing.BasicStateTest("Berlin")
	// Add a contract which calls BLS
	dest := common.HexToAddress("0x00ca11acc3551157")
	addrs := []common.Address{
		common.HexToAddress("0xF1"),
		common.HexToAddress("0xF2"),
		common.HexToAddress("0xF3"),
		common.HexToAddress("0xF4"),
		common.HexToAddress("0xF5"),
		common.HexToAddress("0xF6"),
		common.HexToAddress("0xF7"),
		common.HexToAddress("0xF8"),
		common.HexToAddress("0xF9"),
		common.HexToAddress("0xFA"),
	}
	code := fuzzing.RandCall2200(addrs)
	gst.AddAccount(dest, fuzzing.GenesisAccount{
		Code:    code,
		Balance: new(big.Int),
		Storage: make(map[common.Hash]common.Hash),
	})
	value := []string{randHex(4)}
	data := []string{randHex(100)}
	gasPrice := big.NewInt(0x01)
	gasLimit := []uint64{8000000}
	amount, _ := new(big.Int).SetString(value[0], 16)
	testKey, _ := crypto.HexToECDSA("45a915e4d060149eb4365960e6a7a45f334393093061116b197e3240065ff2d8")
	testAddr := crypto.PubkeyToAddress(testKey.PublicKey)
	tx := types.NewTransaction(0, dest, amount, gasLimit[0], gasPrice, []byte(data[0]))
	tx, err := types.SignTx(tx, types.HomesteadSigner{}, testKey)
	if err != nil {
		panic(err)
	}
	// Generate test chain.
	genesis := generateTestChain(big.NewInt(math.MaxBig63.Int64()), testAddr, dest, code)
	// Create node
	n, err := node.New(&node.Config{})
	if err != nil {
		panic(err)
	}
	// Create Ethereum Service
	config := &eth.Config{Genesis: genesis}
	config.Ethash.PowMode = ethash.ModeFake
	ethservice, err := eth.New(n, config)
	list, err := ethservice.APIBackend.AccessList(context.Background(), nil, 0, tx)
	if err != nil {
		panic(err)
	}
	// The transaction
	if list.Addresses() > 2 || list.StorageKeys() > 2 {
		fmt.Printf("%v\n", list)
	}
	{
		tx := &fuzzing.StTransaction{
			// 8M gaslimit
			GasLimit:   gasLimit,
			Nonce:      0,
			Value:      value,
			Data:       data,
			GasPrice:   gasPrice,
			To:         dest.Hex(),
			PrivateKey: hexutil.MustDecode("0x45a915e4d060149eb4365960e6a7a45f334393093061116b197e3240065ff2d8"),
		}
		gst.SetTx(tx)
	}
	return gst, code
}

// randHex produces some random hex data
func randHex(maxSize int) string {
	size := rand.Intn(maxSize)
	b := make([]byte, size)
	rand.Read(b)
	return hexutil.Encode(b)
}

func generateTestChain(testBalance *big.Int, testAddr common.Address, dest common.Address, code []byte) *core.Genesis {
	config := params.AllEthashProtocolChanges
	genesis := &core.Genesis{
		Config:    config,
		Alloc:     core.GenesisAlloc{testAddr: {Balance: testBalance}, dest: {Balance: new(big.Int), Code: code}},
		ExtraData: []byte("test genesis"),
		Timestamp: 9000,
	}
	return genesis
}
