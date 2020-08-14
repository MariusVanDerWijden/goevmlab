package fuzztarget

import (
	"github.com/holiman/goevmlab/common"
	"github.com/holiman/goevmlab/evms"
	"github.com/holiman/goevmlab/fuzzing"
)

// Create our go-fuzz fuzzing target
func Fuzz(data []byte) int {
	generator := func() *fuzzing.GstMaker {
		base := fuzzing.GenerateFullFuzz(data)
		target := base.GetDestination()
		base.SetCode(target, fuzzing.RandCallBlake())
		return base
	}
	vms := []evms.Evm{
		evms.NewGethEVM("/home/matematik/go/src/github.com/ethereum/go-ethereum/build/bin/evm"),
	}
	if err := common.RunTest(vms, generator, "evmFuzz"); err != nil {
		panic(err)
		return 0
	}
	return 1
}
