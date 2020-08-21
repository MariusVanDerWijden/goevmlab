package fuzztarget

import (
	"encoding/binary"
	mrand "math/rand"
	"time"

	"github.com/holiman/goevmlab/common"
	"github.com/holiman/goevmlab/evms"
	"github.com/holiman/goevmlab/fuzzing"
)

// Create our go-fuzz fuzzing target
func Fuzz(data []byte) int {
	generator := func() *fuzzing.GstMaker {
		base := fuzzing.GenerateFullFuzz(data)
		//target := base.GetDestination()
		//base.SetCode(target, fuzzing.RandCallBlake())
		return base
	}
	vms := []evms.Evm{
		evms.NewGethEVM("/home/matematik/go/src/github.com/ethereum/go-ethereum/build/bin/evm"),
		evms.NewParityVM("/home/matematik/ethereum/openethereum/target/release/openethereum-evm"),
		evms.NewNethermindVM("/home/matematik/ethereum/nethermind/nethtest"),
		//evms.NewBesuVM("/home/matematik/ethereum/besu/ethereum/evmtool/build/install/evmtool/bin/evm"),
	}
	var seedData [8]byte
	copy(seedData[:], data)
	seed := int64(binary.BigEndian.Uint64(seedData[:]))
	rand := mrand.New(mrand.NewSource(time.Now().UnixNano() ^ seed))
	if err := common.RunTest(vms, generator, "evmFuzz", rand); err != nil {
		panic(err)
		return 0
	}
	return 1
}
