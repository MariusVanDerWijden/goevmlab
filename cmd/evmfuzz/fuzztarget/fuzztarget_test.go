package fuzztarget

import "testing"

func TestRepro(t *testing.T) {
	data := "do"
	Fuzz([]byte(data))
}
