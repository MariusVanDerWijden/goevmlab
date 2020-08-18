package fuzztarget

import "testing"

func TestRepro(t *testing.T) {
	data := "gg\xc9\xe9\x95>/\xf1\x88\x95>770770"
	Fuzz([]byte(data))
}
