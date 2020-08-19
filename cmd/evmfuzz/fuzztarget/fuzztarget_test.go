package fuzztarget

import "testing"

func TestRepro(t *testing.T) {
	data := "\x11\x92�\x16^"
	Fuzz([]byte(data))
}
