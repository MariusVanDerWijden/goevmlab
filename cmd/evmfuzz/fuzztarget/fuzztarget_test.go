package fuzztarget

import "testing"

func TestRepro(t *testing.T) {
	data := "\xa3"
	Fuzz([]byte(data))
}
