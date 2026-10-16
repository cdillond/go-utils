package jwt

import (
	"testing"
)

func TestDecode(t *testing.T) {
	// todo: add real tests
	p := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

	var j JWT

	err := j.Decode([]byte(p))
	if err != nil {
		t.Error(err, j)
	}

	t.Log(j)

	t.Fail()
}
