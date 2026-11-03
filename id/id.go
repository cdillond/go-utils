package id

import (
	"unsafe"
	"uuid"
)

func AsValidV4(b []byte) *uuid.UUID {
	if len(b) != 16 {
		return nil
	}

	// version 4
	if b[6]>>4 != 4 {
		return nil
	}

	// variant 2
	if b[8]>>6 != 2 {
		return nil
	}

	return (*uuid.UUID)(unsafe.Pointer(&b[0]))
}
