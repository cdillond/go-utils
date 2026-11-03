package id

import (
	"unsafe"
	"uuid"
)

// IsValidV4UUID returns true if the bytes contained by b constitute a valid
// V4 UUID (variant 2), and false otherwise.
func IsValidV4UUID(b []byte) bool {
	if len(b) != 16 {
		return false
	}

	// version 4
	if b[6]>>4 != 4 {
		return false
	}

	// variant 2
	if b[8]>>6 != 2 {
		return false
	}

	return true
}

// AsValidV4UUID returns a pointer to the initial element of b, cast as a pointer to a [uuid.UUID],
// if b forms a valid V4 UUID (variant 2). If b is not valid, AsValidV4UUID returns nil.
func AsValidV4UUID(b []byte) *uuid.UUID {
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
