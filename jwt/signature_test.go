package jwt

import (
	"errors"
	"testing"
)

func TestHS256KeyEqual(t *testing.T) {
	key := newHS256Key("0123456789abcdef0123456789abcdef")
	same := newHS256Key("0123456789abcdef0123456789abcdef")
	other := newHS256Key("fedcba9876543210fedcba9876543210")

	if !key.Equal(same) {
		t.Error("Equal() = false for identical keys")
	}
	if key.Equal(other) {
		t.Error("Equal() = true for different keys")
	}
	if key.Equal(nil) {
		t.Error("Equal() = true for nil key")
	}
}

func TestValidateSignature(t *testing.T) {
	message := []byte("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0")
	hsKey := newHS256Key("0123456789abcdef0123456789abcdef")
	otherHSKey := newHS256Key("fedcba9876543210fedcba9876543210")
	rsaKey := newRSAKey(t)
	ecKey := newECDSAKey(t)

	hsSig := signHS256(t, hsKey, message)
	rsaSig := signRS256(t, rsaKey, message)
	ecSig := signES256(t, ecKey, message)

	badECSig := make([]byte, len(ecSig))
	copy(badECSig, ecSig)
	badECSig[0] ^= 0xff

	tests := []struct {
		name          string
		key           PubKey
		alg           Alg
		message       []byte
		signature     []byte
		allowUnsigned bool
		wantErr       error
	}{
		{
			name:      "HS256 valid",
			key:       hsKey,
			alg:       AlgHS256,
			message:   message,
			signature: hsSig,
		},
		{
			name:      "HS256 invalid signature",
			key:       hsKey,
			alg:       AlgHS256,
			message:   message,
			signature: []byte("invalid"),
			wantErr:   ErrBadSig,
		},
		{
			name:      "HS256 wrong key",
			key:       otherHSKey,
			alg:       AlgHS256,
			message:   message,
			signature: hsSig,
			wantErr:   ErrBadSig,
		},
		{
			name:      "HS256 wrong key type",
			key:       &rsaKey.PublicKey,
			alg:       AlgHS256,
			message:   message,
			signature: hsSig,
			wantErr:   ErrIncorrectAlg,
		},
		{
			name:      "RS256 valid",
			key:       &rsaKey.PublicKey,
			alg:       AlgRS256,
			message:   message,
			signature: rsaSig,
		},
		{
			name:      "RS256 invalid signature",
			key:       &rsaKey.PublicKey,
			alg:       AlgRS256,
			message:   message,
			signature: []byte("invalid"),
			wantErr:   ErrBadSig,
		},
		{
			name:      "RS256 wrong key type",
			key:       hsKey,
			alg:       AlgRS256,
			message:   message,
			signature: rsaSig,
			wantErr:   ErrIncorrectAlg,
		},
		{
			name:      "ES256 valid",
			key:       &ecKey.PublicKey,
			alg:       AlgES256,
			message:   message,
			signature: ecSig,
		},
		{
			name:      "ES256 invalid signature",
			key:       &ecKey.PublicKey,
			alg:       AlgES256,
			message:   message,
			signature: badECSig,
			wantErr:   ErrBadSig,
		},
		{
			name:      "ES256 signature has invalid length",
			key:       &ecKey.PublicKey,
			alg:       AlgES256,
			message:   message,
			signature: []byte("too-short"),
			wantErr:   ErrBadSigLen,
		},
		{
			name:      "ES256 wrong key type",
			key:       hsKey,
			alg:       AlgES256,
			message:   message,
			signature: ecSig,
			wantErr:   ErrIncorrectAlg,
		},
		{
			name:          "none allowed",
			alg:           AlgNone,
			message:       message,
			allowUnsigned: true,
		},
		{
			name:          "none not allowed",
			alg:           AlgNone,
			message:       message,
			allowUnsigned: false,
			wantErr:       ErrUnsigned,
		},
		{
			name:          "none with signature",
			alg:           AlgNone,
			message:       message,
			signature:     []byte("signature"),
			allowUnsigned: true,
			wantErr:       ErrBadSig,
		},
		{
			name:          "unspecified algorithm allowed",
			alg:           AlgUnspecified,
			message:       message,
			allowUnsigned: true,
		},
		{
			name:          "unspecified algorithm not allowed",
			alg:           AlgUnspecified,
			message:       message,
			allowUnsigned: false,
			wantErr:       ErrUnsigned,
		},
		{
			name:      "unsupported algorithm",
			key:       hsKey,
			alg:       Alg("HS512"),
			message:   message,
			signature: hsSig,
			wantErr:   ErrUnimplemented,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateSignature(tt.key, tt.alg, tt.message, tt.signature, tt.allowUnsigned)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("ValidateSignature() error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}
