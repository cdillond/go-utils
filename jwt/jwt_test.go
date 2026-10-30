package jwt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"testing"
)

func newHS256Key(secret string) HS256Key {
	var key HS256Key
	copy(key[:], secret)
	return key
}

func encodeSegment(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

func signingInput(header, payload string) []byte {
	return []byte(encodeSegment([]byte(header)) + "." + encodeSegment([]byte(payload)))
}

func compactToken(header, payload string, signature []byte) []byte {
	return []byte(string(signingInput(header, payload)) + "." + encodeSegment(signature))
}

func unsignedToken(header, payload string) []byte {
	return signingInput(header, payload)
}

func signHS256(t *testing.T, key HS256Key, input []byte) []byte {
	t.Helper()
	mac := hmac.New(sha256.New, key[:])
	mac.Write(input)
	return mac.Sum(nil)
}

func signRS256(t *testing.T, key *rsa.PrivateKey, input []byte) []byte {
	t.Helper()
	hash := sha256.Sum256(input)
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hash[:])
	if err != nil {
		t.Fatalf("signing RS256 token: %v", err)
	}
	return sig
}

func signES256(t *testing.T, key *ecdsa.PrivateKey, input []byte) []byte {
	t.Helper()
	hash := sha256.Sum256(input)
	r, s, err := ecdsa.Sign(rand.Reader, key, hash[:])
	if err != nil {
		t.Fatalf("signing ES256 token: %v", err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return sig
}

func newRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating RSA key: %v", err)
	}
	return key
}

func newECDSAKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating ECDSA key: %v", err)
	}
	return key
}

func TestErrorStrings(t *testing.T) {
	if got, want := ErrBadSig.Error(), "JWT signature validation error: signature failed validation"; got != want {
		t.Errorf("ErrBadSig.Error() = %q, want %q", got, want)
	}
	if got, want := ErrInvalidHeader.Error(), "JWT decode error: invalid header"; got != want {
		t.Errorf("ErrInvalidHeader.Error() = %q, want %q", got, want)
	}
}

func TestDecode(t *testing.T) {
	key := newHS256Key("0123456789abcdef0123456789abcdef")
	header := `{"alg":"HS256","typ":"JWT","kid":"key-1"}`
	payload := `{"sub":"1234567890","name":"John Doe","iat":1516239022}`
	token := compactToken(header, payload, signHS256(t, key, signingInput(header, payload)))

	var j JWT
	if err := j.UnmarshalCompact(token, func(JWT) PubKey { return key }, false); err != nil {
		t.Fatalf("UnmarshalCompact() error = %v", err)
	}

	if j.Header.Alg != AlgHS256 {
		t.Errorf("Header.Alg = %q, want %q", j.Header.Alg, AlgHS256)
	}
	if j.Header.Typ != "JWT" {
		t.Errorf("Header.Typ = %q, want %q", j.Header.Typ, "JWT")
	}
	if j.Header.Kid != "key-1" {
		t.Errorf("Header.Kid = %q, want %q", j.Header.Kid, "key-1")
	}
	if j.Payload.Sub != "1234567890" {
		t.Errorf("Payload.Sub = %q, want %q", j.Payload.Sub, "1234567890")
	}
	if j.Payload.Iat != 1516239022 {
		t.Errorf("Payload.Iat = %d, want %d", j.Payload.Iat, 1516239022)
	}
	if got := string(j.Payload.Unknown["name"]); got != `"John Doe"` {
		t.Errorf("Payload.Unknown[name] = %s, want %s", got, `"John Doe"`)
	}
}

func TestJWTUnmarshalCompact(t *testing.T) {
	key := newHS256Key("0123456789abcdef0123456789abcdef")
	otherKey := newHS256Key("fedcba9876543210fedcba9876543210")
	header := `{"alg":"HS256","kid":"key-1"}`
	payload := `{"sub":"subject","exp":123}`
	input := signingInput(header, payload)
	signature := signHS256(t, key, input)

	t.Run("valid token", func(t *testing.T) {
		var j JWT
		if err := j.UnmarshalCompact(compactToken(header, payload, signature), func(JWT) PubKey { return key }, false); err != nil {
			t.Fatalf("UnmarshalCompact() error = %v", err)
		}
		if j.Payload.Sub != "subject" {
			t.Errorf("Payload.Sub = %q, want %q", j.Payload.Sub, "subject")
		}
	})

	t.Run("wrong key", func(t *testing.T) {
		var j JWT
		err := j.UnmarshalCompact(compactToken(header, payload, signature), func(JWT) PubKey { return otherKey }, false)
		if !errors.Is(err, ErrBadSig) {
			t.Fatalf("UnmarshalCompact() error = %v, want %v", err, ErrBadSig)
		}
	})

	t.Run("tampered payload", func(t *testing.T) {
		tamperedPayload := `{"sub":"attacker","exp":123}`
		var j JWT
		err := j.UnmarshalCompact(compactToken(header, tamperedPayload, signature), func(JWT) PubKey { return key }, false)
		if !errors.Is(err, ErrBadSig) {
			t.Fatalf("UnmarshalCompact() error = %v, want %v", err, ErrBadSig)
		}
	})

	t.Run("nil lookup", func(t *testing.T) {
		var j JWT
		err := j.UnmarshalCompact(compactToken(header, payload, signature), nil, false)
		if !errors.Is(err, ErrIncorrectAlg) {
			t.Fatalf("UnmarshalCompact() error = %v, want %v", err, ErrIncorrectAlg)
		}
	})

	t.Run("lookup returns nil", func(t *testing.T) {
		var j JWT
		err := j.UnmarshalCompact(compactToken(header, payload, signature), func(JWT) PubKey { return nil }, false)
		if !errors.Is(err, ErrIncorrectAlg) {
			t.Fatalf("UnmarshalCompact() error = %v, want %v", err, ErrIncorrectAlg)
		}
	})

	t.Run("lookup receives decoded token", func(t *testing.T) {
		var (
			j      JWT
			got    JWT
			called bool
		)
		lookup := func(token JWT) PubKey {
			called = true
			got = token
			return key
		}
		if err := j.UnmarshalCompact(compactToken(header, payload, signature), lookup, false); err != nil {
			t.Fatalf("UnmarshalCompact() error = %v", err)
		}
		if !called {
			t.Fatal("lookup was not called")
		}
		if got.Header.Kid != "key-1" {
			t.Errorf("lookup header Kid = %q, want %q", got.Header.Kid, "key-1")
		}
		if got.Payload.Sub != "subject" {
			t.Errorf("lookup payload Sub = %q, want %q", got.Payload.Sub, "subject")
		}
	})

	t.Run("malformed compact serialization", func(t *testing.T) {
		var j JWT
		err := j.UnmarshalCompact([]byte("not-a-jwt"), nil, false)
		if !errors.Is(err, ErrTooFewParts) {
			t.Fatalf("UnmarshalCompact() error = %v, want %v", err, ErrTooFewParts)
		}
	})

	t.Run("invalid header JSON", func(t *testing.T) {
		token := compactToken(`{`, payload, signature)
		var j JWT
		err := j.UnmarshalCompact(token, func(JWT) PubKey { return key }, false)
		if !errors.Is(err, ErrInvalidHeader) {
			t.Fatalf("UnmarshalCompact() error = %v, want %v", err, ErrInvalidHeader)
		}
	})
}

func TestJWTUnmarshalCompactUnsigned(t *testing.T) {
	header := `{"alg":"none"}`
	payload := `{"sub":"anonymous"}`

	t.Run("allowed", func(t *testing.T) {
		var j JWT
		if err := j.UnmarshalCompact(unsignedToken(header, payload), nil, true); err != nil {
			t.Fatalf("UnmarshalCompact() error = %v", err)
		}
		if j.Payload.Sub != "anonymous" {
			t.Errorf("Payload.Sub = %q, want %q", j.Payload.Sub, "anonymous")
		}
	})

	t.Run("not allowed", func(t *testing.T) {
		var j JWT
		err := j.UnmarshalCompact(unsignedToken(header, payload), nil, false)
		if !errors.Is(err, ErrUnsigned) {
			t.Fatalf("UnmarshalCompact() error = %v, want %v", err, ErrUnsigned)
		}
	})

	t.Run("signature present", func(t *testing.T) {
		var j JWT
		err := j.UnmarshalCompact(compactToken(header, payload, []byte("signature")), nil, true)
		if !errors.Is(err, ErrBadSig) {
			t.Fatalf("UnmarshalCompact() error = %v, want %v", err, ErrBadSig)
		}
	})
}

func TestJWTUnmarshalCompactAlgorithms(t *testing.T) {
	hsKey := newHS256Key("0123456789abcdef0123456789abcdef")
	rsaKey := newRSAKey(t)
	ecKey := newECDSAKey(t)

	tests := []struct {
		name   string
		header string
		key    PubKey
		sign   func([]byte) []byte
	}{
		{
			name:   "HS256",
			header: `{"alg":"HS256"}`,
			key:    hsKey,
			sign:   func(input []byte) []byte { return signHS256(t, hsKey, input) },
		},
		{
			name:   "RS256",
			header: `{"alg":"RS256"}`,
			key:    &rsaKey.PublicKey,
			sign:   func(input []byte) []byte { return signRS256(t, rsaKey, input) },
		},
		{
			name:   "ES256",
			header: `{"alg":"ES256"}`,
			key:    &ecKey.PublicKey,
			sign:   func(input []byte) []byte { return signES256(t, ecKey, input) },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := `{"sub":"alice"}`
			token := compactToken(tt.header, payload, tt.sign(signingInput(tt.header, payload)))

			var j JWT
			err := j.UnmarshalCompact(token, func(JWT) PubKey { return tt.key }, false)
			if err != nil {
				t.Fatalf("UnmarshalCompact() error = %v", err)
			}
			if j.Header.Alg != Alg(tt.name) {
				t.Errorf("Header.Alg = %q, want %q", j.Header.Alg, tt.name)
			}
			if j.Payload.Sub != "alice" {
				t.Errorf("Payload.Sub = %q, want %q", j.Payload.Sub, "alice")
			}
		})
	}
}
