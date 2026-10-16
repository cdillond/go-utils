// Package jwt includes functions for parsing JSON web tokens.
package jwt

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"io"
	"math/big"
)

type CompactSerialization struct {
	Header     []byte
	Payload    []byte
	Signature  []byte
	RawMessage []byte
}

func DecodeCompact(b []byte) (CompactSerialization, error) {
	var (
		c     CompactSerialization
		err   error
		parts = bytes.Split(b, []byte{'.'})
	)

	if len(parts) < 2 {
		return c, ErrTooFewParts
	}
	c.Header, err = base64.RawURLEncoding.AppendDecode(c.Header, parts[0])
	if err != nil {
		return c, errors.Join(ErrInvalidHeader, err)
	}
	c.Payload, err = base64.RawURLEncoding.AppendDecode(c.Payload, parts[1])
	if err != nil {
		return c, errors.Join(ErrInvalidPayload, err)
	}
	if len(parts) < 3 {
		return c, nil
	}
	c.Signature, err = base64.RawURLEncoding.AppendDecode(c.Payload, parts[1])
	if err != nil {
		return c, errors.Join(ErrInvalidSig, err)
	}

	c.RawMessage = b[:len(b)-len(parts[2])-1]

	return c, nil
}

type JWT struct {
	Header  JWSHeader
	Payload Claims
}

type PubKey interface {
	Equal(x crypto.PublicKey) bool
}

type HS256Key [sha256.Size]byte

func (h HS256Key) Equal(x crypto.PublicKey) bool {
	other, ok := x.(HS256Key)
	if !ok {
		return false
	}
	return subtle.ConstantTimeCompare(h[:], other[:]) == 1
}

type SigValidationError string

func (s SigValidationError) Error() string {
	return "JWT signature validation error: " + string(s)
}

const (
	ErrIncorrectAlg  SigValidationError = "algorithm does not match the provided key type"
	ErrBadSigLen     SigValidationError = "signature length is invalid"
	ErrUnsigned      SigValidationError = "JWT is not signed"
	ErrUnimplemented SigValidationError = "algorithm not implemented"
	ErrBadSig        SigValidationError = "signature failed validation"
)

type Alg string

const (
	AlgHS256       Alg = "HS256"
	AlgRS256       Alg = "RS256"
	AlgES256       Alg = "ES256"
	AlgNone        Alg = "none"
	AlgUnspecified Alg = ""
)

func ValidateSignature(key PubKey, alg Alg, message, signature []byte, allowUnsigned bool) error {
	switch alg {
	case AlgHS256:
		raw, ok := key.(HS256Key)
		if !ok {
			return ErrIncorrectAlg
		}
		mac := hmac.New(sha256.New, raw[:])
		if !hmac.Equal(mac.Sum(message), signature) {
			return ErrBadSig
		}
	case AlgRS256:
		raw, ok := key.(*rsa.PublicKey)
		if !ok {
			return ErrIncorrectAlg
		}
		h := sha256.Sum256(message)
		if err := rsa.VerifyPKCS1v15(raw, crypto.SHA256, h[:], signature); err != nil {
			return errors.Join(ErrBadSig, err)
		}
	case AlgES256:
		raw, ok := key.(*ecdsa.PublicKey)
		if !ok {
			return ErrIncorrectAlg
		}
		if len(signature) != 64 {
			return ErrBadSigLen
		}
		r := new(big.Int).SetBytes(signature[:32])
		s := new(big.Int).SetBytes(signature[32:])
		h := sha256.Sum256(message)
		if !ecdsa.Verify(raw, h[:], r, s) {
			return ErrBadSig
		}
	case AlgUnspecified, AlgNone:
		if len(signature) > 0 {
			return ErrBadSig
		}
		if !allowUnsigned {
			return ErrUnsigned
		}
	default:
		return ErrUnimplemented
	}
	return nil
}

type DecodeError string

func (d DecodeError) Error() string {
	return "JWT decode error: " + string(d)
}

const (
	ErrTooFewParts    DecodeError = "src bytes contain too few parts"
	ErrTooManyParts   DecodeError = "src bytes contain too many parts and may contain an unsupported JWE"
	ErrInvalidHeader  DecodeError = "invalid header"
	ErrInvalidPayload DecodeError = "invalid payload"
	ErrInvalidSig     DecodeError = "invalid signature"
	ErrInvalidJSON    DecodeError = "invalid JSON"
	ErrDuplicateField DecodeError = "JWT contains duplicate fields"
)

// A LookupFn should resolve a JWT to an associated PubKey that can be used for signature validation. If no key
// is found, it should return nil.
type LookupFn func(JWT) PubKey

// FromCompact decodes a CompactSerialization to a JWT and validates the message/signature pair.
func (j *JWT) FromCompact(c CompactSerialization, lookup LookupFn, allowUnsigned bool) error {
	var (
		err error
		key PubKey
	)

	if err = j.Header.UnmarshalJSONFrom(jsontext.NewDecoder(bytes.NewBuffer(c.Header))); err != nil {
		return errors.Join(ErrInvalidHeader, err)
	}
	if err = j.Payload.UnmarshalJSONFrom(jsontext.NewDecoder(bytes.NewBuffer(c.Payload))); err != nil {
		return errors.Join(ErrInvalidPayload, err)
	}

	key = lookup(*j)

	return ValidateSignature(key, Alg(j.Header.Alg), c.RawMessage, c.Signature, allowUnsigned)
}

type Claims struct {
	Iss string
	Sub string
	Aud string
	Exp int64
	Nbf int64
	Iat int64
	Jti string
	// Unknown holds all privately-defined claims and all publicly registered claims not inluded
	// as struct fields. If no such claims exist in the raw payload, Unknown will be nil.
	Unknown map[string]jsontext.Value
}

func (c *Claims) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	var (
		err  error
		t    jsontext.Token
		val  jsontext.Value
		str  string
		seen = make(map[string]struct{})
	)

	defer func() {
		if err == io.EOF {
			err = nil
		}
	}()

	if t, err = dec.ReadToken(); err != nil {
		return err
	}

	if t.Kind() != jsontext.KindBeginObject {
		return ErrInvalidJSON
	}

	for t, err = dec.ReadToken(); err == nil; t, err = dec.ReadToken() {
		if t.Kind() == jsontext.KindEndObject {
			// we ignore any trailing garbage.
			return err
		}
		if t.Kind() != jsontext.KindString {
			return ErrInvalidJSON
		}
		str = t.String()

		if _, ok := seen[str]; ok {
			return ErrDuplicateField
		}
		seen[str] = struct{}{}

		if val, err = dec.ReadValue(); err != nil {
			return err
		}

		var x any

		switch str {
		case "iss":
			x = &c.Iss
		case "sub":
			x = &c.Sub
		case "aud":
			x = &c.Aud
		case "exp":
			x = &c.Exp
		case "nbf":
			x = &c.Nbf
		case "iat":
			x = &c.Iat
		case "jti":
			x = &c.Jti
		default:
			if c.Unknown == nil {
				c.Unknown = make(map[string]jsontext.Value)
			}
			c.Unknown[str] = val.Clone()
		}

		if x != nil {
			if err = json.Unmarshal([]byte(val), x); err != nil {
				return err
			}
		}
	}

	return err
}

type JWSHeader struct {
	Alg      Alg
	Jku      string
	Jwk      string
	Kid      string
	X5u      string
	X5c      []string
	X5t      string
	X55tS256 string `json:"x5t#S256"`
	Typ      string
	Cty      string
	Crit     []string `json:"crit,omitempty"`
	// Unknown holds all privately-defined header parameters and all publicly registered
	// header parameters not inluded as struct fields. If no such parameters exist in the
	// raw header, Unknown will be nil.
	Unknown map[string]jsontext.Value
}

func (j *JWSHeader) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	var (
		err  error
		t    jsontext.Token
		val  jsontext.Value
		str  string
		seen = make(map[string]struct{})
	)

	defer func() {
		if err == io.EOF {
			err = nil
		}
	}()

	if t, err = dec.ReadToken(); err != nil {
		return nil
	}

	if t.Kind() != jsontext.KindBeginObject {
		return ErrInvalidJSON
	}

	for t, err = dec.ReadToken(); err == nil; t, err = dec.ReadToken() {
		if t.Kind() == jsontext.KindEndObject {
			// we ignore any trailing garbage.
			return err
		}
		if t.Kind() != jsontext.KindString {
			return ErrInvalidJSON
		}

		str = t.String()

		if _, ok := seen[str]; ok {
			return ErrDuplicateField
		}
		seen[str] = struct{}{}

		if val, err = dec.ReadValue(); err != nil {
			return err
		}

		var x any

		switch str {
		case "alg":
			x = &j.Alg
		case "jku":
			x = &j.Jku
		case "jwk":
			x = &j.Jwk
		case "kid":
			x = &j.Kid
		case "x5u":
			x = &j.X5u
		case "x5c":
			x = &j.X5c
		case "x5t":
			x = &j.X5t
		case "x5t#S256":
			x = &j.X55tS256
		case "typ":
			x = &j.Typ
		case "cty":
			x = &j.Cty
		case "crit":
			x = &j.Crit
		default:
			if j.Unknown == nil {
				j.Unknown = make(map[string]jsontext.Value)
			}
			j.Unknown[str] = val.Clone()
		}

		if x != nil {
			if err = json.Unmarshal([]byte(val), x); err != nil {
				return err
			}
		}
	}

	return err
}
