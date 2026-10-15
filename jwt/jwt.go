// Package jwt includes functions for parsing JSON web tokens.
package jwt

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"io"
	"math/big"
)

type JWT struct {
	Header  JWSHeader
	Payload Claims
	// Message contains the raw base-64 encoded, period-delimited header and payload values.
	Message []byte
	// Signature contains the decoded signature.
	Signature []byte
}

func (j JWT) HasValidSignature(key any) bool {
	// todo: improve key type safety

	switch j.Header.Alg {
	case "HS256":
		raw, ok := key.([]byte)
		if !ok {
			return false
		}
		mac := hmac.New(sha256.New, raw)
		return hmac.Equal(mac.Sum(j.Message), j.Signature)
	case "RS256":
		raw, ok := key.(*rsa.PublicKey)
		if !ok {
			return false
		}
		return rsa.VerifyPKCS1v15(raw, crypto.SHA256, sha256.New().Sum(j.Message), j.Signature) == nil
	case "ES256":
		raw, ok := key.(ecdsa.PublicKey)
		if !ok {
			return false
		}

		if len(j.Signature) != 64 {
			return false
		}
		r := new(big.Int).SetBytes(j.Signature[:32])
		s := new(big.Int).SetBytes(j.Signature[32:])

		return ecdsa.Verify(&raw, sha256.New().Sum(j.Message), r, s)

	}

	return false
}

func (j *JWT) Decode(b []byte) error {
	var err error
	parts := bytes.Split(b, []byte{'.'})
	if len(parts) != 3 {
		return errors.New("bad input")
	}

	if len(parts[0]) > 0 {
		var rawHeader []byte
		rawHeader, err = base64.RawURLEncoding.AppendDecode(rawHeader, parts[0])
		if err != nil {
			return err
		}
		if err = j.Header.UnmarshalJSONFrom(jsontext.NewDecoder(bytes.NewBuffer(rawHeader))); err != nil {
			return err
		}
	}

	if len(parts[1]) > 0 {
		var rawClaims []byte
		rawClaims, err = base64.RawURLEncoding.AppendDecode(rawClaims, parts[1])
		if err != nil {
			return err
		}
		if err = j.Payload.UnmarshalJSONFrom(jsontext.NewDecoder(bytes.NewBuffer(rawClaims))); err != nil {
			return err
		}
	}

	if len(parts[2]) > 0 {
		j.Signature, err = base64.RawURLEncoding.AppendDecode(j.Signature, parts[2])
		if err != nil {
			return err
		}
	}

	j.Message = b[:len(b)-len(parts[2])-1]

	return nil
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
		err error
		t   jsontext.Token
		val jsontext.Value
		str string
	)

	defer func() {
		if err == io.EOF {
			err = nil
		}
	}()

	if t, err = dec.ReadToken(); err != nil {
		return errors.New("invalid Claims: empty input")
	}

	if t.Kind() != jsontext.KindBeginObject {
		return errors.New("invalid Claims: not a JSON object")
	}

	for t, err = dec.ReadToken(); err == nil; t, err = dec.ReadToken() {
		if t.Kind() == jsontext.KindEndObject {
			// we ignore any trailing garbage.
			return err
		}
		if t.Kind() != jsontext.KindString {
			return errors.New("invalid field type")
		}
		str = t.String()

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
	Alg      string
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
		err error
		t   jsontext.Token
		val jsontext.Value
		str string
	)

	defer func() {
		if err == io.EOF {
			err = nil
		}
	}()

	if t, err = dec.ReadToken(); err != nil {
		return errors.New("invalid JWSHeader: empty input")
	}

	if t.Kind() != jsontext.KindBeginObject {
		return errors.New("invalid JWSHeader: not a JSON object")
	}

	for t, err = dec.ReadToken(); err == nil; t, err = dec.ReadToken() {
		if t.Kind() == jsontext.KindEndObject {
			// we ignore any trailing garbage.
			return err
		}
		if t.Kind() != jsontext.KindString {
			return errors.New("invalid field type")
		}

		str = t.String()

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
