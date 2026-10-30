package jwt

import (
	"bytes"
	"encoding/json/jsontext"
	"errors"
	"testing"
)

func TestClaimsDecoding(t *testing.T) {
	payload := `{"iss":"issuer","sub":"subject","aud":"audience","exp":1,"nbf":2,"iat":3,"jti":"id","auth_time":4,"nonce":"nonce","acr":"acr","amr":["pwd","otp"],"azr":"azr","private":"value","nested":{"a":1}}`

	var j JWT
	err := j.FromCompactSerialization(CompactSerialization{
		Header:  []byte(`{"alg":"none"}`),
		Payload: []byte(payload),
	})
	if err != nil {
		t.Fatalf("FromCompactSerialization() error = %v", err)
	}

	claims := j.Payload
	if claims.Iss != "issuer" {
		t.Errorf("Iss = %q, want %q", claims.Iss, "issuer")
	}
	if claims.Sub != "subject" {
		t.Errorf("Sub = %q, want %q", claims.Sub, "subject")
	}
	if claims.Aud != "audience" {
		t.Errorf("Aud = %q, want %q", claims.Aud, "audience")
	}
	if claims.Exp != 1 {
		t.Errorf("Exp = %d, want %d", claims.Exp, 1)
	}
	if claims.Nbf != 2 {
		t.Errorf("Nbf = %d, want %d", claims.Nbf, 2)
	}
	if claims.Iat != 3 {
		t.Errorf("Iat = %d, want %d", claims.Iat, 3)
	}
	if claims.Jti != "id" {
		t.Errorf("Jti = %q, want %q", claims.Jti, "id")
	}
	if claims.AuthTime != 4 {
		t.Errorf("AuthTime = %d, want %d", claims.AuthTime, 4)
	}
	if claims.Nonce != "nonce" {
		t.Errorf("Nonce = %q, want %q", claims.Nonce, "nonce")
	}
	if claims.Acr != "acr" {
		t.Errorf("Acr = %q, want %q", claims.Acr, "acr")
	}
	if len(claims.Amr) != 2 || claims.Amr[0] != "pwd" || claims.Amr[1] != "otp" {
		t.Errorf("Amr = %v, want [pwd otp]", claims.Amr)
	}
	if claims.Azr != "azr" {
		t.Errorf("Azr = %q, want %q", claims.Azr, "azr")
	}
	if len(claims.Unknown) != 2 {
		t.Fatalf("len(Unknown) = %d, want 2", len(claims.Unknown))
	}
	if got := string(claims.Unknown["private"]); got != `"value"` {
		t.Errorf("Unknown[private] = %s, want %s", got, `"value"`)
	}
	if got := string(claims.Unknown["nested"]); got != `{"a":1}` {
		t.Errorf("Unknown[nested] = %s, want %s", got, `{"a":1}`)
	}
}

func TestJWSHeaderDecoding(t *testing.T) {
	header := `{"alg":"RS256","jku":"https://example.com/keys","jwk":"jwk","kid":"key-1","x5u":"https://example.com/cert","x5c":["cert-1","cert-2"],"x5t":"thumb","x5t#S256":"thumb-sha256","typ":"JWT","cty":"JWT","crit":["exp"],"private":true}`

	var j JWT
	err := j.FromCompactSerialization(CompactSerialization{
		Header:  []byte(header),
		Payload: []byte(`{}`),
	})
	if err != nil {
		t.Fatalf("FromCompactSerialization() error = %v", err)
	}

	h := j.Header
	if h.Alg != AlgRS256 {
		t.Errorf("Alg = %q, want %q", h.Alg, AlgRS256)
	}
	if h.Jku != "https://example.com/keys" {
		t.Errorf("Jku = %q, want %q", h.Jku, "https://example.com/keys")
	}
	if h.Jwk != "jwk" {
		t.Errorf("Jwk = %q, want %q", h.Jwk, "jwk")
	}
	if h.Kid != "key-1" {
		t.Errorf("Kid = %q, want %q", h.Kid, "key-1")
	}
	if h.X5u != "https://example.com/cert" {
		t.Errorf("X5u = %q, want %q", h.X5u, "https://example.com/cert")
	}
	if len(h.X5c) != 2 || h.X5c[0] != "cert-1" || h.X5c[1] != "cert-2" {
		t.Errorf("X5c = %v, want [cert-1 cert-2]", h.X5c)
	}
	if h.X5t != "thumb" {
		t.Errorf("X5t = %q, want %q", h.X5t, "thumb")
	}
	if h.X55tS256 != "thumb-sha256" {
		t.Errorf("X55tS256 = %q, want %q", h.X55tS256, "thumb-sha256")
	}
	if h.Typ != "JWT" {
		t.Errorf("Typ = %q, want %q", h.Typ, "JWT")
	}
	if h.Cty != "JWT" {
		t.Errorf("Cty = %q, want %q", h.Cty, "JWT")
	}
	if len(h.Crit) != 1 || h.Crit[0] != "exp" {
		t.Errorf("Crit = %v, want [exp]", h.Crit)
	}
	if len(h.Unknown) != 1 {
		t.Fatalf("len(Unknown) = %d, want 1", len(h.Unknown))
	}
	if got := string(h.Unknown["private"]); got != "true" {
		t.Errorf("Unknown[private] = %s, want true", got)
	}
}

func TestJWTDecodeErrors(t *testing.T) {
	tests := []struct {
		name    string
		header  string
		payload string
		wantErr []error
	}{
		{
			name:    "empty header",
			header:  ``,
			payload: `{}`,
			wantErr: []error{ErrInvalidHeader},
		},
		{
			name:    "invalid header JSON",
			header:  `{`,
			payload: `{}`,
			wantErr: []error{ErrInvalidHeader},
		},
		{
			name:    "header is not an object",
			header:  `[]`,
			payload: `{}`,
			wantErr: []error{ErrInvalidHeader, ErrInvalidJSON},
		},
		{
			name:    "duplicate header field",
			header:  `{"alg":"none","alg":"HS256"}`,
			payload: `{}`,
			wantErr: []error{ErrInvalidHeader},
		},
		{
			name:    "header field has wrong type",
			header:  `{"alg":1}`,
			payload: `{}`,
			wantErr: []error{ErrInvalidHeader},
		},
		{
			name:    "header field name is not a string",
			header:  `{1:2}`,
			payload: `{}`,
			wantErr: []error{ErrInvalidHeader},
		},
		{
			name:    "header field value is malformed",
			header:  `{"alg":}`,
			payload: `{}`,
			wantErr: []error{ErrInvalidHeader},
		},
		{
			name:    "empty payload",
			header:  `{"alg":"none"}`,
			payload: ``,
			wantErr: []error{ErrInvalidPayload},
		},
		{
			name:    "invalid payload JSON",
			header:  `{"alg":"none"}`,
			payload: `{`,
			wantErr: []error{ErrInvalidPayload},
		},
		{
			name:    "payload is not an object",
			header:  `{"alg":"none"}`,
			payload: `[]`,
			wantErr: []error{ErrInvalidPayload, ErrInvalidJSON},
		},
		{
			name:    "duplicate payload field",
			header:  `{"alg":"none"}`,
			payload: `{"sub":"one","sub":"two"}`,
			wantErr: []error{ErrInvalidPayload},
		},
		{
			name:    "payload field has wrong type",
			header:  `{"alg":"none"}`,
			payload: `{"exp":"soon"}`,
			wantErr: []error{ErrInvalidPayload},
		},
		{
			name:    "payload field name is not a string",
			header:  `{"alg":"none"}`,
			payload: `{1:2}`,
			wantErr: []error{ErrInvalidPayload},
		},
		{
			name:    "payload field value is malformed",
			header:  `{"alg":"none"}`,
			payload: `{"sub":}`,
			wantErr: []error{ErrInvalidPayload},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var j JWT
			err := j.FromCompactSerialization(CompactSerialization{
				Header:  []byte(tt.header),
				Payload: []byte(tt.payload),
			})
			for _, want := range tt.wantErr {
				if !errors.Is(err, want) {
					t.Errorf("FromCompactSerialization() error = %v, want errors.Is(_, %v)", err, want)
				}
			}
		})
	}
}

func TestJWTDecodeIgnoresTrailingData(t *testing.T) {
	var j JWT
	err := j.FromCompactSerialization(CompactSerialization{
		Header:  []byte(`{"alg":"none"}trailing`),
		Payload: []byte(`{"sub":"subject"}trailing`),
	})
	if err != nil {
		t.Fatalf("FromCompactSerialization() error = %v", err)
	}
	if j.Payload.Sub != "subject" {
		t.Errorf("Payload.Sub = %q, want %q", j.Payload.Sub, "subject")
	}
}

func TestClaimsUnmarshalDuplicateField(t *testing.T) {
	dec := jsontext.NewDecoder(
		bytes.NewBufferString(`{"sub":"one","sub":"two"}`),
		jsontext.AllowDuplicateNames(true),
	)

	var claims Claims
	err := claims.UnmarshalJSONFrom(dec)
	if !errors.Is(err, ErrDuplicateField) {
		t.Fatalf("UnmarshalJSONFrom() error = %v, want %v", err, ErrDuplicateField)
	}
}

func TestJWSHeaderUnmarshalDuplicateField(t *testing.T) {
	dec := jsontext.NewDecoder(
		bytes.NewBufferString(`{"alg":"none","alg":"HS256"}`),
		jsontext.AllowDuplicateNames(true),
	)

	var header JWSHeader
	err := header.UnmarshalJSONFrom(dec)
	if !errors.Is(err, ErrDuplicateField) {
		t.Fatalf("UnmarshalJSONFrom() error = %v, want %v", err, ErrDuplicateField)
	}
}
