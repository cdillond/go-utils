package jwt

import (
	"bytes"
	"errors"
	"testing"
)

func TestCompactSerializationUnmarshalCompact(t *testing.T) {
	header := `{"alg":"HS256","typ":"JWT"}`
	payload := `{"sub":"1234567890"}`
	signature := []byte{0x01, 0x02, 0x03, 0x04}

	tests := []struct {
		name        string
		input       []byte
		wantHeader  []byte
		wantPayload []byte
		wantSig     []byte
		wantRaw     []byte
		wantErr     error
	}{
		{
			name:        "signed",
			input:       compactToken(header, payload, signature),
			wantHeader:  []byte(header),
			wantPayload: []byte(payload),
			wantSig:     signature,
			wantRaw:     signingInput(header, payload),
		},
		{
			name:        "unsigned",
			input:       unsignedToken(header, payload),
			wantHeader:  []byte(header),
			wantPayload: []byte(payload),
			wantRaw:     unsignedToken(header, payload),
		},
		{
			name:        "empty signature segment",
			input:       []byte(string(signingInput(header, payload)) + "."),
			wantHeader:  []byte(header),
			wantPayload: []byte(payload),
			wantRaw:     signingInput(header, payload),
		},
		{
			name:    "too few parts",
			input:   []byte("only-one-part"),
			wantErr: ErrTooFewParts,
		},
		{
			name:    "empty input",
			input:   nil,
			wantErr: ErrTooFewParts,
		},
		{
			name:    "too many parts",
			input:   []byte("a.b.c.d"),
			wantErr: ErrTooManyParts,
		},
		{
			name:    "invalid header encoding",
			input:   []byte("!!!." + encodeSegment([]byte(payload))),
			wantErr: ErrInvalidHeader,
		},
		{
			name:    "invalid payload encoding",
			input:   []byte(encodeSegment([]byte(header)) + ".!!!"),
			wantErr: ErrInvalidPayload,
		},
		{
			name:    "invalid signature encoding",
			input:   []byte(string(signingInput(header, payload)) + ".!!!"),
			wantErr: ErrInvalidSig,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var c CompactSerialization
			err := c.UnmarshalCompact(tt.input)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("UnmarshalCompact() error = %v, want %v", err, tt.wantErr)
			}
			if tt.wantErr != nil {
				return
			}

			if !bytes.Equal(c.Header, tt.wantHeader) {
				t.Errorf("Header = %s, want %s", c.Header, tt.wantHeader)
			}
			if !bytes.Equal(c.Payload, tt.wantPayload) {
				t.Errorf("Payload = %s, want %s", c.Payload, tt.wantPayload)
			}
			if !bytes.Equal(c.Signature, tt.wantSig) {
				t.Errorf("Signature = %v, want %v", c.Signature, tt.wantSig)
			}
			if !bytes.Equal(c.RawMessage, tt.wantRaw) {
				t.Errorf("RawMessage = %s, want %s", c.RawMessage, tt.wantRaw)
			}
		})
	}
}
