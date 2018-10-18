package iron

import "testing"

func TestPack(t *testing.T) {
	var tests = []struct {
		msg  *message
		name string
		want string
	}{
		{&message{}, "empty message", "Fe26.2*******"},
		{&message{base: "base"}, "with a base", "base**"},
		{&message{HMAC: []byte("hmac")}, "with hmac", "Fe26.2*******aG1hYw"},
		{&message{HMAC: []byte("hmac"), HMACSalt: []byte("hmacsalt")}, "with hmac-salt", "Fe26.2******hmacsalt*aG1hYw"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.msg.Pack()
			if got != tt.want {
				t.Errorf("message.Pack() got %s, want %s", got, tt.want)
			}
		})
	}
}

func TestUnpack(t *testing.T) {
	var tests = []struct {
		msg      *message
		name     string
		str      string
		errIsNil bool
	}{
		{&message{}, "not 8 parts", "", false},
		{&message{}, "not a mac prefix", "a*a*a*a*a*a*a*a", false},
		{&message{}, "invalid expiration time", "Fe26.2*a*a*a*a*a*a*a", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.msg.Unpack(tt.str)
			gotErrIsNil := err == nil
			if gotErrIsNil != tt.errIsNil {
				t.Errorf("message.Unpack(%s) got errIsNil=%t, want errIsNil=%t, err: %v", tt.str, gotErrIsNil, tt.errIsNil, err)
			}
		})
	}
}

func TestBase(t *testing.T) {
	var tests = []struct {
		msg  *message
		name string
		want string
	}{
		{&message{base: "base"}, "non-empty base", "base"},
		{&message{IV: []byte("iv")}, "with iv", "Fe26.2***aXY**"},
		{&message{IV: []byte("iv"), EncryptedBody: []byte("body")}, "with iv and encrypted-body", "Fe26.2***aXY*Ym9keQ*"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.msg.Base()
			if got != tt.want {
				t.Errorf("message.Base() got %s, want %s", got, tt.want)
			}
		})
	}
}
