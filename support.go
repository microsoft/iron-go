package iron

import (
	"crypto/rand"
	"encoding/base64"
	"strconv"
	"strings"
	"time"
)

type message struct {
	base string // this is the cookie message excluding the hmac and salt

	Salt          []byte
	IV            []byte
	EncryptedBody []byte
	Expiration    time.Time
	HMACSalt      []byte
	HMAC          []byte
}

// Unpack attempts to populate the message by unmarshaling the provided string.
// It returns an UnsealError if the string isn't valid.
func (m *message) Unpack(s string) error {
	parts := strings.Split(s, "*")
	if len(parts) != 8 {
		return UnsealError{"Incorrect number of sealed components"}
	}
	if parts[0] != expectedMacPrefix {
		return UnsealError{"Wrong mac prefix"}
	}
	if len(parts[5]) > 0 {
		exp, err := strconv.ParseInt(parts[5], 10, 64)
		if err != nil {
			return UnsealError{"Invalid expiration time"}
		}
		m.Expiration = time.Unix(0, exp)
	}

	errs := []error{
		basee64decodeInto(&m.IV, parts[3]),
		basee64decodeInto(&m.EncryptedBody, parts[4]),
		basee64decodeInto(&m.HMAC, parts[7]),
	}

	for _, err := range errs {
		if err != nil {
			return UnsealError{"Invalid component encoding"}
		}
	}

	m.Salt = []byte(parts[2])
	m.HMACSalt = []byte(parts[6])
	m.base = s[0 : len(s)-len(parts[7])-1-len(parts[6])-1]
	return nil
}

// Base returns the MAC base string, which is the cookie excluding the
// salt and hmac components.
func (m *message) Base() string {
	if m.base != "" {
		return m.base
	}

	panic("base string not set")
}

// basee64decodeInto attempts to base64 decode the source string into the
// target address. It returns an error if the source is invalid.
func basee64decodeInto(target *[]byte, src string) error {
	res, err := base64.RawURLEncoding.DecodeString(src)
	*target = res
	return err
}

// randBits creates and returns n random bits.
func randBits(n uint) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	return b, err
}

// UnsealError is returned from Unseal() if the message is invalid.
type UnsealError struct{ message string }

// Error implements error.Error
func (u UnsealError) Error() string { return u.message }
