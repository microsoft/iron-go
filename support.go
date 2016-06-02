package iron

import (
	"crypto/rand"
	"encoding/base64"
	"strconv"
	"strings"
	"time"
)

var (
	macFormatVersion = "2"
	macPrefix        = "Fe26." + macFormatVersion
	delimiter        = "*"
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
	parts := strings.Split(s, delimiter)
	if len(parts) != 8 {
		return UnsealError{"Incorrect number of sealed components"}
	}
	if parts[0] != macPrefix {
		return UnsealError{"Wrong mac prefix"}
	}
	if len(parts[5]) > 0 {
		exp, err := strconv.ParseInt(parts[5], 10, 64)
		if err != nil {
			return UnsealError{"Invalid expiration time"}
		}
		m.Expiration = time.Unix(0, exp*int64(time.Millisecond))
	}

	errs := []error{
		base64decodeInto(&m.IV, parts[3]),
		base64decodeInto(&m.EncryptedBody, parts[4]),
		base64decodeInto(&m.HMAC, parts[7]),
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

// Pack serializes the message into a cookie string.
func (m *message) Pack() string {
	return strings.Join([]string{
		m.Base(),
		string(m.HMACSalt),
		base64.RawURLEncoding.EncodeToString(m.HMAC),
	}, delimiter)
}

// Base returns the MAC base string, which is the cookie excluding the
// salt and hmac components.
func (m *message) Base() string {
	if m.base != "" {
		return m.base
	}

	parts := []string{
		macPrefix,
		"", // todo: password rotation component
		string(m.Salt),
		base64.RawURLEncoding.EncodeToString(m.IV),
		base64.RawURLEncoding.EncodeToString(m.EncryptedBody),
		"",
	}

	if !m.Expiration.IsZero() {
		parts[5] = strconv.FormatInt(m.Expiration.UnixNano()/int64(time.Millisecond), 10)
	}

	m.base = strings.Join(parts, delimiter)
	return m.base
}

// base64decodeInto attempts to base64 decode the source string into the
// target address. It returns an error if the source is invalid.
func base64decodeInto(target *[]byte, src string) error {
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
