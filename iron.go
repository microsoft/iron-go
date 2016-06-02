package iron

import (
	"bytes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"hash"
	"time"

	"golang.org/x/crypto/pbkdf2"
)

// Padding symbol used by Iron. This will be added when encrypting and trimmed
// out when decrypting.
const padder = '\t'

// An Integrity struct is contained in the Options struct and describes
// configuration for cookie integrity verification.
type Integrity struct {
	// KeyBits defines how large the signing key should be.
	KeyBits uint

	// Iteracts is the number of iterations to derive a key from the
	// secret. Set to ` by default.
	Iterations uint

	// The size of the salt (random buffer used to ensure that two identical
	// objects will generate a different encrypted result. Ignored if salt
	// set explicitly.
	SaltBits uint

	// Hash returns a new hasher used to digest the cookie.
	Hash func() hash.Hash
}

// An Encryption struct is contained in the Options object and used to
// configure how cookies are encrypted.
type Encryption struct {
	// KeyBits defines how large the signing key should be.
	KeyBits uint

	// Iteracts is the number of iterations to derive a key from the
	// secret. Set to ` by default.
	Iterations uint

	// The size of the salt (random buffer used to ensure that two identical
	// objects will generate a different encrypted result. Ignored if salt
	// set explicitly.
	SaltBits uint

	// Cipher is the cipher used to encrypt and decrypt the cookie.
	Cipher CipherFactory

	// IVBits is the number of IV bits to generate, ignored if the the IV
	// property is set explicitly.
	IVBits uint
}

// Options is passed into New() to configure the cookie options.
type Options struct {
	// Secret key to use for encrypting/decrypting data.
	Secret []byte
	// TTL is the sealed object lifetime, infinite if zero. Defaults to zero.
	TTL time.Duration
	// Permitted clock skew for incoming expirations. Defaults to 60 seconds.
	TimestampSkew time.Duration
	// Local clock offset, defaults to zero.
	LocalTimeOffset time.Duration

	Encryption *Encryption
	Integrity  *Integrity
}

// fillDefaults creates a new Options object with default values filled in.
func (o Options) fillDefaults() Options {
	if len(o.Secret) < 32 {
		panic("iron-go: secret key may not be less than 32 bits")
	}

	if o.TimestampSkew == 0 {
		o.TimestampSkew = time.Second * 60
	}

	if o.Encryption == nil {
		o.Encryption = &Encryption{
			IVBits:     16,
			KeyBits:    256,
			Iterations: 1,
			SaltBits:   32,
			Cipher:     AES256,
		}
	}

	if o.Integrity == nil {
		o.Integrity = &Integrity{
			Hash:       sha256.New,
			KeyBits:    256,
			Iterations: 1,
			SaltBits:   32,
		}
	}

	return o
}

// New creates a new Vault which can seal and unseal Iron cookies.
func New(options Options) *Vault { return &Vault{options.fillDefaults()} }

// Vault is a structure capable is sealing and unsealing Iron cookies.
type Vault struct{ opts Options }

func (v *Vault) generateKey(keybits uint, iterations uint, salt []byte) []byte {
	return pbkdf2.Key(v.opts.Secret, salt, int(iterations), int(keybits/8), sha1.New)
}

type hmacResult struct {
	Digest []byte
	Salt   []byte
}

func (v *Vault) hmacWithPassword(salt []byte, data string) (digest []byte, err error) {
	key := v.generateKey(v.opts.Integrity.KeyBits, v.opts.Integrity.Iterations, salt)
	h := hmac.New(v.opts.Integrity.Hash, key)
	if _, err := h.Write([]byte(data)); err != nil {
		return nil, err
	}

	return h.Sum(nil), nil
}

func (v *Vault) decrypt(msg *message) ([]byte, error) {
	key := v.generateKey(v.opts.Encryption.KeyBits, v.opts.Encryption.Iterations, msg.Salt)
	_, decrypt, err := v.opts.Encryption.Cipher(key, msg.IV)
	if err != nil {
		return nil, err
	}

	data := make([]byte, len(msg.EncryptedBody))
	decrypt.CryptBlocks(data, msg.EncryptedBody)
	return bytes.TrimRight(data, string(padder)), nil
}

func (v *Vault) generateSalt(size uint) ([]byte, error) {
	rawSalt, err := randBits(v.opts.Encryption.SaltBits)
	if err != nil {
		return nil, err
	}
	salt := make([]byte, base64.RawURLEncoding.EncodedLen(len(rawSalt)))
	base64.RawURLEncoding.Encode(salt, rawSalt)
	return salt, nil
}

func (v *Vault) encryptBlocks(block cipher.BlockMode, b []byte) []byte {
	size := block.BlockSize()
	b = append(b, bytes.Repeat([]byte{padder}, size-len(b)%size)...)
	out := make([]byte, len(b))

	for i := 0; i < len(b); i += size {
		block.CryptBlocks(out[i:i+size], b[i:i+size])
	}

	return out
}

func (v *Vault) encrypt(b []byte) (*message, error) {
	salt, err := v.generateSalt(v.opts.Encryption.SaltBits)
	if err != nil {
		return nil, err
	}

	key := v.generateKey(v.opts.Encryption.KeyBits, v.opts.Encryption.Iterations, salt)
	iv, err := randBits(v.opts.Encryption.IVBits)
	if err != nil {
		return nil, err
	}

	encrypt, _, err := v.opts.Encryption.Cipher(key, iv)
	if err != nil {
		return nil, err
	}

	return &message{
		EncryptedBody: v.encryptBlocks(encrypt, b),
		IV:            iv,
		Salt:          salt,
	}, nil
}

// Unseal attempts to extract the encrypted information from the message.
// It takes some options, or nil to use defaults. It returns an
// UnsealError if the message is invalid.
func (v *Vault) Unseal(str string) ([]byte, error) {
	msg := &message{}
	if err := msg.Unpack(str); err != nil {
		return nil, err
	}

	// 1. Check expiration

	if !msg.Expiration.IsZero() {
		delta := msg.Expiration.Sub(time.Now().Add(v.opts.LocalTimeOffset))
		if delta < -v.opts.TimestampSkew {
			return nil, UnsealError{"Expired or invalid seal"}
		}
	}

	// 2. Run the MAC digest against the message excluding our additional
	// salt and hmac

	digest, err := v.hmacWithPassword(msg.HMACSalt, msg.Base())
	if err != nil {
		return nil, err
	}

	// 3. Check the HMAC

	if subtle.ConstantTimeCompare(digest, msg.HMAC) == 0 {
		return nil, UnsealError{"Bad hmac value"}
	}

	// 4. Decrypt!

	return v.decrypt(msg)
}

// Seal encrypts and signs the byte slice into an Iron cookie.
func (v *Vault) Seal(b []byte) (string, error) {

	// 1. Encrypt the payload

	msg, err := v.encrypt(b)
	if err != nil {
		return "", err
	}
	if v.opts.TTL > 0 {
		msg.Expiration = time.Now().Add(v.opts.TTL)
	}

	// 2. Generate an HMAC signature

	hmacSalt, err := v.generateSalt(v.opts.Integrity.SaltBits)
	if err != nil {
		return "", err
	}
	digest, err := v.hmacWithPassword(hmacSalt, msg.Base())

	// 3. Generate the packed result

	msg.HMACSalt = hmacSalt
	msg.HMAC = digest
	return msg.Pack(), nil
}
