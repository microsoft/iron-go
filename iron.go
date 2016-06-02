package iron

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"hash"
	"time"

	"golang.org/x/crypto/pbkdf2"
)

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
			IVBits:     128,
			KeyBits:    256,
			Iterations: 1,
			SaltBits:   256,
			Cipher:     AES256,
		}
	}

	if o.Integrity == nil {
		o.Integrity = &Integrity{
			Hash:       sha256.New,
			KeyBits:    256,
			Iterations: 1,
			SaltBits:   256,
		}
	}

	return o
}

// New creates a new Vault which can seal and unseal Iron cookies.
func New(options Options) *Vault { return &Vault{options.fillDefaults()} }

// Vault is a structure capable is sealing and unsealing Iron cookies.
type Vault struct{ opts Options }

var (
	macFormatVersion  = "2"
	expectedMacPrefix = "Fe26." + macFormatVersion
)

func (v *Vault) generateKey(keybits uint, iterations uint, salt []byte) []byte {
	return pbkdf2.Key(v.opts.Secret, salt, int(iterations), int(keybits/8), sha1.New)
}

type hmacResult struct {
	Digest []byte
	Salt   []byte
}

func (v *Vault) hmacWithPassword(salt []byte, data string) (out hmacResult, err error) {
	key := v.generateKey(v.opts.Integrity.KeyBits, v.opts.Integrity.Iterations, salt)
	h := hmac.New(v.opts.Integrity.Hash, key)
	if _, err := h.Write([]byte(data)); err != nil {
		return out, err
	}

	out.Digest = h.Sum(nil)
	return out, nil
}

func (v *Vault) decrypt(msg *message) ([]byte, error) {
	key := v.generateKey(v.opts.Encryption.KeyBits, v.opts.Encryption.Iterations, msg.Salt)
	_, decrypt, err := v.opts.Encryption.Cipher(key, msg.IV)
	if err != nil {
		return nil, err
	}

	data := make([]byte, len(msg.EncryptedBody))
	decrypt.CryptBlocks(data, msg.EncryptedBody)
	return data, nil
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
		delta := time.Now().Add(v.opts.LocalTimeOffset).Sub(msg.Expiration)
		if delta > v.opts.TimestampSkew || delta < v.opts.TimestampSkew {
			return nil, UnsealError{"Expired or invalid seal"}
		}
	}

	// 2. Run the MAC digest against the message excluding our additional
	// salt and hmac

	mac, err := v.hmacWithPassword(msg.HMACSalt, msg.Base())
	if err != nil {
		return nil, err
	}

	// 3. Check the HMAC

	if subtle.ConstantTimeCompare(mac.Digest, msg.HMAC) == 0 {
		return nil, UnsealError{"Bad hmac value"}
	}

	// 4. Decrypt!

	return v.decrypt(msg)
}
