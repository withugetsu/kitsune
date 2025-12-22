package ciphers

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	
	"github.com/zeebo/blake3"
	"golang.org/x/crypto/chacha20poly1305"
)

var (
	ErrKeySize  = errors.New("ciphers: invalid key size")
	ErrSaltSize = errors.New("ciphers: invalid salt size")
)

const (
	AEAD2022BLAKE3AES128GCM Method = iota
	AEAD2022BLAKE3AES256GCM
	AEAD2022BLAKE3Chacha20Poly1305
)

type Method int

func (m Method) KeySize() (int, error) {
	switch m {
	case AEAD2022BLAKE3AES128GCM:
		return 16, nil
	case AEAD2022BLAKE3AES256GCM, AEAD2022BLAKE3Chacha20Poly1305:
		return 32, nil
	default:
		return 0, ErrKeySize
	}
}

type Cipher struct {
	cipher.AEAD
	M    Method
	Salt []byte
	
	counter Counter
}

func NewCipher(m Method, key []byte) (*Cipher, error) {
	keySize, err := m.KeySize()
	if err != nil {
		return nil, err
	}
	
	if len(key) != keySize {
		return nil, ErrKeySize
	}
	
	salt, err := NewSalt(m)
	if err != nil {
		return nil, err
	}
	
	return newCipherWithSalt(m, key, salt, keySize)
}

func NewCipherWithSalt(m Method, key []byte, salt []byte) (*Cipher, error) {
	keySize, err := m.KeySize()
	if err != nil {
		return nil, err
	}
	
	if len(key) != keySize {
		return nil, ErrKeySize
	}
	
	if len(salt) != keySize {
		return nil, ErrSaltSize
	}
	
	return newCipherWithSalt(m, key, salt, keySize)
}

func newCipherWithSalt(m Method, key []byte, salt []byte, keySize int) (*Cipher, error) {
	sessionSubKey := deriveKey(key, salt, keySize)
	
	var aead cipher.AEAD
	if m == AEAD2022BLAKE3AES128GCM || m == AEAD2022BLAKE3AES256GCM {
		block, err := aes.NewCipher(sessionSubKey)
		if err != nil {
			return nil, err
		}
		aead, err = cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}
	} else {
		var err error
		aead, err = chacha20poly1305.New(sessionSubKey)
		if err != nil {
			return nil, err
		}
	}
	
	c := &Cipher{
		AEAD: aead,
		M:    m,
		Salt: salt,
	}
	
	return c, nil
}

func (c *Cipher) Seal(dst, plaintext []byte) []byte {
	dst = c.AEAD.Seal(dst, c.counter.Nonce(), plaintext, nil)
	c.counter.Count()
	return dst
}

func (c *Cipher) Open(dst, ciphertext []byte) ([]byte, error) {
	dst, err := c.AEAD.Open(dst, c.counter.Nonce(), ciphertext, nil)
	if err != nil {
		return nil, err
	}
	c.counter.Count()
	return dst, nil
}

func deriveKey(key, salt []byte, keySize int) []byte {
	out := make([]byte, keySize)
	blake3.DeriveKey("shadowsocks 2022 session subkey", append(key, salt...), out)
	return out
}
