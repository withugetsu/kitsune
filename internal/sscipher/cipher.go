package sscipher

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	
	"github.com/zeebo/blake3"
	"golang.org/x/crypto/chacha20poly1305"
)

var (
	ErrMethodType = errors.New("ciphers: method not supported")
)

type Method string

const (
	Method2022BLAKE3AES128GCM        Method = "2022-blake3-aes-128-gcm"
	Method2022BLAKE3AES256GCM        Method = "2022-blake3-aes-256-gcm"
	Method2022BLAKE3Chacha20Poly1305 Method = "2022-blake3-chacha20-poly1305"
)

func ParseMethod(method string) (Method, error) {
	switch method {
	case "2022-blake3-aes-128-gcm":
		return Method2022BLAKE3AES128GCM, nil
	case "2022-blake3-aes-256-gcm":
		return Method2022BLAKE3AES256GCM, nil
	case "2022-blake3-chacha20-poly1305":
		return Method2022BLAKE3Chacha20Poly1305, nil
	default:
		return "", ErrMethodType
	}
}

func DeriveKey(key, salt []byte) []byte {
	out := make([]byte, len(key))
	blake3.DeriveKey("shadowsocks 2022 session subkey", append(key, salt...), out)
	return out
}

type Cipher struct {
	aead    cipher.AEAD
	counter Counter
	
	key    []byte
	salt   []byte
	method Method
}

func NewAEAD2022BLAKE3AESGCM(key []byte, salt []byte, method Method) (*Cipher, error) {
	drivenKey := DeriveKey(key, salt)
	block, err := aes.NewCipher(drivenKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Cipher{aead: gcm, key: key, salt: salt, method: method}, nil
}

func NewAEAD2022BLAKE3Chacha20Poly1305(key []byte, salt []byte, method Method) (*Cipher, error) {
	drivenKey := DeriveKey(key, salt)
	aead, err := chacha20poly1305.New(drivenKey)
	if err != nil {
		return nil, err
	}
	return &Cipher{aead: aead, key: key, salt: salt, method: method}, nil
}

func NewCipher(key, salt []byte, method Method) (*Cipher, error) {
	switch method {
	case Method2022BLAKE3AES128GCM, Method2022BLAKE3AES256GCM:
		return NewAEAD2022BLAKE3AESGCM(key, salt, method)
	case Method2022BLAKE3Chacha20Poly1305:
		return NewAEAD2022BLAKE3Chacha20Poly1305(key, salt, method)
	default:
		return nil, ErrMethodType
	}
}

func (c *Cipher) NonceSize() int {
	return c.aead.NonceSize()
}

func (c *Cipher) Overhead() int {
	return c.aead.Overhead()
}

func (c *Cipher) Seal(dst, plaintext []byte) []byte {
	dst = c.aead.Seal(dst, c.counter.Nonce(), plaintext, nil)
	c.counter.Count()
	return dst
}

func (c *Cipher) Open(dst, ciphertext []byte) ([]byte, error) {
	dst, err := c.aead.Open(dst, c.counter.Nonce(), ciphertext, nil)
	if err != nil {
		return nil, err
	}
	c.counter.Count()
	return dst, nil
}

func (c *Cipher) Salt() []byte {
	salt := make([]byte, len(c.salt))
	copy(salt, c.salt)
	return salt
}

func (c *Cipher) ReNew(salt []byte) (*Cipher, error) {
	return NewCipher(c.key, salt, c.method)
}
