package ciphers

import (
	"context"
	"crypto/rand"
	"sync"
	"time"
)

func NewSalt(ct Method) ([]byte, error) {
	keySize, err := ct.KeySize()
	if err != nil {
		return nil, err
	}
	
	salt := make([]byte, keySize)
	if _, err = rand.Read(salt); err != nil {
		return nil, err
	}
	
	return salt, nil
}

type SaltPool struct {
	ctx context.Context
	m   sync.Map
}

func NewSaltPool(ctx context.Context) *SaltPool {
	return &SaltPool{
		ctx: ctx,
	}
}

func (sp *SaltPool) AddSalt(salt []byte) bool {
	key := string(salt)
	_, loaded := sp.m.LoadOrStore(key, time.Now())
	return !loaded
}

func (sp *SaltPool) Run() {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			sp.m.Range(func(key, value any) bool {
				ts := value.(time.Time)
				if time.Since(ts) > time.Minute {
					sp.m.Delete(key)
				}
				return true
			})
		case <-sp.ctx.Done():
			return
		}
	}
}
