package ciphers

import "sync"

type Counter struct {
	buf [12]byte
	mu  sync.Mutex
}

func (c *Counter) Count() {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	for i := range c.buf {
		if c.buf[i] == 255 {
			c.buf[i] = 0
		} else {
			c.buf[i]++
			break
		}
	}
}

func (c *Counter) Nonce() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	nonce := make([]byte, 12)
	copy(nonce, c.buf[:])
	return nonce
}
