package tool

import (
	crand "crypto/rand"
	"encoding/binary"
	"io"
	"math/rand/v2"
)

func ReadExact(r io.Reader, exact int) ([]byte, error) {
	buf := make([]byte, exact)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func RandomPadding(minPaddingLength, maxPaddingLength uint) ([]byte, error) {
	n := rand.UintN(maxPaddingLength) + minPaddingLength
	buf := make([]byte, 2+n)
	binary.BigEndian.PutUint16(buf, uint16(n))
	
	_, err := crand.Read(buf[2:])
	if err != nil {
		return nil, err
	}
	
	return buf, nil
}
