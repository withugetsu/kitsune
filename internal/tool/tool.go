package tool

import (
	crand "crypto/rand"
	"encoding/binary"
	"io"
	"math/big"
)

func ReadExact(r io.Reader, exact int) ([]byte, error) {
	buf := make([]byte, exact)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func Padding(min, max uint16) ([]byte, error) {
	n, err := crand.Int(crand.Reader, big.NewInt(int64(max-min)))
	if err != nil {
		return nil, err
	}
	nn := uint16(n.Int64())
	
	buf := make([]byte, 2+nn)
	binary.BigEndian.PutUint16(buf, nn)
	
	_, err = crand.Read(buf[2:])
	if err != nil {
		return nil, err
	}
	
	return buf, nil
}
