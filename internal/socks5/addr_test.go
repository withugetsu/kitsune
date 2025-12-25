package socks5

import (
	"encoding/binary"
	"net"
	"reflect"
	"testing"
)

func TestAddr_Bytes(t *testing.T) {
	type fields struct {
		ATYP Atyp
		Addr []byte
		Port uint16
	}
	tests := []struct {
		name   string
		fields fields
		want   []byte
	}{
		{
			name: "127.0.0.1:8080",
			fields: fields{
				ATYP: AtypIPV4,
				Addr: []byte{
					127, 0, 0, 1,
				},
				Port: 8080,
			},
			want: func() []byte {
				buf := make([]byte, 0, 1+net.IPv4len+2)
				
				buf = append(buf, byte(AtypIPV4))
				
				buf = append(buf, net.IPv4(127, 0, 0, 1).To4()...)
				
				p := make([]byte, 2)
				binary.BigEndian.PutUint16(p, uint16(8080))
				
				buf = append(buf, p...)
				
				return buf
			}(),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &Addr{
				ATYP: tt.fields.ATYP,
				Addr: tt.fields.Addr,
				Port: tt.fields.Port,
			}
			if got := a.Bytes(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Bytes() = %v, want %v", got, tt.want)
			}
		})
	}
}
