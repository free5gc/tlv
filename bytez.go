package tlv

import (
	"encoding/binary"
	"io"
)

// bytez is a zero-copy read-only byte buffer,
// name selected to avoid clashing with the standard library's bytes package
type bytez []byte

func (b *bytez) ReadUint8() (v uint8, err error) {
	if len(*b) < 1 {
		return 0, io.EOF
	}
	v, *b = (*b)[0], (*b)[1:]
	return
}

func (b *bytez) ReadUint16() (v uint16, err error) {
	if len(*b) < 2 {
		return 0, io.EOF
	}
	v, *b = binary.BigEndian.Uint16(*b), (*b)[2:]
	return
}

func (b *bytez) ReadUint32() (v uint32, err error) {
	if len(*b) < 4 {
		return 0, io.EOF
	}
	v, *b = binary.BigEndian.Uint32(*b), (*b)[4:]
	return
}

func (b *bytez) ReadUint64() (v uint64, err error) {
	if len(*b) < 8 {
		return 0, io.EOF
	}
	v, *b = binary.BigEndian.Uint64(*b), (*b)[8:]
	return
}

func (b *bytez) ReadInt8() (v int8, err error) {
	if len(*b) < 1 {
		return 0, io.EOF
	}
	v, *b = int8((*b)[0]), (*b)[1:]
	return
}

func (b *bytez) ReadInt16() (v int16, err error) {
	if len(*b) < 2 {
		return 0, io.EOF
	}
	v, *b = int16(binary.BigEndian.Uint16(*b)), (*b)[2:]
	return
}

func (b *bytez) ReadInt32() (v int32, err error) {
	if len(*b) < 4 {
		return 0, io.EOF
	}
	v, *b = int32(binary.BigEndian.Uint32(*b)), (*b)[4:]
	return
}

func (b *bytez) ReadInt64() (v int64, err error) {
	if len(*b) < 8 {
		return 0, io.EOF
	}
	v, *b = int64(binary.BigEndian.Uint64(*b)), (*b)[8:]
	return
}

func (b *bytez) ReadSlice(n int) (v bytez, err error) {
	if len(*b) < n {
		return nil, io.EOF
	}
	v, *b = (*b)[:n], (*b)[n:]
	return
}

func (b *bytez) ReadString(n int) (v string, err error) {
	s, err := b.ReadSlice(n)
	v = string(s)
	return
}
