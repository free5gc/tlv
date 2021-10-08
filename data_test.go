package tlv

import "strconv"

type BinaryMarshalTest struct {
	Value int
}

func (mt *BinaryMarshalTest) MarshalBinary() (data []byte, err error) {
	return []byte(strconv.Itoa(mt.Value)), nil
}

func (mt *BinaryMarshalTest) UnmarshalBinary(data []byte) (err error) {
	mt.Value, err = strconv.Atoi(string(data))
	return err
}
