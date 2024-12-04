package tlv

import (
	"encoding/hex"
)

func unhex(s string) []byte {
	if b, err := hex.DecodeString(s); err != nil {
		panic(err)
	} else {
		return b
	}
}

// TODO: Primitive valued TLVs don't seem to exist?
//       Why are we handling the marshal/unmarshal for them at all?

type tints struct {
	I8  int8  `tlv:"101"`
	I16 int16 `tlv:"102"`
	I32 int32 `tlv:"103"`
	I64 int64 `tlv:"104"`
}

type tuints struct {
	UI8  uint8  `tlv:"105"`
	UI16 uint16 `tlv:"106"`
	UI32 uint32 `tlv:"107"`
	UI64 uint64 `tlv:"108"`
}

type tstrings struct {
	S string `tlv:"109"`
	B []byte `tlv:"110"`
}

type tslice struct {
	Grouped []customMarshal `tlv:"112"`
}

type tpointer struct {
	Optional *customMarshal `tlv:"113"`
}

type tsliceofpointers struct {
	Grouped []*customMarshal `tlv:"114"`
}

type tchonky struct {
	I  *tints            `tlv:"115"`
	S  *tslice           `tlv:"116"`
	R  *tpointer         `tlv:"117"`
	SR *tsliceofpointers `tlv:"118"`
}

type customMarshal struct{ Value []byte }

func (mt *customMarshal) MarshalBinary() ([]byte, error) { return mt.Value, nil }

func (mt *customMarshal) UnmarshalBinary(data []byte) error { mt.Value = data; return nil }

var cases = []struct {
	name    string
	decoded any
	encoded []byte
}{
	{
		name: "integers",
		decoded: tints{
			I8:  0x7A,
			I16: -0x7AFE,
			I32: 0x7AFEDEAD,
			I64: -0x7AFEDEAD7AFEDEAD,
		},
		encoded: unhex("006500017A006600028502006700047AFEDEAD006800088501215285012153"),
	},
	{
		name: "unsigned integers",
		decoded: tuints{
			UI8:  0xCA,
			UI16: 0xCAFE,
			UI32: 0xCAFEDEAD,
			UI64: 0xCAFEDEADCAFEDEAD,
		},
		encoded: unhex("00690001CA006A0002CAFE006B0004CAFEDEAD006C0008CAFEDEADCAFEDEAD"),
	},
	{
		name: "strings",
		decoded: tstrings{
			S: "Hello, World!",
			B: []byte("Byebye, World!"),
		},
		encoded: unhex("006D000D48656C6C6F2C20576F726C6421006E000E4279656279652C20576F726C6421"),
	},
	{
		name: "slice",
		decoded: tslice{Grouped: []customMarshal{
			{Value: []byte("Hello")},
			{Value: []byte("free5GC")},
			{Value: []byte("World")},
		}},
		encoded: unhex("0070000548656C6C6F007000076672656535474300700005576F726C64"),
	},
	{
		name:    "pointer",
		decoded: tpointer{Optional: &customMarshal{Value: []byte("Hello?")}},
		encoded: unhex("0071000648656C6C6F3F"),
	},
	{
		name: "slice of pointers",
		decoded: tsliceofpointers{Grouped: []*customMarshal{
			{Value: []byte("Hello?")},
			{Value: []byte("free5GC?")},
			{Value: []byte("World?")},
		}},
		encoded: unhex("0072000648656C6C6F3F00720008667265653547433F00720006576F726C643F"),
	},
	{
		name: "chonky",
		decoded: tchonky{
			I: &tints{I8: 1, I16: 2, I32: 3, I64: 4},
			S: &tslice{Grouped: []customMarshal{
				{Value: []byte("Far")},
				{Value: []byte("Over")},
				{Value: []byte("The")},
			}},
			R: &tpointer{Optional: &customMarshal{Value: []byte("Misty?")}},
			SR: &tsliceofpointers{Grouped: []*customMarshal{
				{Value: []byte("Mountains?")},
				{Value: []byte("Cold?")},
				{Value: []byte("To?")},
			}},
		},
		encoded: unhex("0073001F00650001010066000200020067000400000003006800080000000000000004" +
			"0074001600700003466172007000044F766572007000035468650075000A007100064D697374793F0076" +
			"001E0072000A4D6F756E7461696E733F00720005436F6C643F00720003546F3F"),
	},
}
