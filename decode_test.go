package tlv

import (
	"errors"
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestUnmarshal(t *testing.T) {
	moreCases := append(cases, []struct {
		name    string
		decoded any
		encoded []byte
	}{
		{
			name:    "unexpected tlvs",
			decoded: tpointer{Optional: &customMarshal{Value: []byte("Hello?")}},
			encoded: unhex("DEAD0002CAFE0071000648656C6C6F3FCAFE0002DEAD"),
		},
	}...)

	for _, tc := range moreCases {
		t.Run(tc.name, func(t *testing.T) {
			// create a new empty instance of the same type
			instanceType := reflect.TypeOf(tc.decoded)
			testInstance := reflect.New(instanceType).Interface()

			err := Unmarshal(tc.encoded, testInstance)
			require.NoError(t, err)

			// dereference and compare to original
			testInstance = reflect.ValueOf(testInstance).Elem().Interface()
			require.Equal(t, tc.decoded, testInstance)
		})
	}
}

func BenchmarkUnmarshal(b *testing.B) {
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		decoded := reflect.New(reflect.TypeOf(cases[i%len(cases)].decoded)).Interface()
		if err := Unmarshal(cases[i%len(cases)].encoded, decoded); err != nil {
			b.Error(err)
		}
	}
}

type tBrokenUnmarshal struct{}

func (t tBrokenUnmarshal) UnmarshalBinary(_ []byte) error { return errors.New("irreparably broken") }

type tOkayish struct {
	V *customMarshal `tlv:"1"`
}
type tSliceUnsupported struct {
	V []chan any `tlv:"1"`
}
type tMalformedTLV1 struct {
	V *customMarshal `tlv:"NaN"`
}
type tMalformedTLV2 struct {
	V *customMarshal `tlv:"65555"`
}
type tNested struct {
	V1 *tNested1 `tlv:"1"`
}
type tNested1 struct {
	V2 []*tNested2 `tlv:"2"`
}
type tNested2 struct {
	V3 *tBrokenUnmarshal `tlv:"3"`
}

func TestUnmarshalErrors(t *testing.T) {
	bytesOkayish := unhex("00010001FFFFFF")

	cases := []struct {
		name   string
		target any
		bytes  []byte
	}{
		{name: "eof tag", target: &tOkayish{}, bytes: unhex("FF")},
		{name: "eof len", target: &tOkayish{}, bytes: unhex("FFFFFF")},
		{name: "eof value", target: &tOkayish{}, bytes: unhex("FFFFFFFF")},
		{name: "nil", target: nil, bytes: bytesOkayish},
		{name: "non-pointer", target: "not a pointer", bytes: bytesOkayish},
		{name: "unsupported type", target: ref(make(chan any)), bytes: bytesOkayish},
		{name: "unsupported slice type", target: &tSliceUnsupported{}, bytes: bytesOkayish},
		{name: "field unexported", target: &struct{ v customMarshal }{}, bytes: bytesOkayish},
		{name: "field missing tlv", target: &struct{ V customMarshal }{}, bytes: bytesOkayish},
		{name: "field malformed tlv 1", target: &tMalformedTLV1{}, bytes: bytesOkayish},
		{name: "field malformed tlv 2", target: &tMalformedTLV2{}, bytes: bytesOkayish},
		{name: "nested error", target: &tNested{}, bytes: unhex("000100090002000500030001FF")},
		//{name: "unexpected tlv", target: &tOkayish{}, bytes: unhex("DEAD0001FF")},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := Unmarshal(tc.bytes, tc.target)
			t.Log(err)
			require.Error(t, err)
		})
	}
}
