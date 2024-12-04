package tlv

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMarshal(t *testing.T) {
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			buf, err := Marshal(tc.decoded)
			require.NoError(t, err)
			require.Equal(t, tc.encoded, buf)
		})
	}
}

func BenchmarkMarshal(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		if _, err := Marshal(cases[i%len(cases)].decoded); err != nil {
			b.Error(err)
		}
	}
}
