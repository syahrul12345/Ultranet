package lib

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBreakUpInvMsg(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_, _ = assert, require

	invMsg := &MsgUltranetInv{
		InvList: []*InvVect{
			&InvVect{
				Type: InvTypeTx,
				Hash: *mustDecodeHexBlockHash("0000000000000000000000000000000000000000000000000000000000000000"),
			},
			&InvVect{
				Type: InvTypeTx,
				Hash: *mustDecodeHexBlockHash("1000000000000000000000000000000000000000000000000000000000000000"),
			},
			&InvVect{
				Type: InvTypeTx,
				Hash: *mustDecodeHexBlockHash("2000000000000000000000000000000000000000000000000000000000000000"),
			},
			&InvVect{
				Type: InvTypeTx,
				Hash: *mustDecodeHexBlockHash("3000000000000000000000000000000000000000000000000000000000000000"),
			},
			&InvVect{
				Type: InvTypeTx,
				Hash: *mustDecodeHexBlockHash("4000000000000000000000000000000000000000000000000000000000000000"),
			},
			&InvVect{
				Type: InvTypeTx,
				Hash: *mustDecodeHexBlockHash("5000000000000000000000000000000000000000000000000000000000000000"),
			},
			&InvVect{
				Type: InvTypeTx,
				Hash: *mustDecodeHexBlockHash("6000000000000000000000000000000000000000000000000000000000000000"),
			},
		},
	}

	brokenUpInvs := _breakUpInvMsg(invMsg, 3)
	require.Equal(3, len(brokenUpInvs))
	require.Equal(3, len(brokenUpInvs[0].InvList))
	require.Equal(3, len(brokenUpInvs[1].InvList))
	require.Equal(1, len(brokenUpInvs[2].InvList))
	//spew.Dump(brokenUpInvs)
}

func TestBreakUpHashes(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_, _ = assert, require

	hashes := []*BlockHash{
		mustDecodeHexBlockHash("0000000000000000000000000000000000000000000000000000000000000000"),
		mustDecodeHexBlockHash("1000000000000000000000000000000000000000000000000000000000000000"),
		mustDecodeHexBlockHash("2000000000000000000000000000000000000000000000000000000000000000"),
		mustDecodeHexBlockHash("3000000000000000000000000000000000000000000000000000000000000000"),
		mustDecodeHexBlockHash("4000000000000000000000000000000000000000000000000000000000000000"),
		mustDecodeHexBlockHash("5000000000000000000000000000000000000000000000000000000000000000"),
		mustDecodeHexBlockHash("6000000000000000000000000000000000000000000000000000000000000000"),
	}

	brokenUpHashes := _breakUpHashes(hashes, 3)
	require.Equal(3, len(brokenUpHashes))
	require.Equal(3, len(brokenUpHashes[0]))
	require.Equal(3, len(brokenUpHashes[1]))
	require.Equal(1, len(brokenUpHashes[2]))
	//spew.Dump(brokenUpInvs)
}
