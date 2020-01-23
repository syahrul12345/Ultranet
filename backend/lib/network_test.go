package lib

import (
	"bytes"
	"math"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var expectedVer = &MsgUltranetVersion{
	Version:              1,
	Services:             SFFullNode,
	TstampSecs:           2,
	Nonce:                uint64(0xffffffffffffffff),
	UserAgent:            "abcdef",
	StartBlockHeight:     4,
	MinFeeRateNanosPerKB: 10,
	JSONAPIPort:          12345,
}

var expectedBlockHeader = &MsgUltranetHeader{
	Version: 1,
	PrevBlockHash: &BlockHash{
		0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11,
		0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x20, 0x21,
		0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x30, 0x31,
		0x32, 0x33,
	},
	TransactionMerkleRoot: &BlockHash{
		0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x40, 0x41, 0x42, 0x43,
		0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x50, 0x51, 0x52, 0x53,
		0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x60, 0x61, 0x62, 0x63,
		0x64, 0x65,
	},
	TstampSecs: uint32(0x70717273),
	Height:     uint32(99999),
	Nonce:      uint32(123456),
}

func TestGetHeadersSerialization(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	hash1 := expectedBlockHeader.PrevBlockHash
	hash2 := expectedBlockHeader.TransactionMerkleRoot

	getHeaders := &MsgUltranetGetHeaders{
		StopHash:     hash1,
		BlockLocator: []*BlockHash{hash1, hash2, hash1},
	}

	messageBytes, err := getHeaders.ToBytes(false)
	require.NoError(err)
	newMessage := &MsgUltranetGetHeaders{}
	err = newMessage.FromBytes(messageBytes)
	require.NoError(err)
	require.Equal(getHeaders, newMessage)
}

func TestHeaderBundleSerialization(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	hash1 := expectedBlockHeader.PrevBlockHash

	headerBundle := &MsgUltranetHeaderBundle{
		Headers:   []*MsgUltranetHeader{expectedBlockHeader, expectedBlockHeader},
		TipHash:   hash1,
		TipHeight: 12345,
	}

	messageBytes, err := headerBundle.ToBytes(false)
	require.NoError(err)
	newMessage := &MsgUltranetHeaderBundle{}
	err = newMessage.FromBytes(messageBytes)
	require.NoError(err)
	require.Equal(headerBundle, newMessage)
}

func TestEnumExtras(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	// For all the enum strings we've defined, ensure we return
	// a non-nil NewMessage.
	for ii := uint8(1); !strings.Contains(MsgType(ii).String(), "UNRECOGNIZED"); ii++ {
		assert.NotNilf(NewMessage(MsgType(ii)), "String() defined for MsgType (%v) but NewMessage() returns nil.", MsgType(ii))
	}

	// For all the NewMessage() calls that return non-nil, ensure we have a String()
	for ii := uint8(1); NewMessage(MsgType(ii)) != nil; ii++ {
		hasString := !strings.Contains(MsgType(ii).String(), "UNRECOGNIZED")
		assert.Truef(hasString, "String() undefined for MsgType (%v) but NewMessage() returns non-nil.", MsgType(ii))
	}
}

func TestHeaderConversion(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require
	networkType := NetworkType_MAINNET

	{
		data, err := expectedBlockHeader.ToBytes(false)
		assert.NoError(err)

		testHdr := NewMessage(MsgTypeHeader)
		err = testHdr.FromBytes(data)
		assert.NoError(err)

		assert.Equal(expectedBlockHeader, testHdr)

		// Test read write.
		var buf bytes.Buffer
		payload, err := WriteMessage(&buf, expectedBlockHeader, networkType)
		assert.NoError(err)
		// Form the header from the payload and make sure it matches.
		hdrFromPayload := NewMessage(MsgTypeHeader).(*MsgUltranetHeader)
		assert.NotNil(hdrFromPayload, "NewMessage(MsgTypeHeader) should not return nil.")
		assert.Equal(uint32(0), hdrFromPayload.Nonce, "NewMessage(MsgTypeHeader) should initialize Nonce to empty byte slice.")
		err = hdrFromPayload.FromBytes(payload)
		assert.NoError(err)
		assert.Equal(expectedBlockHeader, hdrFromPayload)

		hdrBytes := buf.Bytes()
		testMsg, data, err := ReadMessage(bytes.NewReader(hdrBytes),
			networkType)
		assert.NoError(err)
		assert.Equal(expectedBlockHeader, testMsg)

		// Compute the header payload bytes so we can compare them.
		hdrPayload, err := expectedBlockHeader.ToBytes(false)
		assert.NoError(err)
		assert.Equal(hdrPayload, data)
	}

	assert.Equalf(6, reflect.TypeOf(expectedBlockHeader).Elem().NumField(),
		"Number of fields in HEADER message is different from expected. "+
			"Did you add a new field? If so, make sure the serialization code "+
			"works, add the new field to the test case, and fix this error.")
}

func TestVersionConversion(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	data, err := expectedVer.ToBytes(false)
	assert.NoError(err)

	testVer := NewMessage(MsgTypeVersion)
	err = testVer.FromBytes(data)
	assert.NoError(err)

	assert.Equal(expectedVer, testVer)

	assert.Equalf(8, reflect.TypeOf(expectedVer).Elem().NumField(),
		"Number of fields in VERSION message is different from expected. "+
			"Did you add a new field? If so, make sure the serialization code "+
			"works, add the new field to the test case, and fix this error.")
}

func TestReadWrite(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	networkType := NetworkType_MAINNET
	var buf bytes.Buffer

	payload, err := WriteMessage(&buf, expectedVer, networkType)
	assert.NoError(err)
	// Form the version from the payload and make sure it matches.
	verFromPayload := NewMessage(MsgTypeVersion)
	assert.NotNil(verFromPayload, "NewMessage(MsgTypeVersion) should not return nil.")
	err = verFromPayload.FromBytes(payload)
	assert.NoError(err)
	assert.Equal(expectedVer, verFromPayload)

	verBytes := buf.Bytes()
	testMsg, data, err := ReadMessage(bytes.NewReader(verBytes),
		networkType)
	assert.NoError(err)
	assert.Equal(expectedVer, testMsg)

	// Compute the version payload bytes so we can compare them.
	verPayload, err := expectedVer.ToBytes(false)
	assert.NoError(err)
	assert.Equal(verPayload, data)

	// Incorrect network type should error.
	testMsg, data, err = ReadMessage(bytes.NewReader(verBytes),
		NetworkType_TESTNET)
	assert.Error(err, "Incorrect network should fail.")

	// Payload too large should error.
	bigBytes := make([]byte, MaxMessagePayload*1.1)
	testMsg, data, err = ReadMessage(bytes.NewReader(bigBytes),
		NetworkType_MAINNET)
	assert.Error(err, "Payload too large should fail.")

	// Corrupted payload should fail.
	verBytes[len(verBytes)-1] = 0x00
	testMsg, data, err = ReadMessage(bytes.NewReader(verBytes),
		NetworkType_MAINNET)
	assert.Error(err, "Corrupted payload should fail.")
}

func TestVerack(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	networkType := NetworkType_MAINNET
	var buf bytes.Buffer

	nonce := uint64(12345678910)
	_, err := WriteMessage(&buf, &MsgUltranetVerack{Nonce: nonce}, networkType)
	require.NoError(err)
	verBytes := buf.Bytes()
	testMsg, _, err := ReadMessage(bytes.NewReader(verBytes),
		networkType)
	require.NoError(err)
	require.Equal(&MsgUltranetVerack{Nonce: nonce}, testMsg)
}

var expectedBlock = &MsgUltranetBlock{
	Header: expectedBlockHeader,
	Txns: []*MsgUltranetTxn{
		&MsgUltranetTxn{
			TxInputs: []*UltranetInput{
				&UltranetInput{
					TxID: *CopyBytesIntoBlockHash([]byte{
						// random bytes
						0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10,
						0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x20,
						0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x30,
						0x31, 0x32,
					}),
					Index: 111,
				},
				&UltranetInput{
					TxID: *CopyBytesIntoBlockHash([]byte{
						// random bytes
						0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x50,
						0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x70,
						0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x90,
						0x91, 0x92,
					}),
					Index: 222,
				},
			},
			TxOutputs: []*UltranetOutput{
				&UltranetOutput{
					PublicKey: []byte{
						// random bytes
						0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10,
						0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x30,
						0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x30,
						0x21, 0x22, 0x23,
					},
					AmountNanos: 333,
				},
				&UltranetOutput{
					PublicKey: []byte{
						// random bytes
						0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x10,
						0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x30,
						0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x30,
						0x21, 0x22, 0x23,
					},
					AmountNanos: 333,
				},
			},
			TxnMeta: &BlockRewardMetadataa{
				MerchantMerkleRoot: &BlockHash{
					0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x10,
					0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x30,
					0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x30,
					0x21, 0x22,
				},
				ExtraData: []byte{
					// random bytes
					0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x10,
					0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x90,
				},
			},
			// random bytes
			PublicKey: []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99},
			//Signature: []byte{0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90},
		},
		&MsgUltranetTxn{
			TxInputs: []*UltranetInput{
				&UltranetInput{
					TxID: *CopyBytesIntoBlockHash([]byte{
						// random bytes
						0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x30,
						0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x20,
						0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10,
						0x31, 0x32,
					}),
					Index: 111,
				},
				&UltranetInput{
					TxID: *CopyBytesIntoBlockHash([]byte{
						// random bytes
						0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x70,
						0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x50,
						0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x90,
						0x91, 0x92,
					}),
					Index: 222,
				},
			},
			TxOutputs: []*UltranetOutput{
				&UltranetOutput{
					PublicKey: []byte{
						// random bytes
						0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x30,
						0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10,
						0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x30,
						0x21, 0x22, 0x23,
					},
					AmountNanos: 333,
				},
				&UltranetOutput{
					PublicKey: []byte{
						// random bytes
						0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x30,
						0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x10,
						0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x30,
						0x21, 0x22, 0x23,
					},
					AmountNanos: 333,
				},
			},
			TxnMeta: &BlockRewardMetadataa{
				MerchantMerkleRoot: &BlockHash{
					0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x10,
					0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x30,
					0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x30,
					0x21, 0x22,
				},
				ExtraData: []byte{
					// random bytes
					0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x90,
					0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x10,
				},
			},
			// random bytes
			PublicKey: []byte{0x55, 0x66, 0x77, 0x88, 0x11, 0x22, 0x33, 0x44, 0x99},
			//Signature: []byte{0x50, 0x60, 0x70, 0x80, 0x90, 0x10, 0x20, 0x30, 0x40},
		},
	},
}

func TestBlockRewardTransactionSerialize(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	data, err := expectedBlock.Txns[0].ToBytes(false)
	require.NoError(err)

	testTxn := NewMessage(MsgTypeTxn).(*MsgUltranetTxn)
	err = testTxn.FromBytes(data)
	require.NoError(err)
}

func TestBlockSerialize(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	data, err := expectedBlock.ToBytes(false)
	require.NoError(err)

	testBlock := NewMessage(MsgTypeBlock).(*MsgUltranetBlock)
	err = testBlock.FromBytes(data)
	require.NoError(err)

	assert.Equal(*expectedBlock, *testBlock)
}

func TestListingSerialize(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	listingMessage := MsgUltranetListing{
		MerchantID: expectedBlock.Header.PrevBlockHash,
		PublicKey: []byte{
			// random bytes
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10,
			0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x30,
			0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x30,
			0x21, 0x22, 0x23,
		},

		TstampSecs:   uint32(12345),
		ListingIndex: uint32(69483),

		Title:    []byte{01, 2, 23, 4},
		Body:     []byte{34, 4, 123, 42, 34},
		Category: []byte{0, 1, 2, 3, 2, 2, 3},

		ThumbnailImage: []byte{2, 3, 31, 2, 3},
		ListingImages:  [][]byte{[]byte{2, 3, 31, 2, 3}, []byte{3, 34, 4, 3}},

		Deleted: true,

		PricePerUnitNanos: uint64(12345),
		UnitNameSingular:  []byte{3, 4, 2, 2, 3},
		UnitNamePlural:    []byte{2, 3, 3, 32, 3},
		MinQuantity:       uint64(123),
		MaxQuantity:       uint64(566),
		RequiredFields: []*RequiredField{&RequiredField{
			IsRequired: true,
			Label:      []byte{4, 3, 4, 45},
		},
			&RequiredField{
				IsRequired: false,
				Label:      []byte{45, 3, 4, 45},
			},
		},

		ProductType: ProductTypeInstant,
		TipComment:  []byte{1, 2, 2, 3, 6, 7, 83, 1},

		ShipsTo:   []byte{1, 23, 34, 4},
		ShipsFrom: []byte{34, 43, 3, 4},
		Signature: _getSigForTesting(t),
	}

	bb, err := listingMessage.ToBytes(false)
	require.NoError(err)
	parsedListing := &MsgUltranetListing{}
	require.NoError(parsedListing.FromBytes(bb))
	require.Equal(*parsedListing, listingMessage)

	// Make sure preSignature leaves out the signature.
	preSigBytes, err := listingMessage.ToBytes(true)
	require.NoError(err)
	preSigMsg := &MsgUltranetListing{}
	require.NoError(preSigMsg.FromBytes(preSigBytes))
	require.Nil(preSigMsg.Signature)
	prevSig := listingMessage.Signature
	listingMessage.Signature = nil
	require.Equal(*preSigMsg, listingMessage)
	listingMessage.Signature = prevSig

	// Do the bundle
	bundle := MsgUltranetListingBundle{
		Listings: []*MsgUltranetListing{
			&listingMessage,
			&listingMessage,
			&listingMessage,
		},
	}
	bb, err = bundle.ToBytes(false /*preSignature*/)
	require.NoError(err)
	parsedBundle := &MsgUltranetListingBundle{}
	parsedBundle.FromBytes(bb)
	require.Equal(3, len(parsedBundle.Listings))
	require.Equal(bundle.Listings[0], parsedBundle.Listings[0])
	require.Equal(bundle.Listings[1], parsedBundle.Listings[1])
	require.Equal(bundle.Listings[2], parsedBundle.Listings[2])
}

func TestRegisterMerchantMetadataSerialize(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	registerMerchantMeta := RegisterMerchantMetadata{
		Username:        []byte{1, 2, 3, 4, 5, 6, 7},
		Description:     []byte{5, 6, 4, 2, 4, 3, 2, 3, 2, 3, 2, 3, 33, 3},
		BurnAmountNanos: 123546,
	}
	bb, err := registerMerchantMeta.ToBytes(false)
	require.NoError(err)
	fromBytes := &RegisterMerchantMetadata{}
	fromBytes.FromBytes(bb)

	require.Equal(registerMerchantMeta, *fromBytes)
}

func TestUpdateMerchantMetadataSerialize(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	updateMerchantMeta := UpdateMerchantMetadata{
		MerchantID:      &BlockHash{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		NewUsername:     []byte{1, 2, 3, 2, 12, 1},
		NewPublicKey:    []byte{1, 23, 4, 3, 3, 4, 4, 2, 3, 3, 1, 23, 4, 3, 3, 4, 4, 2, 3, 3, 1, 23, 4, 3, 3, 4, 4, 2, 3, 3, 2, 2, 1},
		NewDescription:  []byte{2, 3, 2, 121, 2, 3, 2, 2, 1, 122, 3, 2},
		BurnAmountNanos: 10201,
	}
	bb, err := updateMerchantMeta.ToBytes(false)
	require.NoError(err)
	fromBytes := &UpdateMerchantMetadata{}
	fromBytes.FromBytes(bb)

	require.Equal(updateMerchantMeta, *fromBytes)
}

func TestSerializeInv(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	invMsg := &MsgUltranetInv{
		InvList: []*InvVect{
			&InvVect{
				Type: InvTypeBlock,
				Hash: BlockHash{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0},
			},
			&InvVect{
				Type: InvTypeTx,
				Hash: BlockHash{2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0},
			},
			&InvVect{
				Type: InvTypeListing,
				Hash: BlockHash{3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0},
			},
		},
		IsSyncResponse: true,
	}

	bb, err := invMsg.ToBytes(false)
	require.NoError(err)
	invMsgFromBuf := &MsgUltranetInv{}
	invMsgFromBuf.FromBytes(bb)
	require.Equal(*invMsg, *invMsgFromBuf)
}

func TestSerializePlaceOrder(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	placeOrderMsg := &PlaceOrderMetadata{
		MerchantID:        &BlockHash{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0},
		AmountLockedNanos: uint64(12345),
		BuyerMessage:      []byte("hey, 10 please"),
	}

	bb, err := placeOrderMsg.ToBytes(false)
	require.NoError(err)
	placeOrderFromBuf := &PlaceOrderMetadata{}
	placeOrderFromBuf.FromBytes(bb)
	require.Equal(*placeOrderMsg, *placeOrderFromBuf)
}

func TestSerializeEncryptBuyerMessage(t *testing.T) {
	require := require.New(t)

	bm := &BuyerMessage{
		RequiredFields: []string{
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			"bbbbbbbbbbbbbbbbbbbbbbbbb\nccccccccccccccccccccccc\ndddddddddddddddddddd\n\n",
			"uniccccccccccc000\000\000\x99\x61\xe4\xb8\xad\xd0\xaf\u9999\u1929\u8392\x029ksajdlakj",
		},
		OptionalFields: []string{
			"aaaaaaaaaaaslkdjalsdkjaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			"bbalskdjalskjdbbbbbbbbbbbbbbbbbbbbbbb\nccccccccccccccccccccccc\ndddddddddddddddddddd\n\n",
			"uniccccccccccaosdjaalskdjhc000\000\000\x99\x61\xe4kalsdjal\xb8\xad\xd0\xaf\u9999\u1929\u8392\x029ksajdlakj",
		},
		ItemQuantity:   math.MaxFloat64,
		TipAmountNanos: 999,
		ListingIndex:   10,
	}

	{
		bmBytes := bm.ToBytes()
		bmFromBytes := &BuyerMessage{}
		require.NoError(bmFromBytes.FromBytes(bmBytes))
		require.Equal(bm, bmFromBytes)
	}
	{
		priv, err := btcec.NewPrivateKey(btcec.S256())
		require.NoError(err)
		pub := priv.PubKey()

		bmEncryptedBytes, err := bm.EncryptWithPubKey(pub)
		require.NoError(err)

		bmFromEncryptedBytes := &BuyerMessage{}
		require.NoError(bmFromEncryptedBytes.DecryptWithPrivKey(bmEncryptedBytes, priv))

		require.Equal(bm, bmFromEncryptedBytes)
	}
}

func TestSerializeAddresses(t *testing.T) {
	require := require.New(t)

	addrs := &MsgUltranetAddr{
		AddrList: []*SingleAddr{
			&SingleAddr{
				Timestamp: time.Unix(1000, 0),
				Services:  SFFullNode,
				IP:        []byte{0x01, 0x02, 0x03, 0x04},
				Port:      12345,
			},
			&SingleAddr{
				Timestamp: time.Unix(100000, 0),
				Services:  0,
				IP:        []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16},
				Port:      54321,
			},
		},
	}

	bb, err := addrs.ToBytes(false)
	require.NoError(err)
	parsedAddrs := &MsgUltranetAddr{}
	err = parsedAddrs.FromBytes(bb)
	require.NoError(err)
	require.Equal(addrs, parsedAddrs)
}
