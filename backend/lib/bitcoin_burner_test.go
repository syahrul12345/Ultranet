package lib

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"testing"

	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func _readBlockCypherAPIDataForBurnAddress() (
	_res *BlockCypherAPIFullAddressResponse, _err error) {

	data, err := ioutil.ReadFile(TestDataDir + "/burn_address_transactions.json")
	if err != nil {
		return nil, err
	}

	decoder := json.NewDecoder(bytes.NewReader(data))
	resData := &BlockCypherAPIFullAddressResponse{}
	if err := decoder.Decode(resData); err != nil {
		return nil, err
	}

	return resData, nil
}

func TestCreateBitcoinTransaction(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	chain, params, db := NewLowDifficultyBlockchain()
	mempool, miner := NewTestMiner(t, chain, params, true /*isSender*/)

	getBitcoinUtxosForAddr := func(addrString string, params *UltranetParams) (
		[]*BitcoinUtxo, error) {

		apiData, err := _readBlockCypherAPIDataForBurnAddress()
		if err != nil {
			return nil, err
		}

		return BlockCypherExtractBitcoinUtxosFromResponse(apiData, addrString, params)
	}

	privateKey, _ := _privStringToKeys(t, BitcoinTestnetBurnPriv)
	bitcoinTxn, _, _, err := CreateBitcoinSpendTransaction(
		10000, 100, privateKey, BitcoinTestnetPub1, params, getBitcoinUtxosForAddr)

	// Use this to print the hex for the transaction generated.
	/*
		buf := bytes.Buffer{}
		bitcoinTxn.Serialize(&buf)
		fmt.Println(hex.EncodeToString(buf.Bytes()))
		require.True(false)
	*/

	expectedBitcoinTxn := &wire.MsgTx{}
	expectedBitcoinTxnBytes, err := hex.DecodeString("0200000003e5471e9e1cf4d23d0166b1b1b6a72af049b52857d1af95e2049070ab5d45193b000000006a473044022018eaa06f592dd76ccd1cdae73818fc4a4c158281093dec58a7932a2fc57aa6ca02206969ccc25261cc5a7c60b1660f26ecae04d31a9b0ee789f4283a352e02c2cb53012102bcb72f2dcc0a21aaa31ba792c8bf4a13e3393d7d1b3073afbac613a06dd1d99fffffffff919923c448973fbe020d9cfd14d3829d6ea823cb3891ffe6d6340e06e88042b7000000006b483045022100ce3ee6535b75e6c259d93a583084e2badf87217ace9cae2949277e4c48119b6c02202f8a74277e6c6d079489ddf2fc172c27892c4dc0544785b8b34f5ab7c87d1327012102bcb72f2dcc0a21aaa31ba792c8bf4a13e3393d7d1b3073afbac613a06dd1d99fffffffffffee982899a1d1e1f4bc55c9cebee1a4f09127ef2713bd36229f7de8922d2f7f000000006b483045022100fc16d86e073c5b74e202548c41d8055e965fe8d57c31786f6fb5eb0fa604c7cc02207b90473f621c078a2316db247ca9b49a66a25a02b45464f2a94c124888861b6a012102bcb72f2dcc0a21aaa31ba792c8bf4a13e3393d7d1b3073afbac613a06dd1d99fffffffff0210270000000000001976a91471919e6f68957a3e971f3163d0388087737e429a88ac58110000000000001976a9147fa9dd145fc6cc9072971d479b317b71ee8e234088ac00000000")
	require.NoError(err)
	expectedBitcoinTxn.Deserialize(bytes.NewBuffer(expectedBitcoinTxnBytes))

	require.Equal(expectedBitcoinTxn, bitcoinTxn)

	_, _, _ = db, mempool, miner
}

var (
	runPrivateTests = flag.Bool(
		"run_private_tests", false,
		"Whether or not to run the private tests.")
)

func TestFetchBlockCypherBitcoinTransaction(t *testing.T) {
	flag.Parse()

	if !*runPrivateTests {
		fmt.Println("NOT running private test")
		return
	}

	require := require.New(t)
	_, params, _ := NewLowDifficultyBlockchain()

	privKeyBurn, _ := _privStringToKeys(t, BitcoinTestnetBurnPriv)

	// Asking for too many satoshis should error.
	{
		_, _, _, err := CreateBitcoinSpendTransaction(
			20000000, 10000, privKeyBurn, BitcoinTestnetPub1, params, BlockCypherUtxoSource)
		require.Error(err)
	}

	// Asking for a proper amount of satoshis should work.
	bitcoinTxn, _, _, err := CreateBitcoinSpendTransaction(
		20000, 50000, privKeyBurn, BitcoinTestnetPub1, params, BlockCypherUtxoSource)
	require.NoError(err)

	// Use this to print the hex for the transaction generated.
	/*
		buf := bytes.Buffer{}
		bitcoinTxn.Serialize(&buf)
		fmt.Println(hex.EncodeToString(buf.Bytes()))
		require.True(false)
	*/

	expectedBitcoinTxn := &wire.MsgTx{}
	expectedBitcoinTxnBytes, err := hex.DecodeString("020000000151ade05772432fe85cc7032d8f5ac3000ab17180cc70f21842bd538ca85468c9000000006a473044022040cff3476596101b57219c6bf65f949020fc7339be5880a4e85e2ec2ef84859a02200ea2b3dc6c23657c0fd3ca0b4f208ff32da0fc66f39e2b53d1a3e2abab34cff7012102bcb72f2dcc0a21aaa31ba792c8bf4a13e3393d7d1b3073afbac613a06dd1d99fffffffff02204e0000000000001976a91471919e6f68957a3e971f3163d0388087737e429a88acb0c30e00000000001976a9147fa9dd145fc6cc9072971d479b317b71ee8e234088ac00000000")
	require.NoError(err)
	expectedBitcoinTxn.Deserialize(bytes.NewBuffer(expectedBitcoinTxnBytes))

	require.Equal(expectedBitcoinTxn, bitcoinTxn)
}
