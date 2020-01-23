package lib

import (
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"math/big"
	"testing"
	"time"

	chainlib "github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcec"
	"github.com/dgraph-io/badger"
	"github.com/golang/glog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProcessBlock(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	//hexBytes, _ := hex.DecodeString("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
	{
		hexBytes, err := hex.DecodeString("00000000e9a0b8435a2fc5e19952ceb3a2d5042fb87b6d5f180ea825f3a4cd65")
		assert.NoError(err)
		assert.Equal("000000000000000000000000000000000000000000000000000000011883b96c", fmt.Sprintf("%064x", *ExpectedWorkForBlockHash(CopyBytesIntoBlockHash(hexBytes))))

	}
	// Satoshi's genesis block hash.
	{
		hexBytes, err := hex.DecodeString("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f")
		assert.NoError(err)
		assert.Equal("000000000000000000000000000000000000000000000000000009e8770a5c23", fmt.Sprintf("%064x", *ExpectedWorkForBlockHash(CopyBytesIntoBlockHash(hexBytes))))
	}
	// A more serious block.
	{

		hexBytes, err := hex.DecodeString("00000000000000000000c4c7bfde307b37ca6e4234d636cdea3e443df2926fff")
		assert.NoError(err)
		assert.Equal(
			"000000000000000000000000000000000000000000014d0aa0d2497b13fcd703",
			fmt.Sprintf("%064x", *ExpectedWorkForBlockHash(CopyBytesIntoBlockHash(hexBytes))))
	}
	// Some annoying edge cases.
	{
		hexBytes, err := hex.DecodeString("0000000000000000000000000000000000000000000000000000000000000000")
		assert.NoError(err)
		assert.Equal(
			"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
			fmt.Sprintf("%064x", *ExpectedWorkForBlockHash(CopyBytesIntoBlockHash(hexBytes))))
	}
	{
		hexBytes, err := hex.DecodeString("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
		assert.NoError(err)
		assert.Equal(
			"0000000000000000000000000000000000000000000000000000000000000000",
			fmt.Sprintf("%064x", *ExpectedWorkForBlockHash(CopyBytesIntoBlockHash(hexBytes))))
	}
	{
		hexBytes, err := hex.DecodeString("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe")
		assert.NoError(err)
		assert.Equal(
			"0000000000000000000000000000000000000000000000000000000000000001",
			fmt.Sprintf("%064x", *ExpectedWorkForBlockHash(CopyBytesIntoBlockHash(hexBytes))))
	}
}

func _copyBlock(blk *MsgUltranetBlock) *MsgUltranetBlock {
	data, _ := blk.ToBytes(false)

	testBlock := NewMessage(MsgTypeBlock).(*MsgUltranetBlock)
	_ = testBlock.FromBytes(data)

	return testBlock
}

var (
	// Generated using MagicPrintBlock
	// The blocks below represent a tree that looks as follows:
	//  genesis -> a1 -> a2
	//       \ - > b1 -> b2 -> b3
	blockA1Hex = "500000000049a2226589a5dd46dd90b270980bdcb837ed818b984bdacbabd12a6dd5d0415724756a26fe9fd4e6770d16e7c5919f9ead1e249be00de938b8dd28c9962aede32dfb195e010000009d540000015700010342d943b8dba93a4ce29b858479c67f1e4f1110eecbe1f83dc01b455eb8b123b380a8d6b907012b00000000000000000000000000000000000000000000000000000000000000000ac4eeeec286978fc9c0010000"
	blockA2Hex = "50000000000000bbaf3ca1206e1bd5171b10aa72330d2cd8b5f3dc1aa10364e9983a0a08ced92e92209c8e36813b2bb1291981879d980613287264091f18a876e7ac9fbf3f36fb195e0200000038bf0000015600010342d943b8dba93a4ce29b858479c67f1e4f1110eecbe1f83dc01b455eb8b123b380a8d6b907012a000000000000000000000000000000000000000000000000000000000000000009939ac283c0ccd1ae1c0000"
	blockB1Hex = "500000000049a2226589a5dd46dd90b270980bdcb837ed818b984bdacbabd12a6dd5d04157b2ed0064d40b01511a462e608c707807167ad3b57dec7c5ab10207130cbb6af2a1fb195e01000000562f0100015700010342d943b8dba93a4ce29b858479c67f1e4f1110eecbe1f83dc01b455eb8b123b380a8d6b907012b00000000000000000000000000000000000000000000000000000000000000000a93d89ea5ac8ac7f3fd010000"
	blockB2Hex = "50000000000000434aacde77304afcaf822fc66379e4c4708dbd3524e9137b844ad4076a38b4b5ab4b20684d6a89953b19db8eb8a1989493d85a2b12fb4bdd71de62ef5ba5a9fb195e0200000041bc0000015700010342d943b8dba93a4ce29b858479c67f1e4f1110eecbe1f83dc01b455eb8b123b380a8d6b907012b00000000000000000000000000000000000000000000000000000000000000000ab2cedd80aff98a9fd701000000"
	blockB3Hex = "50000000000000d52e96c4fa43cb42ae39f01f14a487cb97cd5416bebef8382ac21dd6138d3c050fbe9211039bc1db9dcc30c8e8cda4fcab19dd9230c0daaae8d31cb1c182b1fb195e0300000053160000015600010342d943b8dba93a4ce29b858479c67f1e4f1110eecbe1f83dc01b455eb8b123b380a8d6b907012a000000000000000000000000000000000000000000000000000000000000000009c7cabaaa829bf88e130000"
	blockB4Hex = "500000000000003c4c03887369c24d7d44a076b88eceffd8433a647cb8559434d4adf6559440bb8ac80eac2bc52ced3db021a8a8f96900bf046f6427eaf42dafb2a6d8eef3b9fb195e04000000b8690000015700010342d943b8dba93a4ce29b858479c67f1e4f1110eecbe1f83dc01b455eb8b123b380a8d6b907012b00000000000000000000000000000000000000000000000000000000000000000aa3feb9ee9f9cbfd7b6010000"
	blockB5Hex = "500000000000009e4f14683d1a21107d757edf408dca676f978ab0f1ad806d0f06b29710a9c670af5747230083b9098057746d4e2183f4d58890f11218e4354ae4a08fc8dec1fb195e05000000f6970000015700010342d943b8dba93a4ce29b858479c67f1e4f1110eecbe1f83dc01b455eb8b123b380a8d6b907012b00000000000000000000000000000000000000000000000000000000000000000aeff6a183abf1ffc2d7010000"
)

func NewTestBlockchain() (*Blockchain, *UltranetParams, *badger.DB) {
	db, _ := _GetTestBadgerDb()
	timesource := chainlib.NewMedianTime()
	ch := make(chan *ServerMessage)

	// Set some special parameters for testing. If the blocks above are changed
	// these values should be updated to reflect the latest testnet values.
	paramsCopy := UltranetTestnetParams

	chain, err := NewBlockchain(&paramsCopy, timesource, db, nil, ch)
	if err != nil {
		log.Fatal(err)
	}

	return chain, &paramsCopy, db
}

func NewLowDifficultyBlockchain() (*Blockchain, *UltranetParams, *badger.DB) {
	db, _ := _GetTestBadgerDb()
	timesource := chainlib.NewMedianTime()
	ch := make(chan *ServerMessage)

	// Set some special parameters for testing. If the blocks above are changed
	// these values should be updated to reflect the latest testnet values.
	paramsCopy := UltranetTestnetParams
	paramsCopy.GenesisBlock = &MsgUltranetBlock{
		Header: &MsgUltranetHeader{
			Version:               0,
			PrevBlockHash:         mustDecodeHexBlockHash("0000000000000000000000000000000000000000000000000000000000000000"),
			TransactionMerkleRoot: mustDecodeHexBlockHash("097158f0d27e6d10565c4dc696c784652c3380e0ff8382d3599a4d18b782e965"),
			TstampSecs:            uint32(1560735050),
			Height:                uint32(0),
			Nonce:                 uint32(0),
		},
		Txns: GenesisBlock.Txns,
	}
	paramsCopy.MinDifficultyTargetHex = "999999948931e5874cf66a74c0fda790dd8c7458243d400324511a4c71f54faa"
	paramsCopy.MinChainWorkHex = "0000000000000000000000000000000000000000000000000000000000000000"
	// Set maturity to 2 blocks so we can test spending on short chains. The
	// tests rely on the maturity equaling exactly two blocks (i.e. being
	// two times the time between blocks).
	paramsCopy.TimeBetweenBlocks = 2 * time.Second
	paramsCopy.BlockRewardMaturity = time.Second * 4
	paramsCopy.TimeBetweenDifficultyRetargets = 100 * time.Second
	paramsCopy.MaxDifficultyRetargetFactor = 2

	chain, err := NewBlockchain(&paramsCopy, timesource, db, nil, ch)
	if err != nil {
		log.Fatal(err)
	}

	return chain, &paramsCopy, db
}

func NewTestMiner(t *testing.T, chain *Blockchain, params *UltranetParams, isSender bool) (*TxPool, *UltranetMiner) {
	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	mempool := NewTxPool(chain, 0 /* rateLimitFeeRateNanosPerKB */, 0 /* minFeeRateNanosPerKB */)
	minerPubKeys := []string{}
	if isSender {
		minerPubKeys = append(minerPubKeys, senderPkString)
	} else {
		minerPubKeys = append(minerPubKeys, recipientPkString)
	}

	newMiner, err := NewUltranetMiner(minerPubKeys, 1 /*numThreads*/, mempool, chain, nil, params)
	require.NoError(err)
	return mempool, newMiner
}

func _getBalance(t *testing.T, chain *Blockchain, mempool *TxPool, pkStr string) uint64 {
	pkBytes, _, err := Base58CheckDecode(pkStr)
	require.NoError(t, err)

	utxoEntriesFound, err := chain.GetSpendableUtxosForPublicKey(pkBytes, mempool)
	require.NoError(t, err)

	balanceForUserNanos := uint64(0)
	for _, utxoEntry := range utxoEntriesFound {
		balanceForUserNanos += utxoEntry.AmountNanos
	}
	return balanceForUserNanos
}

func TestBasicTransferReorg(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	chain1, params, _ := NewLowDifficultyBlockchain()
	{
		mempool1, miner1 := NewTestMiner(t, chain1, params, true /*isSender*/)

		// Mine two blocks to give the sender some Ultra.
		block, err := miner1._mineAndProcessSingleBlock(0 /*threadIndex*/)
		require.NoError(err)
		block, err = miner1._mineAndProcessSingleBlock(0 /*threadIndex*/)
		require.NoError(err)

		// Have the sender send some Ultra to the recipient and have the
		// recipient send some back. Mine both of these transactions into
		// a block.
		{
			txn := _assembleBasicTransferTxnFullySigned(t, chain1, 17, 0,
				senderPkString, recipientPkString, senderPrivString, mempool1)
			_, err := mempool1.ProcessTransaction(txn, false /*allowOrphan*/, false /*rateLimit*/, 0 /*peerID*/, true /*verifySignatures*/)
			require.NoError(err)
		}
		{
			txn := _assembleBasicTransferTxnFullySigned(t, chain1, 4, 0,
				recipientPkString, senderPkString, recipientPrivString, mempool1)
			_, err := mempool1.ProcessTransaction(txn, false /*allowOrphan*/, false /*rateLimit*/, 0 /*peerID*/, true /*verifySignatures*/)
			require.NoError(err)
		}
		block, err = miner1._mineAndProcessSingleBlock(0 /*threadIndex*/)
		require.NoError(err)
		mempool1.UpdateAfterConnectBlock(block)
		// block reward adds one txn.
		require.Equal(3, len(block.Txns))
		require.Equal(uint64(13), _getBalance(t, chain1, mempool1, recipientPkString))

		// Have the sender send a bit more Ultra over and mine that into a
		// block.
		{
			txn := _assembleBasicTransferTxnFullySigned(t, chain1, 2, 0,
				senderPkString, recipientPkString, senderPrivString, mempool1)
			_, err := mempool1.ProcessTransaction(txn, false /*allowOrphan*/, false /*rateLimit*/, 0 /*peerID*/, true /*verifySignatures*/)
			require.NoError(err)
		}
		block, err = miner1._mineAndProcessSingleBlock(0 /*threadIndex*/)
		require.NoError(err)
		mempool1.UpdateAfterConnectBlock(block)
		// block reward adds one txn.
		require.Equal(2, len(block.Txns))
		require.Equal(uint64(15), _getBalance(t, chain1, mempool1, recipientPkString))

		// A transaction signed by the wrong private key should be rejected.
		{
			txn := _assembleBasicTransferTxnFullySigned(t, chain1, 2, 0,
				senderPkString, recipientPkString, recipientPrivString, mempool1)
			_, err := mempool1.ProcessTransaction(txn, false /*allowOrphan*/, false /*rateLimit*/, 0 /*peerID*/, true /*verifySignatures*/)
			require.Error(err)
			require.Contains(err.Error(), RuleErrorInvalidTransactionSignature)
		}

		// Have the recipient send some Ultra back and mine that into a block.
		{
			txn := _assembleBasicTransferTxnFullySigned(t, chain1, 8, 0,
				recipientPkString, senderPkString, recipientPrivString, mempool1)
			_, err := mempool1.ProcessTransaction(txn, false /*allowOrphan*/, false /*rateLimit*/, 0 /*peerID*/, true /*verifySignatures*/)
			require.NoError(err)
		}
		block, err = miner1._mineAndProcessSingleBlock(0 /*threadIndex*/)
		require.NoError(err)
		mempool1.UpdateAfterConnectBlock(block)
		// block reward adds one txn.
		require.Equal(2, len(block.Txns))

		// Recipient should have exactly 7 Ultra after all this.
		require.Equal(uint64(7), _getBalance(t, chain1, mempool1, recipientPkString))
	}

	// Create a second test chain so we can mine a fork.
	// Mine enough blocks to create a fork. Throw in a transaction
	// from the sender to the recipient right before the third block
	// just to make things interesting.
	chain2, _, _ := NewLowDifficultyBlockchain()
	forkBlocks := []*MsgUltranetBlock{}
	{
		mempool2, miner2 := NewTestMiner(t, chain2, params, true /*isSender*/)

		// Mine two blocks to give the sender some Ultra.
		block, err := miner2._mineAndProcessSingleBlock(0 /*threadIndex*/)
		require.NoError(err)
		forkBlocks = append(forkBlocks, block)
		block, err = miner2._mineAndProcessSingleBlock(0 /*threadIndex*/)
		require.NoError(err)
		forkBlocks = append(forkBlocks, block)

		// Have the sender send some Ultra to the recipient and have the
		// recipient send some back. Mine both of these transactions into
		// a block.
		{
			txn := _assembleBasicTransferTxnFullySigned(t, chain2, 7, 0,
				senderPkString, recipientPkString, senderPrivString, mempool2)
			_, err := mempool2.ProcessTransaction(txn, false /*allowOrphan*/, false /*rateLimit*/, 0 /*peerID*/, true /*verifySignatures*/)
			require.NoError(err)
		}
		{
			txn := _assembleBasicTransferTxnFullySigned(t, chain2, 2, 0,
				recipientPkString, senderPkString, recipientPrivString, mempool2)
			_, err := mempool2.ProcessTransaction(txn, false /*allowOrphan*/, false /*rateLimit*/, 0 /*peerID*/, true /*verifySignatures*/)
			require.NoError(err)
		}
		block, err = miner2._mineAndProcessSingleBlock(0 /*threadIndex*/)
		require.NoError(err)
		forkBlocks = append(forkBlocks, block)
		mempool2.UpdateAfterConnectBlock(block)
		// block reward adds one txn.
		require.Equal(3, len(block.Txns))
		require.Equal(uint64(5), _getBalance(t, chain2, mempool2, recipientPkString))

		// Mine several more blocks so we can make the fork dominant.
		block, err = miner2._mineAndProcessSingleBlock(0 /*threadIndex*/)
		require.NoError(err)
		forkBlocks = append(forkBlocks, block)
		block, err = miner2._mineAndProcessSingleBlock(0 /*threadIndex*/)
		require.NoError(err)
		forkBlocks = append(forkBlocks, block)
		block, err = miner2._mineAndProcessSingleBlock(0 /*threadIndex*/)
		require.NoError(err)
		forkBlocks = append(forkBlocks, block)
		block, err = miner2._mineAndProcessSingleBlock(0 /*threadIndex*/)
		require.NoError(err)
		forkBlocks = append(forkBlocks, block)
		block, err = miner2._mineAndProcessSingleBlock(0 /*threadIndex*/)
		require.NoError(err)
		forkBlocks = append(forkBlocks, block)
	}

	// Process all of the fork blocks on the original chain to make it
	// experience a reorg.
	for _, forkBlock := range forkBlocks {
		_, _, err := chain1.ProcessBlock(forkBlock, true /*verifySignatures*/)
		require.NoError(err)
	}

	// Require that the tip of the first chain is now the same as the last
	// fork block.
	lastForkBlockHash, _ := forkBlocks[len(forkBlocks)-1].Hash()
	require.Equal(*lastForkBlockHash, *chain1.blockTip().Hash)

	// After the reorg, all of the transactions should have been undone
	// expcept the single spend from the sender to the recipient that
	/// occurred in the fork. As such the fork chain's balance should now
	// reflect the updated balance.
	require.Equal(uint64(5), _getBalance(t, chain1, nil, recipientPkString))
}

func _hexToBlock(t *testing.T, blockHex string) *MsgUltranetBlock {
	require := require.New(t)
	block := &MsgUltranetBlock{}
	blockBytes, err := hex.DecodeString(blockHex)
	require.NoError(err)
	require.NoError(block.FromBytes(blockBytes))
	return block
}

func TestProcessBlockConnectBlocks(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	chain, _, _ := NewTestBlockchain()

	_shouldConnectBlock(_hexToBlock(t, blockA1Hex), t, chain)
}

func _shouldConnectBlock(blk *MsgUltranetBlock, t *testing.T, chain *Blockchain) {
	require := require.New(t)

	blockHash, _ := blk.Hash()

	verifySignatures := true
	isMainChain, isOrphan, err := chain.ProcessBlock(blk, verifySignatures)
	require.NoError(err)
	require.Falsef(isOrphan, "Block %v should not be an orphan", blockHash)
	require.Truef(isMainChain, "Block %v should be on the main chain", blockHash)

	// The header tip and the block tip should now be equal to this block.
	require.Equal(*blockHash, *chain.headerTip().Hash)
	require.Equal(*blockHash, *chain.blockTip().Hash)
}

func init() {
	flag.Parse()

	// Set up logging.
	glog.GlogFlags.AlsoToStderr = true
	glog.Init()
	log.Printf("Logging to folder: %s", glog.GlogFlags.LogDir)
	log.Printf("Symlink to latest: %s", glog.GlogFlags.Symlink)
	log.Println("To log output on commandline, run with -alsologtostderr")
	glog.CopyStandardLogTo("INFO")
}

func TestProcessBlockReorgBlocks(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	chain, _, db := NewTestBlockchain()

	blockA1 := _hexToBlock(t, blockA1Hex)
	blockA2 := _hexToBlock(t, blockA2Hex)
	blockB1 := _hexToBlock(t, blockB1Hex)
	blockB2 := _hexToBlock(t, blockB2Hex)
	blockB3 := _hexToBlock(t, blockB3Hex)

	// These should connect without issue.
	fmt.Println("Connecting block a1")
	require.Equal(uint64(0), GetUtxoNumEntries(db))
	_shouldConnectBlock(blockA1, t, chain)

	fmt.Println("Connecting block a2")
	require.Equal(uint64(1), GetUtxoNumEntries(db))
	_shouldConnectBlock(blockA2, t, chain)

	// These should not be on the main chain.
	// Block b1
	fmt.Println("Connecting block b1")
	require.Equal(uint64(2), GetUtxoNumEntries(db))
	verifySignatures := true
	isMainChain, isOrphan, err := chain.ProcessBlock(blockB1, verifySignatures)
	require.NoError(err)
	require.Falsef(isOrphan, "Block b1 should not be an orphan")
	require.Falsef(isMainChain, "Block b1 should not be on the main chain")

	// Block b2
	fmt.Println("Connecting block b2")
	require.Equal(uint64(2), GetUtxoNumEntries(db))
	isMainChain, isOrphan, err = chain.ProcessBlock(blockB2, verifySignatures)
	require.NoError(err)
	require.Falsef(isOrphan, "Block b2 should not be an orphan")
	require.Falsef(isMainChain, "Block b2 should not be on the main chain")

	// This should cause the fork to take over, changing the main chain.
	fmt.Println("Connecting block b3")
	require.Equal(uint64(2), GetUtxoNumEntries(db))
	_shouldConnectBlock(blockB3, t, chain)

	fmt.Println("b3 is connected")
	require.Equal(uint64(3), GetUtxoNumEntries(db))
}

func _assembleBasicTransferTxnNoInputs(t *testing.T, amountNanos uint64) *MsgUltranetTxn {
	require := require.New(t)

	// manual_entropy_hex=0
	senderPkBytes, _, err := Base58CheckDecode(senderPkString)
	require.NoError(err)

	// manual_entropy_hex=1
	recipientPkBytes, _, err := Base58CheckDecode(recipientPkString)
	require.NoError(err)

	// Assemble the transaction so that inputs can be found and fees can
	// be computed.
	txnOutputs := []*UltranetOutput{}
	txnOutputs = append(txnOutputs, &UltranetOutput{
		PublicKey:   recipientPkBytes,
		AmountNanos: amountNanos,
	})
	txn := &MsgUltranetTxn{
		// The inputs will be set below.
		TxInputs:  []*UltranetInput{},
		TxOutputs: txnOutputs,
		PublicKey: senderPkBytes,
		TxnMeta:   &BasicTransferMetadata{},
		// We wait to compute the signature until we've added all the
		// inputs and change.
	}

	return txn
}

func _getSigForTesting(t *testing.T) *btcec.Signature {
	require := require.New(t)

	privKeyBytes, _, err := Base58CheckDecode(senderPrivString)
	require.NoError(err)
	privKey, _ := btcec.PrivKeyFromBytes(btcec.S256(), privKeyBytes)
	require.NoError(err)
	sig, err := privKey.Sign([]byte("whatever"))
	require.NoError(err)
	return sig
}

func _signTxn(t *testing.T, txn *MsgUltranetTxn, privKeyStrArg string) {
	require := require.New(t)

	privKeyBytes, _, err := Base58CheckDecode(privKeyStrArg)
	require.NoError(err)
	privKey, _ := btcec.PrivKeyFromBytes(btcec.S256(), privKeyBytes)
	require.NoError(err)
	txnSignature, err := txn.Sign(privKey)
	require.NoError(err)
	txn.Signature = txnSignature
}

func _assembleBasicTransferTxnFullySigned(t *testing.T, chain *Blockchain,
	amountNanos uint64, feeRateNanosPerKB uint64, senderPkStrArg string,
	recipientPkStrArg string, privKeyStrArg string,
	mempool *TxPool) *MsgUltranetTxn {

	require := require.New(t)

	// go run transaction_util.go --operation_type=generate_keys --manual_entropy_hex=0
	senderPkBytes, _, err := Base58CheckDecode(senderPkStrArg)
	require.NoError(err)

	// go run transaction_util.go --operation_type=generate_keys --manual_entropy_hex=1
	recipientPkBytes, _, err := Base58CheckDecode(recipientPkStrArg)
	require.NoError(err)

	// Assemble the transaction so that inputs can be found and fees can
	// be computed.
	txnOutputs := []*UltranetOutput{}
	txnOutputs = append(txnOutputs, &UltranetOutput{
		PublicKey:   recipientPkBytes,
		AmountNanos: amountNanos,
	})
	txn := &MsgUltranetTxn{
		// The inputs will be set below.
		TxInputs:  []*UltranetInput{},
		TxOutputs: txnOutputs,
		PublicKey: senderPkBytes,
		TxnMeta:   &BasicTransferMetadata{},
		// We wait to compute the signature until we've added all the
		// inputs and change.
	}

	totalInputAdded, spendAmount, totalChangeAdded, fee, err :=
		chain.AddInputsAndChangeToTransaction(txn, feeRateNanosPerKB, mempool)
	require.NoError(err)
	require.Equal(totalInputAdded, spendAmount+totalChangeAdded+fee)

	_signTxn(t, txn, privKeyStrArg)

	return txn
}

func TestAddInputsAndChangeToTransaction(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	chain, _, db := NewTestBlockchain()
	_ = db

	blockB1 := _hexToBlock(t, blockB1Hex)
	blockB2 := _hexToBlock(t, blockB2Hex)
	blockB3 := _hexToBlock(t, blockB3Hex)

	// Spending nothing should be OK. It shouldn't add anything to the transaction.
	{
		txn := _assembleBasicTransferTxnNoInputs(t, 0)
		feeRateNanosPerKB := uint64(0)

		totalInputAdded, spendAmount, totalChangeAdded, fee, err :=
			chain.AddInputsAndChangeToTransaction(txn, feeRateNanosPerKB, nil)
		require.NoError(err)
		require.Equal(0, len(txn.TxInputs))
		require.Equal(1, len(txn.TxOutputs))
		require.Equal(totalInputAdded, uint64(0))
		require.Equal(spendAmount, uint64(0))
		require.Equal(totalChangeAdded, uint64(0))
		require.Equal(fee, uint64(0))
	}

	// Spending a nonzero amount should fail before we have mined a block
	// reward for ourselves.
	{
		txn := _assembleBasicTransferTxnNoInputs(t, 1)
		feeRateNanosPerKB := uint64(0)

		_, _, _, _, err :=
			chain.AddInputsAndChangeToTransaction(txn, feeRateNanosPerKB, nil)
		require.Error(err)
	}

	// Nonzero/high fee should also cause an error if we have no money.
	{
		txn := _assembleBasicTransferTxnNoInputs(t, 0)
		feeRateNanosPerKB := uint64(1000)

		_, _, _, _, err :=
			chain.AddInputsAndChangeToTransaction(txn, feeRateNanosPerKB, nil)
		require.Error(err)
	}

	// Save the block reward in the first block to use it for testing.
	firstBlockReward := CalcBlockRewardNanos(1)

	// Connect a block. The sender address should have mined some Ultra but
	// it should be unspendable until the block after this one. See
	// BlockRewardMaturity.
	_shouldConnectBlock(blockB1, t, chain)

	// Verify that spending a nonzero amount fails after the first block.
	{
		txn := _assembleBasicTransferTxnNoInputs(t, 1)
		feeRateNanosPerKB := uint64(0)

		_, _, _, _, err :=
			chain.AddInputsAndChangeToTransaction(txn, feeRateNanosPerKB, nil)
		require.Error(err)
	}

	_shouldConnectBlock(blockB2, t, chain)

	// Verify that spending a nonzero amount passes after the second block
	// since at this point it is presumed the transaction will be mined
	// into the third block at which point the block reward shouild be
	// mature.

	// Verify a moderate spend with a moderate feerate works.
	{
		testSpend := firstBlockReward / 2
		txn := _assembleBasicTransferTxnNoInputs(t, testSpend)
		feeRateNanosPerKB := uint64(testSpend)

		totalInputAdded, spendAmount, totalChangeAdded, fee, err :=
			chain.AddInputsAndChangeToTransaction(txn, feeRateNanosPerKB, nil)
		require.NoError(err)
		require.Equal(1, len(txn.TxInputs))
		require.Equal(2, len(txn.TxOutputs))
		require.Equal(spendAmount, uint64(testSpend))
		require.Greater(fee, uint64(0))
		require.Equal(uint64(firstBlockReward), totalInputAdded)
		require.Equal(totalInputAdded, spendAmount+totalChangeAdded+fee)
	}

	// Verify spending more than a block reward fails.
	{
		testSpend := firstBlockReward + 1
		txn := _assembleBasicTransferTxnNoInputs(t, testSpend)
		feeRateNanosPerKB := uint64(0)

		_, _, _, _, err :=
			chain.AddInputsAndChangeToTransaction(txn, feeRateNanosPerKB, nil)
		require.Error(err)
	}

	_shouldConnectBlock(blockB3, t, chain)

	// Verify spending more than the first block reward passes after the
	// next block.
	{
		testSpend := firstBlockReward + 1
		txn := _assembleBasicTransferTxnNoInputs(t, testSpend)
		feeRateNanosPerKB := uint64(0)

		_, _, _, _, err :=
			chain.AddInputsAndChangeToTransaction(txn, feeRateNanosPerKB, nil)
		require.NoError(err)
	}
}

func TestValidateBasicTransfer(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	chain, _, db := NewTestBlockchain()
	_ = db

	blockB1 := _hexToBlock(t, blockB1Hex)
	blockB2 := _hexToBlock(t, blockB2Hex)

	// Save the block reward in the first block to use it for testing.
	firstBlockReward := CalcBlockRewardNanos(1)

	// Connect a block. The sender address should have mined some Ultra but
	// it should be unspendable until the block after this one. See
	// BlockRewardMaturity.
	_shouldConnectBlock(blockB1, t, chain)
	_shouldConnectBlock(blockB2, t, chain)

	// Verify that a transaction spending a nonzero amount passes validation
	// after the second block due to the block reward having matured.
	{
		spendAmount := firstBlockReward / 2
		feeRateNanosPerKB := firstBlockReward
		txn := _assembleBasicTransferTxnFullySigned(t, chain, spendAmount, feeRateNanosPerKB,
			senderPkString, recipientPkString, senderPrivString, nil)
		err := chain.ValidateTransaction(txn, chain.BlockTip().Height+1,
			true /*verifySignatures*/, true /*verifyMerchantMerkleRoot*/, false /*enforceMinBitcoinBurnWork*/, nil)
		require.NoError(err)
	}

	// Verify that a transaction spending more than its input is shot down.
	{
		spendAmount := firstBlockReward / 2
		feeRateNanosPerKB := firstBlockReward
		txn := _assembleBasicTransferTxnFullySigned(t, chain, spendAmount, feeRateNanosPerKB,
			senderPkString, recipientPkString, senderPrivString, nil)
		{
			senderPkBytes, _, err := Base58CheckDecode(senderPkString)
			require.NoError(err)
			txn.TxOutputs = append(txn.TxOutputs, &UltranetOutput{
				PublicKey: senderPkBytes,
				// Guaranteed to be more than we're allowed to spend.
				AmountNanos: firstBlockReward,
			})
			// Re-sign the transaction.
			_signTxn(t, txn, senderPrivString)
		}

		err := chain.ValidateTransaction(txn, chain.BlockTip().Height+1,
			true /*verifySignatures*/, true, /*verifyMerchantMerkleRoot*/
			false /*enforceMinBitcoinBurnWork*/, nil)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorTxnOutputExceedsInput)
	}

	// Verify that a transaction spending an immature block reward is shot down.
	{
		spendAmount := firstBlockReward
		feeRateNanosPerKB := uint64(0)
		txn := _assembleBasicTransferTxnFullySigned(t, chain, spendAmount, feeRateNanosPerKB,
			senderPkString, recipientPkString, senderPrivString, nil)
		// Try and spend the block reward from block B2, which should not have matured
		// yet.
		b2RewardHash := blockB2.Txns[0].Hash()
		require.NotNil(b2RewardHash)
		txn.TxInputs = append(txn.TxInputs, &UltranetInput{
			TxID:  *b2RewardHash,
			Index: 0,
		})
		// Re-sign the transaction.
		_signTxn(t, txn, senderPrivString)
		err := chain.ValidateTransaction(txn, chain.BlockTip().Height+1,
			true /*verifySignatures*/, true, /*verifyMerchantMerkleRoot*/
			false /*enforceMinBitcoinBurnWork*/, nil)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorInputSpendsImmatureBlockReward)
	}
}

func TestComputeMerkle(t *testing.T) {
	//assert := assert.New(t)
	//require := require.New(t)
	//_ = assert
	//_ = require

	//blk := _copyBlock(expectedBlock)
	//merkleRoot1, _, err := ComputeMerkleRoot(blk.Txns)
	//require.NoError(err)

	//blk.Header.Nonce[0] = 0x00
	//merkleRoot2, _, err := ComputeMerkleRoot(blk.Txns)
	//require.NoError(err)
	//assert.Equal(merkleRoot1, merkleRoot2)

	//oldSigVal := blk.Txns[1].Signature[5]
	//blk.Txns[1].Signature[5] = 0x00
	//merkleRoot3, _, err := ComputeMerkleRoot(blk.Txns)
	//require.NoError(err)
	//assert.NotEqual(merkleRoot1, merkleRoot3)

	//blk.Txns[1].Signature[5] = oldSigVal
	//merkleRoot4, _, err := ComputeMerkleRoot(blk.Txns)
	//require.NoError(err)
	//assert.Equal(merkleRoot1, merkleRoot4)
}

func TestCalcNextDifficultyTargetHalvingDoublingHitLimit(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	fakeParams := &UltranetParams{
		MinDifficultyTargetHex:         hex.EncodeToString(BigintToHash(big.NewInt(100000))[:]),
		TimeBetweenDifficultyRetargets: 6 * time.Second,
		TimeBetweenBlocks:              2 * time.Second,
		MaxDifficultyRetargetFactor:    2,
	}

	nodes := []*BlockNode{}
	diffsAsInts := []int64{}
	for ii := 0; ii < 13; ii++ {
		var lastNode *BlockNode
		if ii > 0 {
			lastNode = nodes[ii-1]
		}
		nextDiff, err := CalcNextDifficultyTarget(lastNode, fakeParams)
		require.NoErrorf(err, "Block index: %d", ii)
		nodes = append(nodes, NewBlockNode(
			lastNode,
			nil,
			uint32(ii),
			nextDiff,
			nil,
			&MsgUltranetHeader{
				// Blocks generating every 1 second, which is 2x too fast.
				TstampSecs: uint32(ii),
			},
			StatusNone,
		))

		diffsAsInts = append(diffsAsInts, HashToBigint(nextDiff).Int64())
	}

	assert.Equal([]int64{
		100000,
		100000,
		100000,
		100000,
		100000,
		100000,
		100000,
		50000,
		50000,
		50000,
		25000,
		25000,
		25000,
	}, diffsAsInts)

	diffsAsInts = []int64{}
	for ii := 13; ii < 30; ii++ {
		lastNode := nodes[ii-1]
		nextDiff, err := CalcNextDifficultyTarget(lastNode, fakeParams)
		require.NoErrorf(err, "Block index: %d", ii)
		nodes = append(nodes, NewBlockNode(
			lastNode,
			nil,
			uint32(ii),
			nextDiff,
			nil,
			&MsgUltranetHeader{
				// Blocks generating every 4 second, which is 2x too slow.
				TstampSecs: uint32(ii * 4),
			},
			StatusNone,
		))

		diffsAsInts = append(diffsAsInts, HashToBigint(nextDiff).Int64())
	}

	assert.Equal([]int64{
		12500,
		12500,
		12500,
		25000,
		25000,
		25000,
		50000,
		50000,
		50000,
		100000,
		100000,
		100000,
		100000,
		100000,
		100000,
		100000,
		100000,
	}, diffsAsInts)
}

func TestCalcNextDifficultyTargetHittingLimitsSlow(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	fakeParams := &UltranetParams{
		MinDifficultyTargetHex:         hex.EncodeToString(BigintToHash(big.NewInt(100000))[:]),
		TimeBetweenDifficultyRetargets: 6 * time.Second,
		TimeBetweenBlocks:              2 * time.Second,
		MaxDifficultyRetargetFactor:    2,
	}

	nodes := []*BlockNode{}
	diffsAsInts := []int64{}
	for ii := 0; ii < 13; ii++ {
		var lastNode *BlockNode
		if ii > 0 {
			lastNode = nodes[ii-1]
		}
		nextDiff, err := CalcNextDifficultyTarget(lastNode, fakeParams)
		require.NoErrorf(err, "Block index: %d", ii)
		nodes = append(nodes, NewBlockNode(
			lastNode,
			nil,
			uint32(ii),
			nextDiff,
			nil,
			&MsgUltranetHeader{
				// Blocks generating every 1 second, which is 2x too fast.
				TstampSecs: uint32(ii),
			},
			StatusNone,
		))

		diffsAsInts = append(diffsAsInts, HashToBigint(nextDiff).Int64())
	}

	assert.Equal([]int64{
		100000,
		100000,
		100000,
		100000,
		100000,
		100000,
		100000,
		50000,
		50000,
		50000,
		25000,
		25000,
		25000,
	}, diffsAsInts)

	diffsAsInts = []int64{}
	for ii := 13; ii < 30; ii++ {
		lastNode := nodes[ii-1]
		nextDiff, err := CalcNextDifficultyTarget(lastNode, fakeParams)
		require.NoErrorf(err, "Block index: %d", ii)
		nodes = append(nodes, NewBlockNode(
			lastNode,
			nil,
			uint32(ii),
			nextDiff,
			nil,
			&MsgUltranetHeader{
				// Blocks generating every 8 second, which is >2x too slow.
				TstampSecs: uint32(ii * 4),
			},
			StatusNone,
		))

		diffsAsInts = append(diffsAsInts, HashToBigint(nextDiff).Int64())
	}

	assert.Equal([]int64{
		12500,
		12500,
		12500,
		25000,
		25000,
		25000,
		50000,
		50000,
		50000,
		100000,
		100000,
		100000,
		100000,
		100000,
		100000,
		100000,
		100000,
	}, diffsAsInts)
}

func TestCalcNextDifficultyTargetHittingLimitsFast(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	fakeParams := &UltranetParams{
		MinDifficultyTargetHex:         hex.EncodeToString(BigintToHash(big.NewInt(100000))[:]),
		TimeBetweenDifficultyRetargets: 6 * time.Second,
		TimeBetweenBlocks:              2 * time.Second,
		MaxDifficultyRetargetFactor:    2,
	}

	nodes := []*BlockNode{}
	diffsAsInts := []int64{}
	for ii := 0; ii < 13; ii++ {
		var lastNode *BlockNode
		if ii > 0 {
			lastNode = nodes[ii-1]
		}
		nextDiff, err := CalcNextDifficultyTarget(lastNode, fakeParams)
		require.NoErrorf(err, "Block index: %d", ii)
		nodes = append(nodes, NewBlockNode(
			lastNode,
			nil,
			uint32(ii),
			nextDiff,
			nil,
			&MsgUltranetHeader{
				// Blocks generating all at once.
				TstampSecs: uint32(0),
			},
			StatusNone,
		))

		diffsAsInts = append(diffsAsInts, HashToBigint(nextDiff).Int64())
	}

	assert.Equal([]int64{
		100000,
		100000,
		100000,
		100000,
		100000,
		100000,
		100000,
		50000,
		50000,
		50000,
		25000,
		25000,
		25000,
	}, diffsAsInts)
}

func TestCalcNextDifficultyTargetJustRight(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	fakeParams := &UltranetParams{
		MinDifficultyTargetHex:         hex.EncodeToString(BigintToHash(big.NewInt(100000))[:]),
		TimeBetweenDifficultyRetargets: 6 * time.Second,
		TimeBetweenBlocks:              2 * time.Second,
		MaxDifficultyRetargetFactor:    3,
	}

	nodes := []*BlockNode{}
	diffsAsInts := []int64{}
	for ii := 0; ii < 13; ii++ {
		var lastNode *BlockNode
		if ii > 0 {
			lastNode = nodes[ii-1]
		}
		nextDiff, err := CalcNextDifficultyTarget(lastNode, fakeParams)
		require.NoErrorf(err, "Block index: %d", ii)
		nodes = append(nodes, NewBlockNode(
			lastNode,
			nil,
			uint32(ii),
			nextDiff,
			nil,
			&MsgUltranetHeader{
				// Blocks generating every 2 second, which is under the limit.
				TstampSecs: uint32(ii * 2),
			},
			StatusNone,
		))

		diffsAsInts = append(diffsAsInts, HashToBigint(nextDiff).Int64())
	}

	assert.Equal([]int64{
		100000,
		100000,
		100000,
		100000,
		100000,
		100000,
		100000,
		100000,
		100000,
		100000,
		100000,
		100000,
		100000,
	}, diffsAsInts)
}

func TestCalcNextDifficultyTargetSlightlyOff(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	fakeParams := &UltranetParams{
		MinDifficultyTargetHex:         hex.EncodeToString(BigintToHash(big.NewInt(100000))[:]),
		TimeBetweenDifficultyRetargets: 6 * time.Second,
		TimeBetweenBlocks:              2 * time.Second,
		MaxDifficultyRetargetFactor:    2,
	}

	nodes := []*BlockNode{}
	diffsAsInts := []int64{}
	for ii := 0; ii < 13; ii++ {
		var lastNode *BlockNode
		if ii > 0 {
			lastNode = nodes[ii-1]
		}
		nextDiff, err := CalcNextDifficultyTarget(lastNode, fakeParams)
		require.NoErrorf(err, "Block index: %d", ii)
		nodes = append(nodes, NewBlockNode(
			lastNode,
			nil,
			uint32(ii),
			nextDiff,
			nil,
			&MsgUltranetHeader{
				// Blocks generating every 1 second, which is 2x too fast.
				TstampSecs: uint32(ii),
			},
			StatusNone,
		))

		diffsAsInts = append(diffsAsInts, HashToBigint(nextDiff).Int64())
	}

	assert.Equal([]int64{
		100000,
		100000,
		100000,
		100000,
		100000,
		100000,
		100000,
		50000,
		50000,
		50000,
		25000,
		25000,
		25000,
	}, diffsAsInts)

	diffsAsInts = []int64{}
	for ii := 13; ii < 34; ii++ {
		lastNode := nodes[ii-1]
		nextDiff, err := CalcNextDifficultyTarget(lastNode, fakeParams)
		require.NoErrorf(err, "Block index: %d", ii)
		nodes = append(nodes, NewBlockNode(
			lastNode,
			nil,
			uint32(ii),
			nextDiff,
			nil,
			&MsgUltranetHeader{
				// Blocks generating every 3 seconds, which is slow but under the limit.
				TstampSecs: uint32(float32(ii) * 3),
			},
			StatusNone,
		))

		diffsAsInts = append(diffsAsInts, HashToBigint(nextDiff).Int64())
	}

	assert.Equal([]int64{
		12500,
		12500,
		12500,
		25000,
		25000,
		25000,
		37500,
		37500,
		37500,
		56250,
		56250,
		56250,
		84375,
		84375,
		84375,
		100000,
		100000,
		100000,
		100000,
		100000,
		100000,
	}, diffsAsInts)
}

func _testMerkleRoot(t *testing.T, shouldFail bool, blockHex string) {
	assert := assert.New(t)
	require := require.New(t)
	_, _ = assert, require

	blockBytes, err := hex.DecodeString(blockHex)
	require.NoError(err)
	blk := &MsgUltranetBlock{}
	require.NoError(blk.FromBytes(blockBytes))
	computedMerkle, _, err := ComputeMerkleRoot(blk.Txns)
	require.NoError(err)
	if shouldFail {
		require.NotEqual(blk.Header.TransactionMerkleRoot, computedMerkle)
	} else {
		require.Equal(blk.Header.TransactionMerkleRoot, computedMerkle)
	}
}

func TestBadMerkleRoot(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_, _ = assert, require

	// Grab some block hex by running miner.go at v=2 and use test_scratch.go
	// to perturb the merkle root to mess it up.
	_testMerkleRoot(t, false /*shouldFail*/, "5000000000a2609ff6931a1c6c1a52f6d229a1e18b97549929eb5704ae5aeb836b4c041904e699b35383e67e2ca676cb7c3597de51818d7fcf18bdc1ec15ae68c03259624b36d7125e0100000018570000015700010342d943b8dba93a4ce29b858479c67f1e4f1110eecbe1f83dc01b455eb8b123b380a8d6b907012b00000000000000000000000000000000000000000000000000000000000000000abaaa93ccf284d0b8f0010000")
	_testMerkleRoot(t, true /*shouldFail*/, "5000000000000007ecaac40bb6d08e8ab5f712485db41149b1df5f95e3313dc284121b12490000000000000000000000000000000000000000000000000000000000000000e854ed5d2300000089230000015600010342d943b8dba93a4ce29b858479c67f1e4f1110eecbe1f83dc01b455eb8b123b380a8d6b907012a00000000000000000000000000000000000000000000000000000000000000000985c887c2e1bddee5680000")
}
