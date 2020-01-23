package lib

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"math"
	"math/big"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/wire"
	"github.com/dgraph-io/badger"
	merkletree "github.com/laser/go-merkle-tree"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func _strToPk(t *testing.T, pkStr string) []byte {
	require := require.New(t)

	pkBytes, _, err := Base58CheckDecode(pkStr)
	require.NoError(err)

	return pkBytes
}

func TestBasicTransfer(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	chain, params, db := NewLowDifficultyBlockchain()
	mempool, miner := NewTestMiner(t, chain, params, true /*isSender*/)
	// Mine two blocks to give the sender some Ultra.
	block, err := miner._mineAndProcessSingleBlock(0 /*threadIndex*/)
	require.NoError(err)
	block, err = miner._mineAndProcessSingleBlock(0 /*threadIndex*/)
	require.NoError(err)
	_, _ = block, mempool

	senderPkBytes, _, err := Base58CheckDecode(senderPkString)
	require.NoError(err)
	recipientPkBytes, _, err := Base58CheckDecode(recipientPkString)
	require.NoError(err)

	// A basic transfer whose input public keys differ from the
	// transaction-level public key should fail.
	{
		txn := &MsgUltranetTxn{
			// The inputs will be set below.
			TxInputs: []*UltranetInput{},
			TxOutputs: []*UltranetOutput{
				&UltranetOutput{
					PublicKey:   recipientPkBytes,
					AmountNanos: 1,
				},
			},
			PublicKey: senderPkBytes,
			TxnMeta:   &BasicTransferMetadata{},
		}

		totalInput, spendAmount, changeAmount, fees, err :=
			chain.AddInputsAndChangeToTransaction(txn, 10, nil)
		require.NoError(err)
		require.Equal(totalInput, spendAmount+changeAmount+fees)
		require.Greater(totalInput, uint64(0))

		// At this point the txn has inputs for senderPkString. Change
		// the public key to recipientPkString and sign it with the
		// recipientPrivString.
		txn.PublicKey = recipientPkBytes

		_signTxn(t, txn, recipientPrivString)
		utxoView, err := NewUtxoView(db, params, nil)
		txHash := txn.Hash()
		blockHeight := chain.blockTip().Height + 1
		_, _, _, _, err =
			utxoView.ConnectTransaction(txn, txHash, blockHeight, true /*verifySignature*/, true /*verifyMerchantMerkleRoot*/)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorInputWithPublicKeyDifferentFromTxnPublicKey)
	}

	// Just a basic transfer with a bad signature.
	{
		txn := &MsgUltranetTxn{
			// The inputs will be set below.
			TxInputs: []*UltranetInput{},
			TxOutputs: []*UltranetOutput{
				&UltranetOutput{
					PublicKey:   recipientPkBytes,
					AmountNanos: 1,
				},
			},
			PublicKey: senderPkBytes,
			TxnMeta:   &BasicTransferMetadata{},
		}

		totalInput, spendAmount, changeAmount, fees, err :=
			chain.AddInputsAndChangeToTransaction(txn, 10, nil)
		require.NoError(err)
		require.Equal(totalInput, spendAmount+changeAmount+fees)
		require.Greater(totalInput, uint64(0))

		// Sign the transaction with the recipient's key rather than the
		// sender's key.
		_signTxn(t, txn, recipientPrivString)
		utxoView, err := NewUtxoView(db, params, nil)
		txHash := txn.Hash()
		blockHeight := chain.blockTip().Height + 1
		_, _, _, _, err =
			utxoView.ConnectTransaction(txn, txHash, blockHeight, true /*verifySignature*/, true /*verifyMerchantMerkleRoot*/)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorInvalidTransactionSignature)
	}

	// A block reward with a bad signature should fail.
	{
		txn := &MsgUltranetTxn{
			// The inputs will be set below.
			TxInputs: []*UltranetInput{},
			TxOutputs: []*UltranetOutput{
				&UltranetOutput{
					PublicKey:   recipientPkBytes,
					AmountNanos: 1,
				},
			},
			PublicKey: senderPkBytes,
			TxnMeta: &BlockRewardMetadataa{
				MerchantMerkleRoot: &BlockHash{},
				ExtraData:          []byte{0x00, 0x01},
			},
		}
		_signTxn(t, txn, senderPrivString)
		utxoView, err := NewUtxoView(db, params, nil)
		txHash := txn.Hash()
		blockHeight := chain.blockTip().Height + 1
		_, _, _, _, err =
			utxoView.ConnectTransaction(txn, txHash, blockHeight, true /*verifySignature*/, true /*verifyMerchantMerkleRoot*/)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorBlockRewardTxnNotAllowedToHaveSignature)
	}

	// A block reward with an input, even if it's signed legitimately,
	// should fail.
	{
		txn := &MsgUltranetTxn{
			// The inputs will be set below.
			TxInputs: []*UltranetInput{},
			TxOutputs: []*UltranetOutput{
				&UltranetOutput{
					PublicKey:   recipientPkBytes,
					AmountNanos: 1,
				},
			},
			PublicKey: senderPkBytes,
			TxnMeta: &BlockRewardMetadataa{
				ExtraData: []byte{0x00, 0x01},
			},
		}

		totalInput, spendAmount, changeAmount, fees, err :=
			chain.AddInputsAndChangeToTransaction(txn, 10, nil)
		require.NoError(err)
		require.Equal(totalInput, spendAmount+changeAmount+fees)
		require.Greater(totalInput, uint64(0))

		_signTxn(t, txn, senderPrivString)
		utxoView, err := NewUtxoView(db, params, nil)
		txHash := txn.Hash()
		blockHeight := chain.blockTip().Height + 1
		_, _, _, _, err =
			utxoView.ConnectTransaction(txn, txHash, blockHeight, true /*verifySignature*/, true /*verifyMerchantMerkleRoot*/)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorBlockRewardTxnNotAllowedToHaveInputs)
	}

	// A block with too much block reward should fail.
	allowedBlockReward := CalcBlockRewardNanos(chain.BlockTip().Height)
	require.Equal(allowedBlockReward, 2*NanosPerUnit)
	blockToMine, _, _, err := miner._getBlockToMine(0 /*threadIndex*/)
	require.NoError(err)
	{
		blockToMine.Txns[0].TxOutputs[0].AmountNanos = allowedBlockReward + 1
		// One iteration should be sufficient to find us a good block.
		_, bestNonce, err := FindLowestHash(blockToMine.Header, 10000)
		require.NoError(err)
		blockToMine.Header.Nonce = bestNonce

		txHashes, err := ComputeTransactionHashes(blockToMine.Txns)
		require.NoError(err)
		utxoView, err := NewUtxoView(db, params, nil)
		_, err = utxoView.ConnectBlock(blockToMine, txHashes, true /*verifySignatures*/, true /*verifyMerchantMerkleRoot*/)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorBlockRewardExceedsMaxAllowed)
	}

	// A block with less than the max block reward should be OK.
	{
		blockToMine.Txns[0].TxOutputs[0].AmountNanos = allowedBlockReward - 1
		// One iteration should be sufficient to find us a good block.
		_, bestNonce, err := FindLowestHash(blockToMine.Header, 10000)
		require.NoError(err)
		blockToMine.Header.Nonce = bestNonce

		txHashes, err := ComputeTransactionHashes(blockToMine.Txns)
		require.NoError(err)
		utxoView, err := NewUtxoView(db, params, nil)
		_, err = utxoView.ConnectBlock(blockToMine, txHashes, true /*verifySignatures*/, true /*verifyMerchantMerkleRoot*/)
		require.NoError(err)
	}
}

func _assembleRegisterMerchantFullySigned(
	t *testing.T, chain *Blockchain, pkStr string, privStr string,
	feeRateNanosPerKB uint64, burnAmountNanos uint64, mempool *TxPool) *MsgUltranetTxn {

	require := require.New(t)

	pkBytes, _, err := Base58CheckDecode(pkStr)
	require.NoError(err)
	txn := &MsgUltranetTxn{
		// The inputs will be set below.
		TxInputs:  []*UltranetInput{},
		TxOutputs: []*UltranetOutput{},
		PublicKey: pkBytes,
		TxnMeta: &RegisterMerchantMetadata{
			Username:        []byte(pkStr),
			Description:     []byte("i mean she's the best "),
			BurnAmountNanos: burnAmountNanos,
		},

		// We wait to compute the signature until we've added all the
		// inputs and change.
	}

	totalInput, spendAmount, changeAmount, fees, err :=
		chain.AddInputsAndChangeToTransaction(txn, feeRateNanosPerKB, mempool)
	require.NoError(err)
	require.Equal(totalInput, spendAmount+changeAmount+fees)
	// The burn amount is interpreted by this function as the amount spent.
	// Treating it this way allows it to fetch the right amount of input.
	require.Equal(burnAmountNanos, spendAmount)

	// Sign the transaction now that its inputs are set up.
	_signTxn(t, txn, privStr)

	return txn
}

func TestRegisterMerchantMerkleAllSameBurnAmountLimiteNumMerchants(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	chain, params, db := NewLowDifficultyBlockchain()
	mempool, miner := NewTestMiner(t, chain, params, true /*isSender*/)

	// This is the key thing we change in this test.
	params.MaxMerchantsToIndex = 3

	// Mine two blocks to give the sender some Ultra.
	block, err := miner._mineAndProcessSingleBlock(0 /*threadIndex*/)
	require.NoError(err)
	require.Equal(&BlockHash{}, block.Txns[0].TxnMeta.(*BlockRewardMetadataa).MerchantMerkleRoot)
	block, err = miner._mineAndProcessSingleBlock(0 /*threadIndex*/)
	require.NoError(err)
	require.Equal(&BlockHash{}, block.Txns[0].TxnMeta.(*BlockRewardMetadataa).MerchantMerkleRoot)
	// Mine a block to give some other public keys some Ultra as well.
	m0Pub := "tUN2RExHhcCWqXqT9r7syGupJS6hxrBPDQMssSph6ki1FZLJTczUm4"
	m0Priv := "tunSykM1Si6Wab5mRKBDu7YK5ubpBxr1ciGiiDXmSpMATB12sAawx"
	m1Pub := "tUN2RUx1U7By7i2CZn5sZEEb5jjEHfoyc4Nvk2P9gc6Lf8Bc29xzzB"
	m1Priv := "tunSJ83kV4PNkC7MPEgbmKWNZeJk1mTbjwXUh9oy7kyBLRWsgFjVw"
	// Non-merchants
	m2Pub := "tUN2NazDYX2zmbPMXagebSjHmK6QcybHBGRvFMrHDRgn5Us8YPs1De"
	m2Priv := "tunTBiMhRjKVmeK6bF8kJFQpmxH2UnTweB8zYsvH3bJPjyVMZr5kS"
	m3Pub := "tUN2Q3nYf8KNgZ5q3ftFeEq3fRFpB8CCzXTW5KV4kGrCm4LEvdv67e"
	m3Priv := "tunSRyKa6shh2S6LH3WsFa6jtT42ktUgVcSdZFqTsMBy3KPnHC9kR"

	_, _, _, _ = m1Priv, m2Priv, m3Priv, db
	{
		txn := _assembleBasicTransferTxnFullySigned(
			t, chain, 1000, 100, senderPkString, m0Pub, senderPrivString, mempool)
		_, err := mempool.processTransaction(txn, false, true, 0, true)
		require.NoError(err)
	}
	{
		txn := _assembleBasicTransferTxnFullySigned(
			t, chain, 1001, 100, senderPkString, m1Pub, senderPrivString, mempool)
		_, err := mempool.processTransaction(txn, false, true, 0, true)
		require.NoError(err)
	}
	{
		txn := _assembleBasicTransferTxnFullySigned(
			t, chain, 1002, 100, senderPkString, m2Pub, senderPrivString, mempool)
		_, err := mempool.processTransaction(txn, false, true, 0, true)
		require.NoError(err)
	}
	{
		txn := _assembleBasicTransferTxnFullySigned(
			t, chain, 1003, 100, senderPkString, m3Pub, senderPrivString, mempool)
		_, err := mempool.processTransaction(txn, false, true, 0, true)
		require.NoError(err)
	}
	block, err = miner._mineAndProcessSingleBlock(0 /*threadIndex*/)
	require.Equal(5, len(block.Txns))
	require.Equal(&BlockHash{}, block.Txns[0].TxnMeta.(*BlockRewardMetadataa).MerchantMerkleRoot)
	require.Equal(int64(1000), int64(_getBalance(t, chain, nil, m0Pub)))
	require.Equal(int64(1001), int64(_getBalance(t, chain, nil, m1Pub)))
	require.Equal(int64(1002), int64(_getBalance(t, chain, nil, m2Pub)))
	require.Equal(int64(1003), int64(_getBalance(t, chain, nil, m3Pub)))
	require.NoError(err)
	mempool.UpdateAfterConnectBlock(block)

	// Register a single merchant and verify that the merchant merkle of the next
	// block is consistent with it.
	var m0MerchantID *BlockHash
	{
		txn := _assembleRegisterMerchantFullySigned(t, chain, m0Pub, m0Priv, 100, 10, nil)
		_, err := mempool.processTransaction(txn, false, true, 0, true)
		require.NoError(err)
		m0MerchantID = txn.Hash()
	}
	block, err = miner._mineAndProcessSingleBlock(0 /*threadIndex*/)
	require.NoError(err)
	require.Equal(2, len(block.Txns))
	// Merkle root should be zero since there were no merchants *before* this block.
	require.Equal(&BlockHash{}, block.Txns[0].TxnMeta.(*BlockRewardMetadataa).MerchantMerkleRoot)
	mempool.UpdateAfterConnectBlock(block)

	// If we mine another block its merkle root should show that there is one merchant
	// in the db.
	block, err = miner._mineAndProcessSingleBlock(0 /*threadIndex*/)
	require.NoError(err)
	require.Equal(1, len(block.Txns))
	// Get the single merchant entry from the db and compute the merkle tree that
	// consists solely of it.
	{
		merchantEntry1 := DbGetMerchantEntryForMerchantID(db, m0MerchantID)
		merchantEntry1Hash := HashMerchantEntry(merchantEntry1)
		merkleRoot1 := &BlockHash{}
		copy(merkleRoot1[:], merkletree.NewTreeFromHashes(
			merkletree.Sha256DoubleHash,
			[][]byte{merchantEntry1Hash[:]}).Root.GetHash()[:])
		require.Equal(merkleRoot1, block.Txns[0].TxnMeta.(*BlockRewardMetadataa).MerchantMerkleRoot)
	}
	// Register the other merchants.
	var m1MerchantID *BlockHash
	var m2MerchantID *BlockHash
	var m3MerchantID *BlockHash
	{
		txn := _assembleRegisterMerchantFullySigned(t, chain, m1Pub, m1Priv, 100, 10, nil)
		_, err := mempool.processTransaction(txn, false, true, 0, true)
		require.NoError(err)
		m1MerchantID = txn.Hash()
	}
	{
		txn := _assembleRegisterMerchantFullySigned(t, chain, m2Pub, m2Priv, 100, 10, nil)
		_, err := mempool.processTransaction(txn, false, true, 0, true)
		require.NoError(err)
		m2MerchantID = txn.Hash()
	}
	{
		txn := _assembleRegisterMerchantFullySigned(t, chain, m3Pub, m3Priv, 100, 10, nil)
		_, err := mempool.processTransaction(txn, false, true, 0, true)
		require.NoError(err)
		m3MerchantID = txn.Hash()
	}
	block, err = miner._mineAndProcessSingleBlock(0 /*threadIndex*/)
	require.NoError(err)
	require.Equal(4, len(block.Txns))
	mempool.UpdateAfterConnectBlock(block)
	// Merkle root should match the single merchant merkle root since there was only
	// one merchant *before* this block.
	{
		merchantEntry1 := DbGetMerchantEntryForMerchantID(db, m0MerchantID)
		merchantEntry1Hash := HashMerchantEntry(merchantEntry1)
		merkleRoot1 := &BlockHash{}
		copy(merkleRoot1[:], merkletree.NewTreeFromHashes(
			merkletree.Sha256DoubleHash,
			[][]byte{merchantEntry1Hash[:]}).Root.GetHash()[:])
		require.Equal(merkleRoot1, block.Txns[0].TxnMeta.(*BlockRewardMetadataa).MerchantMerkleRoot)

	}
	block, err = miner._mineAndProcessSingleBlock(0 /*threadIndex*/)
	require.NoError(err)
	require.Equal(1, len(block.Txns))
	mempool.UpdateAfterConnectBlock(block)
	// Now the merkle root should reflect all the merchants since they were all present
	// before this block.
	{
		merchantEntry0 := DbGetMerchantEntryForMerchantID(db, m0MerchantID)
		merchantEntry1 := DbGetMerchantEntryForMerchantID(db, m1MerchantID)
		merchantEntry2 := DbGetMerchantEntryForMerchantID(db, m2MerchantID)
		merchantEntry3 := DbGetMerchantEntryForMerchantID(db, m3MerchantID)
		merchantEntries := []*MerchantEntry{merchantEntry0, merchantEntry1, merchantEntry2, merchantEntry3}
		sort.Slice(merchantEntries, func(ii, jj int) bool {
			return PkToString(
				merchantEntries[ii].merchantID[:], params) > PkToString(merchantEntries[jj].merchantID[:], params)
		})

		merkleRoot := &BlockHash{}
		// Should be sorted by merchantID.
		copy(merkleRoot[:], merkletree.NewTreeFromHashes(
			merkletree.Sha256DoubleHash,
			[][]byte{
				HashMerchantEntry(merchantEntries[0])[:],
				HashMerchantEntry(merchantEntries[1])[:],
				HashMerchantEntry(merchantEntries[2])[:],
			},
		).Root.GetHash()[:])
		require.Equalf(merkleRoot, block.Txns[0].TxnMeta.(*BlockRewardMetadataa).MerchantMerkleRoot,
			"make sure the merchants are sorted by MerchantID: %v %v %v %v",
			m0MerchantID, m1MerchantID, m2MerchantID, m3MerchantID)
	}

	// ConnectTransaction should fail when verifyMerchantMerkleRoot is true and
	// succeed when it's false.
	_, _, block = miner._mineSingleBlock(0 /*threadIndex*/)
	require.Equal(1, len(block.Txns))
	block.Txns[0].TxnMeta.(*BlockRewardMetadataa).MerchantMerkleRoot = &BlockHash{}
	{
		utxoView, err := NewUtxoView(db, params, nil)
		require.NoError(err)
		_, _, _, _, err = utxoView.ConnectTransaction(
			block.Txns[0], block.Txns[0].Hash(), block.Header.Height,
			true /*verifySignatures*/, true /*verifyMerchantMerkleRoot*/)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorInvalidMerchantMerkleRoot)
	}

	// Should succeed now that transaction is far in the past.
	{
		utxoView, err := NewUtxoView(db, params, nil)
		require.NoError(err)
		_, _, _, _, err = utxoView.ConnectTransaction(
			block.Txns[0], block.Txns[0].Hash(), block.Header.Height,
			true /*verifySignatures*/, false /*verifyMerchantMerkleRoot*/)
		require.NoError(err)
	}

	_, _, _ = m1MerchantID, m2MerchantID, m3MerchantID
}

func TestRegisterMerchantMerkleAllSameBurnAmount(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	chain, params, db := NewLowDifficultyBlockchain()
	mempool, miner := NewTestMiner(t, chain, params, true /*isSender*/)
	// Mine two blocks to give the sender some Ultra.
	block, err := miner._mineAndProcessSingleBlock(0 /*threadIndex*/)
	require.NoError(err)
	require.Equal(&BlockHash{}, block.Txns[0].TxnMeta.(*BlockRewardMetadataa).MerchantMerkleRoot)
	block, err = miner._mineAndProcessSingleBlock(0 /*threadIndex*/)
	require.NoError(err)
	require.Equal(&BlockHash{}, block.Txns[0].TxnMeta.(*BlockRewardMetadataa).MerchantMerkleRoot)
	// Mine a block to give some other public keys some Ultra as well.
	m0Pub := "tUN2RExHhcCWqXqT9r7syGupJS6hxrBPDQMssSph6ki1FZLJTczUm4"
	m0Priv := "tunSykM1Si6Wab5mRKBDu7YK5ubpBxr1ciGiiDXmSpMATB12sAawx"
	m1Pub := "tUN2RUx1U7By7i2CZn5sZEEb5jjEHfoyc4Nvk2P9gc6Lf8Bc29xzzB"
	m1Priv := "tunSJ83kV4PNkC7MPEgbmKWNZeJk1mTbjwXUh9oy7kyBLRWsgFjVw"
	// Non-merchants
	m2Pub := "tUN2NazDYX2zmbPMXagebSjHmK6QcybHBGRvFMrHDRgn5Us8YPs1De"
	m2Priv := "tunTBiMhRjKVmeK6bF8kJFQpmxH2UnTweB8zYsvH3bJPjyVMZr5kS"
	m3Pub := "tUN2Q3nYf8KNgZ5q3ftFeEq3fRFpB8CCzXTW5KV4kGrCm4LEvdv67e"
	m3Priv := "tunSRyKa6shh2S6LH3WsFa6jtT42ktUgVcSdZFqTsMBy3KPnHC9kR"

	_, _, _, _ = m1Priv, m2Priv, m3Priv, db
	{
		txn := _assembleBasicTransferTxnFullySigned(
			t, chain, 1000, 100, senderPkString, m0Pub, senderPrivString, mempool)
		_, err := mempool.processTransaction(txn, false, true, 0, true)
		require.NoError(err)
	}
	{
		txn := _assembleBasicTransferTxnFullySigned(
			t, chain, 1001, 100, senderPkString, m1Pub, senderPrivString, mempool)
		_, err := mempool.processTransaction(txn, false, true, 0, true)
		require.NoError(err)
	}
	{
		txn := _assembleBasicTransferTxnFullySigned(
			t, chain, 1002, 100, senderPkString, m2Pub, senderPrivString, mempool)
		_, err := mempool.processTransaction(txn, false, true, 0, true)
		require.NoError(err)
	}
	{
		txn := _assembleBasicTransferTxnFullySigned(
			t, chain, 1003, 100, senderPkString, m3Pub, senderPrivString, mempool)
		_, err := mempool.processTransaction(txn, false, true, 0, true)
		require.NoError(err)
	}
	block, err = miner._mineAndProcessSingleBlock(0 /*threadIndex*/)
	require.Equal(5, len(block.Txns))
	require.Equal(&BlockHash{}, block.Txns[0].TxnMeta.(*BlockRewardMetadataa).MerchantMerkleRoot)
	require.Equal(int64(1000), int64(_getBalance(t, chain, nil, m0Pub)))
	require.Equal(int64(1001), int64(_getBalance(t, chain, nil, m1Pub)))
	require.Equal(int64(1002), int64(_getBalance(t, chain, nil, m2Pub)))
	require.Equal(int64(1003), int64(_getBalance(t, chain, nil, m3Pub)))
	require.NoError(err)
	mempool.UpdateAfterConnectBlock(block)

	// Register a single merchant and verify that the merchant merkle of the next
	// block is consistent with it.
	var m0MerchantID *BlockHash
	{
		txn := _assembleRegisterMerchantFullySigned(t, chain, m0Pub, m0Priv, 100, 10, nil)
		_, err := mempool.processTransaction(txn, false, true, 0, true)
		require.NoError(err)
		m0MerchantID = txn.Hash()
	}
	block, err = miner._mineAndProcessSingleBlock(0 /*threadIndex*/)
	require.NoError(err)
	require.Equal(2, len(block.Txns))
	// Merkle root should be zero since there were no merchants *before* this block.
	require.Equal(&BlockHash{}, block.Txns[0].TxnMeta.(*BlockRewardMetadataa).MerchantMerkleRoot)
	mempool.UpdateAfterConnectBlock(block)

	// If we mine another block its merkle root should show that there is one merchant
	// in the db.
	block, err = miner._mineAndProcessSingleBlock(0 /*threadIndex*/)
	require.NoError(err)
	require.Equal(1, len(block.Txns))
	// Get the single merchant entry from the db and compute the merkle tree that
	// consists solely of it.
	{
		merchantEntry1 := DbGetMerchantEntryForMerchantID(db, m0MerchantID)
		merchantEntry1Hash := HashMerchantEntry(merchantEntry1)
		merkleRoot1 := &BlockHash{}
		copy(merkleRoot1[:], merkletree.NewTreeFromHashes(
			merkletree.Sha256DoubleHash,
			[][]byte{merchantEntry1Hash[:]}).Root.GetHash()[:])
		require.Equal(merkleRoot1, block.Txns[0].TxnMeta.(*BlockRewardMetadataa).MerchantMerkleRoot)
	}
	// Register the other merchants.
	var m1MerchantID *BlockHash
	var m2MerchantID *BlockHash
	var m3MerchantID *BlockHash
	{
		txn := _assembleRegisterMerchantFullySigned(t, chain, m1Pub, m1Priv, 100, 10, nil)
		_, err := mempool.processTransaction(txn, false, true, 0, true)
		require.NoError(err)
		m1MerchantID = txn.Hash()
	}
	{
		txn := _assembleRegisterMerchantFullySigned(t, chain, m2Pub, m2Priv, 100, 10, nil)
		_, err := mempool.processTransaction(txn, false, true, 0, true)
		require.NoError(err)
		m2MerchantID = txn.Hash()
	}
	{
		txn := _assembleRegisterMerchantFullySigned(t, chain, m3Pub, m3Priv, 100, 10, nil)
		_, err := mempool.processTransaction(txn, false, true, 0, true)
		require.NoError(err)
		m3MerchantID = txn.Hash()
	}
	block, err = miner._mineAndProcessSingleBlock(0 /*threadIndex*/)
	require.NoError(err)
	require.Equal(4, len(block.Txns))
	mempool.UpdateAfterConnectBlock(block)
	// Merkle root should match the single merchant merkle root since there was only
	// one merchant *before* this block.
	{
		merchantEntry1 := DbGetMerchantEntryForMerchantID(db, m0MerchantID)
		merchantEntry1Hash := HashMerchantEntry(merchantEntry1)
		merkleRoot1 := &BlockHash{}
		copy(merkleRoot1[:], merkletree.NewTreeFromHashes(
			merkletree.Sha256DoubleHash,
			[][]byte{merchantEntry1Hash[:]}).Root.GetHash()[:])
		require.Equal(merkleRoot1, block.Txns[0].TxnMeta.(*BlockRewardMetadataa).MerchantMerkleRoot)

	}
	block, err = miner._mineAndProcessSingleBlock(0 /*threadIndex*/)
	require.NoError(err)
	require.Equal(1, len(block.Txns))
	mempool.UpdateAfterConnectBlock(block)
	// Now the merkle root should reflect all the merchants since they were all present
	// before this block.
	{
		merchantEntry0 := DbGetMerchantEntryForMerchantID(db, m0MerchantID)
		merchantEntry1 := DbGetMerchantEntryForMerchantID(db, m1MerchantID)
		merchantEntry2 := DbGetMerchantEntryForMerchantID(db, m2MerchantID)
		merchantEntry3 := DbGetMerchantEntryForMerchantID(db, m3MerchantID)
		merchantEntries := []*MerchantEntry{merchantEntry0, merchantEntry1, merchantEntry2, merchantEntry3}
		sort.Slice(merchantEntries, func(ii, jj int) bool {
			return PkToString(
				merchantEntries[ii].merchantID[:], params) > PkToString(merchantEntries[jj].merchantID[:], params)
		})

		merkleRoot := &BlockHash{}
		// Should be sorted by merchantID.
		copy(merkleRoot[:], merkletree.NewTreeFromHashes(
			merkletree.Sha256DoubleHash,
			[][]byte{
				HashMerchantEntry(merchantEntries[0])[:],
				HashMerchantEntry(merchantEntries[1])[:],
				HashMerchantEntry(merchantEntries[2])[:],
				HashMerchantEntry(merchantEntries[3])[:],
			},
		).Root.GetHash()[:])
		require.Equalf(merkleRoot, block.Txns[0].TxnMeta.(*BlockRewardMetadataa).MerchantMerkleRoot,
			"make sure the merchants are sorted by MerchantID: %v %v %v %v",
			m0MerchantID, m1MerchantID, m2MerchantID, m3MerchantID)
	}

	// ConnectTransaction should fail when verifyMerchantMerkleRoot is true and
	// succeed when it's false.
	_, _, block = miner._mineSingleBlock(0 /*threadIndex*/)
	require.Equal(1, len(block.Txns))
	block.Txns[0].TxnMeta.(*BlockRewardMetadataa).MerchantMerkleRoot = &BlockHash{}
	{
		utxoView, err := NewUtxoView(db, params, nil)
		require.NoError(err)
		_, _, _, _, err = utxoView.ConnectTransaction(
			block.Txns[0], block.Txns[0].Hash(), block.Header.Height,
			true /*verifySignatures*/, true /*verifyMerchantMerkleRoot*/)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorInvalidMerchantMerkleRoot)
	}

	// Should succeed now that transaction is far in the past.
	{
		utxoView, err := NewUtxoView(db, params, nil)
		require.NoError(err)
		_, _, _, _, err = utxoView.ConnectTransaction(
			block.Txns[0], block.Txns[0].Hash(), block.Header.Height,
			true /*verifySignatures*/, false /*verifyMerchantMerkleRoot*/)
		require.NoError(err)
	}

	_, _, _ = m1MerchantID, m2MerchantID, m3MerchantID
}

func TestRegisterMerchantMerkleDifferentBurnAmountsLimitMerchants(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	chain, params, db := NewLowDifficultyBlockchain()
	mempool, miner := NewTestMiner(t, chain, params, true /*isSender*/)

	// This is the core thing we change in this test.
	params.MaxMerchantsToIndex = 3

	// Mine two blocks to give the sender some Ultra.
	block, err := miner._mineAndProcessSingleBlock(0 /*threadIndex*/)
	require.NoError(err)
	require.Equal(&BlockHash{}, block.Txns[0].TxnMeta.(*BlockRewardMetadataa).MerchantMerkleRoot)
	block, err = miner._mineAndProcessSingleBlock(0 /*threadIndex*/)
	require.NoError(err)
	require.Equal(&BlockHash{}, block.Txns[0].TxnMeta.(*BlockRewardMetadataa).MerchantMerkleRoot)
	// Mine a block to give some other public keys some Ultra as well.
	m0Pub := "tUN2RExHhcCWqXqT9r7syGupJS6hxrBPDQMssSph6ki1FZLJTczUm4"
	m0Priv := "tunSykM1Si6Wab5mRKBDu7YK5ubpBxr1ciGiiDXmSpMATB12sAawx"
	m1Pub := "tUN2RUx1U7By7i2CZn5sZEEb5jjEHfoyc4Nvk2P9gc6Lf8Bc29xzzB"
	m1Priv := "tunSJ83kV4PNkC7MPEgbmKWNZeJk1mTbjwXUh9oy7kyBLRWsgFjVw"
	// Non-merchants
	m2Pub := "tUN2NazDYX2zmbPMXagebSjHmK6QcybHBGRvFMrHDRgn5Us8YPs1De"
	m2Priv := "tunTBiMhRjKVmeK6bF8kJFQpmxH2UnTweB8zYsvH3bJPjyVMZr5kS"
	m3Pub := "tUN2Q3nYf8KNgZ5q3ftFeEq3fRFpB8CCzXTW5KV4kGrCm4LEvdv67e"
	m3Priv := "tunSRyKa6shh2S6LH3WsFa6jtT42ktUgVcSdZFqTsMBy3KPnHC9kR"
	_, _, _, _ = m1Priv, m2Priv, m3Priv, db
	{
		txn := _assembleBasicTransferTxnFullySigned(
			t, chain, 1000, 100, senderPkString, m0Pub, senderPrivString, mempool)
		_, err := mempool.processTransaction(txn, false, true, 0, true)
		require.NoError(err)
	}
	{
		txn := _assembleBasicTransferTxnFullySigned(
			t, chain, 1001, 100, senderPkString, m1Pub, senderPrivString, mempool)
		_, err := mempool.processTransaction(txn, false, true, 0, true)
		require.NoError(err)
	}
	{
		txn := _assembleBasicTransferTxnFullySigned(
			t, chain, 1002, 100, senderPkString, m2Pub, senderPrivString, mempool)
		_, err := mempool.processTransaction(txn, false, true, 0, true)
		require.NoError(err)
	}
	{
		txn := _assembleBasicTransferTxnFullySigned(
			t, chain, 1003, 100, senderPkString, m3Pub, senderPrivString, mempool)
		_, err := mempool.processTransaction(txn, false, true, 0, true)
		require.NoError(err)
	}
	block, err = miner._mineAndProcessSingleBlock(0 /*threadIndex*/)
	require.Equal(5, len(block.Txns))
	require.Equal(&BlockHash{}, block.Txns[0].TxnMeta.(*BlockRewardMetadataa).MerchantMerkleRoot)
	require.Equal(int64(1000), int64(_getBalance(t, chain, nil, m0Pub)))
	require.Equal(int64(1001), int64(_getBalance(t, chain, nil, m1Pub)))
	require.Equal(int64(1002), int64(_getBalance(t, chain, nil, m2Pub)))
	require.Equal(int64(1003), int64(_getBalance(t, chain, nil, m3Pub)))
	require.NoError(err)
	mempool.UpdateAfterConnectBlock(block)

	// Register a single merchant and verify that the merchant merkle of the next
	// block is consistent with it.
	var m0MerchantID *BlockHash
	{
		txn := _assembleRegisterMerchantFullySigned(t, chain, m0Pub, m0Priv, 100, 1, nil)
		_, err := mempool.processTransaction(txn, false, true, 0, true)
		require.NoError(err)
		m0MerchantID = txn.Hash()
	}
	block, err = miner._mineAndProcessSingleBlock(0 /*threadIndex*/)
	require.NoError(err)
	require.Equal(2, len(block.Txns))
	// Merkle root should be zero since there were no merchants *before* this block.
	require.Equal(&BlockHash{}, block.Txns[0].TxnMeta.(*BlockRewardMetadataa).MerchantMerkleRoot)
	mempool.UpdateAfterConnectBlock(block)

	// If we mine another block its merkle root should show that there is one merchant
	// in the db.
	block, err = miner._mineAndProcessSingleBlock(0 /*threadIndex*/)
	require.NoError(err)
	require.Equal(1, len(block.Txns))
	// Get the single merchant entry from the db and compute the merkle tree that
	// consists solely of it.
	{
		merchantEntry1 := DbGetMerchantEntryForMerchantID(db, m0MerchantID)
		merchantEntry1Hash := HashMerchantEntry(merchantEntry1)
		merkleRoot1 := &BlockHash{}
		copy(merkleRoot1[:], merkletree.NewTreeFromHashes(
			merkletree.Sha256DoubleHash,
			[][]byte{merchantEntry1Hash[:]}).Root.GetHash()[:])
		require.Equal(merkleRoot1, block.Txns[0].TxnMeta.(*BlockRewardMetadataa).MerchantMerkleRoot)
	}
	// Register the other merchants.
	var m1MerchantID *BlockHash
	var m2MerchantID *BlockHash
	var m3MerchantID *BlockHash
	{
		txn := _assembleRegisterMerchantFullySigned(t, chain, m1Pub, m1Priv, 100, 10, nil)
		_, err := mempool.processTransaction(txn, false, true, 0, true)
		require.NoError(err)
		m1MerchantID = txn.Hash()
	}
	{
		txn := _assembleRegisterMerchantFullySigned(t, chain, m2Pub, m2Priv, 100, 3, nil)
		_, err := mempool.processTransaction(txn, false, true, 0, true)
		require.NoError(err)
		m2MerchantID = txn.Hash()
	}
	{
		txn := _assembleRegisterMerchantFullySigned(t, chain, m3Pub, m3Priv, 100, 7, nil)
		_, err := mempool.processTransaction(txn, false, true, 0, true)
		require.NoError(err)
		m3MerchantID = txn.Hash()
	}
	block, err = miner._mineAndProcessSingleBlock(0 /*threadIndex*/)
	require.NoError(err)
	require.Equal(4, len(block.Txns))
	mempool.UpdateAfterConnectBlock(block)
	// Merkle root should match the single merchant merkle root since there was only
	// one merchant *before* this block.
	{
		merchantEntry1 := DbGetMerchantEntryForMerchantID(db, m0MerchantID)
		merchantEntry1Hash := HashMerchantEntry(merchantEntry1)
		merkleRoot1 := &BlockHash{}
		copy(merkleRoot1[:], merkletree.NewTreeFromHashes(
			merkletree.Sha256DoubleHash,
			[][]byte{merchantEntry1Hash[:]}).Root.GetHash()[:])
		require.Equal(merkleRoot1, block.Txns[0].TxnMeta.(*BlockRewardMetadataa).MerchantMerkleRoot)

	}
	block, err = miner._mineAndProcessSingleBlock(0 /*threadIndex*/)
	require.NoError(err)
	require.Equal(1, len(block.Txns))
	mempool.UpdateAfterConnectBlock(block)
	// Now the merkle root should reflect all the merchants since they were all present
	// before this block.
	{
		// merchantEntry0 := DbGetMerchantEntryForMerchantID(db, m0MerchantID)
		merchantEntry1 := DbGetMerchantEntryForMerchantID(db, m1MerchantID)
		merchantEntry2 := DbGetMerchantEntryForMerchantID(db, m2MerchantID)
		merchantEntry3 := DbGetMerchantEntryForMerchantID(db, m3MerchantID)
		// merchantEntry0Hash := HashMerchantEntry(merchantEntry0)
		merchantEntry1Hash := HashMerchantEntry(merchantEntry1)
		merchantEntry2Hash := HashMerchantEntry(merchantEntry2)
		merchantEntry3Hash := HashMerchantEntry(merchantEntry3)
		merkleRoot := &BlockHash{}
		copy(merkleRoot[:], merkletree.NewTreeFromHashes(
			merkletree.Sha256DoubleHash,
			[][]byte{
				merchantEntry1Hash[:], merchantEntry3Hash[:], merchantEntry2Hash[:],
			}).Root.GetHash()[:])
		require.Equal(merkleRoot, block.Txns[0].TxnMeta.(*BlockRewardMetadataa).MerchantMerkleRoot)
	}

	// ConnectTransaction should fail when verifyMerchantMerkleRoot is true and
	// succeed when it's false.
	_, _, block = miner._mineSingleBlock(0 /*threadIndex*/)
	require.Equal(1, len(block.Txns))
	block.Txns[0].TxnMeta.(*BlockRewardMetadataa).MerchantMerkleRoot = &BlockHash{}
	{
		utxoView, err := NewUtxoView(db, params, nil)
		require.NoError(err)
		_, _, _, _, err = utxoView.ConnectTransaction(
			block.Txns[0], block.Txns[0].Hash(), block.Header.Height,
			true /*verifySignatures*/, true /*verifyMerchantMerkleRoot*/)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorInvalidMerchantMerkleRoot)
	}

	// Should succeed now that transaction is far in the past.
	{
		utxoView, err := NewUtxoView(db, params, nil)
		require.NoError(err)
		_, _, _, _, err = utxoView.ConnectTransaction(
			block.Txns[0], block.Txns[0].Hash(), block.Header.Height,
			true /*verifySignatures*/, false /*verifyMerchantMerkleRoot*/)
		require.NoError(err)
	}

	_, _, _ = m1MerchantID, m2MerchantID, m3MerchantID
}

func TestRegisterMerchantMerkleDifferentBurnAmounts(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	chain, params, db := NewLowDifficultyBlockchain()
	mempool, miner := NewTestMiner(t, chain, params, true /*isSender*/)
	// Mine two blocks to give the sender some Ultra.
	block, err := miner._mineAndProcessSingleBlock(0 /*threadIndex*/)
	require.NoError(err)
	require.Equal(&BlockHash{}, block.Txns[0].TxnMeta.(*BlockRewardMetadataa).MerchantMerkleRoot)
	block, err = miner._mineAndProcessSingleBlock(0 /*threadIndex*/)
	require.NoError(err)
	require.Equal(&BlockHash{}, block.Txns[0].TxnMeta.(*BlockRewardMetadataa).MerchantMerkleRoot)
	// Mine a block to give some other public keys some Ultra as well.
	m0Pub := "tUN2RExHhcCWqXqT9r7syGupJS6hxrBPDQMssSph6ki1FZLJTczUm4"
	m0Priv := "tunSykM1Si6Wab5mRKBDu7YK5ubpBxr1ciGiiDXmSpMATB12sAawx"
	m1Pub := "tUN2RUx1U7By7i2CZn5sZEEb5jjEHfoyc4Nvk2P9gc6Lf8Bc29xzzB"
	m1Priv := "tunSJ83kV4PNkC7MPEgbmKWNZeJk1mTbjwXUh9oy7kyBLRWsgFjVw"
	// Non-merchants
	m2Pub := "tUN2NazDYX2zmbPMXagebSjHmK6QcybHBGRvFMrHDRgn5Us8YPs1De"
	m2Priv := "tunTBiMhRjKVmeK6bF8kJFQpmxH2UnTweB8zYsvH3bJPjyVMZr5kS"
	m3Pub := "tUN2Q3nYf8KNgZ5q3ftFeEq3fRFpB8CCzXTW5KV4kGrCm4LEvdv67e"
	m3Priv := "tunSRyKa6shh2S6LH3WsFa6jtT42ktUgVcSdZFqTsMBy3KPnHC9kR"
	_, _, _, _ = m1Priv, m2Priv, m3Priv, db
	{
		txn := _assembleBasicTransferTxnFullySigned(
			t, chain, 1000, 100, senderPkString, m0Pub, senderPrivString, mempool)
		_, err := mempool.processTransaction(txn, false, true, 0, true)
		require.NoError(err)
	}
	{
		txn := _assembleBasicTransferTxnFullySigned(
			t, chain, 1001, 100, senderPkString, m1Pub, senderPrivString, mempool)
		_, err := mempool.processTransaction(txn, false, true, 0, true)
		require.NoError(err)
	}
	{
		txn := _assembleBasicTransferTxnFullySigned(
			t, chain, 1002, 100, senderPkString, m2Pub, senderPrivString, mempool)
		_, err := mempool.processTransaction(txn, false, true, 0, true)
		require.NoError(err)
	}
	{
		txn := _assembleBasicTransferTxnFullySigned(
			t, chain, 1003, 100, senderPkString, m3Pub, senderPrivString, mempool)
		_, err := mempool.processTransaction(txn, false, true, 0, true)
		require.NoError(err)
	}
	block, err = miner._mineAndProcessSingleBlock(0 /*threadIndex*/)
	require.Equal(5, len(block.Txns))
	require.Equal(&BlockHash{}, block.Txns[0].TxnMeta.(*BlockRewardMetadataa).MerchantMerkleRoot)
	require.Equal(int64(1000), int64(_getBalance(t, chain, nil, m0Pub)))
	require.Equal(int64(1001), int64(_getBalance(t, chain, nil, m1Pub)))
	require.Equal(int64(1002), int64(_getBalance(t, chain, nil, m2Pub)))
	require.Equal(int64(1003), int64(_getBalance(t, chain, nil, m3Pub)))
	require.NoError(err)
	mempool.UpdateAfterConnectBlock(block)

	// Register a single merchant and verify that the merchant merkle of the next
	// block is consistent with it.
	var m0MerchantID *BlockHash
	{
		txn := _assembleRegisterMerchantFullySigned(t, chain, m0Pub, m0Priv, 100, 1, nil)
		_, err := mempool.processTransaction(txn, false, true, 0, true)
		require.NoError(err)
		m0MerchantID = txn.Hash()
	}
	block, err = miner._mineAndProcessSingleBlock(0 /*threadIndex*/)
	require.NoError(err)
	require.Equal(2, len(block.Txns))
	// Merkle root should be zero since there were no merchants *before* this block.
	require.Equal(&BlockHash{}, block.Txns[0].TxnMeta.(*BlockRewardMetadataa).MerchantMerkleRoot)
	mempool.UpdateAfterConnectBlock(block)

	// If we mine another block its merkle root should show that there is one merchant
	// in the db.
	block, err = miner._mineAndProcessSingleBlock(0 /*threadIndex*/)
	require.NoError(err)
	require.Equal(1, len(block.Txns))
	// Get the single merchant entry from the db and compute the merkle tree that
	// consists solely of it.
	{
		merchantEntry1 := DbGetMerchantEntryForMerchantID(db, m0MerchantID)
		merchantEntry1Hash := HashMerchantEntry(merchantEntry1)
		merkleRoot1 := &BlockHash{}
		copy(merkleRoot1[:], merkletree.NewTreeFromHashes(
			merkletree.Sha256DoubleHash,
			[][]byte{merchantEntry1Hash[:]}).Root.GetHash()[:])
		require.Equal(merkleRoot1, block.Txns[0].TxnMeta.(*BlockRewardMetadataa).MerchantMerkleRoot)
	}
	// Register the other merchants.
	var m1MerchantID *BlockHash
	var m2MerchantID *BlockHash
	var m3MerchantID *BlockHash
	{
		txn := _assembleRegisterMerchantFullySigned(t, chain, m1Pub, m1Priv, 100, 10, nil)
		_, err := mempool.processTransaction(txn, false, true, 0, true)
		require.NoError(err)
		m1MerchantID = txn.Hash()
	}
	{
		txn := _assembleRegisterMerchantFullySigned(t, chain, m2Pub, m2Priv, 100, 3, nil)
		_, err := mempool.processTransaction(txn, false, true, 0, true)
		require.NoError(err)
		m2MerchantID = txn.Hash()
	}
	{
		txn := _assembleRegisterMerchantFullySigned(t, chain, m3Pub, m3Priv, 100, 7, nil)
		_, err := mempool.processTransaction(txn, false, true, 0, true)
		require.NoError(err)
		m3MerchantID = txn.Hash()
	}
	block, err = miner._mineAndProcessSingleBlock(0 /*threadIndex*/)
	require.NoError(err)
	require.Equal(4, len(block.Txns))
	mempool.UpdateAfterConnectBlock(block)
	// Merkle root should match the single merchant merkle root since there was only
	// one merchant *before* this block.
	{
		merchantEntry1 := DbGetMerchantEntryForMerchantID(db, m0MerchantID)
		merchantEntry1Hash := HashMerchantEntry(merchantEntry1)
		merkleRoot1 := &BlockHash{}
		copy(merkleRoot1[:], merkletree.NewTreeFromHashes(
			merkletree.Sha256DoubleHash,
			[][]byte{merchantEntry1Hash[:]}).Root.GetHash()[:])
		require.Equal(merkleRoot1, block.Txns[0].TxnMeta.(*BlockRewardMetadataa).MerchantMerkleRoot)

	}
	block, err = miner._mineAndProcessSingleBlock(0 /*threadIndex*/)
	require.NoError(err)
	require.Equal(1, len(block.Txns))
	mempool.UpdateAfterConnectBlock(block)
	// Now the merkle root should reflect all the merchants since they were all present
	// before this block.
	{
		merchantEntry0 := DbGetMerchantEntryForMerchantID(db, m0MerchantID)
		merchantEntry1 := DbGetMerchantEntryForMerchantID(db, m1MerchantID)
		merchantEntry2 := DbGetMerchantEntryForMerchantID(db, m2MerchantID)
		merchantEntry3 := DbGetMerchantEntryForMerchantID(db, m3MerchantID)
		merchantEntry0Hash := HashMerchantEntry(merchantEntry0)
		merchantEntry1Hash := HashMerchantEntry(merchantEntry1)
		merchantEntry2Hash := HashMerchantEntry(merchantEntry2)
		merchantEntry3Hash := HashMerchantEntry(merchantEntry3)
		merkleRoot := &BlockHash{}
		copy(merkleRoot[:], merkletree.NewTreeFromHashes(
			merkletree.Sha256DoubleHash,
			[][]byte{
				merchantEntry1Hash[:], merchantEntry3Hash[:], merchantEntry2Hash[:], merchantEntry0Hash[:],
			}).Root.GetHash()[:])
		require.Equal(merkleRoot, block.Txns[0].TxnMeta.(*BlockRewardMetadataa).MerchantMerkleRoot)
	}

	// ConnectTransaction should fail when verifyMerchantMerkleRoot is true and
	// succeed when it's false.
	_, _, block = miner._mineSingleBlock(0 /*threadIndex*/)
	require.Equal(1, len(block.Txns))
	block.Txns[0].TxnMeta.(*BlockRewardMetadataa).MerchantMerkleRoot = &BlockHash{}
	{
		utxoView, err := NewUtxoView(db, params, nil)
		require.NoError(err)
		_, _, _, _, err = utxoView.ConnectTransaction(
			block.Txns[0], block.Txns[0].Hash(), block.Header.Height,
			true /*verifySignatures*/, true /*verifyMerchantMerkleRoot*/)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorInvalidMerchantMerkleRoot)
	}

	// Should succeed now that transaction is far in the past.
	{
		utxoView, err := NewUtxoView(db, params, nil)
		require.NoError(err)
		_, _, _, _, err = utxoView.ConnectTransaction(
			block.Txns[0], block.Txns[0].Hash(), block.Header.Height,
			true /*verifySignatures*/, false /*verifyMerchantMerkleRoot*/)
		require.NoError(err)
	}

	_, _, _ = m1MerchantID, m2MerchantID, m3MerchantID
}

func TestRegisterMerchantBasic(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	chain, params, db := NewLowDifficultyBlockchain()
	mempool, miner := NewTestMiner(t, chain, params, true /*isSender*/)
	// Mine two blocks to give the sender some Ultra.
	block, err := miner._mineAndProcessSingleBlock(0 /*threadIndex*/)
	require.NoError(err)
	block, err = miner._mineAndProcessSingleBlock(0 /*threadIndex*/)
	require.NoError(err)
	_, _ = block, mempool

	balanceBefore := _getBalance(t, chain, nil, senderPkString)

	// Add a RegisterMerchant transaction and save the UtxoOperations.
	// Flush the view to the db.
	savedUtxoOps, savedTxn, savedHeight := _doRegisterMerchantWithViewFlush(
		t, chain, db, params, "god", senderPkString,
		senderPrivString, 7 /*feerate*/, 11 /*burn amount*/)

	// Balance should have been adjusted by this transaction since we flushed
	// the view.
	{
		balanceAfter := _getBalance(t, chain, nil, senderPkString)
		require.NotEqual(balanceBefore, balanceAfter)
	}

	// Do some sanity checks using the db.
	txnHash := savedTxn.Hash()
	merchantID := txnHash
	{
		merchantEntry := DbGetMerchantEntryForMerchantID(db, merchantID)
		require.NotNil(merchantEntry)
		require.Equal(uint64(0), merchantEntry.Pos)
		require.Equal(uint64(1), GetNumMerchantEntries(db))
		merchantIDFromDB := GetMerchantIDForPos(db, 0)
		require.Equal(*merchantID, *merchantIDFromDB)
	}

	// Initialize a new view and roll back the RegisterMerchant operation using
	// the UtxoOperations from before. Flush the view once finished.
	{
		utxoView, err := NewUtxoView(db, params, nil)
		err = utxoView._disconnectRegisterMerchant(savedTxn, txnHash, savedUtxoOps, savedHeight)
		require.NoError(err)

		require.NoError(utxoView.FlushToDb())
	}

	// Do some sanity checks using the db.
	{
		merchantEntry := DbGetMerchantEntryForMerchantID(db, merchantID)
		require.Nil(merchantEntry)
		require.Equal(uint64(0), GetNumMerchantEntries(db))
		merchantIDFromDB := GetMerchantIDForPos(db, 0)
		require.Nil(merchantIDFromDB)
	}

	// The user's balance before and after shouldn't change.
	{
		balanceAfter := _getBalance(t, chain, nil, senderPkString)
		require.Equal(balanceBefore, balanceAfter)
	}
}

func _doBasicTransferWithViewFlush(t *testing.T, chain *Blockchain, db *badger.DB,
	params *UltranetParams, pkSenderStr string, pkReceiverStr string, privStr string,
	amountNanos uint64, feeRateNanosPerKB uint64) (
	_utxoOps []*UtxoOperation, _txn *MsgUltranetTxn, _height uint32) {

	assert := assert.New(t)
	require := require.New(t)
	_, _ = assert, require

	txn := _assembleBasicTransferTxnFullySigned(
		t, chain, amountNanos, feeRateNanosPerKB, pkSenderStr, pkReceiverStr, privStr, nil)

	utxoView, err := NewUtxoView(db, params, nil)
	require.NoError(err)

	// Always use height+1 for validation since it's assumed the transaction will
	// get mined into the next block.
	txHash := txn.Hash()
	blockHeight := chain.blockTip().Height + 1
	utxoOps, totalInput, totalOutput, fees, err :=
		utxoView.ConnectTransaction(txn, txHash, blockHeight, true /*verifySignature*/, true /*verifyMerchantMerkleRoot*/)
	require.NoError(err)
	require.GreaterOrEqual(totalOutput, amountNanos)
	require.Equal(totalInput, totalOutput+fees)

	// We should have one SPEND UtxoOperation for each input, one ADD operation
	// for each output, and one REGISTER_MERCHANT operation at the end.
	require.Equal(len(txn.TxInputs)+len(txn.TxOutputs), len(utxoOps))
	for ii := 0; ii < len(txn.TxInputs); ii++ {
		require.Equal(OperationTypeSpendUtxo, utxoOps[ii].Type)
	}
	for ii := len(txn.TxInputs); ii < len(txn.TxInputs)+len(txn.TxOutputs); ii++ {
		require.Equal(OperationTypeAddUtxo, utxoOps[ii].Type)
	}

	require.NoError(utxoView.FlushToDb())

	return utxoOps, txn, blockHeight
}

func _doRegisterMerchantWithViewFlush(t *testing.T, chain *Blockchain, db *badger.DB,
	params *UltranetParams, username string, pkStr string, privStr string,
	feeRateNanosPerKB uint64, burnAmountNanos uint64) (
	_utxoOps []*UtxoOperation, _txn *MsgUltranetTxn, _height uint32) {

	utxoOps, txn, height, _ := _doRegisterMerchantWithViewFlushWithError(
		t, chain, db, params, username, pkStr, privStr, feeRateNanosPerKB, burnAmountNanos, false)

	return utxoOps, txn, height
}

func _doRegisterMerchantWithViewFlushWithError(t *testing.T, chain *Blockchain, db *badger.DB,
	params *UltranetParams, username string, pkStr string, privStr string,
	feeRateNanosPerKB uint64, burnAmountNanos uint64, expectError bool) (
	_utxoOps []*UtxoOperation, _txn *MsgUltranetTxn, _height uint32, _err error) {

	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	senderPkBytes, _, err := Base58CheckDecode(pkStr)
	require.NoError(err)

	utxoView, err := NewUtxoView(db, params, nil)
	require.NoError(err)

	// Assemble the transaction so that inputs can be found and fees can
	// be computed. Note we assume there will be no outputs for this type of
	// transaction.
	txn := &MsgUltranetTxn{
		// The inputs will be set below.
		TxInputs:  []*UltranetInput{},
		TxOutputs: []*UltranetOutput{},
		PublicKey: senderPkBytes,
		TxnMeta: &RegisterMerchantMetadata{
			Username:        []byte(username),
			Description:     []byte("i mean she's the best "),
			BurnAmountNanos: burnAmountNanos,
		},

		// We wait to compute the signature until we've added all the
		// inputs and change.
	}

	totalInput, spendAmount, changeAmount, fees, err :=
		chain.AddInputsAndChangeToTransaction(txn, feeRateNanosPerKB, nil)
	require.NoError(err)
	require.Equal(totalInput, spendAmount+changeAmount+fees)
	// The burn amount is interpreted by this function as the amount spent.
	// Treating it this way allows it to fetch the right amount of input.
	require.Equal(burnAmountNanos, spendAmount)
	// Fees should be less than the burn amount since the transaction is definitely
	// smaller than a kilobyte.
	require.Less(fees, burnAmountNanos, "is the transaction larger than a kilobyte?")

	// Sign the transaction now that its inputs are set up.
	_signTxn(t, txn, privStr)

	txHash := txn.Hash()
	// Always use height+1 for validation since it's assumed the transaction will
	// get mined into the next block.
	blockHeight := chain.blockTip().Height + 1
	utxoOps, totalInput, totalOutput, fees, err :=
		utxoView.ConnectTransaction(txn, txHash, blockHeight, true /*verifySignature*/, true /*verifyMerchantMerkleRoot*/)
	// ConnectTransaction should treat the burn amount as contributing to the
	// output.
	if expectError {
		require.Error(err)
		return nil, nil, 0, err
	}

	require.NoError(err)
	require.GreaterOrEqual(totalOutput, burnAmountNanos)
	require.GreaterOrEqual(totalInput, totalOutput+fees)
	// We should have one SPEND UtxoOperation for each input, one ADD operation
	// for each output, and one REGISTER_MERCHANT operation at the end.
	require.Equal(len(txn.TxInputs)+len(txn.TxOutputs)+1, len(utxoOps))
	for ii := 0; ii < len(txn.TxInputs); ii++ {
		require.Equal(OperationTypeSpendUtxo, utxoOps[ii].Type)
	}
	require.Equal(OperationTypeAddMerchantEntry, utxoOps[len(utxoOps)-1].Type)

	require.NoError(utxoView.FlushToDb())

	return utxoOps, txn, blockHeight, nil
}

func TestRegisterMerchantWithBasicTransfers(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	chain, params, db := NewLowDifficultyBlockchain()
	mempool, miner := NewTestMiner(t, chain, params, true /*isSender*/)
	// Mine two blocks to give the sender some Ultra.
	block, err := miner._mineAndProcessSingleBlock(0 /*threadIndex*/)
	require.NoError(err)
	block, err = miner._mineAndProcessSingleBlock(0 /*threadIndex*/)
	require.NoError(err)
	_, _ = block, mempool

	txnOps := [][]*UtxoOperation{}
	txns := []*MsgUltranetTxn{}
	var savedHeight uint32
	expectedSenderBalances := []uint64{}
	expectedRecipientBalances := []uint64{}

	//spew.Dump(GetAllUtxoKeys(db))

	// Do a basic transfer.
	{
		expectedSenderBalances = append(expectedSenderBalances, _getBalance(t, chain, nil, senderPkString))
		expectedRecipientBalances = append(expectedRecipientBalances, _getBalance(t, chain, nil, recipientPkString))
		currentOps, currentTxn, height := _doBasicTransferWithViewFlush(
			t, chain, db, params, senderPkString, recipientPkString,
			senderPrivString, 7 /*amount to send*/, 11 /*feerate*/)

		txnOps = append(txnOps, currentOps)
		txns = append(txns, currentTxn)
		savedHeight = height
		//spew.Dump(currentTxn)
	}

	//spew.Dump(GetAllUtxoKeys(db))

	// Register the merchant.
	{
		expectedSenderBalances = append(expectedSenderBalances, _getBalance(t, chain, nil, senderPkString))
		expectedRecipientBalances = append(expectedRecipientBalances, _getBalance(t, chain, nil, recipientPkString))
		currentOps, currentTxn, _ := _doRegisterMerchantWithViewFlush(
			t, chain, db, params, "god", senderPkString,
			senderPrivString, 13 /*feerate*/, 17 /*burn amount*/)
		txnOps = append(txnOps, currentOps)
		txns = append(txns, currentTxn)
		//spew.Dump(currentTxn)
	}

	//spew.Dump(GetAllUtxoKeys(db))

	// Another basic transfer.
	{
		expectedSenderBalances = append(expectedSenderBalances, _getBalance(t, chain, nil, senderPkString))
		expectedRecipientBalances = append(expectedRecipientBalances, _getBalance(t, chain, nil, recipientPkString))
		currentOps, currentTxn, _ := _doBasicTransferWithViewFlush(
			t, chain, db, params, senderPkString, recipientPkString,
			senderPrivString, 5 /*amount to send*/, 3 /*feerate*/)
		txnOps = append(txnOps, currentOps)
		txns = append(txns, currentTxn)
		//spew.Dump(currentTxn)
	}

	//spew.Dump(GetAllUtxoKeys(db))

	// Roll back all of the above using the utxoOps from each.
	for ii := 0; ii < len(txnOps); ii++ {
		backwardIter := len(txnOps) - 1 - ii
		fmt.Printf("Disconnecting transaction with index %d (going backwards)\n", backwardIter)
		currentOps := txnOps[backwardIter]
		currentTxn := txns[backwardIter]

		utxoView, err := NewUtxoView(db, params, nil)
		require.NoError(err)

		currentHash := currentTxn.Hash()
		err = utxoView.DisconnectTransaction(currentTxn, currentHash, currentOps, savedHeight)
		require.NoError(err)

		require.NoError(utxoView.FlushToDb())

		// After disconnecting, the balances should be restored to what they
		// were before this transaction was applied.
		require.Equal(expectedSenderBalances[backwardIter], _getBalance(t, chain, nil, senderPkString))
		require.Equal(expectedRecipientBalances[backwardIter], _getBalance(t, chain, nil, recipientPkString))
	}
}

func TestRegisterMerchantDuplicateUsernameOrPublicKey(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	chain, params, db := NewLowDifficultyBlockchain()
	mempool, miner := NewTestMiner(t, chain, params, true /*isSender*/)
	// Mine a few blocks to give the sender some Ultra.
	block, err := miner._mineAndProcessSingleBlock(0 /*threadIndex*/)
	require.NoError(err)
	block, err = miner._mineAndProcessSingleBlock(0 /*threadIndex*/)
	require.NoError(err)
	block, err = miner._mineAndProcessSingleBlock(0 /*threadIndex*/)
	require.NoError(err)
	_, _ = block, mempool

	// Give some money to the other guy.
	_, _, _ = _doBasicTransferWithViewFlush(
		t, chain, db, params, senderPkString, recipientPkString,
		senderPrivString, 17 /*amount to send*/, 11 /*feerate*/)

	// Register a merchant.
	_, _, _, err = _doRegisterMerchantWithViewFlushWithError(
		t, chain, db, params, "u1", senderPkString, senderPrivString,
		13 /*feerate*/, 3 /*burn amount*/, false)
	require.NoError(err)

	// Same public key different username should fail.
	_, _, _, err = _doRegisterMerchantWithViewFlushWithError(
		t, chain, db, params, "u2", senderPkString, senderPrivString,
		13 /*feerate*/, 3 /*burn amount*/, true)
	require.Error(err)
	require.Contains(err.Error(), RuleErrorMerchantPkExists)

	// Same username different key different should fail.
	_, _, _, err = _doRegisterMerchantWithViewFlushWithError(
		t, chain, db, params, "u1", recipientPkString, recipientPrivString,
		13 /*feerate*/, 3 /*burn amount*/, true)
	require.Error(err)
	require.Contains(err.Error(), RuleErrorMerchantUsernameExists)
}

func TestRegisterMerchantHardcore(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	chain, params, db := NewLowDifficultyBlockchain()
	mempool, miner := NewTestMiner(t, chain, params, true /*isSender*/)
	// Mine a few blocks to give the sender some Ultra.
	block, err := miner._mineAndProcessSingleBlock(0 /*threadIndex*/)
	require.NoError(err)
	block, err = miner._mineAndProcessSingleBlock(0 /*threadIndex*/)
	require.NoError(err)
	block, err = miner._mineAndProcessSingleBlock(0 /*threadIndex*/)
	require.NoError(err)
	block, err = miner._mineAndProcessSingleBlock(0 /*threadIndex*/)
	require.NoError(err)
	_, _ = block, mempool

	txnOps := [][]*UtxoOperation{}
	txns := []*MsgUltranetTxn{}
	var savedHeight uint32
	expectedSenderBalances := []uint64{}
	expectedRecipientBalances := []uint64{}

	registerOrTransfer := func(username string,
		senderPk string, recipientPk string, senderPriv string) {

		expectedSenderBalances = append(expectedSenderBalances, _getBalance(t, chain, nil, senderPkString))
		expectedRecipientBalances = append(expectedRecipientBalances, _getBalance(t, chain, nil, recipientPkString))
		if recipientPk == "" {
			currentOps, currentTxn, height := _doRegisterMerchantWithViewFlush(
				t, chain, db, params, username, senderPk, senderPriv, 13 /*feerate*/, 3 /*burn amount*/)
			txnOps = append(txnOps, currentOps)
			txns = append(txns, currentTxn)
			savedHeight = height
		} else {
			currentOps, currentTxn, height := _doBasicTransferWithViewFlush(
				t, chain, db, params, senderPk, recipientPk,
				senderPriv, 7 /*amount to send*/, 11 /*feerate*/)

			txnOps = append(txnOps, currentOps)
			txns = append(txns, currentTxn)
			savedHeight = height
		}
	}

	// Just apply a bunch of different flavors of basic transfers and registrations
	// among two users.

	// Some transfers
	registerOrTransfer("", senderPkString, recipientPkString, senderPrivString)
	registerOrTransfer("", senderPkString, recipientPkString, senderPrivString)
	registerOrTransfer("", recipientPkString, senderPkString, recipientPrivString)
	registerOrTransfer("", senderPkString, recipientPkString, senderPrivString)
	registerOrTransfer("", senderPkString, recipientPkString, senderPrivString)

	// A registration
	registerOrTransfer("m1", senderPkString, "", senderPrivString)
	merchantID1 := txns[len(txns)-1].Hash()

	// A few more transfers transfer
	registerOrTransfer("", recipientPkString, senderPkString, recipientPrivString)
	registerOrTransfer("", senderPkString, recipientPkString, senderPrivString)
	registerOrTransfer("", senderPkString, recipientPkString, senderPrivString)

	// A few registrations
	registerOrTransfer("m2", recipientPkString, "", recipientPrivString)
	merchantID2 := txns[len(txns)-1].Hash()
	// go run transaction_util.go --operation_type=generate_keys --manual_entropy_hex=2,3,4,5
	registerOrTransfer("", senderPkString, "tUN2RExHhcCWqXqT9r7syGupJS6hxrBPDQMssSph6ki1FZLJTczUm4", senderPrivString)
	registerOrTransfer("", senderPkString, "tUN2RUx1U7By7i2CZn5sZEEb5jjEHfoyc4Nvk2P9gc6Lf8Bc29xzzB", senderPrivString)
	registerOrTransfer("", senderPkString, "tUN2NazDYX2zmbPMXagebSjHmK6QcybHBGRvFMrHDRgn5Us8YPs1De", senderPrivString)
	registerOrTransfer("", senderPkString, "tUN2Q3nYf8KNgZ5q3ftFeEq3fRFpB8CCzXTW5KV4kGrCm4LEvdv67e", senderPrivString)
	registerOrTransfer("m3", "tUN2RExHhcCWqXqT9r7syGupJS6hxrBPDQMssSph6ki1FZLJTczUm4", "", "tunSykM1Si6Wab5mRKBDu7YK5ubpBxr1ciGiiDXmSpMATB12sAawx")
	merchantID3 := txns[len(txns)-1].Hash()
	registerOrTransfer("m4", "tUN2RUx1U7By7i2CZn5sZEEb5jjEHfoyc4Nvk2P9gc6Lf8Bc29xzzB", "", "tunSJ83kV4PNkC7MPEgbmKWNZeJk1mTbjwXUh9oy7kyBLRWsgFjVw")
	merchantID4 := txns[len(txns)-1].Hash()
	registerOrTransfer("m5", "tUN2NazDYX2zmbPMXagebSjHmK6QcybHBGRvFMrHDRgn5Us8YPs1De", "", "tunTBiMhRjKVmeK6bF8kJFQpmxH2UnTweB8zYsvH3bJPjyVMZr5kS")
	merchantID5 := txns[len(txns)-1].Hash()
	registerOrTransfer("m6", "tUN2Q3nYf8KNgZ5q3ftFeEq3fRFpB8CCzXTW5KV4kGrCm4LEvdv67e", "", "tunSRyKa6shh2S6LH3WsFa6jtT42ktUgVcSdZFqTsMBy3KPnHC9kR")
	merchantID6 := txns[len(txns)-1].Hash()

	// Verify that all of the merchants can be fetched by their public keys.
	require.Equal(merchantID1, DbGetMerchantIDForPubKey(db, mustBase58CheckDecode(senderPkString)))
	require.Equal(merchantID2, DbGetMerchantIDForPubKey(db, mustBase58CheckDecode(recipientPkString)))
	require.Equal(merchantID3, DbGetMerchantIDForPubKey(db, mustBase58CheckDecode("tUN2RExHhcCWqXqT9r7syGupJS6hxrBPDQMssSph6ki1FZLJTczUm4")))
	require.Equal(merchantID4, DbGetMerchantIDForPubKey(db, mustBase58CheckDecode("tUN2RUx1U7By7i2CZn5sZEEb5jjEHfoyc4Nvk2P9gc6Lf8Bc29xzzB")))
	require.Equal(merchantID5, DbGetMerchantIDForPubKey(db, mustBase58CheckDecode("tUN2NazDYX2zmbPMXagebSjHmK6QcybHBGRvFMrHDRgn5Us8YPs1De")))
	require.Equal(merchantID6, DbGetMerchantIDForPubKey(db, mustBase58CheckDecode("tUN2Q3nYf8KNgZ5q3ftFeEq3fRFpB8CCzXTW5KV4kGrCm4LEvdv67e")))

	// Check the top merchants are as expected.
	{
		topMerchantIDs, topMerchantScores, topMerchantEntries, err :=
			DbGetBlockchainTopMerchants(db, math.MaxUint64, false /*noMerchantEntries*/)
		require.NoError(err)
		_, _, _ = topMerchantIDs, topMerchantScores, topMerchantEntries
	}

	// Roll back all of the above using the utxoOps from each.
	for ii := 0; ii < len(txnOps); ii++ {
		backwardIter := len(txnOps) - 1 - ii
		fmt.Printf("Disconnecting transaction with index %d (going backwards)\n", backwardIter)
		currentOps := txnOps[backwardIter]
		currentTxn := txns[backwardIter]

		utxoView, err := NewUtxoView(db, params, nil)
		require.NoError(err)

		currentHash := currentTxn.Hash()
		err = utxoView.DisconnectTransaction(currentTxn, currentHash, currentOps, savedHeight)
		require.NoError(err)

		require.NoError(utxoView.FlushToDb())

		// After disconnecting, the balances should be restored to what they
		// were before this transaction was applied.
		require.Equal(expectedSenderBalances[backwardIter], _getBalance(t, chain, nil, senderPkString))
		require.Equal(expectedRecipientBalances[backwardIter], _getBalance(t, chain, nil, recipientPkString))
	}

	// Verify all the entry mappings are gone.
	require.Nil(DbGetMerchantIDForPubKey(db, mustBase58CheckDecode(senderPkString)))
	require.Nil(DbGetMerchantIDForPubKey(db, mustBase58CheckDecode(recipientPkString)))
	require.Nil(DbGetMerchantIDForPubKey(db, mustBase58CheckDecode("tUN2RExHhcCWqXqT9r7syGupJS6hxrBPDQMssSph6ki1FZLJTczUm4")))
	require.Nil(DbGetMerchantIDForPubKey(db, mustBase58CheckDecode("tUN2RUx1U7By7i2CZn5sZEEb5jjEHfoyc4Nvk2P9gc6Lf8Bc29xzzB")))
	require.Nil(DbGetMerchantIDForPubKey(db, mustBase58CheckDecode("tUN2NazDYX2zmbPMXagebSjHmK6QcybHBGRvFMrHDRgn5Us8YPs1De")))
	require.Nil(DbGetMerchantIDForPubKey(db, mustBase58CheckDecode("tUN2Q3nYf8KNgZ5q3ftFeEq3fRFpB8CCzXTW5KV4kGrCm4LEvdv67e")))
}

func _doUpdateMerchantWithViewFlush(t *testing.T, chain *Blockchain, db *badger.DB,
	params *UltranetParams, pkStr string, privStr string,
	merchantID *BlockHash, newPublicKeyStr string, newUsername string,
	newDescription string,
	feeRateNanosPerKB uint64, burnAmountNanos uint64) (
	_utxoOps []*UtxoOperation, _txn *MsgUltranetTxn, _height uint32, _err error) {

	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	senderPkBytes, _, err := Base58CheckDecode(pkStr)
	require.NoError(err)

	var newPkBytes []byte
	if len(newPublicKeyStr) != 0 {
		newPkBytes, _, err = Base58CheckDecode(newPublicKeyStr)
		require.NoError(err)
	}

	utxoView, err := NewUtxoView(db, params, nil)
	require.NoError(err)

	// Assemble the transaction so that inputs can be found and fees can
	// be computed. Note we assume there will be no outputs for this type of
	// transaction.
	txn := &MsgUltranetTxn{
		// The inputs will be set below.
		TxInputs:  []*UltranetInput{},
		TxOutputs: []*UltranetOutput{},
		PublicKey: senderPkBytes,
		TxnMeta: &UpdateMerchantMetadata{
			MerchantID:      merchantID,
			NewPublicKey:    newPkBytes,
			NewUsername:     []byte(newUsername),
			NewDescription:  []byte(newDescription),
			BurnAmountNanos: burnAmountNanos,
		},

		// We wait to compute the signature until we've added all the
		// inputs and change.
	}

	totalInput, spendAmount, changeAmount, fees, err :=
		chain.AddInputsAndChangeToTransaction(txn, feeRateNanosPerKB, nil)
	require.NoError(err)
	require.Equal(totalInput, spendAmount+changeAmount+fees)
	// The burn amount is interpreted by this function as the amount spent.
	// Treating it this way allows it to fetch the right amount of input.
	require.Equal(burnAmountNanos, spendAmount)
	// Fees should be less than the burn amount since the transaction is definitely
	// smaller than a kilobyte.
	require.Less(fees, burnAmountNanos, "is the transaction larger than a kilobyte?")

	// Sign the transaction now that its inputs are set up.
	_signTxn(t, txn, privStr)

	txHash := txn.Hash()
	// Always use height+1 for validation since it's assumed the transaction will
	// get mined into the next block.
	blockHeight := chain.blockTip().Height + 1
	utxoOps, totalInput, totalOutput, fees, err :=
		utxoView.ConnectTransaction(txn, txHash, blockHeight, true /*verifySignature*/, true /*verifyMerchantMerkleRoot*/)
	// ConnectTransaction should treat the burn amount as contributing to the
	// output.
	if err != nil {
		return nil, nil, 0, err
	}
	require.NoError(err)
	require.GreaterOrEqual(totalOutput, burnAmountNanos)
	require.GreaterOrEqual(totalInput, totalOutput+fees)
	// We should have one SPEND UtxoOperation for each input, one ADD operation
	// for each output, and one UPDATE_MERCHANT operation at the end.
	require.Equal(len(txn.TxInputs)+len(txn.TxOutputs)+1, len(utxoOps))
	for ii := 0; ii < len(txn.TxInputs); ii++ {
		require.Equal(OperationTypeSpendUtxo, utxoOps[ii].Type)
	}
	require.Equal(OperationTypeUpdateMerchantEntry, utxoOps[len(utxoOps)-1].Type)

	require.NoError(utxoView.FlushToDb())

	return utxoOps, txn, blockHeight, nil
}

func TestUpdateMerchant(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	chain, params, db := NewLowDifficultyBlockchain()
	mempool, miner := NewTestMiner(t, chain, params, true /*isSender*/)
	// Mine a few blocks to give the sender some Ultra.
	block, err := miner._mineAndProcessSingleBlock(0 /*threadIndex*/)
	require.NoError(err)
	block, err = miner._mineAndProcessSingleBlock(0 /*threadIndex*/)
	require.NoError(err)
	block, err = miner._mineAndProcessSingleBlock(0 /*threadIndex*/)
	require.NoError(err)
	block, err = miner._mineAndProcessSingleBlock(0 /*threadIndex*/)
	require.NoError(err)
	_, _ = block, mempool

	txnOps := [][]*UtxoOperation{}
	txns := []*MsgUltranetTxn{}
	var savedHeight uint32
	expectedSenderBalances := []uint64{}
	expectedRecipientBalances := []uint64{}

	merchantIDs := []*BlockHash{}
	usernames := []string{}
	publicKeys := []string{}

	registerOrTransfer := func(username string,
		senderPk string, recipientPk string, senderPriv string) {

		expectedSenderBalances = append(expectedSenderBalances, _getBalance(t, chain, nil, senderPkString))
		expectedRecipientBalances = append(expectedRecipientBalances, _getBalance(t, chain, nil, recipientPkString))
		if recipientPk == "" {
			currentOps, currentTxn, height := _doRegisterMerchantWithViewFlush(
				t, chain, db, params, username, senderPk, senderPriv, 13 /*feerate*/, 3 /*burn amount*/)
			txnOps = append(txnOps, currentOps)
			txns = append(txns, currentTxn)
			savedHeight = height
		} else {
			currentOps, currentTxn, height := _doBasicTransferWithViewFlush(
				t, chain, db, params, senderPk, recipientPk,
				senderPriv, 7 /*amount to send*/, 11 /*feerate*/)

			txnOps = append(txnOps, currentOps)
			txns = append(txns, currentTxn)
			savedHeight = height
		}
	}

	// Some transfers
	registerOrTransfer("", senderPkString, recipientPkString, senderPrivString)
	registerOrTransfer("", senderPkString, recipientPkString, senderPrivString)
	registerOrTransfer("", recipientPkString, senderPkString, recipientPrivString)
	registerOrTransfer("", senderPkString, recipientPkString, senderPrivString)
	registerOrTransfer("", senderPkString, recipientPkString, senderPrivString)

	// A registration
	registerOrTransfer("m1", senderPkString, "", senderPrivString)
	merchantID := txns[len(txns)-1].Hash()
	merchantIDs = append(merchantIDs, merchantID)
	usernames = append(usernames, "m1")
	publicKeys = append(publicKeys, senderPkString)

	// A few more transfers transfer
	registerOrTransfer("", recipientPkString, senderPkString, recipientPrivString)
	registerOrTransfer("", senderPkString, recipientPkString, senderPrivString)
	registerOrTransfer("", senderPkString, recipientPkString, senderPrivString)

	// A few registrations
	registerOrTransfer("m2", recipientPkString, "", recipientPrivString)
	merchantID = txns[len(txns)-1].Hash()
	merchantIDs = append(merchantIDs, merchantID)
	usernames = append(usernames, "m2")
	publicKeys = append(publicKeys, recipientPkString)

	// Give the keys some money
	// go run transaction_util.go --operation_type=generate_keys --manual_entropy_hex=2,3,4,5
	registerOrTransfer("", senderPkString, "tUN2RExHhcCWqXqT9r7syGupJS6hxrBPDQMssSph6ki1FZLJTczUm4", senderPrivString)
	registerOrTransfer("", senderPkString, "tUN2RUx1U7By7i2CZn5sZEEb5jjEHfoyc4Nvk2P9gc6Lf8Bc29xzzB", senderPrivString)
	registerOrTransfer("", senderPkString, "tUN2NazDYX2zmbPMXagebSjHmK6QcybHBGRvFMrHDRgn5Us8YPs1De", senderPrivString)
	registerOrTransfer("", senderPkString, "tUN2NazDYX2zmbPMXagebSjHmK6QcybHBGRvFMrHDRgn5Us8YPs1De", senderPrivString)
	registerOrTransfer("", senderPkString, "tUN2Q3nYf8KNgZ5q3ftFeEq3fRFpB8CCzXTW5KV4kGrCm4LEvdv67e", senderPrivString)

	registerOrTransfer("m3", "tUN2RExHhcCWqXqT9r7syGupJS6hxrBPDQMssSph6ki1FZLJTczUm4", "", "tunSykM1Si6Wab5mRKBDu7YK5ubpBxr1ciGiiDXmSpMATB12sAawx")
	merchantID = txns[len(txns)-1].Hash()
	merchantIDs = append(merchantIDs, merchantID)
	usernames = append(usernames, "m3")
	publicKeys = append(publicKeys, "tUN2RExHhcCWqXqT9r7syGupJS6hxrBPDQMssSph6ki1FZLJTczUm4")

	registerOrTransfer("m4", "tUN2RUx1U7By7i2CZn5sZEEb5jjEHfoyc4Nvk2P9gc6Lf8Bc29xzzB", "", "tunSJ83kV4PNkC7MPEgbmKWNZeJk1mTbjwXUh9oy7kyBLRWsgFjVw")
	merchantID = txns[len(txns)-1].Hash()
	merchantIDs = append(merchantIDs, merchantID)
	usernames = append(usernames, "m4")
	publicKeys = append(publicKeys, "tUN2RUx1U7By7i2CZn5sZEEb5jjEHfoyc4Nvk2P9gc6Lf8Bc29xzzB")

	registerOrTransfer("m5", "tUN2NazDYX2zmbPMXagebSjHmK6QcybHBGRvFMrHDRgn5Us8YPs1De", "", "tunTBiMhRjKVmeK6bF8kJFQpmxH2UnTweB8zYsvH3bJPjyVMZr5kS")
	merchantID = txns[len(txns)-1].Hash()
	merchantIDs = append(merchantIDs, merchantID)
	usernames = append(usernames, "m5")
	publicKeys = append(publicKeys, "tUN2NazDYX2zmbPMXagebSjHmK6QcybHBGRvFMrHDRgn5Us8YPs1De")

	for ii, merchantID := range merchantIDs {
		fmt.Printf("Checking db for merchant with username: %s\n", usernames[ii])
		merchantEntry := DbGetMerchantEntryForMerchantID(db, merchantID)
		require.NotNil(merchantEntry)
		require.Equal(usernames[ii], string(merchantEntry.Username))
		require.Equal(publicKeys[ii], PkToStringTestnet(merchantEntry.PublicKey))
		require.Equal("i mean she's the best ", string(merchantEntry.Description))
		require.False(merchantEntry.isDeleted)
	}

	// Update the second merchant to have all new values.
	// manual_entropy_hex=6
	newPkForMerchant2 := "tUN2Q3nYf8KNgZ5q3ftFeEq3fRFpB8CCzXTW5KV4kGrCm4LEvdv67e"
	newPrivForMerchant2 := "tunSRyKa6shh2S6LH3WsFa6jtT42ktUgVcSdZFqTsMBy3KPnHC9kR"
	newUsernameForMerchant2 := "m2prime"
	newDescriptionForMerchant2 := "hi im 2"
	{
		expectedSenderBalances = append(expectedSenderBalances, _getBalance(t, chain, nil, senderPkString))
		expectedRecipientBalances = append(expectedRecipientBalances, _getBalance(t, chain, nil, recipientPkString))

		tmpOps, tmpTxn, _, err := _doUpdateMerchantWithViewFlush(t, chain, db,
			params, recipientPkString, recipientPrivString,
			merchantIDs[1], newPkForMerchant2, newUsernameForMerchant2,
			newDescriptionForMerchant2, 7, 3)
		require.NoError(err)
		txnOps = append(txnOps, tmpOps)
		txns = append(txns, tmpTxn)

		// Verify that everything in the database is updated for the merchant.
		merchantEntry := DbGetMerchantEntryForMerchantID(db, merchantIDs[1])
		require.NotNil(merchantEntry)
		require.Equal(newUsernameForMerchant2, string(merchantEntry.Username))
		require.Equal(newPkForMerchant2, PkToStringTestnet(merchantEntry.PublicKey))
		require.Equal(newDescriptionForMerchant2, string(merchantEntry.Description))
		require.False(merchantEntry.isDeleted)
	}

	// Update the second merchant a second time.
	// manual_entropy_hex=7
	newPkForMerchant2Prime := "tUN2PDN9qdsRnkLhFTn3UGN4z52fAavYBZcutiV8oPm1MLexg2k2yh"
	//newPrivForMerchant2Prime := "tunRYEMczH52fb4bLEo2ch9tkNt6p6MLKMhGLtV746tnempVHVEFK"
	newUsernameForMerchant2Prime := "m2doubleprime"
	newDescriptionForMerchant2Prime := "hi im 2 double prime"
	{
		// The burn amount should increase from this operation.
		burnAmountBefore := DbGetMerchantEntryForMerchantID(db, merchantIDs[1]).Stats.AmountBurnedNanos

		expectedSenderBalances = append(expectedSenderBalances, _getBalance(t, chain, nil, senderPkString))
		expectedRecipientBalances = append(expectedRecipientBalances, _getBalance(t, chain, nil, recipientPkString))

		tmpOps, tmpTxn, _, err := _doUpdateMerchantWithViewFlush(t, chain, db,
			params, newPkForMerchant2, newPrivForMerchant2,
			merchantIDs[1], newPkForMerchant2Prime, newUsernameForMerchant2Prime,
			newDescriptionForMerchant2Prime, 7, 3)
		require.NoError(err)
		txnOps = append(txnOps, tmpOps)
		txns = append(txns, tmpTxn)

		// Verify that everything in the database is updated for the merchant.
		merchantEntry := DbGetMerchantEntryForMerchantID(db, merchantIDs[1])
		require.NotNil(merchantEntry)
		require.Equal(newUsernameForMerchant2Prime, string(merchantEntry.Username))
		require.Equal(newPkForMerchant2Prime, PkToStringTestnet(merchantEntry.PublicKey))
		require.Equal(newDescriptionForMerchant2Prime, string(merchantEntry.Description))
		require.False(merchantEntry.isDeleted)

		burnAmountAfter := DbGetMerchantEntryForMerchantID(db, merchantIDs[1]).Stats.AmountBurnedNanos
		require.Equal(uint64(3), burnAmountAfter-burnAmountBefore)
	}

	// Updating to a pubkey or username that already exists should fail.
	{
		_, _, _, err := _doUpdateMerchantWithViewFlush(t, chain, db,
			params, senderPkString, senderPrivString,
			merchantIDs[0], newPkForMerchant2Prime, "random_username_not_used_yet",
			newDescriptionForMerchant2Prime, 7, 3)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorMerchantPkExists)

		_, _, _, err = _doUpdateMerchantWithViewFlush(t, chain, db,
			params, senderPkString, senderPrivString,
			merchantIDs[0], "", "m4",
			newDescriptionForMerchant2Prime, 7, 3)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorMerchantUsernameExists)
	}

	// Update the last merchant to only change her public key.
	{
		lastMerchantIndex := len(merchantIDs) - 1

		// The burn amount should increase from this operation.
		burnAmountBefore := DbGetMerchantEntryForMerchantID(db, merchantIDs[lastMerchantIndex]).Stats.AmountBurnedNanos

		expectedSenderBalances = append(expectedSenderBalances, _getBalance(t, chain, nil, senderPkString))
		expectedRecipientBalances = append(expectedRecipientBalances, _getBalance(t, chain, nil, recipientPkString))

		tmpOps, tmpTxn, _, err := _doUpdateMerchantWithViewFlush(t, chain, db,
			params, "tUN2NazDYX2zmbPMXagebSjHmK6QcybHBGRvFMrHDRgn5Us8YPs1De",
			"tunTBiMhRjKVmeK6bF8kJFQpmxH2UnTweB8zYsvH3bJPjyVMZr5kS",
			merchantIDs[lastMerchantIndex], "tUN2RMr1HX6G1EZnLfKKxNhcby6b3TmQ5FRuh3hgBECPd8nw4UT4Fp",
			"", "", 7, 3)
		require.NoError(err)
		txnOps = append(txnOps, tmpOps)
		txns = append(txns, tmpTxn)

		// Verify that everything in the database is updated for the merchant.
		merchantEntry := DbGetMerchantEntryForMerchantID(db, merchantIDs[lastMerchantIndex])
		require.NotNil(merchantEntry)
		require.Equal("m5", string(merchantEntry.Username))
		require.Equal("tUN2RMr1HX6G1EZnLfKKxNhcby6b3TmQ5FRuh3hgBECPd8nw4UT4Fp", PkToStringTestnet(merchantEntry.PublicKey))
		require.Equal("i mean she's the best ", string(merchantEntry.Description))
		require.False(merchantEntry.isDeleted)

		burnAmountAfter := DbGetMerchantEntryForMerchantID(db, merchantIDs[lastMerchantIndex]).Stats.AmountBurnedNanos
		require.Equal(uint64(3), burnAmountAfter-burnAmountBefore)
	}

	// Update the first merchant to only change her username.
	{
		expectedSenderBalances = append(expectedSenderBalances, _getBalance(t, chain, nil, senderPkString))
		expectedRecipientBalances = append(expectedRecipientBalances, _getBalance(t, chain, nil, recipientPkString))

		tmpOps, tmpTxn, _, err := _doUpdateMerchantWithViewFlush(t, chain, db,
			params, senderPkString, senderPrivString,
			merchantIDs[0], "", "asdf", "", 7, 3)
		require.NoError(err)
		txnOps = append(txnOps, tmpOps)
		txns = append(txns, tmpTxn)

		// Verify that everything in the database is updated for the merchant.
		merchantEntry := DbGetMerchantEntryForMerchantID(db, merchantIDs[0])
		require.NotNil(merchantEntry)
		require.Equal("asdf", string(merchantEntry.Username))
		require.Equal(senderPkString, PkToStringTestnet(merchantEntry.PublicKey))
		require.Equal("i mean she's the best ", string(merchantEntry.Description))
		require.False(merchantEntry.isDeleted)
	}

	// Trying to take the first user's old username m1 with the same public key that
	// the first user currently has should fail.
	{
		_, _, _, err := _doRegisterMerchantWithViewFlushWithError(
			t, chain, db, params, "m1", senderPkString, senderPrivString, 10, 7, true)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorMerchantPkExists)
	}

	// Do some basic transfers to shake things up a bit.
	registerOrTransfer("", senderPkString, recipientPkString, senderPrivString)
	registerOrTransfer("", senderPkString, recipientPkString, senderPrivString)

	// Registering a new merchant with the username of the first user (=m1) and the
	// public key of the second user (pk=recipientPkString) should
	// succeed now because m1 and recipientPkString are no longer in use.
	{
		registerOrTransfer("m1", recipientPkString, "", recipientPrivString)
	}
	// The mempool isn't smart enough to accept this transaction because of the way
	// it looks up dependencies. In particular, because the merchant who previously
	// owned m1 has a different merchantID than the one currently claiming m1, the
	// transaction in which the first merchant gives up the m1 username won't be
	// fetched as a dependency of this transaction, and so it will appear as though
	// m1 is still taken when this transaction is applied. This isn't really a problem,
	// just a minor inconvenience. An easy way to fix this would be to have the mempool
	// reapply all transactions in it before processing each new transaction but this
	// would be bad from a performance standpoint so the current tradeoff is reasonable.
	txnToExcludeFromMempoolProcessing := txns[len(txns)-1].Hash()

	registerOrTransfer("", recipientPkString, senderPkString, recipientPrivString)
	registerOrTransfer("", senderPkString, recipientPkString, senderPrivString)

	// Check all of the public keys and public keys in the db.
	_checkPublicKeysAndUsernames := func() {
		{
			publicKeys, merchantIDs, merchantEntries, err := DbGetAllPubKeyMerchantIDMappings(db)
			require.NoError(err)
			require.Equal(6, len(merchantIDs))
			expectedPks := []string{
				senderPkString,
				recipientPkString,
				"tUN2RExHhcCWqXqT9r7syGupJS6hxrBPDQMssSph6ki1FZLJTczUm4",
				"tUN2RUx1U7By7i2CZn5sZEEb5jjEHfoyc4Nvk2P9gc6Lf8Bc29xzzB",
				"tUN2RMr1HX6G1EZnLfKKxNhcby6b3TmQ5FRuh3hgBECPd8nw4UT4Fp",
				newPkForMerchant2Prime,
			}
			pkMap := make(map[string]bool)
			for ii, pk := range publicKeys {
				pkMap[PkToStringTestnet(pk)] = true
				require.Truef(reflect.DeepEqual(publicKeys[ii], merchantEntries[ii].PublicKey),
					"Public key found %v with merchantEntry having different public key %v",
					PkToStringTestnet(publicKeys[ii]), merchantEntries[ii])
			}
			for _, expectedPk := range expectedPks {
				_, exists := pkMap[expectedPk]
				require.Truef(exists, "Pk %s not found in dump of <pk, merchantIDs>", expectedPk)
			}
		}
		{
			usernames, merchantIDs, merchantEntries, err := DbGetAllUsernameMerchantIDMappings(db)
			require.NoError(err)
			require.Equal(6, len(merchantIDs))
			expectedUsernames := []string{
				"asdf",
				"m1",
				"m2doubleprime",
				"m3",
				"m4",
				"m5",
			}
			unameMap := make(map[string]bool)
			for ii, uname := range usernames {
				unameMap[string(uname)] = true
				require.Equalf(string(usernames[ii]), string(merchantEntries[ii].Username),
					"Username found %v with merchantEntry having different public key %v",
					usernames[ii], merchantEntries[ii])
			}
			for _, expectedUname := range expectedUsernames {
				_, exists := unameMap[expectedUname]
				require.Truef(exists, "Username %s not found in dump of <username, merchantIDs>", expectedUname)
			}
		}
	}
	_checkPublicKeysAndUsernames()

	// Check the top merchants are as expected.
	{
		topMerchantIDs, topMerchantScores, topMerchantEntries, err :=
			DbGetBlockchainTopMerchants(db, math.MaxUint64, false /*noMerchantEntries*/)
		require.NoError(err)
		_, _, _ = topMerchantIDs, topMerchantScores, topMerchantEntries
	}

	// Roll back all of the above using the utxoOps from each.
	for ii := 0; ii < len(txnOps); ii++ {
		backwardIter := len(txnOps) - 1 - ii
		fmt.Printf("Disconnecting transaction with index %d (going backwards)\n", backwardIter)
		currentOps := txnOps[backwardIter]
		currentTxn := txns[backwardIter]

		utxoView, err := NewUtxoView(db, params, nil)
		require.NoError(err)

		currentHash := currentTxn.Hash()
		err = utxoView.DisconnectTransaction(currentTxn, currentHash, currentOps, savedHeight)
		require.NoError(err)

		require.NoError(utxoView.FlushToDb())

		// After disconnecting, the balances should be restored to what they
		// were before this transaction was applied.
		require.Equal(expectedSenderBalances[backwardIter], _getBalance(t, chain, nil, senderPkString))
		require.Equal(expectedRecipientBalances[backwardIter], _getBalance(t, chain, nil, recipientPkString))
	}

	// Verify all the mappings are now gone from the db.
	require.Equal(uint64(0), GetNumMerchantEntries(db))
	for _, merchantID := range merchantIDs {
		require.Nil(DbGetMerchantEntryForMerchantID(db, merchantID))
	}

	// Check that everything has been deleted from the db.
	pks, _, _, err := DbGetAllPubKeyMerchantIDMappings(db)
	require.NoError(err)
	require.Equal(0, len(pks))
	unames, _, _, err := DbGetAllUsernameMerchantIDMappings(db)
	require.NoError(err)
	require.Equal(0, len(unames))

	// Apply all the transactions to a mempool object and make sure we don't get any
	// errors.
	for ii, tx := range txns {
		// See comment above on this transaction.
		if *tx.Hash() == *txnToExcludeFromMempoolProcessing {
			break
		}
		fmt.Printf("Adding txn %d of type %v to mempool\n", ii, tx.TxnMeta.GetTxnType())

		require.Equal(expectedSenderBalances[ii], _getBalance(t, chain, mempool, senderPkString))
		require.Equal(expectedRecipientBalances[ii], _getBalance(t, chain, mempool, recipientPkString))

		_, err := mempool.ProcessTransaction(tx, false, false, 0, true)
		require.NoError(err, "Problem adding transaction %d to mempool: %v", ii, tx)
	}

	// Apply all the transactions to a view and flush the view to the db.
	utxoView, err := NewUtxoView(db, params, nil)
	require.NoError(err)
	for ii, txn := range txns {
		fmt.Printf("Adding txn %v of type %v to UtxoView\n", ii, txn.TxnMeta.GetTxnType())

		// Always use height+1 for validation since it's assumed the transaction will
		// get mined into the next block.
		txHash := txn.Hash()
		blockHeight := chain.blockTip().Height + 1
		_, _, _, _, err :=
			utxoView.ConnectTransaction(txn, txHash, blockHeight, true /*verifySignature*/, true /*verifyMerchantMerkleRoot*/)
		require.NoError(err)

		// Dump the username contents of the view.
		//for uname, mentry := range utxoView.UsernameToMerchantEntry {
		//fmt.Printf("     %s: %v\n", uname, mentry)
		//}
		// Dump the public key contents of the view.
		//for pk, mentry := range utxoView.PkToMerchantEntry {
		//fmt.Printf("     %s: %v\n", PkToStringTestnet(pk[:]), mentry)
		//}
	}
	// Flush the utxoView after having added all the transactions.
	require.NoError(utxoView.FlushToDb())

	// Check the top merchants are as expected.
	{
		topMerchantIDs, topMerchantScores, topMerchantEntries, err :=
			DbGetBlockchainTopMerchants(db, math.MaxUint64, false /*noMerchantEntries*/)
		require.NoError(err)
		_, _, _ = topMerchantIDs, topMerchantScores, topMerchantEntries
	}

	// Check that the state of the db after the flush is the same as when we added each
	// transaction individually.
	_checkPublicKeysAndUsernames()

	// Disonnect the transactions from a single view in the same way as above
	// i.e. without flushing each time.
	utxoView2, err := NewUtxoView(db, params, nil)
	require.NoError(err)
	for ii := 0; ii < len(txnOps); ii++ {
		backwardIter := len(txnOps) - 1 - ii
		fmt.Printf("Disconnecting transaction with index %d (going backwards)\n", backwardIter)
		currentOps := txnOps[backwardIter]
		currentTxn := txns[backwardIter]

		currentHash := currentTxn.Hash()
		err = utxoView2.DisconnectTransaction(currentTxn, currentHash, currentOps, savedHeight)
		require.NoError(err)
	}
	require.NoError(utxoView2.FlushToDb())
	require.Equal(expectedSenderBalances[0], _getBalance(t, chain, nil, senderPkString))
	require.Equal(expectedRecipientBalances[0], _getBalance(t, chain, nil, recipientPkString))

	// Verify all the mappings are now gone from the db.
	require.Equal(uint64(0), GetNumMerchantEntries(db))
	for _, merchantID := range merchantIDs {
		require.Nil(DbGetMerchantEntryForMerchantID(db, merchantID))
	}

	// Check that everything has been deleted from the db.
	pks, _, _, err = DbGetAllPubKeyMerchantIDMappings(db)
	require.NoError(err)
	require.Equal(0, len(pks))
	unames, _, _, err = DbGetAllUsernameMerchantIDMappings(db)
	require.NoError(err)
	require.Equal(0, len(unames))
}

func _placeOrder(t *testing.T, chain *Blockchain, db *badger.DB,
	params *UltranetParams, feeRateNanosPerKB uint64, buyerPkBase58Check string, buyerPrivBase58Check string,
	merchantIDBase58Check string,
	amountLockedNanos uint64, buyerMessage string, mempool *TxPool) (
	_utxoOps []*UtxoOperation, _txn *MsgUltranetTxn, _height uint32, _err error) {

	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	buyerPkBytes, _, err := Base58CheckDecode(buyerPkBase58Check)

	merchantIDBytes, _, err := Base58CheckDecode(merchantIDBase58Check)
	require.NoError(err)
	merchantID := &BlockHash{}
	copy(merchantID[:], merchantIDBytes)

	txn, _, _, _, _, err := chain.CreatePlaceOrderTxn(
		buyerPkBytes, merchantID, amountLockedNanos, buyerMessage,
		feeRateNanosPerKB, mempool)
	if err != nil {
		return nil, nil, 0, err
	}

	// Sign the transaction now that its inputs are set up.
	_signTxn(t, txn, buyerPrivBase58Check)

	utxoView, err := NewUtxoView(db, params, nil)
	require.NoError(err)

	txHash := txn.Hash()
	// Always use height+1 for validation since it's assumed the transaction will
	// get mined into the next block.
	blockHeight := chain.blockTip().Height + 1
	utxoOps, totalInput, totalOutput, fees, err :=
		utxoView.ConnectTransaction(txn, txHash, blockHeight, true /*verifySignature*/, true /*verifyMerchantMerkleRoot*/)
	// ConnectTransaction should treat the amount locked as contributing to the
	// output.
	if err != nil {
		return nil, nil, 0, err
	}
	require.GreaterOrEqual(totalOutput, amountLockedNanos)
	require.GreaterOrEqual(totalInput, totalOutput+fees)

	// We should have one SPEND UtxoOperation for each input, one ADD operation
	// for each output, and one OperationTypeAddOrderEntry operation at the end.
	require.Equal(len(txn.TxInputs)+len(txn.TxOutputs)+1, len(utxoOps))
	for ii := 0; ii < len(txn.TxInputs); ii++ {
		require.Equal(OperationTypeSpendUtxo, utxoOps[ii].Type)
	}
	require.Equal(OperationTypeAddOrderEntry, utxoOps[len(utxoOps)-1].Type)

	require.NoError(utxoView.FlushToDb())

	return utxoOps, txn, blockHeight, nil
}

func _unsafeCancelOrder(t *testing.T, chain *Blockchain, db *badger.DB,
	params *UltranetParams, feeRateNanosPerKB uint64, buyerPkBase58Check string, buyerPrivBase58Check string,
	orderID *BlockHash) error {

	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	buyerPkBytes, _, err := Base58CheckDecode(buyerPkBase58Check)
	require.NoError(err)

	utxoView, err := NewUtxoView(db, params, nil)
	require.NoError(err)

	// Get the OrderEntry for the OrderID from the view. This will hit the db
	// only if there were no modifications to the order in the mempool, which
	// is exactly what we want.
	orderEntry := utxoView._getOrderEntryForOrderID(orderID)

	// Compute the fee based on the size of the order with just one output
	// refunding the buyer.
	txn := &MsgUltranetTxn{
		// The inputs will be set below.
		TxInputs: []*UltranetInput{},
		TxOutputs: []*UltranetOutput{
			&UltranetOutput{
				PublicKey: buyerPkBytes,
				// Set to zero initially to the amount we expect to be
				// refunded.
				AmountNanos: orderEntry.AmountLockedNanos,
			},
		},
		PublicKey: buyerPkBytes,
		TxnMeta: &CancelOrderMetadata{
			OrderID: orderID,
		},

		// We wait to compute the signature until we've added all the
		// inputs and change.
	}
	// Estimate the size of the transaction.
	maxFee := _computeMaxTxFee(txn, feeRateNanosPerKB)

	// Now that we know the fee is less than the amount locked, deduct the fee from
	// the output, which was initially refunding the full amount locked.
	txn.TxOutputs[0].AmountNanos -= maxFee

	// Sign the transaction now that its inputs are set up.
	_signTxn(t, txn, buyerPrivBase58Check)

	txHash := txn.Hash()
	// Always use height+1 for validation since it's assumed the transaction will
	// get mined into the next block.
	blockHeight := chain.blockTip().Height + 1
	_, _, _, _, err =
		utxoView.ConnectTransaction(txn, txHash, blockHeight, true /*verifySignature*/, true /*verifyMerchantMerkleRoot*/)

	return err
}

func _cancelOrder(t *testing.T, chain *Blockchain, db *badger.DB,
	params *UltranetParams, feeRateNanosPerKB uint64, buyerPkBase58Check string, buyerPrivBase58Check string,
	orderID *BlockHash, mempool *TxPool) (
	_utxoOps []*UtxoOperation, _txn *MsgUltranetTxn, _height uint32, _err error) {

	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	buyerPkBytes, _, err := Base58CheckDecode(buyerPkBase58Check)
	require.NoError(err)

	utxoView, err := NewUtxoView(db, params, nil)
	require.NoError(err)
	orderEntry := utxoView._getOrderEntryForOrderID(orderID)

	txn, refundAmount, fee, err := chain.CreateCancelOrderTxn(
		buyerPkBytes, orderID, feeRateNanosPerKB, mempool)
	require.NoError(err)
	require.Equal(orderEntry.AmountLockedNanos, refundAmount+fee)

	// Sign the transaction now that its inputs are set up.
	_signTxn(t, txn, buyerPrivBase58Check)

	txHash := txn.Hash()
	// Always use height+1 for validation since it's assumed the transaction will
	// get mined into the next block.
	blockHeight := chain.blockTip().Height + 1
	utxoOps, totalInput, totalOutput, fees, err :=
		utxoView.ConnectTransaction(txn, txHash, blockHeight, true /*verifySignature*/, true /*verifyMerchantMerkleRoot*/)
	// ConnectTransaction should treat the amount locked as contributing to the
	// output.
	if err != nil {
		return nil, nil, 0, err
	}
	require.Equal(totalInput, totalOutput+fees)

	// We should have one SPEND UtxoOperation for each input, one ADD operation
	// for each output, and one OperationTypeCancelOrder operation at the end.
	require.Equal(len(txn.TxInputs)+len(txn.TxOutputs)+1, len(utxoOps))
	for ii := 0; ii < len(txn.TxInputs); ii++ {
		require.Equal(OperationTypeSpendUtxo, utxoOps[ii].Type)
	}
	require.Equal(OperationTypeCancelOrder, utxoOps[len(utxoOps)-1].Type)

	require.NoError(utxoView.FlushToDb())

	return utxoOps, txn, blockHeight, nil
}

func _unsafeRejectOrder(t *testing.T, chain *Blockchain, db *badger.DB,
	params *UltranetParams, feeRateNanosPerKB uint64, merchantPkBase58Check string, merchantPrivBase58Check string,
	orderID *BlockHash) error {

	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	merchantPkBytes, _, err := Base58CheckDecode(merchantPkBase58Check)
	require.NoError(err)

	utxoView, err := NewUtxoView(db, params, nil)
	require.NoError(err)

	// Get the OrderEntry for the OrderID from the view.
	orderEntry := utxoView._getOrderEntryForOrderID(orderID)

	// Compute the fee based on the size of the order with just one output
	// refunding the buyer.
	txn := &MsgUltranetTxn{
		// The inputs will be set below.
		TxInputs: []*UltranetInput{},
		TxOutputs: []*UltranetOutput{
			&UltranetOutput{
				PublicKey: orderEntry.BuyerPk,
				// Set to zero initially to the amount we expect to be
				// refunded.
				AmountNanos: 0,
			},
		},
		PublicKey: merchantPkBytes,
		TxnMeta: &RejectOrderMetadata{
			OrderID:      orderID,
			RejectReason: []byte("no tip honey?"),
		},

		// We wait to compute the signature until we've added all the
		// inputs and change.
	}

	_, _, _, _, err =
		chain.AddInputsAndChangeToTransaction(txn, feeRateNanosPerKB, nil)
	if err != nil {
		return err
	}

	txn.TxOutputs[0].AmountNanos = orderEntry.AmountLockedNanos

	// Sign the transaction now that its inputs are set up.
	_signTxn(t, txn, merchantPrivBase58Check)

	txHash := txn.Hash()
	// Always use height+1 for validation since it's assumed the transaction will
	// get mined into the next block.
	blockHeight := chain.blockTip().Height + 1
	_, _, _, _, err =
		utxoView.ConnectTransaction(txn, txHash, blockHeight, true /*verifySignature*/, true /*verifyMerchantMerkleRoot*/)

	return err
}

func _rejectOrder(t *testing.T, chain *Blockchain, db *badger.DB,
	params *UltranetParams, feeRateNanosPerKB uint64, merchantPkBase58Check string, merchantPrivBase58Check string,
	rejectReason string, orderID *BlockHash) (
	_utxoOps []*UtxoOperation, _txn *MsgUltranetTxn, _height uint32, _err error) {

	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	merchantPkBytes, _, err := Base58CheckDecode(merchantPkBase58Check)
	require.NoError(err)

	utxoView, err := NewUtxoView(db, params, nil)
	require.NoError(err)
	orderEntry := utxoView._getOrderEntryForOrderID(orderID)

	txn, _, err := chain.CreateRejectOrderTxn(
		merchantPkBytes, rejectReason, orderID, feeRateNanosPerKB, nil)
	require.Equal(txn.TxOutputs[0].AmountNanos, orderEntry.AmountLockedNanos)

	// Sign the transaction now that its inputs are set up.
	_signTxn(t, txn, merchantPrivBase58Check)

	txHash := txn.Hash()
	// Always use height+1 for validation since it's assumed the transaction will
	// get mined into the next block.
	blockHeight := chain.blockTip().Height + 1
	utxoOps, totalInput, totalOutput, fees, err :=
		utxoView.ConnectTransaction(txn, txHash, blockHeight, true /*verifySignature*/, true /*verifyMerchantMerkleRoot*/)
	// ConnectTransaction should treat the amount locked as contributing to the
	// output.
	if err != nil {
		return nil, nil, 0, err
	}
	require.Equal(totalInput, totalOutput+fees)

	// We should have one SPEND UtxoOperation for each input, one ADD operation
	// for each output, and one OperationTypeRejectOrder operation at the end.
	require.Equal(len(txn.TxInputs)+len(txn.TxOutputs)+1, len(utxoOps))
	for ii := 0; ii < len(txn.TxInputs); ii++ {
		require.Equal(OperationTypeSpendUtxo, utxoOps[ii].Type)
	}
	require.Equal(OperationTypeRejectOrder, utxoOps[len(utxoOps)-1].Type)

	require.NoError(utxoView.FlushToDb())

	return utxoOps, txn, blockHeight, nil
}

func _refundOrder(t *testing.T, chain *Blockchain, db *badger.DB,
	params *UltranetParams, feeRateNanosPerKB uint64, merchantPkBase58Check string,
	buyerPkBase58Check string,
	merchantPrivBase58Check string, orderID *BlockHash) (
	_utxoOps []*UtxoOperation, _txn *MsgUltranetTxn, _height uint32, _err error) {

	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	merchantPkBytes, _, err := Base58CheckDecode(merchantPkBase58Check)
	require.NoError(err)

	buyerPkBytes, _, err := Base58CheckDecode(buyerPkBase58Check)
	require.NoError(err)

	utxoView, err := NewUtxoView(db, params, nil)
	require.NoError(err)

	// Check the amounts at the end to give the transaction a chance to connect
	// first.
	orderEntry := utxoView._getOrderEntryForOrderID(orderID)
	amountLockedBeforeConnect := orderEntry.AmountLockedNanos

	txn, refundInput, refundAmount, refundChange, fee, err := chain.CreateRefundOrderTxn(
		merchantPkBytes, buyerPkBytes, orderID, feeRateNanosPerKB, nil)
	if err != nil {
		return nil, nil, 0, err
	}
	require.Equal(refundInput, refundAmount+refundChange+fee)

	// Sign the transaction now that its inputs are set up.
	_signTxn(t, txn, merchantPrivBase58Check)

	txHash := txn.Hash()
	// Always use height+1 for validation since it's assumed the transaction will
	// get mined into the next block.
	blockHeight := chain.blockTip().Height + 1
	utxoOps, totalInput, totalOutput, fees, err :=
		utxoView.ConnectTransaction(txn, txHash, blockHeight, true /*verifySignature*/, true /*verifyMerchantMerkleRoot*/)
	// ConnectTransaction should treat the amount locked as contributing to the
	// output.
	if err != nil {
		return nil, nil, 0, err
	}
	require.Equal(totalInput, totalOutput+fees)
	require.Equal(totalInput, refundInput)

	// We should have one SPEND UtxoOperation for each input, one ADD operation
	// for each output, and one OperationTypeRefundOrder operation at the end.
	require.Equal(len(txn.TxInputs)+len(txn.TxOutputs)+1, len(utxoOps))
	for ii := 0; ii < len(txn.TxInputs); ii++ {
		require.Equal(OperationTypeSpendUtxo, utxoOps[ii].Type)
	}
	require.Equal(OperationTypeRefundOrder, utxoOps[len(utxoOps)-1].Type)

	commissionNanos, _, err := _computeCommissionsAndRevenueFromPayment(
		orderEntry.PaymentAmountNanos, params.CommissionBasisPoints)
	require.Equal(commissionNanos, amountLockedBeforeConnect)
	require.Equal(commissionNanos, orderEntry.AmountLockedNanos)

	require.NoError(utxoView.FlushToDb())

	return utxoOps, txn, blockHeight, nil
}

func _fulfillOrder(t *testing.T, chain *Blockchain, db *badger.DB,
	params *UltranetParams, feeRateNanosPerKB uint64, merchantPkBase58Check string,
	merchantPrivBase58Check string, orderID *BlockHash) (
	_utxoOps []*UtxoOperation, _txn *MsgUltranetTxn, _height uint32, _err error) {

	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	merchantPkBytes, _, err := Base58CheckDecode(merchantPkBase58Check)
	require.NoError(err)

	utxoView, err := NewUtxoView(db, params, nil)
	require.NoError(err)

	// Check the amounts at the end to give the transaction a chance to connect
	// first.
	orderEntry := utxoView._getOrderEntryForOrderID(orderID)
	amountLockedBeforeConnect := orderEntry.AmountLockedNanos

	txn, fulfillInput, fulfillChange, fee, err := chain.CreateFulfillOrderTxn(
		merchantPkBytes, orderID, feeRateNanosPerKB, nil)
	if err != nil {
		return nil, nil, 0, err
	}
	require.Equal(fulfillInput, fulfillChange+fee)

	// Sign the transaction now that its inputs are set up.
	_signTxn(t, txn, merchantPrivBase58Check)

	txHash := txn.Hash()
	// Always use height+1 for validation since it's assumed the transaction will
	// get mined into the next block.
	blockHeight := chain.blockTip().Height + 1
	utxoOps, totalInput, totalOutput, fees, err :=
		utxoView.ConnectTransaction(txn, txHash, blockHeight, true /*verifySignature*/, true /*verifyMerchantMerkleRoot*/)
	// ConnectTransaction should treat the amount locked as contributing to the
	// output.
	if err != nil {
		return nil, nil, 0, err
	}
	require.Equal(totalInput, totalOutput+fees)
	require.Equal(totalInput, fulfillInput)

	// We should have one SPEND UtxoOperation for each input, one ADD operation
	// for each output, and one OperationTypeFulfillOrder operation at the end.
	require.Equal(len(txn.TxInputs)+len(txn.TxOutputs)+1, len(utxoOps))
	for ii := 0; ii < len(txn.TxInputs); ii++ {
		require.Equal(OperationTypeSpendUtxo, utxoOps[ii].Type)
	}
	require.Equal(OperationTypeFulfillOrder, utxoOps[len(utxoOps)-1].Type)

	commissionNanos, _, err := _computeCommissionsAndRevenueFromPayment(
		orderEntry.PaymentAmountNanos, params.CommissionBasisPoints)
	require.Equal(commissionNanos, amountLockedBeforeConnect)
	require.Equal(commissionNanos, orderEntry.AmountLockedNanos)

	require.NoError(utxoView.FlushToDb())

	return utxoOps, txn, blockHeight, nil
}

func _reviewOrder(t *testing.T, chain *Blockchain, db *badger.DB,
	params *UltranetParams, feeRateNanosPerKB uint64, buyerPkBase58Check string,
	buyerPrivBase58Check string, orderID *BlockHash, reviewType ReviewType,
	reviewText string) (
	_utxoOps []*UtxoOperation, _txn *MsgUltranetTxn, _height uint32, _err error) {

	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	buyerPkBytes, _, err := Base58CheckDecode(buyerPkBase58Check)
	require.NoError(err)

	utxoView, err := NewUtxoView(db, params, nil)
	require.NoError(err)

	// Check the amounts at the end to give the transaction a chance to connect
	// first.
	orderEntry := utxoView._getOrderEntryForOrderID(orderID)
	amountLockedBeforeConnect := orderEntry.AmountLockedNanos

	txn, reviewInput, reviewChange, fee, err := chain.CreateReviewOrderTxn(
		buyerPkBytes, orderID, reviewType, []byte(reviewText), feeRateNanosPerKB, nil)
	if err != nil {
		return nil, nil, 0, err
	}
	require.Equal(reviewInput, reviewChange+fee)

	// Sign the transaction now that its inputs are set up.
	_signTxn(t, txn, buyerPrivBase58Check)

	txHash := txn.Hash()
	// Always use height+1 for validation since it's assumed the transaction will
	// get mined into the next block.
	blockHeight := chain.blockTip().Height + 1
	utxoOps, totalInput, totalOutput, fees, err :=
		utxoView.ConnectTransaction(txn, txHash, blockHeight, true /*verifySignature*/, true /*verifyMerchantMerkleRoot*/)
	// ConnectTransaction should treat the amount locked as contributing to the
	// output.
	if err != nil {
		return nil, nil, 0, err
	}
	require.Equal(totalInput, totalOutput+fees)
	require.Equal(totalInput, reviewInput)

	// We should have one SPEND UtxoOperation for each input, one ADD operation
	// for each output, and one OperationTypeReviewOrder operation at the end.
	require.Equal(len(txn.TxInputs)+len(txn.TxOutputs)+1, len(utxoOps))
	for ii := 0; ii < len(txn.TxInputs); ii++ {
		require.Equal(OperationTypeSpendUtxo, utxoOps[ii].Type)
	}
	require.Equal(OperationTypeReviewOrder, utxoOps[len(utxoOps)-1].Type)

	commissionNanos, _, err := _computeCommissionsAndRevenueFromPayment(
		orderEntry.PaymentAmountNanos, params.CommissionBasisPoints)
	require.Equal(commissionNanos, amountLockedBeforeConnect)
	require.Equal(commissionNanos, orderEntry.AmountLockedNanos)

	require.NoError(utxoView.FlushToDb())

	return utxoOps, txn, blockHeight, nil
}

func _confirmOrder(t *testing.T, chain *Blockchain, db *badger.DB,
	params *UltranetParams, feeRateNanosPerKB uint64, merchantPkBase58Check string, merchantPrivBase58Check string,
	orderID *BlockHash) (
	_utxoOps []*UtxoOperation, _txn *MsgUltranetTxn, _height uint32, _err error) {

	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	merchantPkBytes, _, err := Base58CheckDecode(merchantPkBase58Check)
	require.NoError(err)

	utxoView, err := NewUtxoView(db, params, nil)
	require.NoError(err)

	// Check the amounts at the end to give the transaction a chance to connect
	// first.
	orderEntry := utxoView._getOrderEntryForOrderID(orderID)
	amountLockedBeforeConnect := orderEntry.AmountLockedNanos

	txn, merchantOutput, commissionsBeingPaid, fee, err := chain.CreateConfirmOrderTxn(
		merchantPkBytes, orderID, feeRateNanosPerKB, nil)
	if err != nil {
		return nil, nil, 0, err
	}

	// Sign the transaction now that its inputs are set up.
	_signTxn(t, txn, merchantPrivBase58Check)

	txHash := txn.Hash()
	// Always use height+1 for validation since it's assumed the transaction will
	// get mined into the next block.
	blockHeight := chain.blockTip().Height + 1
	utxoOps, totalInput, totalOutput, fees, err :=
		utxoView.ConnectTransaction(txn, txHash, blockHeight, true /*verifySignature*/, true /*verifyMerchantMerkleRoot*/)
	// ConnectTransaction should treat the amount locked as contributing to the
	// output.
	if err != nil {
		return nil, nil, 0, err
	}
	require.Equal(totalInput, totalOutput+fees)

	// We should have one SPEND UtxoOperation for each input, one ADD operation
	// for each output, and one OperationTypeConfirmOrder operation at the end.
	require.Equal(len(txn.TxInputs)+len(txn.TxOutputs)+1, len(utxoOps))
	for ii := 0; ii < len(txn.TxInputs); ii++ {
		require.Equal(OperationTypeSpendUtxo, utxoOps[ii].Type)
	}
	require.Equal(OperationTypeConfirmOrder, utxoOps[len(utxoOps)-1].Type)

	require.NoError(utxoView.FlushToDb())

	require.Equal(txn.TxOutputs[0].AmountNanos, amountLockedBeforeConnect-fee-commissionsBeingPaid)
	require.Equal(amountLockedBeforeConnect, merchantOutput+commissionsBeingPaid+fee)

	return utxoOps, txn, blockHeight, nil
}

func _privateMessage(t *testing.T, chain *Blockchain, db *badger.DB,
	params *UltranetParams, feeRateNanosPerKB uint64, senderPkBase58Check string,
	recipientPkBase58Check string,
	senderPrivBase58Check string, unencryptedMessageText string, tstampNanos uint64) (
	_utxoOps []*UtxoOperation, _txn *MsgUltranetTxn, _height uint32, _err error) {

	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	senderPkBytes, _, err := Base58CheckDecode(senderPkBase58Check)
	require.NoError(err)

	recipientPkBytes, _, err := Base58CheckDecode(recipientPkBase58Check)
	require.NoError(err)

	utxoView, err := NewUtxoView(db, params, nil)
	require.NoError(err)

	txn, totalInputMake, changeAmountMake, feesMake, err := chain.CreatePrivateMessageTxn(
		senderPkBytes, recipientPkBytes, unencryptedMessageText,
		tstampNanos, feeRateNanosPerKB, nil)
	if err != nil {
		return nil, nil, 0, err
	}

	require.Equal(totalInputMake, changeAmountMake+feesMake)

	// Sign the transaction now that its inputs are set up.
	_signTxn(t, txn, senderPrivBase58Check)

	txHash := txn.Hash()
	// Always use height+1 for validation since it's assumed the transaction will
	// get mined into the next block.
	blockHeight := chain.blockTip().Height + 1
	utxoOps, totalInput, totalOutput, fees, err :=
		utxoView.ConnectTransaction(txn, txHash, blockHeight, true /*verifySignature*/, true /*verifyMerchantMerkleRoot*/)
	// ConnectTransaction should treat the amount locked as contributing to the
	// output.
	if err != nil {
		return nil, nil, 0, err
	}
	require.Equal(totalInput, totalOutput+fees)
	require.Equal(totalInput, totalInputMake)

	// We should have one SPEND UtxoOperation for each input, one ADD operation
	// for each output, and one OperationTypePrivateMessage operation at the end.
	require.Equal(len(txn.TxInputs)+len(txn.TxOutputs)+1, len(utxoOps))
	for ii := 0; ii < len(txn.TxInputs); ii++ {
		require.Equal(OperationTypeSpendUtxo, utxoOps[ii].Type)
	}
	require.Equal(OperationTypePrivateMessage, utxoOps[len(utxoOps)-1].Type)

	require.NoError(utxoView.FlushToDb())

	return utxoOps, txn, blockHeight, nil
}

func TestPlaceOrder(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	chain, params, db := NewLowDifficultyBlockchain()
	mempool, miner := NewTestMiner(t, chain, params, true /*isSender*/)

	// Set the listing-related params to low values so we can test hitting
	// them.
	params.MaxMerchantsToIndex = 4
	params.MaxListingsPerMerchant = 5
	params.MaxMerchantStorageBytes = 15000 // 15KB
	params.MaxListingSizeBytes = 10000     // 10KB
	params.MaxListingTitleLengthBytes = 100
	params.MaxListingBodyLengthBytes = 100
	params.MaxListingCategoryLengthBytes = 100
	senderPkBytes := mustBase58CheckDecode(senderPkString)

	// Mine a few blocks to give the senderPkString some money.
	block, err := miner._mineAndProcessSingleBlock(0 /*threadIndex*/)
	require.NoError(err)
	_, _ = block, mempool
	block, err = miner._mineAndProcessSingleBlock(0 /*threadIndex*/)
	require.NoError(err)
	block, err = miner._mineAndProcessSingleBlock(0 /*threadIndex*/)
	require.NoError(err)
	block, err = miner._mineAndProcessSingleBlock(0 /*threadIndex*/)
	require.NoError(err)

	// Setup some convenience functions for the test.
	txnOps := [][]*UtxoOperation{}
	txns := []*MsgUltranetTxn{}
	expectedSenderBalances := []uint64{}
	expectedRecipientBalances := []uint64{}
	merchantIDs := []*BlockHash{}
	usernames := []string{}
	publicKeys := []string{}
	// We take the block tip to be the blockchain height rather than the
	// header chain height.
	savedHeight := chain.blockTip().Height + 1
	registerOrTransfer := func(username string,
		senderPk string, recipientPk string, senderPriv string) {

		expectedSenderBalances = append(expectedSenderBalances, _getBalance(t, chain, nil, senderPkString))
		expectedRecipientBalances = append(expectedRecipientBalances, _getBalance(t, chain, nil, recipientPkString))
		if recipientPk == "" {
			currentOps, currentTxn, _ := _doRegisterMerchantWithViewFlush(
				t, chain, db, params, username, senderPk, senderPriv, 13 /*feerate*/, 3 /*burn amount*/)
			txnOps = append(txnOps, currentOps)
			txns = append(txns, currentTxn)
		} else {
			currentOps, currentTxn, _ := _doBasicTransferWithViewFlush(
				t, chain, db, params, senderPk, recipientPk,
				senderPriv, 7 /*amount to send*/, 11 /*feerate*/)

			txnOps = append(txnOps, currentOps)
			txns = append(txns, currentTxn)
		}
		// If we have a username then this is assumed to be a register merchant txn.
		// In thi scase add to the merchantids, usernames, and publickeys.
		if username != "" {
			merchantID := txns[len(txns)-1].Hash()
			merchantIDs = append(merchantIDs, merchantID)
			usernames = append(usernames, username)
			publicKeys = append(publicKeys, senderPk)
		}
	}

	placeOrder := func(
		buyerPkBase58Check string, buyerPrivBase58Check string,
		merchantIDBase58Check string,
		amountLockedNanos uint64, buyerMessage string) {

		expectedSenderBalances = append(expectedSenderBalances, _getBalance(t, chain, nil, senderPkString))
		expectedRecipientBalances = append(expectedRecipientBalances, _getBalance(t, chain, nil, recipientPkString))

		currentOps, currentTxn, _, err := _placeOrder(
			t, chain, db, params, 10 /*feeRateNanosPerKB*/, buyerPkBase58Check,
			buyerPrivBase58Check, merchantIDBase58Check, amountLockedNanos, buyerMessage, mempool)
		require.NoError(err)

		txnOps = append(txnOps, currentOps)
		txns = append(txns, currentTxn)
	}

	// Register two merchants
	// Merchants
	m0Pub := "tUN2RExHhcCWqXqT9r7syGupJS6hxrBPDQMssSph6ki1FZLJTczUm4"
	m0Priv := "tunSykM1Si6Wab5mRKBDu7YK5ubpBxr1ciGiiDXmSpMATB12sAawx"
	m1Pub := "tUN2RUx1U7By7i2CZn5sZEEb5jjEHfoyc4Nvk2P9gc6Lf8Bc29xzzB"
	m1Priv := "tunSJ83kV4PNkC7MPEgbmKWNZeJk1mTbjwXUh9oy7kyBLRWsgFjVw"
	// Non-merchants
	m2Pub := "tUN2NazDYX2zmbPMXagebSjHmK6QcybHBGRvFMrHDRgn5Us8YPs1De"
	m2Priv := "tunTBiMhRjKVmeK6bF8kJFQpmxH2UnTweB8zYsvH3bJPjyVMZr5kS"
	m3Pub := "tUN2Q3nYf8KNgZ5q3ftFeEq3fRFpB8CCzXTW5KV4kGrCm4LEvdv67e"
	m3Priv := "tunSRyKa6shh2S6LH3WsFa6jtT42ktUgVcSdZFqTsMBy3KPnHC9kR"
	// Fund all the keys.
	registerOrTransfer("", senderPkString, m0Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m1Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m1Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m1Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m1Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m1Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m1Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m2Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m3Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m3Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m3Pub, senderPrivString)
	registerOrTransfer("m0", m0Pub, "", m0Priv)
	merchantID0 := txns[len(txns)-1].Hash()
	registerOrTransfer("m1", m1Pub, "", m1Priv)
	merchantID1 := txns[len(txns)-1].Hash()

	_, _, _ = m2Priv, m3Priv, merchantID1

	// Have senderPkString place an order with m0.
	buyerMessage0 := "i want 10 please"
	balBefore0 := _getBalance(t, chain, nil, senderPkString)
	placeOrder(senderPkString, senderPrivString, PkToStringTestnet(merchantID0[:]),
		10, buyerMessage0)
	orderID0 := txns[len(txns)-1].Hash()

	// Balance of user should decrease by at least amountLockedNanos. Balances
	balAfter0 := _getBalance(t, chain, nil, senderPkString)
	require.Greater(balAfter0-balBefore0, uint64(10))

	// Verify that the proper db mappings exist for this OrderEntry.
	_checkOrder0 := func() {

		// Put the <OrderID -> OrderEntry> mapping.
		// _PrefixOrderIDToOrderEntry
		orderEntries, err := DbGetAllOrderEntries(db)
		require.NoError(err)
		require.Equal(1, len(orderEntries))
		require.Equal(orderID0, orderEntries[0].orderID)
		require.Equal(uint64(10), orderEntries[0].AmountLockedNanos)
		require.Equal(senderPkString, PkToStringTestnet(orderEntries[0].BuyerPk))
		require.Equal(merchantID0, orderEntries[0].MerchantID)
		require.Equal(big.NewInt(0), orderEntries[0].MerchantScoreImpact)
		require.Equal(uint64(0), orderEntries[0].Pos)
		require.Equal(OrderStatePlaced, orderEntries[0].State)
		require.Equal(buyerMessage0, string(orderEntries[0].BuyerMessage))
		require.Equal(uint32(0), orderEntries[0].ConfirmationBlockHeight)
		require.Equal(uint32(savedHeight), orderEntries[0].LastModifiedBlock)

		// There should be one entry in each of the below prefix tables.
		// <orderID> -> orderEntry
		merchantIDs, _ := _enumerateKeysForPrefix(db, _PrefixMerchantIDOrderIndex)
		require.Equal(1, len(merchantIDs))
		merchantIDs, _ = _enumerateKeysForPrefix(db, _PrefixBuyerPubKeyOrderIndex)
		require.Equal(1, len(merchantIDs))

		// Get the OrderIDs for the BuyerPk and check them.
		// <pk || lastModified || orderID>
		lastModifiedHeightsForBuyer, orderIDsForBuyer, orderEntriesForBuyer, err := DbGetOrdersForBuyerPublicKey(
			db, senderPkBytes, true /*fetchEntries*/)
		require.NoError(err)
		require.Equal([]uint32{5}, lastModifiedHeightsForBuyer)
		require.Equal([]*BlockHash{orderID0}, orderIDsForBuyer)
		require.Equal(orderEntries, orderEntriesForBuyer)

		// Get the OrderIDs for the MerchantID and check them.
		// <merchantID || lastModified || orderID>
		lastModifiedHeightsForMerchant, orderIDsForMerchant, orderEntriesForMerchant, err := DbGetOrdersForMerchantID(
			db, merchantID0, true /*fetchEntries*/)
		require.NoError(err)
		require.Equal([]uint32{5}, lastModifiedHeightsForMerchant)
		require.Equal([]*BlockHash{orderID0}, orderIDsForMerchant)
		require.Equal(orderEntries, orderEntriesForMerchant)

		// <pos -> OrderID>
		positions, orderIDPositions := _enumerateKeysForPrefix(db, _PrefixPosToOrderID)
		require.Equal(1, len(positions))
		require.Equal(uint64(0), _DecodeUint64(positions[0][1:]))
		require.Equal(orderID0[:], orderIDPositions[0])

		// GetNumOrderEntriesWithTxn
		require.Equal(uint64(1), GetNumOrderEntries(db))
	}
	_checkOrder0()

	buyerMessage1 := "i want 20 please"
	placeOrder(m1Pub, m1Priv, PkToStringTestnet(merchantID1[:]), 20, buyerMessage1)
	orderID1 := txns[len(txns)-1].Hash()

	balBefore2 := _getBalance(t, chain, nil, senderPkString)
	buyerMessage2 := "i want 17 please"
	placeOrder(senderPkString, senderPrivString, PkToStringTestnet(merchantID0[:]), 17, buyerMessage2)
	orderID2 := txns[len(txns)-1].Hash()
	// Balance of user should decrease by at least amountLockedNanos. Balances
	balAfter2 := _getBalance(t, chain, nil, senderPkString)
	require.Greater(balAfter2-balBefore2, uint64(17))

	buyerMessage3 := "i want 7 please"
	placeOrder(m3Pub, m3Priv, PkToStringTestnet(merchantID0[:]), 7, buyerMessage3)
	orderID3 := txns[len(txns)-1].Hash()

	// An order with a bad signature should fail.
	{
		badTxn := &MsgUltranetTxn{
			// The inputs will be set below.
			TxInputs:  []*UltranetInput{},
			TxOutputs: []*UltranetOutput{},
			PublicKey: senderPkBytes,
			TxnMeta: &PlaceOrderMetadata{
				MerchantID:        merchantID0,
				AmountLockedNanos: 13,
				BuyerMessage:      []byte("i want none please"),
			},

			// We wait to compute the signature until we've added all the
			// inputs and change.
		}

		totalInput, spendAmount, changeAmount, fees, err :=
			chain.AddInputsAndChangeToTransaction(badTxn, 10, nil)
		require.NoError(err)
		require.Equal(totalInput, spendAmount+changeAmount+fees)

		utxoView, err := NewUtxoView(db, params, nil)
		require.NoError(err)
		txHash := badTxn.Hash()
		// Always use height+1 for validation since it's assumed the transaction will
		// get mined into the next block.
		blockHeight := chain.blockTip().Height + 1
		_, _, _, _, err =
			utxoView.ConnectTransaction(badTxn, txHash, blockHeight, true /*verifySignature*/, true /*verifyMerchantMerkleRoot*/)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorInvalidTransactionSignature)
	}

	buyerMessage4 := "i want 11 please"
	placeOrder(senderPkString, senderPrivString, PkToStringTestnet(merchantID1[:]), 11, buyerMessage4)
	orderID4 := txns[len(txns)-1].Hash()

	// Do a couple of transfers
	registerOrTransfer("", senderPkString, m1Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m2Pub, senderPrivString)
	registerOrTransfer("", m1Pub, senderPkString, m1Priv)

	// Verify that the proper db mappings exist.
	_checkAllOrders := func() {
		// <OrderID -> OrderEntry> mapping.
		// _PrefixOrderIDToOrderEntry
		orderEntries, err := DbGetAllOrderEntries(db)
		require.NoError(err)
		require.Equal(5, len(orderEntries))

		// To get a consistent ordering, sort the entries on their amount locked, which is
		// unique to each order.
		sort.Slice(orderEntries, func(ii, jj int) bool {
			return orderEntries[ii].AmountLockedNanos < orderEntries[jj].AmountLockedNanos
		})
		// order3 with amountLockedNanos = 7
		{
			currentEntry := orderEntries[0]
			require.Equal(orderID3, currentEntry.orderID)
			require.Equal(uint64(7), currentEntry.AmountLockedNanos)
			require.Equal(m3Pub, PkToStringTestnet(currentEntry.BuyerPk))
			require.Equal(merchantID0, currentEntry.MerchantID)
			require.Equal(big.NewInt(0), currentEntry.MerchantScoreImpact)
			require.Less(currentEntry.Pos, uint64(5))
			require.Equal(OrderStatePlaced, currentEntry.State)
			require.Equal(buyerMessage3, string(currentEntry.BuyerMessage))
			require.Equal(uint32(0), currentEntry.ConfirmationBlockHeight)
			require.Equal(uint32(savedHeight), currentEntry.LastModifiedBlock)

			// Get the OrderIDs for the BuyerPk and check them.
			// <pk || lastModified || orderID>
			lastModifiedHeightsForBuyer, orderIDsForBuyer, orderEntriesForBuyer, err := DbGetOrdersForBuyerPublicKey(
				db, mustBase58CheckDecode(m3Pub), true /*fetchEntries*/)
			require.NoError(err)
			require.Equal(1, len(lastModifiedHeightsForBuyer))
			require.Equal(1, len(orderIDsForBuyer))
			require.Equal(1, len(orderEntriesForBuyer))
			require.Equal([]uint32{5}, lastModifiedHeightsForBuyer)
			require.Equal([]*BlockHash{orderID3}, orderIDsForBuyer)
			require.Equal([]*OrderEntry{orderEntries[0]}, orderEntriesForBuyer)
		}
		// order0 with amountLockedNanos=10
		{
			currentEntry := orderEntries[1]
			pk := senderPkString
			amountNanos := 10
			orderID := orderID0
			message := buyerMessage0
			merchantID := merchantID0
			require.Equal(orderID, currentEntry.orderID)
			require.Equal(uint64(amountNanos), currentEntry.AmountLockedNanos)
			require.Equal(pk, PkToStringTestnet(currentEntry.BuyerPk))
			require.Equal(merchantID, currentEntry.MerchantID)
			require.Equal(big.NewInt(0), currentEntry.MerchantScoreImpact)
			require.Less(currentEntry.Pos, uint64(5))
			require.Equal(OrderStatePlaced, currentEntry.State)
			require.Equal(message, string(currentEntry.BuyerMessage))
			require.Equal(uint32(0), currentEntry.ConfirmationBlockHeight)
			require.Equal(uint32(savedHeight), currentEntry.LastModifiedBlock)

			// Get the OrderIDs for the BuyerPk and check them.
			// <pk || lastModified || orderID>
			lastModifiedHeightsForBuyer, orderIDsForBuyer, orderEntriesForBuyer, err := DbGetOrdersForBuyerPublicKey(
				db, mustBase58CheckDecode(pk), true /*fetchEntries*/)
			require.NoError(err)
			require.Equal(3, len(lastModifiedHeightsForBuyer))
			require.Equal(3, len(orderIDsForBuyer))
			require.Equal(3, len(orderEntriesForBuyer))
			require.Equal([]uint32{5, 5, 5}, lastModifiedHeightsForBuyer)
			sort.Slice(orderEntriesForBuyer, func(ii, jj int) bool {
				return orderEntriesForBuyer[ii].AmountLockedNanos < orderEntriesForBuyer[jj].AmountLockedNanos
			})
			require.Equal([]*OrderEntry{orderEntries[1], orderEntries[2], orderEntries[3]}, orderEntriesForBuyer)
		}
		// order4 with amountLockedNanos=11
		{
			currentEntry := orderEntries[2]
			pk := senderPkString
			amountNanos := 11
			orderID := orderID4
			message := buyerMessage4
			merchantID := merchantID1
			require.Equal(orderID, currentEntry.orderID)
			require.Equal(uint64(amountNanos), currentEntry.AmountLockedNanos)
			require.Equal(pk, PkToStringTestnet(currentEntry.BuyerPk))
			require.Equal(merchantID, currentEntry.MerchantID)
			require.Equal(big.NewInt(0), currentEntry.MerchantScoreImpact)
			require.Less(currentEntry.Pos, uint64(5))
			require.Equal(OrderStatePlaced, currentEntry.State)
			require.Equal(message, string(currentEntry.BuyerMessage))
			require.Equal(uint32(0), currentEntry.ConfirmationBlockHeight)
			require.Equal(uint32(savedHeight), currentEntry.LastModifiedBlock)
		}
		// order2 with amountLockedNanos=17
		{
			currentEntry := orderEntries[3]
			pk := senderPkString
			amountNanos := 17
			orderID := orderID2
			message := buyerMessage2
			merchantID := merchantID0
			require.Equal(orderID, currentEntry.orderID)
			require.Equal(uint64(amountNanos), currentEntry.AmountLockedNanos)
			require.Equal(pk, PkToStringTestnet(currentEntry.BuyerPk))
			require.Equal(merchantID, currentEntry.MerchantID)
			require.Equal(big.NewInt(0), currentEntry.MerchantScoreImpact)
			require.Less(currentEntry.Pos, uint64(5))
			require.Equal(OrderStatePlaced, currentEntry.State)
			require.Equal(message, string(currentEntry.BuyerMessage))
			require.Equal(uint32(0), currentEntry.ConfirmationBlockHeight)
			require.Equal(uint32(savedHeight), currentEntry.LastModifiedBlock)
		}
		// order1 with amountLockedNanos=20
		{
			currentEntry := orderEntries[4]
			pk := m1Pub
			amountNanos := 20
			orderID := orderID1
			message := buyerMessage1
			merchantID := merchantID1
			require.Equal(orderID, currentEntry.orderID)
			require.Equal(uint64(amountNanos), currentEntry.AmountLockedNanos)
			require.Equal(pk, PkToStringTestnet(currentEntry.BuyerPk))
			require.Equal(merchantID, currentEntry.MerchantID)
			require.Equal(big.NewInt(0), currentEntry.MerchantScoreImpact)
			require.Less(currentEntry.Pos, uint64(5))
			require.Equal(OrderStatePlaced, currentEntry.State)
			require.Equal(message, string(currentEntry.BuyerMessage))
			require.Equal(uint32(0), currentEntry.ConfirmationBlockHeight)
			require.Equal(uint32(savedHeight), currentEntry.LastModifiedBlock)

			lastModifiedHeightsForBuyer, orderIDsForBuyer, orderEntriesForBuyer, err := DbGetOrdersForBuyerPublicKey(
				db, mustBase58CheckDecode(m1Pub), true /*fetchEntries*/)
			require.NoError(err)
			require.Equal(1, len(lastModifiedHeightsForBuyer))
			require.Equal(1, len(orderIDsForBuyer))
			require.Equal(1, len(orderEntriesForBuyer))
			require.Equal([]uint32{5}, lastModifiedHeightsForBuyer)
			require.Equal([]*BlockHash{orderID1}, orderIDsForBuyer)
			require.Equal([]*OrderEntry{currentEntry}, orderEntriesForBuyer)
		}

		// GetNumOrderEntriesWithTxn
		require.Equal(uint64(5), GetNumOrderEntries(db))

		// <pos -> OrderID>
		positionBytes, orderIDPositionBytes := _enumerateKeysForPrefix(db, _PrefixPosToOrderID)
		positionMap := make(map[uint64]*BlockHash)
		for ii := range positionBytes {
			pb := positionBytes[ii]
			oid := orderIDPositionBytes[ii]
			oidHash := BlockHash{}
			copy(oidHash[:], oid)

			positionMap[_DecodeUint64(pb[1:])] = &oidHash
		}
		require.Equal(5, len(positionMap))
		for _, orderEntry := range orderEntries {
			require.Contains(positionMap, orderEntry.Pos)
			oid, exists := positionMap[orderEntry.Pos]
			require.True(exists)
			require.Equal(oid, orderEntry.orderID)
		}

		// Get the OrderIDs for the MerchantID and check them.
		// <merchantID || lastModified || orderID>
		// There are two merchants. merchantID0 and merchantID1
		// Verify merchantID0
		lastModifiedHeightsForMerchant0, orderIDsForMerchant0, orderEntriesForMerchant0, err :=
			DbGetOrdersForMerchantID(db, merchantID0, true /*fetchEntries*/)
		require.NoError(err)
		require.Equal(3, len(orderIDsForMerchant0))
		require.Equal([]uint32{5, 5, 5}, lastModifiedHeightsForMerchant0)
		// Sort these orderEntries just like above to have consistency.
		sort.Slice(orderEntriesForMerchant0, func(ii, jj int) bool {
			return orderEntriesForMerchant0[ii].AmountLockedNanos < orderEntriesForMerchant0[jj].AmountLockedNanos
		})
		require.Equal([]*OrderEntry{orderEntries[0], orderEntries[1], orderEntries[3]}, orderEntriesForMerchant0)

		// Verify merchantID1
		lastModifiedHeightsForMerchant1, orderIDsForMerchant1, orderEntriesForMerchant1, err :=
			DbGetOrdersForMerchantID(db, merchantID1, true /*fetchEntries*/)
		require.NoError(err)
		require.Equal(2, len(orderIDsForMerchant1))
		require.Equal([]uint32{5, 5}, lastModifiedHeightsForMerchant1)
		// Sort these orderEntries just like above to have consistency.
		sort.Slice(orderEntriesForMerchant1, func(ii, jj int) bool {
			return orderEntriesForMerchant1[ii].AmountLockedNanos < orderEntriesForMerchant1[jj].AmountLockedNanos
		})
		require.Equal([]*OrderEntry{orderEntries[2], orderEntries[4]}, orderEntriesForMerchant1)
	}
	_checkAllOrders()

	// Roll back all of the above using the utxoOps from each.
	for ii := 0; ii < len(txnOps); ii++ {
		backwardIter := len(txnOps) - 1 - ii
		fmt.Printf("Disconnecting transaction with index %d (going backwards)\n", backwardIter)
		currentOps := txnOps[backwardIter]
		currentTxn := txns[backwardIter]

		utxoView, err := NewUtxoView(db, params, nil)
		require.NoError(err)

		currentHash := currentTxn.Hash()
		err = utxoView.DisconnectTransaction(currentTxn, currentHash, currentOps, savedHeight)
		require.NoError(err)

		require.NoError(utxoView.FlushToDb())

		// After disconnecting, the balances should be restored to what they
		// were before this transaction was applied.
		require.Equal(expectedSenderBalances[backwardIter], _getBalance(t, chain, nil, senderPkString))
		require.Equal(expectedRecipientBalances[backwardIter], _getBalance(t, chain, nil, recipientPkString))
	}

	// Verify all the mappings are now gone from the db.
	{
		merchantIDs, _ := _enumerateKeysForPrefix(db, _PrefixMerchantIDOrderIndex)
		require.Equal(0, len(merchantIDs))
		merchantIDs, _ = _enumerateKeysForPrefix(db, _PrefixBuyerPubKeyOrderIndex)
		require.Equal(0, len(merchantIDs))

		// Get the OrderIDs for the BuyerPk and check them.
		// <pk || lastModified || orderID>
		lastModifiedHeightsForBuyer, orderIDsForBuyer, orderEntriesForBuyer, err := DbGetOrdersForBuyerPublicKey(
			db, senderPkBytes, true /*fetchEntries*/)
		require.NoError(err)
		require.Equal(0, len(lastModifiedHeightsForBuyer))
		require.Equal(0, len(orderIDsForBuyer))
		require.Equal(0, len(orderEntriesForBuyer))

		// Get the OrderIDs for the MerchantID and check them.
		// <merchantID || lastModified || orderID>
		lastModifiedHeightsForMerchant, orderIDsForMerchant, orderEntriesForMerchant, err := DbGetOrdersForMerchantID(
			db, merchantID0, true /*fetchEntries*/)
		require.NoError(err)
		require.Equal(0, len(lastModifiedHeightsForMerchant))
		require.Equal(0, len(orderIDsForMerchant))
		require.Equal(0, len(orderEntriesForMerchant))

		// <pos -> OrderID>
		positions, orderIDPositions := _enumerateKeysForPrefix(db, _PrefixPosToOrderID)
		require.Equal(0, len(positions))
		require.Equal(0, len(orderIDPositions))

		// GetNumOrderEntriesWithTxn
		require.Equal(uint64(0), GetNumOrderEntries(db))
	}

	// Apply all the transactions to a mempool object and make sure we don't get any
	// errors. Verify the balances align as we go.
	for ii, tx := range txns {
		// See comment above on this transaction.
		fmt.Printf("Adding txn %d of type %v to mempool\n", ii, tx.TxnMeta.GetTxnType())

		require.Equal(expectedSenderBalances[ii], _getBalance(t, chain, mempool, senderPkString))
		require.Equal(expectedRecipientBalances[ii], _getBalance(t, chain, mempool, recipientPkString))

		_, err := mempool.ProcessTransaction(tx, false, false, 0, true)
		require.NoError(err, "Problem adding transaction %d to mempool: %v", ii, tx)
	}

	// Apply all the transactions to a view and flush the view to the db.
	utxoView, err := NewUtxoView(db, params, nil)
	require.NoError(err)
	for ii, txn := range txns {
		fmt.Printf("Adding txn %v of type %v to UtxoView\n", ii, txn.TxnMeta.GetTxnType())

		// Always use height+1 for validation since it's assumed the transaction will
		// get mined into the next block.
		txHash := txn.Hash()
		blockHeight := chain.blockTip().Height + 1
		_, _, _, _, err :=
			utxoView.ConnectTransaction(txn, txHash, blockHeight, true /*verifySignature*/, true /*verifyMerchantMerkleRoot*/)
		require.NoError(err)
	}
	// Flush the utxoView after having added all the transactions.
	require.NoError(utxoView.FlushToDb())

	// Check that the state of the db after the flush is the same as when we added each
	// transaction individually.
	_checkAllOrders()

	// Disonnect the transactions from a single view in the same way as above
	// i.e. without flushing each time.
	utxoView2, err := NewUtxoView(db, params, nil)
	require.NoError(err)
	for ii := 0; ii < len(txnOps); ii++ {
		backwardIter := len(txnOps) - 1 - ii
		fmt.Printf("Disconnecting transaction with index %d (going backwards)\n", backwardIter)
		currentOps := txnOps[backwardIter]
		currentTxn := txns[backwardIter]

		currentHash := currentTxn.Hash()
		err = utxoView2.DisconnectTransaction(currentTxn, currentHash, currentOps, savedHeight)
		require.NoError(err)
	}
	require.NoError(utxoView2.FlushToDb())
	require.Equal(expectedSenderBalances[0], _getBalance(t, chain, nil, senderPkString))
	require.Equal(expectedRecipientBalances[0], _getBalance(t, chain, nil, recipientPkString))

	// Verify all the mappings are now gone from the db.
	{
		merchantIDs, _ := _enumerateKeysForPrefix(db, _PrefixMerchantIDOrderIndex)
		require.Equal(0, len(merchantIDs))
		merchantIDs, _ = _enumerateKeysForPrefix(db, _PrefixBuyerPubKeyOrderIndex)
		require.Equal(0, len(merchantIDs))

		// Get the OrderIDs for the BuyerPk and check them.
		// <pk || lastModified || orderID>
		lastModifiedHeightsForBuyer, orderIDsForBuyer, orderEntriesForBuyer, err := DbGetOrdersForBuyerPublicKey(
			db, senderPkBytes, true /*fetchEntries*/)
		require.NoError(err)
		require.Equal(0, len(lastModifiedHeightsForBuyer))
		require.Equal(0, len(orderIDsForBuyer))
		require.Equal(0, len(orderEntriesForBuyer))

		// Get the OrderIDs for the MerchantID and check them.
		// <merchantID || lastModified || orderID>
		lastModifiedHeightsForMerchant, orderIDsForMerchant, orderEntriesForMerchant, err := DbGetOrdersForMerchantID(
			db, merchantID0, true /*fetchEntries*/)
		require.NoError(err)
		require.Equal(0, len(lastModifiedHeightsForMerchant))
		require.Equal(0, len(orderIDsForMerchant))
		require.Equal(0, len(orderEntriesForMerchant))

		// <pos -> OrderID>
		positions, orderIDPositions := _enumerateKeysForPrefix(db, _PrefixPosToOrderID)
		require.Equal(0, len(positions))
		require.Equal(0, len(orderIDPositions))

		// GetNumOrderEntriesWithTxn
		require.Equal(uint64(0), GetNumOrderEntries(db))
	}
}

func TestCancelOrder(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	chain, params, db := NewLowDifficultyBlockchain()
	mempool, miner := NewTestMiner(t, chain, params, true /*isSender*/)

	// Set the listing-related params to low values so we can test hitting
	// them.
	params.MaxMerchantsToIndex = 4
	params.MaxListingsPerMerchant = 5
	params.MaxMerchantStorageBytes = 15000 // 15KB
	params.MaxListingSizeBytes = 10000     // 10KB
	params.MaxListingTitleLengthBytes = 100
	params.MaxListingBodyLengthBytes = 100
	params.MaxListingCategoryLengthBytes = 100
	senderPkBytes := mustBase58CheckDecode(senderPkString)

	// Mine a few blocks to give the senderPkString some money.
	block, err := miner._mineAndProcessSingleBlock(0 /*threadIndex*/)
	require.NoError(err)
	_, _ = block, mempool
	block, err = miner._mineAndProcessSingleBlock(0 /*threadIndex*/)
	require.NoError(err)
	block, err = miner._mineAndProcessSingleBlock(0 /*threadIndex*/)
	require.NoError(err)
	block, err = miner._mineAndProcessSingleBlock(0 /*threadIndex*/)
	require.NoError(err)

	// Setup some convenience functions for the test.
	txnOps := [][]*UtxoOperation{}
	txns := []*MsgUltranetTxn{}
	expectedSenderBalances := []uint64{}
	expectedRecipientBalances := []uint64{}
	merchantIDs := []*BlockHash{}
	usernames := []string{}
	publicKeys := []string{}
	// We take the block tip to be the blockchain height rather than the
	// header chain height.
	savedHeight := chain.blockTip().Height + 1
	registerOrTransfer := func(username string,
		senderPk string, recipientPk string, senderPriv string) {

		expectedSenderBalances = append(expectedSenderBalances, _getBalance(t, chain, nil, senderPkString))
		expectedRecipientBalances = append(expectedRecipientBalances, _getBalance(t, chain, nil, recipientPkString))
		if recipientPk == "" {
			currentOps, currentTxn, _ := _doRegisterMerchantWithViewFlush(
				t, chain, db, params, username, senderPk, senderPriv, 13 /*feerate*/, 3 /*burn amount*/)
			txnOps = append(txnOps, currentOps)
			txns = append(txns, currentTxn)
		} else {
			currentOps, currentTxn, _ := _doBasicTransferWithViewFlush(
				t, chain, db, params, senderPk, recipientPk,
				senderPriv, 7 /*amount to send*/, 11 /*feerate*/)

			txnOps = append(txnOps, currentOps)
			txns = append(txns, currentTxn)
		}
		// If we have a username then this is assumed to be a register merchant txn.
		// In thi scase add to the merchantids, usernames, and publickeys.
		if username != "" {
			merchantID := txns[len(txns)-1].Hash()
			merchantIDs = append(merchantIDs, merchantID)
			usernames = append(usernames, username)
			publicKeys = append(publicKeys, senderPk)
		}
	}

	placeOrder := func(
		buyerPkBase58Check string, buyerPrivBase58Check string,
		merchantIDBase58Check string,
		amountLockedNanos uint64, buyerMessage string) {

		expectedSenderBalances = append(expectedSenderBalances, _getBalance(t, chain, nil, senderPkString))
		expectedRecipientBalances = append(expectedRecipientBalances, _getBalance(t, chain, nil, recipientPkString))

		currentOps, currentTxn, _, err := _placeOrder(
			t, chain, db, params, 10 /*feeRateNanosPerKB*/, buyerPkBase58Check,
			buyerPrivBase58Check, merchantIDBase58Check, amountLockedNanos, buyerMessage, mempool)
		require.NoError(err)

		txnOps = append(txnOps, currentOps)
		txns = append(txns, currentTxn)
	}

	cancelOrder := func(
		buyerPkBase58Check string, buyerPrivBase58Check string, _orderID *BlockHash, mempool *TxPool) {

		expectedSenderBalances = append(expectedSenderBalances, _getBalance(t, chain, nil, senderPkString))
		expectedRecipientBalances = append(expectedRecipientBalances, _getBalance(t, chain, nil, recipientPkString))

		currentOps, currentTxn, _, err := _cancelOrder(
			t, chain, db, params, 10 /*feeRateNanosPerKB*/, buyerPkBase58Check,
			buyerPrivBase58Check, _orderID, mempool)
		require.NoError(err)

		txnOps = append(txnOps, currentOps)
		txns = append(txns, currentTxn)
	}

	// Register two merchants
	// Merchants
	m0Pub := "tUN2RExHhcCWqXqT9r7syGupJS6hxrBPDQMssSph6ki1FZLJTczUm4"
	m0Priv := "tunSykM1Si6Wab5mRKBDu7YK5ubpBxr1ciGiiDXmSpMATB12sAawx"
	m1Pub := "tUN2RUx1U7By7i2CZn5sZEEb5jjEHfoyc4Nvk2P9gc6Lf8Bc29xzzB"
	m1Priv := "tunSJ83kV4PNkC7MPEgbmKWNZeJk1mTbjwXUh9oy7kyBLRWsgFjVw"
	// Non-merchants
	m2Pub := "tUN2NazDYX2zmbPMXagebSjHmK6QcybHBGRvFMrHDRgn5Us8YPs1De"
	m2Priv := "tunTBiMhRjKVmeK6bF8kJFQpmxH2UnTweB8zYsvH3bJPjyVMZr5kS"
	m3Pub := "tUN2Q3nYf8KNgZ5q3ftFeEq3fRFpB8CCzXTW5KV4kGrCm4LEvdv67e"
	m3Priv := "tunSRyKa6shh2S6LH3WsFa6jtT42ktUgVcSdZFqTsMBy3KPnHC9kR"
	// Fund all the keys.
	registerOrTransfer("", senderPkString, m0Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m1Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m1Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m1Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m1Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m1Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m1Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m2Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m3Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m3Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m3Pub, senderPrivString)
	registerOrTransfer("m0", m0Pub, "", m0Priv)
	merchantID0 := txns[len(txns)-1].Hash()
	registerOrTransfer("m1", m1Pub, "", m1Priv)
	merchantID1 := txns[len(txns)-1].Hash()

	_, _, _ = m2Priv, m3Priv, merchantID1

	// Have senderPkString place an order with m0.
	buyerMessage0 := "i want 10 please"
	balBefore0 := _getBalance(t, chain, nil, senderPkString)
	placeOrder(senderPkString, senderPrivString, PkToStringTestnet(merchantID0[:]),
		10, buyerMessage0)
	orderID0 := txns[len(txns)-1].Hash()

	// Balance of user should decrease by at least amountLockedNanos. Balances
	balAfter0 := _getBalance(t, chain, nil, senderPkString)
	require.Greater(balBefore0, balAfter0)
	require.Greater(balBefore0-balAfter0, uint64(10))

	buyerMessage1 := "i want 20 please"
	placeOrder(m1Pub, m1Priv, PkToStringTestnet(merchantID1[:]), 20, buyerMessage1)
	orderID1 := txns[len(txns)-1].Hash()

	balBefore2 := _getBalance(t, chain, nil, senderPkString)
	buyerMessage2 := "i want 17 please"
	placeOrder(senderPkString, senderPrivString, PkToStringTestnet(merchantID0[:]), 17, buyerMessage2)
	orderID2 := txns[len(txns)-1].Hash()
	// Balance of user should decrease by at least amountLockedNanos. Balances
	balAfter2 := _getBalance(t, chain, nil, senderPkString)
	require.Greater(balBefore2, balAfter2)
	require.Greater(balBefore2-balAfter2, uint64(17))

	buyerMessage3 := "i want 7 please"
	placeOrder(m3Pub, m3Priv, PkToStringTestnet(merchantID0[:]), 7, buyerMessage3)
	orderID3 := txns[len(txns)-1].Hash()

	buyerMessage4 := "i want 11 please"
	placeOrder(senderPkString, senderPrivString, PkToStringTestnet(merchantID1[:]), 11, buyerMessage4)
	orderID4 := txns[len(txns)-1].Hash()

	// Do a couple of transfers
	registerOrTransfer("", senderPkString, m1Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m2Pub, senderPrivString)
	registerOrTransfer("", m1Pub, senderPkString, m1Priv)

	// Canceling an order that the user doesn't own should fail.
	{
		err := _unsafeCancelOrder(t, chain, db, params, 10 /*feeRateNanosPerKB*/, senderPkString, senderPrivString, orderID3)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorOnlyBuyerCanCancelOrder)
	}
	// Actually cancel an order
	{
		// Balance should increase by ~11 as a result of the cancelation.
		balBefore4 := _getBalance(t, chain, nil, senderPkString)
		cancelOrder(senderPkString, senderPrivString, orderID4, mempool)
		balAfter4 := _getBalance(t, chain, nil, senderPkString)
		require.Greater(balAfter4, balBefore4)
		require.GreaterOrEqual(balAfter4-balBefore4, uint64(9))

		// Check the entry has been updated.
		canceledEntry := DbGetOrderEntryForOrderID(db, orderID4)
		require.NotNil(canceledEntry)
		require.Equal(OrderStateCanceled, canceledEntry.State)
	}
	// Canceling an order with a bad signature should fail.
	{
		err := _unsafeCancelOrder(
			t, chain, db, params, 0 /*feeRateNanosPerKB*/, senderPkString,
			m0Priv, orderID0)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorInvalidTransactionSignature)
	}
	// Attempting to cancel an already canceled order should error.
	{
		err := _unsafeCancelOrder(
			t, chain, db, params, 0 /*feeRateNanosPerKB*/, senderPkString,
			senderPrivString, orderID4)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorOrderBeingCanceledNotInPlacedState)
	}
	// Cancel another order
	{
		// Balance should increase by ~20 as a result of the cancelation.
		balBefore4 := _getBalance(t, chain, nil, m1Pub)
		cancelOrder(m1Pub, m1Priv, orderID1, mempool)
		balAfter4 := _getBalance(t, chain, nil, m1Pub)
		require.Greater(balAfter4, balBefore4)
		require.GreaterOrEqual(balAfter4-balBefore4, uint64(15))

		// Check the entry has been updated.
		canceledEntry := DbGetOrderEntryForOrderID(db, orderID4)
		require.NotNil(canceledEntry)
		require.Equal(OrderStateCanceled, canceledEntry.State)
	}

	// Do a couple of transfers
	registerOrTransfer("", senderPkString, m1Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m2Pub, senderPrivString)
	registerOrTransfer("", m1Pub, senderPkString, m1Priv)

	// Verify that the proper db mappings exist.
	_checkAllOrders := func() {
		// <OrderID -> OrderEntry> mapping.
		// _PrefixOrderIDToOrderEntry
		orderEntries, err := DbGetAllOrderEntries(db)
		require.NoError(err)
		require.Equal(5, len(orderEntries))

		// To get a consistent ordering, sort the entries on their amount locked, which is
		// unique to each order.
		sort.Slice(orderEntries, func(ii, jj int) bool {
			return strings.Compare(string(orderEntries[ii].BuyerMessage), string(orderEntries[jj].BuyerMessage)) < 0
		})
		// order4 with amountLockedNanos=0
		{
			currentEntry := orderEntries[1]
			pk := senderPkString
			amountNanos := 0
			orderID := orderID4
			message := buyerMessage4
			merchantID := merchantID1
			require.Equal(orderID, currentEntry.orderID)
			require.Equal(uint64(amountNanos), currentEntry.AmountLockedNanos)
			require.Equal(pk, PkToStringTestnet(currentEntry.BuyerPk))
			require.Equal(merchantID, currentEntry.MerchantID)
			require.Equal(big.NewInt(0), currentEntry.MerchantScoreImpact)
			require.Less(currentEntry.Pos, uint64(5))
			require.Equal(OrderStateCanceled, currentEntry.State)
			require.Equal(message, string(currentEntry.BuyerMessage))
			require.Equal(uint32(0), currentEntry.ConfirmationBlockHeight)
			require.Equal(uint32(savedHeight), currentEntry.LastModifiedBlock)
		}
		// order1 with amountLockedNanos=0
		{
			currentEntry := orderEntries[3]
			pk := m1Pub
			amountNanos := 0
			orderID := orderID1
			message := buyerMessage1
			merchantID := merchantID1
			require.Equal(orderID, currentEntry.orderID)
			require.Equal(uint64(amountNanos), currentEntry.AmountLockedNanos)
			require.Equal(pk, PkToStringTestnet(currentEntry.BuyerPk))
			require.Equal(merchantID, currentEntry.MerchantID)
			require.Equal(big.NewInt(0), currentEntry.MerchantScoreImpact)
			require.Less(currentEntry.Pos, uint64(5))
			require.Equal(OrderStateCanceled, currentEntry.State)
			require.Equal(message, string(currentEntry.BuyerMessage))
			require.Equal(uint32(0), currentEntry.ConfirmationBlockHeight)
			require.Equal(uint32(savedHeight), currentEntry.LastModifiedBlock)

			lastModifiedHeightsForBuyer, orderIDsForBuyer, orderEntriesForBuyer, err := DbGetOrdersForBuyerPublicKey(
				db, mustBase58CheckDecode(m1Pub), true /*fetchEntries*/)
			require.NoError(err)
			require.Equal(1, len(lastModifiedHeightsForBuyer))
			require.Equal(1, len(orderIDsForBuyer))
			require.Equal(1, len(orderEntriesForBuyer))
			require.Equal([]uint32{5}, lastModifiedHeightsForBuyer)
			require.Equal([]*BlockHash{orderID1}, orderIDsForBuyer)
			require.Equal([]*OrderEntry{currentEntry}, orderEntriesForBuyer)
		}
		// order3 with amountLockedNanos = 7
		{
			currentEntry := orderEntries[4]
			require.Equal(orderID3, currentEntry.orderID)
			require.Equal(uint64(7), currentEntry.AmountLockedNanos)
			require.Equal(m3Pub, PkToStringTestnet(currentEntry.BuyerPk))
			require.Equal(merchantID0, currentEntry.MerchantID)
			require.Equal(big.NewInt(0), currentEntry.MerchantScoreImpact)
			require.Less(currentEntry.Pos, uint64(5))
			require.Equal(OrderStatePlaced, currentEntry.State)
			require.Equal(buyerMessage3, string(currentEntry.BuyerMessage))
			require.Equal(uint32(0), currentEntry.ConfirmationBlockHeight)
			require.Equal(uint32(savedHeight), currentEntry.LastModifiedBlock)

			// Get the OrderIDs for the BuyerPk and check them.
			// <pk || lastModified || orderID>
			lastModifiedHeightsForBuyer, orderIDsForBuyer, orderEntriesForBuyer, err := DbGetOrdersForBuyerPublicKey(
				db, mustBase58CheckDecode(m3Pub), true /*fetchEntries*/)
			require.NoError(err)
			require.Equal(1, len(lastModifiedHeightsForBuyer))
			require.Equal(1, len(orderIDsForBuyer))
			require.Equal(1, len(orderEntriesForBuyer))
			require.Equal([]uint32{5}, lastModifiedHeightsForBuyer)
			require.Equal([]*BlockHash{orderID3}, orderIDsForBuyer)
			require.Equal([]*OrderEntry{currentEntry}, orderEntriesForBuyer)
		}
		// order0 with amountLockedNanos=10
		{
			currentEntry := orderEntries[0]
			pk := senderPkString
			amountNanos := 10
			orderID := orderID0
			message := buyerMessage0
			merchantID := merchantID0
			require.Equal(orderID, currentEntry.orderID)
			require.Equal(uint64(amountNanos), currentEntry.AmountLockedNanos)
			require.Equal(pk, PkToStringTestnet(currentEntry.BuyerPk))
			require.Equal(merchantID, currentEntry.MerchantID)
			require.Equal(big.NewInt(0), currentEntry.MerchantScoreImpact)
			require.Less(currentEntry.Pos, uint64(5))
			require.Equal(OrderStatePlaced, currentEntry.State)
			require.Equal(message, string(currentEntry.BuyerMessage))
			require.Equal(uint32(0), currentEntry.ConfirmationBlockHeight)
			require.Equal(uint32(savedHeight), currentEntry.LastModifiedBlock)

			// Get the OrderIDs for the BuyerPk and check them.
			// <pk || lastModified || orderID>
			lastModifiedHeightsForBuyer, orderIDsForBuyer, orderEntriesForBuyer, err := DbGetOrdersForBuyerPublicKey(
				db, mustBase58CheckDecode(pk), true /*fetchEntries*/)
			require.NoError(err)
			require.Equal(3, len(lastModifiedHeightsForBuyer))
			require.Equal(3, len(orderIDsForBuyer))
			require.Equal(3, len(orderEntriesForBuyer))
			require.Equal([]uint32{5, 5, 5}, lastModifiedHeightsForBuyer)
			sort.Slice(orderEntriesForBuyer, func(ii, jj int) bool {
				return strings.Compare(string(orderEntriesForBuyer[ii].BuyerMessage), string(orderEntriesForBuyer[jj].BuyerMessage)) < 0
			})
			existingEntries := []*OrderEntry{orderEntries[0], orderEntries[1], orderEntries[2]}
			require.Equal(existingEntries, orderEntriesForBuyer)
		}
		// order2 with amountLockedNanos=17
		{
			currentEntry := orderEntries[2]
			pk := senderPkString
			amountNanos := 17
			orderID := orderID2
			message := buyerMessage2
			merchantID := merchantID0
			require.Equal(orderID, currentEntry.orderID)
			require.Equal(uint64(amountNanos), currentEntry.AmountLockedNanos)
			require.Equal(pk, PkToStringTestnet(currentEntry.BuyerPk))
			require.Equal(merchantID, currentEntry.MerchantID)
			require.Equal(big.NewInt(0), currentEntry.MerchantScoreImpact)
			require.Less(currentEntry.Pos, uint64(5))
			require.Equal(OrderStatePlaced, currentEntry.State)
			require.Equal(message, string(currentEntry.BuyerMessage))
			require.Equal(uint32(0), currentEntry.ConfirmationBlockHeight)
			require.Equal(uint32(savedHeight), currentEntry.LastModifiedBlock)
		}

		// GetNumOrderEntriesWithTxn
		require.Equal(uint64(5), GetNumOrderEntries(db))

		// <pos -> OrderID>
		positionBytes, orderIDPositionBytes := _enumerateKeysForPrefix(db, _PrefixPosToOrderID)
		positionMap := make(map[uint64]*BlockHash)
		for ii := range positionBytes {
			pb := positionBytes[ii]
			oid := orderIDPositionBytes[ii]
			oidHash := BlockHash{}
			copy(oidHash[:], oid)

			positionMap[_DecodeUint64(pb[1:])] = &oidHash
		}
		require.Equal(5, len(positionMap))
		for _, orderEntry := range orderEntries {
			require.Contains(positionMap, orderEntry.Pos)
			oid, exists := positionMap[orderEntry.Pos]
			require.True(exists)
			require.Equal(oid, orderEntry.orderID)
		}

		// Get the OrderIDs for the MerchantID and check them.
		// <merchantID || lastModified || orderID>
		// There are two merchants. merchantID0 and merchantID1
		// Verify merchantID0
		lastModifiedHeightsForMerchant0, orderIDsForMerchant0, orderEntriesForMerchant0, err :=
			DbGetOrdersForMerchantID(db, merchantID0, true /*fetchEntries*/)
		require.NoError(err)
		require.Equal(3, len(orderIDsForMerchant0))
		require.Equal([]uint32{5, 5, 5}, lastModifiedHeightsForMerchant0)
		// Sort these orderEntries just like above to have consistency.
		sort.Slice(orderEntriesForMerchant0, func(ii, jj int) bool {
			return orderEntriesForMerchant0[ii].AmountLockedNanos < orderEntriesForMerchant0[jj].AmountLockedNanos
		})
		require.Equal([]*OrderEntry{orderEntries[4], orderEntries[0], orderEntries[2]}, orderEntriesForMerchant0)

		// Verify merchantID1
		lastModifiedHeightsForMerchant1, orderIDsForMerchant1, orderEntriesForMerchant1, err :=
			DbGetOrdersForMerchantID(db, merchantID1, true /*fetchEntries*/)
		require.NoError(err)
		require.Equal(2, len(orderIDsForMerchant1))
		require.Equal([]uint32{5, 5}, lastModifiedHeightsForMerchant1)
		// Sort these orderEntries just like above to have consistency.
		sort.Slice(orderEntriesForMerchant1, func(ii, jj int) bool {
			return orderEntriesForMerchant1[ii].AmountLockedNanos < orderEntriesForMerchant1[jj].AmountLockedNanos
		})
		require.Contains(orderEntriesForMerchant1, orderEntries[1])
		require.Contains(orderEntriesForMerchant1, orderEntries[3])

		// The merchants should have some PaymentPlacedNanos set.
		{
			me0 := DbGetMerchantEntryForMerchantID(db, merchantID0)
			require.Equal(uint64(34), me0.Stats.PaymentPlacedNanos)
			require.Equal(uint64(0), me0.Stats.PaymentCanceledNanos)
		}
		{
			me1 := DbGetMerchantEntryForMerchantID(db, merchantID1)
			require.Equal(uint64(0), me1.Stats.PaymentPlacedNanos)
			require.Equal(uint64(31), me1.Stats.PaymentCanceledNanos)
		}
	}
	_checkAllOrders()

	// Roll back all of the above using the utxoOps from each.
	for ii := 0; ii < len(txnOps); ii++ {
		backwardIter := len(txnOps) - 1 - ii
		currentOps := txnOps[backwardIter]
		currentTxn := txns[backwardIter]
		fmt.Printf("Disconnecting transaction with type %v index %d (going backwards)\n", currentTxn.TxnMeta.GetTxnType(), backwardIter)

		if backwardIter == 20 {
			{
				me0 := DbGetMerchantEntryForMerchantID(db, merchantID0)
				require.Equal(uint64(34), me0.Stats.PaymentPlacedNanos)
				require.Equal(uint64(0), me0.Stats.PaymentCanceledNanos)
			}
			{
				me1 := DbGetMerchantEntryForMerchantID(db, merchantID1)
				require.Equal(uint64(31), me1.Stats.PaymentPlacedNanos)
				require.Equal(uint64(0), me1.Stats.PaymentCanceledNanos)
			}
		}
		if backwardIter == 12 {
			{
				me0 := DbGetMerchantEntryForMerchantID(db, merchantID0)
				require.Equal(uint64(0), me0.Stats.PaymentPlacedNanos)
				require.Equal(uint64(0), me0.Stats.PaymentCanceledNanos)
			}
			{
				me1 := DbGetMerchantEntryForMerchantID(db, merchantID1)
				require.Equal(uint64(0), me1.Stats.PaymentPlacedNanos)
				require.Equal(uint64(0), me1.Stats.PaymentCanceledNanos)
			}
		}

		utxoView, err := NewUtxoView(db, params, nil)
		require.NoError(err)

		currentHash := currentTxn.Hash()
		err = utxoView.DisconnectTransaction(currentTxn, currentHash, currentOps, savedHeight)
		require.NoError(err)

		require.NoError(utxoView.FlushToDb())

		// After disconnecting, the balances should be restored to what they
		// were before this transaction was applied.
		require.Equal(expectedSenderBalances[backwardIter], _getBalance(t, chain, nil, senderPkString))
		require.Equal(expectedRecipientBalances[backwardIter], _getBalance(t, chain, nil, recipientPkString))
	}

	// Verify all the mappings are now gone from the db.
	{
		merchantIDs, _ := _enumerateKeysForPrefix(db, _PrefixMerchantIDOrderIndex)
		require.Equal(0, len(merchantIDs))
		merchantIDs, _ = _enumerateKeysForPrefix(db, _PrefixBuyerPubKeyOrderIndex)
		require.Equal(0, len(merchantIDs))

		// Get the OrderIDs for the BuyerPk and check them.
		// <pk || lastModified || orderID>
		lastModifiedHeightsForBuyer, orderIDsForBuyer, orderEntriesForBuyer, err := DbGetOrdersForBuyerPublicKey(
			db, senderPkBytes, true /*fetchEntries*/)
		require.NoError(err)
		require.Equal(0, len(lastModifiedHeightsForBuyer))
		require.Equal(0, len(orderIDsForBuyer))
		require.Equal(0, len(orderEntriesForBuyer))

		// Get the OrderIDs for the MerchantID and check them.
		// <merchantID || lastModified || orderID>
		lastModifiedHeightsForMerchant, orderIDsForMerchant, orderEntriesForMerchant, err := DbGetOrdersForMerchantID(
			db, merchantID0, true /*fetchEntries*/)
		require.NoError(err)
		require.Equal(0, len(lastModifiedHeightsForMerchant))
		require.Equal(0, len(orderIDsForMerchant))
		require.Equal(0, len(orderEntriesForMerchant))

		// <pos -> OrderID>
		positions, orderIDPositions := _enumerateKeysForPrefix(db, _PrefixPosToOrderID)
		require.Equal(0, len(positions))
		require.Equal(0, len(orderIDPositions))

		// GetNumOrderEntriesWithTxn
		require.Equal(uint64(0), GetNumOrderEntries(db))
	}

	// Apply all the transactions to a mempool object and make sure we don't get any
	// errors. Verify the balances align as we go.
	for ii, tx := range txns {
		// See comment above on this transaction.
		fmt.Printf("Adding txn %d of type %v to mempool\n", ii, tx.TxnMeta.GetTxnType())

		require.Equal(expectedSenderBalances[ii], _getBalance(t, chain, mempool, senderPkString))
		require.Equal(expectedRecipientBalances[ii], _getBalance(t, chain, mempool, recipientPkString))

		_, err := mempool.ProcessTransaction(tx, false, false, 0, true)
		require.NoError(err, "Problem adding transaction %d to mempool: %v", ii, tx)
	}

	// Apply all the transactions to a view and flush the view to the db.
	utxoView, err := NewUtxoView(db, params, nil)
	require.NoError(err)
	for ii, txn := range txns {
		fmt.Printf("Adding txn %v of type %v to UtxoView\n", ii, txn.TxnMeta.GetTxnType())

		// Always use height+1 for validation since it's assumed the transaction will
		// get mined into the next block.
		txHash := txn.Hash()
		blockHeight := chain.blockTip().Height + 1
		_, _, _, _, err :=
			utxoView.ConnectTransaction(txn, txHash, blockHeight, true /*verifySignature*/, true /*verifyMerchantMerkleRoot*/)
		require.NoError(err)
	}
	// Flush the utxoView after having added all the transactions.
	require.NoError(utxoView.FlushToDb())

	// Check that the state of the db after the flush is the same as when we added each
	// transaction individually.
	_checkAllOrders()

	// Disonnect the transactions from a single view in the same way as above
	// i.e. without flushing each time.
	utxoView2, err := NewUtxoView(db, params, nil)
	require.NoError(err)
	for ii := 0; ii < len(txnOps); ii++ {
		backwardIter := len(txnOps) - 1 - ii
		fmt.Printf("Disconnecting transaction with index %d (going backwards)\n", backwardIter)
		currentOps := txnOps[backwardIter]
		currentTxn := txns[backwardIter]

		if backwardIter == 20 {
			{
				me0 := utxoView2._getMerchantEntryForMerchantID(merchantID0)
				require.Equal(uint64(34), me0.Stats.PaymentPlacedNanos)
				require.Equal(uint64(0), me0.Stats.PaymentCanceledNanos)
			}
			{
				me1 := utxoView2._getMerchantEntryForMerchantID(merchantID1)
				require.Equal(uint64(31), me1.Stats.PaymentPlacedNanos)
				require.Equal(uint64(0), me1.Stats.PaymentCanceledNanos)
			}
		}
		if backwardIter == 12 {
			{
				me0 := utxoView2._getMerchantEntryForMerchantID(merchantID0)
				require.Equal(uint64(0), me0.Stats.PaymentPlacedNanos)
				require.Equal(uint64(0), me0.Stats.PaymentCanceledNanos)
			}
			{
				me1 := utxoView2._getMerchantEntryForMerchantID(merchantID1)
				require.Equal(uint64(0), me1.Stats.PaymentPlacedNanos)
				require.Equal(uint64(0), me1.Stats.PaymentCanceledNanos)
			}
		}

		currentHash := currentTxn.Hash()
		err = utxoView2.DisconnectTransaction(currentTxn, currentHash, currentOps, savedHeight)
		require.NoError(err)
	}
	require.NoError(utxoView2.FlushToDb())
	require.Equal(expectedSenderBalances[0], _getBalance(t, chain, nil, senderPkString))
	require.Equal(expectedRecipientBalances[0], _getBalance(t, chain, nil, recipientPkString))

	// Verify all the mappings are now gone from the db.
	{
		merchantIDs, _ := _enumerateKeysForPrefix(db, _PrefixMerchantIDOrderIndex)
		require.Equal(0, len(merchantIDs))
		merchantIDs, _ = _enumerateKeysForPrefix(db, _PrefixBuyerPubKeyOrderIndex)
		require.Equal(0, len(merchantIDs))

		// Get the OrderIDs for the BuyerPk and check them.
		// <pk || lastModified || orderID>
		lastModifiedHeightsForBuyer, orderIDsForBuyer, orderEntriesForBuyer, err := DbGetOrdersForBuyerPublicKey(
			db, senderPkBytes, true /*fetchEntries*/)
		require.NoError(err)
		require.Equal(0, len(lastModifiedHeightsForBuyer))
		require.Equal(0, len(orderIDsForBuyer))
		require.Equal(0, len(orderEntriesForBuyer))

		// Get the OrderIDs for the MerchantID and check them.
		// <merchantID || lastModified || orderID>
		lastModifiedHeightsForMerchant, orderIDsForMerchant, orderEntriesForMerchant, err := DbGetOrdersForMerchantID(
			db, merchantID0, true /*fetchEntries*/)
		require.NoError(err)
		require.Equal(0, len(lastModifiedHeightsForMerchant))
		require.Equal(0, len(orderIDsForMerchant))
		require.Equal(0, len(orderEntriesForMerchant))

		// <pos -> OrderID>
		positions, orderIDPositions := _enumerateKeysForPrefix(db, _PrefixPosToOrderID)
		require.Equal(0, len(positions))
		require.Equal(0, len(orderIDPositions))

		// GetNumOrderEntriesWithTxn
		require.Equal(uint64(0), GetNumOrderEntries(db))
	}
}

func TestPlaceRejectConfirmOrderAndPrivateMessageToo(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	chain, params, db := NewLowDifficultyBlockchain()
	mempool, miner := NewTestMiner(t, chain, params, true /*isSender*/)

	// Set the listing-related params to low values so we can test hitting
	// them.
	params.MaxMerchantsToIndex = 4
	params.MaxListingsPerMerchant = 5
	params.MaxMerchantStorageBytes = 15000 // 15KB
	params.MaxListingSizeBytes = 10000     // 10KB
	params.MaxListingTitleLengthBytes = 100
	params.MaxListingBodyLengthBytes = 100
	params.MaxListingCategoryLengthBytes = 100
	params.CommissionBasisPoints = 2000
	oldTimeBeforeFulfilled := params.TimeBeforeOrderFulfilled
	params.TimeBeforeOrderFulfilled = 0
	senderPkBytes := mustBase58CheckDecode(senderPkString)
	MaxTransactionDependenciesToProcess = 100
	// Score multiplier doubles every 2 blocks.
	params.MerchantScoreHalfLife = params.TimeBetweenBlocks * 2

	// Mine a few blocks to give the senderPkString some money.
	block, err := miner._mineAndProcessSingleBlock(0 /*threadIndex*/)
	require.NoError(err)
	_, _ = block, mempool
	block, err = miner._mineAndProcessSingleBlock(0 /*threadIndex*/)
	require.NoError(err)
	block, err = miner._mineAndProcessSingleBlock(0 /*threadIndex*/)
	require.NoError(err)
	block, err = miner._mineAndProcessSingleBlock(0 /*threadIndex*/)
	require.NoError(err)

	// Setup some convenience functions for the test.
	txnOps := [][]*UtxoOperation{}
	txns := []*MsgUltranetTxn{}
	expectedSenderBalances := []uint64{}
	expectedRecipientBalances := []uint64{}
	merchantIDs := []*BlockHash{}
	usernames := []string{}
	publicKeys := []string{}
	// We take the block tip to be the blockchain height rather than the
	// header chain height.
	savedHeight := chain.blockTip().Height + 1
	registerOrTransfer := func(username string,
		senderPk string, recipientPk string, senderPriv string) {

		expectedSenderBalances = append(expectedSenderBalances, _getBalance(t, chain, nil, senderPkString))
		expectedRecipientBalances = append(expectedRecipientBalances, _getBalance(t, chain, nil, recipientPkString))
		if recipientPk == "" {
			currentOps, currentTxn, _ := _doRegisterMerchantWithViewFlush(
				t, chain, db, params, username, senderPk, senderPriv, 13 /*feerate*/, 3 /*burn amount*/)
			txnOps = append(txnOps, currentOps)
			txns = append(txns, currentTxn)
		} else {
			currentOps, currentTxn, _ := _doBasicTransferWithViewFlush(
				t, chain, db, params, senderPk, recipientPk,
				senderPriv, 7 /*amount to send*/, 11 /*feerate*/)

			txnOps = append(txnOps, currentOps)
			txns = append(txns, currentTxn)
		}
		// If we have a username then this is assumed to be a register merchant txn.
		// In thi scase add to the merchantids, usernames, and publickeys.
		if username != "" {
			merchantID := txns[len(txns)-1].Hash()
			merchantIDs = append(merchantIDs, merchantID)
			usernames = append(usernames, username)
			publicKeys = append(publicKeys, senderPk)
		}
	}

	placeOrder := func(
		buyerPkBase58Check string, buyerPrivBase58Check string,
		merchantIDBase58Check string,
		amountLockedNanos uint64, buyerMessage string) {

		expectedSenderBalances = append(expectedSenderBalances, _getBalance(t, chain, nil, senderPkString))
		expectedRecipientBalances = append(expectedRecipientBalances, _getBalance(t, chain, nil, recipientPkString))

		currentOps, currentTxn, _, err := _placeOrder(
			t, chain, db, params, 10 /*feeRateNanosPerKB*/, buyerPkBase58Check,
			buyerPrivBase58Check, merchantIDBase58Check, amountLockedNanos, buyerMessage, mempool)
		require.NoError(err)

		txnOps = append(txnOps, currentOps)
		txns = append(txns, currentTxn)
	}

	cancelOrder := func(
		buyerPkBase58Check string, buyerPrivBase58Check string, _orderID *BlockHash) {

		expectedSenderBalances = append(expectedSenderBalances, _getBalance(t, chain, nil, senderPkString))
		expectedRecipientBalances = append(expectedRecipientBalances, _getBalance(t, chain, nil, recipientPkString))

		currentOps, currentTxn, _, err := _cancelOrder(
			t, chain, db, params, 10 /*feeRateNanosPerKB*/, buyerPkBase58Check,
			buyerPrivBase58Check, _orderID, mempool)
		require.NoError(err)

		txnOps = append(txnOps, currentOps)
		txns = append(txns, currentTxn)
	}

	rejectOrder := func(
		merchantPkBase58Check string, merchantPrivBase58Check string, rejectReason string, _orderID *BlockHash) {

		expectedSenderBalances = append(expectedSenderBalances, _getBalance(t, chain, nil, senderPkString))
		expectedRecipientBalances = append(expectedRecipientBalances, _getBalance(t, chain, nil, recipientPkString))

		currentOps, currentTxn, _, err := _rejectOrder(
			t, chain, db, params, 10 /*feeRateNanosPerKB*/, merchantPkBase58Check,
			merchantPrivBase58Check, rejectReason, _orderID)
		require.NoError(err)

		txnOps = append(txnOps, currentOps)
		txns = append(txns, currentTxn)
	}
	_ = rejectOrder

	confirmOrder := func(
		merchantPkBase58Check string, merchantPrivBase58Check string, _orderID *BlockHash) {

		expectedSenderBalances = append(expectedSenderBalances, _getBalance(t, chain, nil, senderPkString))
		expectedRecipientBalances = append(expectedRecipientBalances, _getBalance(t, chain, nil, recipientPkString))

		currentOps, currentTxn, _, err := _confirmOrder(
			t, chain, db, params, 10 /*feeRateNanosPerKB*/, merchantPkBase58Check,
			merchantPrivBase58Check, _orderID)
		require.NoError(err)

		txnOps = append(txnOps, currentOps)
		txns = append(txns, currentTxn)
	}
	_ = confirmOrder

	reviewOrder := func(
		buyerPkBase58Check string, buyerPrivBase58Check string, _orderID *BlockHash,
		reviewType ReviewType, reviewText string) {

		expectedSenderBalances = append(expectedSenderBalances, _getBalance(t, chain, nil, senderPkString))
		expectedRecipientBalances = append(expectedRecipientBalances, _getBalance(t, chain, nil, recipientPkString))

		currentOps, currentTxn, _, err := _reviewOrder(
			t, chain, db, params, 10 /*feeRateNanosPerKB*/, buyerPkBase58Check,
			buyerPrivBase58Check, _orderID, reviewType, reviewText)
		require.NoError(err)

		txnOps = append(txnOps, currentOps)
		txns = append(txns, currentTxn)
	}
	_ = reviewOrder

	fulfillOrder := func(
		merchantPkBase58Check string, merchantPrivBase58Check string, _orderID *BlockHash) {

		expectedSenderBalances = append(expectedSenderBalances, _getBalance(t, chain, nil, senderPkString))
		expectedRecipientBalances = append(expectedRecipientBalances, _getBalance(t, chain, nil, recipientPkString))

		currentOps, currentTxn, _, err := _fulfillOrder(
			t, chain, db, params, 10 /*feeRateNanosPerKB*/, merchantPkBase58Check,
			merchantPrivBase58Check, _orderID)

		require.NoError(err)

		txnOps = append(txnOps, currentOps)
		txns = append(txns, currentTxn)
	}
	_ = fulfillOrder

	refundOrder := func(
		merchantPkBase58Check string, buyerPkBase58Check, merchantPrivBase58Check string, _orderID *BlockHash) {

		expectedSenderBalances = append(expectedSenderBalances, _getBalance(t, chain, nil, senderPkString))
		expectedRecipientBalances = append(expectedRecipientBalances, _getBalance(t, chain, nil, recipientPkString))

		currentOps, currentTxn, _, err := _refundOrder(
			t, chain, db, params, 10 /*feeRateNanosPerKB*/, merchantPkBase58Check,
			buyerPkBase58Check, merchantPrivBase58Check, _orderID)
		require.NoError(err)

		txnOps = append(txnOps, currentOps)
		txns = append(txns, currentTxn)
	}
	_ = refundOrder

	privateMessage := func(
		senderPkBase58Check string, recipientPkBase58Check string,
		senderPrivBase58Check string, unencryptedMessageText string, tstampNanos uint64,
		feeRateNanosPerKB uint64) {

		expectedSenderBalances = append(expectedSenderBalances, _getBalance(t, chain, nil, senderPkString))
		expectedRecipientBalances = append(expectedRecipientBalances, _getBalance(t, chain, nil, recipientPkString))

		currentOps, currentTxn, _, err := _privateMessage(
			t, chain, db, params, feeRateNanosPerKB, senderPkBase58Check,
			recipientPkBase58Check, senderPrivBase58Check, unencryptedMessageText, tstampNanos)
		require.NoError(err)

		txnOps = append(txnOps, currentOps)
		txns = append(txns, currentTxn)
	}
	_ = privateMessage

	// Register two merchants
	// Merchants
	m0Pub := "tUN2RExHhcCWqXqT9r7syGupJS6hxrBPDQMssSph6ki1FZLJTczUm4"
	m0Priv := "tunSykM1Si6Wab5mRKBDu7YK5ubpBxr1ciGiiDXmSpMATB12sAawx"
	m1Pub := "tUN2RUx1U7By7i2CZn5sZEEb5jjEHfoyc4Nvk2P9gc6Lf8Bc29xzzB"
	m1Priv := "tunSJ83kV4PNkC7MPEgbmKWNZeJk1mTbjwXUh9oy7kyBLRWsgFjVw"
	// Non-merchants
	m2Pub := "tUN2NazDYX2zmbPMXagebSjHmK6QcybHBGRvFMrHDRgn5Us8YPs1De"
	m2Priv := "tunTBiMhRjKVmeK6bF8kJFQpmxH2UnTweB8zYsvH3bJPjyVMZr5kS"
	m3Pub := "tUN2Q3nYf8KNgZ5q3ftFeEq3fRFpB8CCzXTW5KV4kGrCm4LEvdv67e"
	m3Priv := "tunSRyKa6shh2S6LH3WsFa6jtT42ktUgVcSdZFqTsMBy3KPnHC9kR"
	// Fund all the keys.
	registerOrTransfer("", senderPkString, m0Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m1Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m1Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m1Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m1Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m1Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m1Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m2Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m3Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m3Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m3Pub, senderPrivString)
	registerOrTransfer("m0", m0Pub, "", m0Priv)
	merchantID0 := txns[len(txns)-1].Hash()
	registerOrTransfer("m1", m1Pub, "", m1Priv)
	merchantID1 := txns[len(txns)-1].Hash()
	{
		me1 := DbGetMerchantEntryForMerchantID(db, merchantID1)
		// Burn = 3, multiplier = 6
		multiplier := ComputeImpactMultiple(5,
			uint32(params.MerchantScoreHalfLife/params.TimeBetweenBlocks))
		require.Equal(big.NewInt(3*multiplier.Int64()), me1.Stats.MerchantScore)
	}

	_, _, _ = m2Priv, m3Priv, merchantID1

	// Have senderPkString place an order with m0.
	buyerMessage0 := "i want 10 please"
	balBefore0 := _getBalance(t, chain, nil, senderPkString)
	placeOrder(senderPkString, senderPrivString, PkToStringTestnet(merchantID0[:]),
		10, buyerMessage0)
	orderID0 := txns[len(txns)-1].Hash()

	// Balance of user should decrease by at least amountLockedNanos. Balances
	balAfter0 := _getBalance(t, chain, nil, senderPkString)
	require.Greater(balBefore0, balAfter0)
	require.Greater(balBefore0-balAfter0, uint64(10))

	buyerMessage1 := "i want 20 please"
	placeOrder(m1Pub, m1Priv, PkToStringTestnet(merchantID1[:]), 20, buyerMessage1)
	orderID1 := txns[len(txns)-1].Hash()

	balBefore2 := _getBalance(t, chain, nil, senderPkString)
	buyerMessage2 := "i want 17 please"
	placeOrder(senderPkString, senderPrivString, PkToStringTestnet(merchantID0[:]), 17, buyerMessage2)
	orderID2 := txns[len(txns)-1].Hash()
	// Balance of user should decrease by at least amountLockedNanos. Balances
	balAfter2 := _getBalance(t, chain, nil, senderPkString)
	require.Greater(balBefore2, balAfter2)
	require.Greater(balBefore2-balAfter2, uint64(17))

	buyerMessage3 := "i want 7 please"
	placeOrder(m3Pub, m3Priv, PkToStringTestnet(merchantID0[:]), 7, buyerMessage3)
	orderID3 := txns[len(txns)-1].Hash()

	buyerMessage4 := "i want 11 please"
	placeOrder(senderPkString, senderPrivString, PkToStringTestnet(merchantID1[:]), 11, buyerMessage4)
	orderID4 := txns[len(txns)-1].Hash()

	// Do a couple of transfers
	registerOrTransfer("", senderPkString, m1Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m2Pub, senderPrivString)
	registerOrTransfer("", m1Pub, senderPkString, m1Priv)

	// Canceling an order that the user doesn't own should fail.
	{
		err := _unsafeCancelOrder(t, chain, db, params, 10 /*feeRateNanosPerKB*/, senderPkString, senderPrivString, orderID3)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorOnlyBuyerCanCancelOrder)
	}
	// Actually cancel an order
	{
		// Balance should increase by ~11 as a result of the cancelation.
		balBefore4 := _getBalance(t, chain, nil, senderPkString)
		cancelOrder(senderPkString, senderPrivString, orderID4)
		balAfter4 := _getBalance(t, chain, nil, senderPkString)
		require.Greater(balAfter4, balBefore4)
		require.GreaterOrEqual(balAfter4-balBefore4, uint64(9))

		// Check the entry has been updated.
		canceledEntry := DbGetOrderEntryForOrderID(db, orderID4)
		require.NotNil(canceledEntry)
		require.Equal(OrderStateCanceled, canceledEntry.State)
	}
	// Attempting to cancel an already canceled order should error.
	{
		err := _unsafeCancelOrder(
			t, chain, db, params, 0 /*feeRateNanosPerKB*/, senderPkString,
			senderPrivString, orderID4)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorOrderBeingCanceledNotInPlacedState)
	}
	// Cancel another order
	{
		// Balance should increase by ~20 as a result of the cancelation.
		balBefore4 := _getBalance(t, chain, nil, m1Pub)
		cancelOrder(m1Pub, m1Priv, orderID1)
		balAfter4 := _getBalance(t, chain, nil, m1Pub)
		require.Greater(balAfter4, balBefore4)
		require.GreaterOrEqual(balAfter4-balBefore4, uint64(15))

		// Check the entry has been updated.
		canceledEntry := DbGetOrderEntryForOrderID(db, orderID4)
		require.NotNil(canceledEntry)
		require.Equal(OrderStateCanceled, canceledEntry.State)
	}

	// Do a couple of transfers
	registerOrTransfer("", senderPkString, m1Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m2Pub, senderPrivString)
	registerOrTransfer("", m1Pub, senderPkString, m1Priv)

	// Verify that the proper db mappings exist.
	_checkOrders1 := func() {
		// <OrderID -> OrderEntry> mapping.
		// _PrefixOrderIDToOrderEntry
		orderEntries, err := DbGetAllOrderEntries(db)
		require.NoError(err)
		require.Equal(5, len(orderEntries))

		// To get a consistent ordering, sort the entries on their amount locked, which is
		// unique to each order.
		sort.Slice(orderEntries, func(ii, jj int) bool {
			return strings.Compare(string(orderEntries[ii].BuyerMessage), string(orderEntries[jj].BuyerMessage)) < 0
		})
		// order4 with amountLockedNanos=0
		{
			currentEntry := orderEntries[1]
			pk := senderPkString
			amountNanos := 0
			orderID := orderID4
			message := buyerMessage4
			merchantID := merchantID1
			require.Equal(orderID, currentEntry.orderID)
			require.Equal(uint64(amountNanos), currentEntry.AmountLockedNanos)
			require.Equal(pk, PkToStringTestnet(currentEntry.BuyerPk))
			require.Equal(merchantID, currentEntry.MerchantID)
			require.Equal(big.NewInt(0), currentEntry.MerchantScoreImpact)
			require.Less(currentEntry.Pos, uint64(5))
			require.Equal(OrderStateCanceled, currentEntry.State)
			require.Equal(message, string(currentEntry.BuyerMessage))
			require.Equal(uint32(0), currentEntry.ConfirmationBlockHeight)
			require.Equal(uint32(savedHeight), currentEntry.LastModifiedBlock)
			require.Equal(uint64(11), currentEntry.PaymentAmountNanos)
		}
		// order1 with amountLockedNanos=0
		{
			currentEntry := orderEntries[3]
			pk := m1Pub
			amountNanos := 0
			orderID := orderID1
			message := buyerMessage1
			merchantID := merchantID1
			require.Equal(orderID, currentEntry.orderID)
			require.Equal(uint64(amountNanos), currentEntry.AmountLockedNanos)
			require.Equal(pk, PkToStringTestnet(currentEntry.BuyerPk))
			require.Equal(merchantID, currentEntry.MerchantID)
			require.Equal(big.NewInt(0), currentEntry.MerchantScoreImpact)
			require.Less(currentEntry.Pos, uint64(5))
			require.Equal(OrderStateCanceled, currentEntry.State)
			require.Equal(message, string(currentEntry.BuyerMessage))
			require.Equal(uint32(0), currentEntry.ConfirmationBlockHeight)
			require.Equal(uint32(savedHeight), currentEntry.LastModifiedBlock)
			require.Equal(uint64(20), currentEntry.PaymentAmountNanos)

			lastModifiedHeightsForBuyer, orderIDsForBuyer, orderEntriesForBuyer, err := DbGetOrdersForBuyerPublicKey(
				db, mustBase58CheckDecode(m1Pub), true /*fetchEntries*/)
			require.NoError(err)
			require.Equal(1, len(lastModifiedHeightsForBuyer))
			require.Equal(1, len(orderIDsForBuyer))
			require.Equal(1, len(orderEntriesForBuyer))
			require.Equal([]uint32{5}, lastModifiedHeightsForBuyer)
			require.Equal([]*BlockHash{orderID1}, orderIDsForBuyer)
			require.Equal([]*OrderEntry{currentEntry}, orderEntriesForBuyer)
		}
		// order3 with amountLockedNanos = 7
		{
			currentEntry := orderEntries[4]
			require.Equal(orderID3, currentEntry.orderID)
			require.Equal(uint64(7), currentEntry.AmountLockedNanos)
			require.Equal(m3Pub, PkToStringTestnet(currentEntry.BuyerPk))
			require.Equal(merchantID0, currentEntry.MerchantID)
			require.Equal(big.NewInt(0), currentEntry.MerchantScoreImpact)
			require.Less(currentEntry.Pos, uint64(5))
			require.Equal(OrderStatePlaced, currentEntry.State)
			require.Equal(buyerMessage3, string(currentEntry.BuyerMessage))
			require.Equal(uint32(0), currentEntry.ConfirmationBlockHeight)
			require.Equal(uint32(savedHeight), currentEntry.LastModifiedBlock)
			require.Equal(uint64(7), currentEntry.PaymentAmountNanos)

			// Get the OrderIDs for the BuyerPk and check them.
			// <pk || lastModified || orderID>
			lastModifiedHeightsForBuyer, orderIDsForBuyer, orderEntriesForBuyer, err := DbGetOrdersForBuyerPublicKey(
				db, mustBase58CheckDecode(m3Pub), true /*fetchEntries*/)
			require.NoError(err)
			require.Equal(1, len(lastModifiedHeightsForBuyer))
			require.Equal(1, len(orderIDsForBuyer))
			require.Equal(1, len(orderEntriesForBuyer))
			require.Equal([]uint32{5}, lastModifiedHeightsForBuyer)
			require.Equal([]*BlockHash{orderID3}, orderIDsForBuyer)
			require.Equal([]*OrderEntry{currentEntry}, orderEntriesForBuyer)
		}
		// order0 with amountLockedNanos=10
		{
			currentEntry := orderEntries[0]
			pk := senderPkString
			amountNanos := 10
			orderID := orderID0
			message := buyerMessage0
			merchantID := merchantID0
			require.Equal(orderID, currentEntry.orderID)
			require.Equal(uint64(amountNanos), currentEntry.AmountLockedNanos)
			require.Equal(pk, PkToStringTestnet(currentEntry.BuyerPk))
			require.Equal(merchantID, currentEntry.MerchantID)
			require.Equal(big.NewInt(0), currentEntry.MerchantScoreImpact)
			require.Less(currentEntry.Pos, uint64(5))
			require.Equal(OrderStatePlaced, currentEntry.State)
			require.Equal(message, string(currentEntry.BuyerMessage))
			require.Equal(uint32(0), currentEntry.ConfirmationBlockHeight)
			require.Equal(uint32(savedHeight), currentEntry.LastModifiedBlock)
			require.Equal(uint64(10), currentEntry.PaymentAmountNanos)

			// Get the OrderIDs for the BuyerPk and check them.
			// <pk || lastModified || orderID>
			lastModifiedHeightsForBuyer, orderIDsForBuyer, orderEntriesForBuyer, err := DbGetOrdersForBuyerPublicKey(
				db, mustBase58CheckDecode(pk), true /*fetchEntries*/)
			require.NoError(err)
			require.Equal(3, len(lastModifiedHeightsForBuyer))
			require.Equal(3, len(orderIDsForBuyer))
			require.Equal(3, len(orderEntriesForBuyer))
			require.Equal([]uint32{5, 5, 5}, lastModifiedHeightsForBuyer)
			sort.Slice(orderEntriesForBuyer, func(ii, jj int) bool {
				return strings.Compare(string(orderEntriesForBuyer[ii].BuyerMessage), string(orderEntriesForBuyer[jj].BuyerMessage)) < 0
			})
			existingEntries := []*OrderEntry{orderEntries[0], orderEntries[1], orderEntries[2]}
			require.Equal(existingEntries, orderEntriesForBuyer)
		}
		// order2 with amountLockedNanos=17
		{
			currentEntry := orderEntries[2]
			pk := senderPkString
			amountNanos := 17
			orderID := orderID2
			message := buyerMessage2
			merchantID := merchantID0
			require.Equal(orderID, currentEntry.orderID)
			require.Equal(uint64(amountNanos), currentEntry.AmountLockedNanos)
			require.Equal(pk, PkToStringTestnet(currentEntry.BuyerPk))
			require.Equal(merchantID, currentEntry.MerchantID)
			require.Equal(big.NewInt(0), currentEntry.MerchantScoreImpact)
			require.Less(currentEntry.Pos, uint64(5))
			require.Equal(OrderStatePlaced, currentEntry.State)
			require.Equal(message, string(currentEntry.BuyerMessage))
			require.Equal(uint32(0), currentEntry.ConfirmationBlockHeight)
			require.Equal(uint32(savedHeight), currentEntry.LastModifiedBlock)
			require.Equal(uint64(amountNanos), currentEntry.PaymentAmountNanos)
		}

		// GetNumOrderEntriesWithTxn
		require.Equal(uint64(5), GetNumOrderEntries(db))

		// <pos -> OrderID>
		positionBytes, orderIDPositionBytes := _enumerateKeysForPrefix(db, _PrefixPosToOrderID)
		positionMap := make(map[uint64]*BlockHash)
		for ii := range positionBytes {
			pb := positionBytes[ii]
			oid := orderIDPositionBytes[ii]
			oidHash := BlockHash{}
			copy(oidHash[:], oid)

			positionMap[_DecodeUint64(pb[1:])] = &oidHash
		}
		require.Equal(5, len(positionMap))
		for _, orderEntry := range orderEntries {
			require.Contains(positionMap, orderEntry.Pos)
			oid, exists := positionMap[orderEntry.Pos]
			require.True(exists)
			require.Equal(oid, orderEntry.orderID)
		}

		// Get the OrderIDs for the MerchantID and check them.
		// <merchantID || lastModified || orderID>
		// There are two merchants. merchantID0 and merchantID1
		// Verify merchantID0
		lastModifiedHeightsForMerchant0, orderIDsForMerchant0, orderEntriesForMerchant0, err :=
			DbGetOrdersForMerchantID(db, merchantID0, true /*fetchEntries*/)
		require.NoError(err)
		require.Equal(3, len(orderIDsForMerchant0))
		require.Equal([]uint32{5, 5, 5}, lastModifiedHeightsForMerchant0)
		// Sort these orderEntries just like above to have consistency.
		sort.Slice(orderEntriesForMerchant0, func(ii, jj int) bool {
			return orderEntriesForMerchant0[ii].AmountLockedNanos < orderEntriesForMerchant0[jj].AmountLockedNanos
		})
		require.Equal([]*OrderEntry{orderEntries[4], orderEntries[0], orderEntries[2]}, orderEntriesForMerchant0)

		// Verify merchantID1
		lastModifiedHeightsForMerchant1, orderIDsForMerchant1, orderEntriesForMerchant1, err :=
			DbGetOrdersForMerchantID(db, merchantID1, true /*fetchEntries*/)
		require.NoError(err)
		require.Equal(2, len(orderIDsForMerchant1))
		require.Equal([]uint32{5, 5}, lastModifiedHeightsForMerchant1)
		// Sort these orderEntries just like above to have consistency.
		sort.Slice(orderEntriesForMerchant1, func(ii, jj int) bool {
			return orderEntriesForMerchant1[ii].AmountLockedNanos < orderEntriesForMerchant1[jj].AmountLockedNanos
		})
		require.Contains(orderEntriesForMerchant1, orderEntries[1])
		require.Contains(orderEntriesForMerchant1, orderEntries[3])

		// The merchants should have some PaymentPlacedNanos set.
		{
			me0 := DbGetMerchantEntryForMerchantID(db, merchantID0)
			require.Equal(uint64(34), me0.Stats.PaymentPlacedNanos)
			require.Equal(uint64(0), me0.Stats.PaymentCanceledNanos)
		}
		{
			me1 := DbGetMerchantEntryForMerchantID(db, merchantID1)
			require.Equal(uint64(0), me1.Stats.PaymentPlacedNanos)
			require.Equal(uint64(31), me1.Stats.PaymentCanceledNanos)
			// Burn = 3, multiplier = 6
			multiplier := ComputeImpactMultiple(5,
				uint32(params.MerchantScoreHalfLife/params.TimeBetweenBlocks))
			require.Equal(big.NewInt(3*multiplier.Int64()), me1.Stats.MerchantScore)
		}
	}
	_checkOrders1()

	// ===================================================================================
	// Tests for rejecting orders.
	// ===================================================================================

	// Give merchantID0 some more money
	registerOrTransfer("", senderPkString, m0Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m0Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m0Pub, senderPrivString)

	// Give merchantID1 another order that's not cancelled.
	buyerMessage5 := "i want 19 please"
	placeOrder(m1Pub, m1Priv, PkToStringTestnet(merchantID1[:]), 19, buyerMessage5)
	orderID5 := txns[len(txns)-1].Hash()

	// Have merchantID0 reject an order.
	{
		rejectReason := "rejecting for kicks"
		rejectOrder(m0Pub, m0Priv, rejectReason, orderID0)

		// Dig up the OrderEntry and check that it is now in the rejected state.
		currentEntry := DbGetOrderEntryForOrderID(db, orderID0)
		require.NotNil(currentEntry)
		pk := senderPkString
		amountNanos := 0
		orderID := orderID0
		message := buyerMessage0
		merchantID := merchantID0
		require.Equal(orderID, currentEntry.orderID)
		require.Equal(uint64(amountNanos), currentEntry.AmountLockedNanos)
		require.Equal(pk, PkToStringTestnet(currentEntry.BuyerPk))
		require.Equal(merchantID, currentEntry.MerchantID)
		require.Equal(big.NewInt(0), currentEntry.MerchantScoreImpact)
		require.Less(currentEntry.Pos, uint64(6))
		require.Equal(OrderStateRejected, currentEntry.State)
		require.Equal(message, string(currentEntry.BuyerMessage))
		require.Equal(uint32(0), currentEntry.ConfirmationBlockHeight)
		require.Equal(uint32(savedHeight), currentEntry.LastModifiedBlock)
		require.Equal(rejectReason, string(currentEntry.RejectReason))
		require.Equal(uint64(10), currentEntry.PaymentAmountNanos)

		// Dig up the MerchantEntry and check that the stats have now changed.
		me0 := DbGetMerchantEntryForMerchantID(db, merchantID0)
		require.Equal(uint64(24), me0.Stats.PaymentPlacedNanos)
		require.Equal(uint64(0), me0.Stats.PaymentCanceledNanos)
		require.Equal(uint64(10), me0.Stats.PaymentRejectedNanos)
	}

	// Give merchantID1 another order that's not cancelled.
	buyerMessage6 := "i want 12 please"
	placeOrder(m0Pub, m0Priv, PkToStringTestnet(merchantID1[:]), 12, buyerMessage6)
	orderID6 := txns[len(txns)-1].Hash()

	// Have merchantID0 reject a second order.
	{
		rejectReason := "rejecting for cause"
		rejectOrder(m0Pub, m0Priv, rejectReason, orderID2)
		// Dig up the OrderEntry and check that it is now in the rejected state.
		currentEntry := DbGetOrderEntryForOrderID(db, orderID2)
		require.NotNil(currentEntry)
		pk := senderPkString
		amountNanos := 0
		orderID := orderID2
		message := buyerMessage2
		merchantID := merchantID0
		require.Equal(orderID, currentEntry.orderID)
		require.Equal(uint64(amountNanos), currentEntry.AmountLockedNanos)
		require.Equal(pk, PkToStringTestnet(currentEntry.BuyerPk))
		require.Equal(merchantID, currentEntry.MerchantID)
		require.Equal(big.NewInt(0), currentEntry.MerchantScoreImpact)
		require.Less(currentEntry.Pos, uint64(10))
		require.Equal(OrderStateRejected, currentEntry.State)
		require.Equal(message, string(currentEntry.BuyerMessage))
		require.Equal(uint32(0), currentEntry.ConfirmationBlockHeight)
		require.Equal(uint32(savedHeight), currentEntry.LastModifiedBlock)
		require.Equal(rejectReason, string(currentEntry.RejectReason))
		require.Equal(uint64(17), currentEntry.PaymentAmountNanos)

		// Dig up the MerchantEntry and check that the stats have now changed.
		me0 := DbGetMerchantEntryForMerchantID(db, merchantID0)
		require.Equal(uint64(7), me0.Stats.PaymentPlacedNanos)
		require.Equal(uint64(0), me0.Stats.PaymentCanceledNanos)
		require.Equal(uint64(27), me0.Stats.PaymentRejectedNanos)
	}

	// Give merchantID1 another order that's not cancelled.
	buyerMessage7 := "i want 7 please"
	placeOrder(m2Pub, m2Priv, PkToStringTestnet(merchantID1[:]), 7, buyerMessage7)
	orderID7 := txns[len(txns)-1].Hash()

	// Have merchantID0 reject a second order.
	{
		rejectReason := "rejecting for third reason"
		rejectOrder(m1Pub, m1Priv, rejectReason, orderID5)
		// Dig up the OrderEntry and check that it is now in the rejected state.
		currentEntry := DbGetOrderEntryForOrderID(db, orderID5)
		require.NotNil(currentEntry)
		pk := m1Pub
		amountNanos := 0
		orderID := orderID5
		message := buyerMessage5
		merchantID := merchantID1
		require.Equal(orderID, currentEntry.orderID)
		require.Equal(uint64(amountNanos), currentEntry.AmountLockedNanos)
		require.Equal(pk, PkToStringTestnet(currentEntry.BuyerPk))
		require.Equal(merchantID, currentEntry.MerchantID)
		require.Equal(big.NewInt(0), currentEntry.MerchantScoreImpact)
		require.Less(currentEntry.Pos, uint64(10))
		require.Equal(OrderStateRejected, currentEntry.State)
		require.Equal(message, string(currentEntry.BuyerMessage))
		require.Equal(uint32(0), currentEntry.ConfirmationBlockHeight)
		require.Equal(uint32(savedHeight), currentEntry.LastModifiedBlock)
		require.Equal(rejectReason, string(currentEntry.RejectReason))
		require.Equal(uint64(19), currentEntry.PaymentAmountNanos)

		// Dig up the MerchantEntry and check that the stats have now changed.
		me1 := DbGetMerchantEntryForMerchantID(db, merchantID1)
		require.Equal(uint64(19), me1.Stats.PaymentPlacedNanos)
		require.Equal(uint64(31), me1.Stats.PaymentCanceledNanos)
		require.Equal(uint64(19), me1.Stats.PaymentRejectedNanos)
		// Burn = 3, multiplier = 6
		multiplier := ComputeImpactMultiple(5,
			uint32(params.MerchantScoreHalfLife/params.TimeBetweenBlocks))
		require.Equal(big.NewInt(3*multiplier.Int64()), me1.Stats.MerchantScore)
	}

	// Give merchantID1 another order that's not cancelled from the buyer who
	// was just rejected.
	buyerMessage8 := "i want 8 please"
	placeOrder(m2Pub, m2Priv, PkToStringTestnet(merchantID1[:]), 8, buyerMessage8)
	orderID8 := txns[len(txns)-1].Hash()
	{
		// Dig up the MerchantEntry and check that the stats have now changed.
		me1 := DbGetMerchantEntryForMerchantID(db, merchantID1)
		require.Equal(uint64(27), me1.Stats.PaymentPlacedNanos)
		require.Equal(uint64(31), me1.Stats.PaymentCanceledNanos)
		require.Equal(uint64(19), me1.Stats.PaymentRejectedNanos)
		// Burn = 3, multiplier = 6
		multiplier := ComputeImpactMultiple(5,
			uint32(params.MerchantScoreHalfLife/params.TimeBetweenBlocks))
		require.Equal(big.NewInt(3*multiplier.Int64()), me1.Stats.MerchantScore)
	}

	// Do some basic transfers
	registerOrTransfer("", senderPkString, m0Pub, senderPrivString)
	registerOrTransfer("", m0Pub, m1Pub, m0Priv)
	registerOrTransfer("", m1Pub, m0Pub, m1Priv)

	_, _, _ = orderID6, orderID7, orderID8

	// ===================================================================================
	// Tests for confirming orders.
	// ===================================================================================

	// Give a few users some money.
	registerOrTransfer("", senderPkString, m0Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m0Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m0Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m2Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m2Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m2Pub, senderPrivString)

	// Confirming an order that is cancelled should fail.
	_, _, _, err = _confirmOrder(t, chain, db, params, 10, /*feeRateNanosPerKB*/
		m1Pub, m1Priv, orderID1)
	require.Error(err)
	require.Contains(err.Error(), RuleErrorOrderBeingConfirmedNotInPlacedState)

	// Confirming an order that is rejected should fail.
	_, _, _, err = _confirmOrder(t, chain, db, params, 10, /*feeRateNanosPerKB*/
		m0Pub, m0Priv, orderID2)
	require.Error(err)
	require.Contains(err.Error(), RuleErrorOrderBeingConfirmedNotInPlacedState)

	// Confirming an order with a bad transaction signature should fail.
	_, _, _, err = _confirmOrder(t, chain, db, params, 10, /*feeRateNanosPerKB*/
		m2Pub, m0Priv, orderID8)
	require.Error(err)
	require.Contains(err.Error(), RuleErrorInvalidTransactionSignature)

	// Confirming an order as not the merchant who is responsible for the order
	// should fail.
	_, _, _, err = _confirmOrder(t, chain, db, params, 10, /*feeRateNanosPerKB*/
		m0Pub, m0Priv, orderID8)
	require.Error(err)
	require.Contains(err.Error(), RuleErrorConfirmTransactionMustBeSignedByMerchant)

	// Confirming an order as not the merchant who is responsible for the order
	// should fail.
	_, _, _, err = _confirmOrder(t, chain, db, params, 10, /*feeRateNanosPerKB*/
		m0Pub, m0Priv, orderID8)
	require.Error(err)
	require.Contains(err.Error(), RuleErrorConfirmTransactionMustBeSignedByMerchant)

	// Confirming an order as the merchant responsible for it should work.
	confirmOrder(m1Pub, m1Priv, orderID8)
	{
		// Verify the fields of the order entry.
		currentEntry := DbGetOrderEntryForOrderID(db, orderID8)
		require.NotNil(currentEntry)
		originalPayment := uint64(8)
		commissionNanos, revenueNanos, err := _computeCommissionsAndRevenueFromPayment(
			originalPayment, params.CommissionBasisPoints)
		require.NoError(err)
		pk := m2Pub
		orderID := orderID8
		message := buyerMessage8
		merchantID := merchantID1
		blockHeight := uint32(5)
		require.Equal(orderID, currentEntry.orderID)
		require.Equal(uint64(commissionNanos), currentEntry.AmountLockedNanos)
		require.Equal(pk, PkToStringTestnet(currentEntry.BuyerPk))
		require.Equal(merchantID, currentEntry.MerchantID)
		require.Less(currentEntry.Pos, uint64(10))
		require.Equal(OrderStateConfirmed, currentEntry.State)
		require.Equal(message, string(currentEntry.BuyerMessage))
		require.Equal(uint32(5), currentEntry.ConfirmationBlockHeight)
		require.Equal(uint32(5), currentEntry.LastModifiedBlock)
		require.Equal("", string(currentEntry.RejectReason))
		require.Equal(uint64(originalPayment), currentEntry.PaymentAmountNanos)

		// commissionNanos = +1, revenueNanos = -7, adjustment = -6, multiplier = 6
		multiplier := ComputeImpactMultiple(blockHeight,
			uint32(params.MerchantScoreHalfLife/params.TimeBetweenBlocks))
		adjustment := (int64(commissionNanos) - int64(revenueNanos)) * multiplier.Int64()
		require.Equal(big.NewInt(adjustment), currentEntry.MerchantScoreImpact)

		// Dig up the MerchantEntry and check that the stats have now changed.
		me1 := DbGetMerchantEntryForMerchantID(db, merchantID1)
		require.Equal(uint64(19), me1.Stats.PaymentPlacedNanos)
		require.Equal(uint64(31), me1.Stats.PaymentCanceledNanos)
		require.Equal(uint64(19), me1.Stats.PaymentRejectedNanos)
		require.Equal(uint64(revenueNanos), me1.Stats.RevenueConfirmedNanos)
		require.Equal(uint64(commissionNanos), me1.Stats.CommissionsNanos)
		// budned = 3, adjustment = -6, multiplier = 6
		require.Equal(big.NewInt((3-6)*multiplier.Int64()), me1.Stats.MerchantScore)
	}

	// Also confirm orders 6 and 7.
	confirmOrder(m1Pub, m1Priv, orderID6)
	{
		// Verify the fields of the order entry.
		currentEntry := DbGetOrderEntryForOrderID(db, orderID6)
		require.NotNil(currentEntry)
		originalPayment := uint64(12)
		commissionNanos, revenueNanos, err := _computeCommissionsAndRevenueFromPayment(
			originalPayment, params.CommissionBasisPoints)
		require.NoError(err)
		pk := m0Pub
		orderID := orderID6
		message := buyerMessage6
		merchantID := merchantID1
		blockHeight := uint32(5)
		require.Equal(orderID, currentEntry.orderID)
		require.Equal(uint64(commissionNanos), currentEntry.AmountLockedNanos)
		require.Equal(pk, PkToStringTestnet(currentEntry.BuyerPk))
		require.Equal(merchantID, currentEntry.MerchantID)
		require.Less(currentEntry.Pos, uint64(10))
		require.Equal(OrderStateConfirmed, currentEntry.State)
		require.Equal(message, string(currentEntry.BuyerMessage))
		require.Equal(uint32(5), currentEntry.ConfirmationBlockHeight)
		require.Equal(uint32(5), currentEntry.LastModifiedBlock)
		require.Equal("", string(currentEntry.RejectReason))
		require.Equal(uint64(originalPayment), currentEntry.PaymentAmountNanos)

		// commissionNanos = +1, revenueNanos = -7, adjustment = -6, multiplier = 6
		multiplier := ComputeImpactMultiple(blockHeight,
			uint32(params.MerchantScoreHalfLife/params.TimeBetweenBlocks))
		adjustment := (int64(commissionNanos) - int64(revenueNanos)) * multiplier.Int64()
		require.Equal(big.NewInt(adjustment), currentEntry.MerchantScoreImpact)

		// Dig up the MerchantEntry and check that the stats have now changed.
		me1 := DbGetMerchantEntryForMerchantID(db, merchantID1)
		require.Equal(&MerchantStats{
			LastRejectedOrderHeight:  5,
			LastCanceledOrderHeight:  5,
			LastConfirmedOrderHeight: 5,
			LastPlacedOrderHeight:    5,
			AmountBurnedNanos:        3,
			PaymentPlacedNanos:       7,
			PaymentCanceledNanos:     31,
			PaymentRejectedNanos:     19,
			RevenueConfirmedNanos:    17,
			CommissionsNanos:         3,
			MerchantScore:            big.NewInt(-66),
		}, me1.Stats)
	}
	confirmOrder(m1Pub, m1Priv, orderID7)

	// ===================================================================================
	// Tests for reviewing orders.
	// ===================================================================================

	// Reviewing an order that is cancelled should fail.
	_, _, _, err = _reviewOrder(t, chain, db, params, 10, /*feeRateNanosPerKB*/
		senderPkString, senderPrivString, orderID4, ReviewTypeNegative, "no review")
	require.Error(err)
	require.Contains(err.Error(), RuleErrorReviewingOrderNotInPlacedOrFulfilledOrReviewedState)

	// Reviewing an order that is rejected should fail.
	_, _, _, err = _reviewOrder(t, chain, db, params, 10, /*feeRateNanosPerKB*/
		senderPkString, senderPrivString, orderID2, ReviewTypeNegative, "no review")
	require.Error(err)
	require.Contains(err.Error(), RuleErrorReviewingOrderNotInPlacedOrFulfilledOrReviewedState)

	// Reviewing an order with a bad transaction signature should fail.
	_, _, _, err = _reviewOrder(t, chain, db, params, 10, /*feeRateNanosPerKB*/
		m2Pub, senderPrivString, orderID8, ReviewTypeNegative, "no review")
	require.Error(err)
	require.Contains(err.Error(), RuleErrorInvalidTransactionSignature)

	// Reviewing an order as not the buyer who made the initial purchase
	// should fail.
	_, _, _, err = _reviewOrder(t, chain, db, params, 10, /*feeRateNanosPerKB*/
		senderPkString, senderPrivString, orderID8, ReviewTypeNegative, "no review")
	require.Error(err)
	require.Contains(err.Error(), RuleErrorOnlyBuyerCanReviewOrder)

	// Reviewing a confirmed order should work.
	reviewOrder(
		m2Pub, m2Priv, orderID8, ReviewTypeNegative, "not great")

	// Re-reviewing an already-reviewed order should work.
	reviewOrder(
		m2Pub, m2Priv, orderID8, ReviewTypePositive, "merchant fixed everything")
	{
		// Verify the state of the order.
		orderID := orderID8
		currentEntry := DbGetOrderEntryForOrderID(db, orderID)
		require.NotNil(currentEntry)
		originalPayment := uint64(8)
		commissionNanos, _, err := _computeCommissionsAndRevenueFromPayment(
			originalPayment, params.CommissionBasisPoints)
		require.NoError(err)
		pk := m2Pub
		message := buyerMessage8
		merchantID := merchantID1
		blockHeight := uint32(5)
		require.Equal(orderID, currentEntry.orderID)
		require.Equal(uint64(commissionNanos), currentEntry.AmountLockedNanos)
		require.Equal(pk, PkToStringTestnet(currentEntry.BuyerPk))
		require.Equal(merchantID, currentEntry.MerchantID)
		require.Less(currentEntry.Pos, uint64(10))
		require.Equal(OrderStateReviewed, currentEntry.State)
		require.Equal(message, string(currentEntry.BuyerMessage))
		require.Equal(uint32(blockHeight), currentEntry.ConfirmationBlockHeight)
		require.Equal(uint32(blockHeight), currentEntry.LastModifiedBlock)
		require.Equal("", string(currentEntry.RejectReason))
		require.Equal(uint64(originalPayment), currentEntry.PaymentAmountNanos)
		require.Equal("merchant fixed everything", string(currentEntry.ReviewText))
		require.Equal(ReviewTypePositive, currentEntry.ReviewType)
		// 1 = commissions * 6 = multiplier
		require.Equal(big.NewInt(6), currentEntry.MerchantScoreImpact)
		require.Equal(uint64(1), commissionNanos)

		// Dig up the MerchantEntry and check that the stats have now changed.
		me1 := DbGetMerchantEntryForMerchantID(db, merchantID1)
		require.Equal(&MerchantStats{
			LastRejectedOrderHeight:       blockHeight,
			LastCanceledOrderHeight:       blockHeight,
			LastConfirmedOrderHeight:      blockHeight,
			LastPlacedOrderHeight:         blockHeight,
			LastPositiveReviewOrderHeight: blockHeight,
			LastNegativeReviewOrderHeight: blockHeight,
			AmountBurnedNanos:             3,
			PaymentPlacedNanos:            0,
			PaymentCanceledNanos:          31,
			PaymentRejectedNanos:          19,
			RevenueConfirmedNanos:         16,
			CommissionsNanos:              4,
			RevenuePositiveNanos:          7,
			MerchantScore:                 big.NewInt(-54),
		}, me1.Stats)
	}

	// ===================================================================================
	// Tests for fulfilling orders.
	// ===================================================================================

	// Fulfilling an order that is cancelled should fail.
	_, _, _, err = _fulfillOrder(t, chain, db, params, 10, /*feeRateNanosPerKB*/
		senderPkString, senderPrivString, orderID4)
	require.Error(err)
	require.Contains(err.Error(), RuleErrorFulfillingOrderNotInConfirmedState)

	// Fulfilling an order that is rejected should fail.
	_, _, _, err = _fulfillOrder(t, chain, db, params, 10, /*feeRateNanosPerKB*/
		senderPkString, senderPrivString, orderID2)
	require.Error(err)
	require.Contains(err.Error(), RuleErrorFulfillingOrderNotInConfirmedState)

	// Fulfilling an order with a bad transaction signature should fail.
	_, _, _, err = _fulfillOrder(t, chain, db, params, 10, /*feeRateNanosPerKB*/
		m1Pub, m2Priv, orderID7)
	require.Error(err)
	require.Contains(err.Error(), RuleErrorInvalidTransactionSignature)

	// Fulfilling an order as not the merchant who is responsible for the
	// order should fail.
	_, _, _, err = _fulfillOrder(t, chain, db, params, 10, /*feeRateNanosPerKB*/
		m2Pub, m2Priv, orderID7)
	require.Error(err)
	require.Contains(err.Error(), RuleErrorOnlyMerchantCanFulfillOrder)

	// Fulfilling an order bef0re its time should fail.
	params.TimeBeforeOrderFulfilled = oldTimeBeforeFulfilled
	_, _, _, err = _fulfillOrder(t, chain, db, params, 10, /*feeRateNanosPerKB*/
		m2Pub, m2Priv, orderID7)
	require.Error(err)
	require.Contains(err.Error(), RuleErrorFulfillingOrderTooSoon)
	params.TimeBeforeOrderFulfilled = 0

	// Fulfilling a confirmed order should work and positively impact the score.
	fulfillOrder(m1Pub, m1Priv, orderID7)
	{
		// Verify the state of the order.
		orderID := orderID7
		currentEntry := DbGetOrderEntryForOrderID(db, orderID)
		require.NotNil(currentEntry)
		originalPayment := uint64(7)
		commissionNanos, _, err := _computeCommissionsAndRevenueFromPayment(
			originalPayment, params.CommissionBasisPoints)
		require.NoError(err)
		pk := m2Pub
		message := buyerMessage7
		merchantID := merchantID1
		blockHeight := uint32(5)
		require.Equal(orderID, currentEntry.orderID)
		require.Equal(uint64(commissionNanos), currentEntry.AmountLockedNanos)
		require.Equal(pk, PkToStringTestnet(currentEntry.BuyerPk))
		require.Equal(merchantID, currentEntry.MerchantID)
		require.Less(currentEntry.Pos, uint64(10))
		require.Equal(OrderStateFulfilled, currentEntry.State)
		require.Equal(message, string(currentEntry.BuyerMessage))
		require.Equal(uint32(blockHeight), currentEntry.ConfirmationBlockHeight)
		require.Equal(uint32(blockHeight), currentEntry.LastModifiedBlock)
		require.Equal("", string(currentEntry.RejectReason))
		require.Equal(uint64(originalPayment), currentEntry.PaymentAmountNanos)
		require.Equal("", string(currentEntry.ReviewText))
		// 1 = commissions * 6 = multiplier
		require.Equal(big.NewInt(6), currentEntry.MerchantScoreImpact)
		require.Equal(uint64(1), commissionNanos)

		// Dig up the MerchantEntry and check that the stats have now changed.
		me1 := DbGetMerchantEntryForMerchantID(db, merchantID1)
		require.Equal(&MerchantStats{
			LastRejectedOrderHeight:       blockHeight,
			LastCanceledOrderHeight:       blockHeight,
			LastConfirmedOrderHeight:      blockHeight,
			LastPlacedOrderHeight:         blockHeight,
			LastPositiveReviewOrderHeight: blockHeight,
			LastNegativeReviewOrderHeight: blockHeight,
			LastFulfilledOrderHeight:      blockHeight,
			AmountBurnedNanos:             3,
			PaymentPlacedNanos:            0,
			PaymentCanceledNanos:          31,
			PaymentRejectedNanos:          19,
			RevenueConfirmedNanos:         10,
			RevenueFulfilledNanos:         6,
			CommissionsNanos:              4,
			RevenuePositiveNanos:          7,
			MerchantScore:                 big.NewInt(-18),
		}, me1.Stats)
	}

	// ===================================================================================
	// Tests for refunding orders.
	// ===================================================================================

	// Refunding an order that is cancelled should fail.
	_, _, _, err = _refundOrder(t, chain, db, params, 10, /*feeRateNanosPerKB*/
		m1Pub, senderPkString, m1Priv, orderID4)
	require.Error(err)
	require.Contains(err.Error(), RuleErrorRefundingOrderNotInStateConfirmedOrReviewdOrFulfilled)

	// Refunding an order that is rejected should fail.
	_, _, _, err = _refundOrder(t, chain, db, params, 10, /*feeRateNanosPerKB*/
		m0Pub, senderPkString, m0Priv, orderID2)
	require.Error(err)
	require.Contains(err.Error(), RuleErrorRefundingOrderNotInStateConfirmedOrReviewdOrFulfilled)

	// Refunding an order with a bad transaction signature should fail.
	_, _, _, err = _refundOrder(t, chain, db, params, 10, /*feeRateNanosPerKB*/
		m1Pub, m2Pub, m2Priv, orderID7)
	require.Error(err)
	require.Contains(err.Error(), RuleErrorInvalidTransactionSignature)

	// Refunding an order as not the merchant who is responsible for the
	// order should fail.
	_, _, _, err = _refundOrder(t, chain, db, params, 10, /*feeRateNanosPerKB*/
		m2Pub, m1Pub, m2Priv, orderID7)
	require.Error(err)
	require.Contains(err.Error(), RuleErrorOnlyMerchantCanRefundOrder)

	// Refunding a confirmed order should work.
	refundOrder(m1Pub, m0Pub, m1Priv, orderID6)
	{
		// Verify the order fields. Merchant score should improve.
		orderID := orderID6
		currentEntry := DbGetOrderEntryForOrderID(db, orderID)
		require.NotNil(currentEntry)
		originalPayment := uint64(12)
		commissionNanos, _, err := _computeCommissionsAndRevenueFromPayment(
			originalPayment, params.CommissionBasisPoints)
		require.NoError(err)
		pk := m0Pub
		message := buyerMessage6
		merchantID := merchantID1
		blockHeight := uint32(5)
		require.Equal(orderID, currentEntry.orderID)
		require.Equal(uint64(commissionNanos), currentEntry.AmountLockedNanos)
		require.Equal(pk, PkToStringTestnet(currentEntry.BuyerPk))
		require.Equal(merchantID, currentEntry.MerchantID)
		require.Less(currentEntry.Pos, uint64(10))
		require.Equal(OrderStateRefunded, currentEntry.State)
		require.Equal(message, string(currentEntry.BuyerMessage))
		require.Equal(uint32(blockHeight), currentEntry.ConfirmationBlockHeight)
		require.Equal(uint32(blockHeight), currentEntry.LastModifiedBlock)
		require.Equal("", string(currentEntry.RejectReason))
		require.Equal(uint64(originalPayment), currentEntry.PaymentAmountNanos)
		require.Equal("", string(currentEntry.ReviewText))
		// 2 = commissions * 6 = multiplier
		require.Equal(big.NewInt(0), currentEntry.MerchantScoreImpact)
		require.Equal(uint64(2), commissionNanos)

		// Dig up the MerchantEntry and check that the stats have now changed.
		me1 := DbGetMerchantEntryForMerchantID(db, merchantID1)
		require.Equal(&MerchantStats{
			LastRejectedOrderHeight:       blockHeight,
			LastCanceledOrderHeight:       blockHeight,
			LastConfirmedOrderHeight:      blockHeight,
			LastPlacedOrderHeight:         blockHeight,
			LastPositiveReviewOrderHeight: blockHeight,
			LastNegativeReviewOrderHeight: blockHeight,
			LastFulfilledOrderHeight:      blockHeight,
			LastRefundedOrderHeight:       blockHeight,
			AmountBurnedNanos:             3,
			PaymentPlacedNanos:            0,
			PaymentCanceledNanos:          31,
			PaymentRejectedNanos:          19,
			RevenueConfirmedNanos:         0,
			RevenueFulfilledNanos:         6,
			RevenueRefundedNanos:          10,
			// Commissions go down because a refund nullifies the commissions.
			// See comment in block_view for why.
			CommissionsNanos:     2,
			RevenuePositiveNanos: 7,
			MerchantScore:        big.NewInt(30),
		}, me1.Stats)
	}

	// Refunding a reviewed order should work. The merchant score should
	// go down because the review was positive.
	refundOrder(m1Pub, m2Pub, m1Priv, orderID8)
	{
		// Verify the order fields. Merchant score should improve.
		orderID := orderID8
		currentEntry := DbGetOrderEntryForOrderID(db, orderID)
		require.NotNil(currentEntry)
		originalPayment := uint64(8)
		commissionNanos, _, err := _computeCommissionsAndRevenueFromPayment(
			originalPayment, params.CommissionBasisPoints)
		require.NoError(err)
		pk := m2Pub
		message := buyerMessage8
		merchantID := merchantID1
		blockHeight := uint32(5)
		require.Equal(orderID, currentEntry.orderID)
		require.Equal(uint64(commissionNanos), currentEntry.AmountLockedNanos)
		require.Equal(pk, PkToStringTestnet(currentEntry.BuyerPk))
		require.Equal(merchantID, currentEntry.MerchantID)
		require.Less(currentEntry.Pos, uint64(10))
		require.Equal(OrderStateRefunded, currentEntry.State)
		require.Equal(message, string(currentEntry.BuyerMessage))
		require.Equal(uint32(blockHeight), currentEntry.ConfirmationBlockHeight)
		require.Equal(uint32(blockHeight), currentEntry.LastModifiedBlock)
		require.Equal("", string(currentEntry.RejectReason))
		require.Equal(uint64(originalPayment), currentEntry.PaymentAmountNanos)
		require.Equal("merchant fixed everything", string(currentEntry.ReviewText))
		// 1 = commissions * 6 = multiplier
		require.Equal(big.NewInt(0), currentEntry.MerchantScoreImpact)
		require.Equal(uint64(1), commissionNanos)

		// Dig up the MerchantEntry and check that the stats have now changed.
		me1 := DbGetMerchantEntryForMerchantID(db, merchantID1)
		require.Equal(&MerchantStats{
			LastRejectedOrderHeight:       blockHeight,
			LastCanceledOrderHeight:       blockHeight,
			LastConfirmedOrderHeight:      blockHeight,
			LastPlacedOrderHeight:         blockHeight,
			LastPositiveReviewOrderHeight: blockHeight,
			LastNegativeReviewOrderHeight: blockHeight,
			LastFulfilledOrderHeight:      blockHeight,
			LastRefundedOrderHeight:       blockHeight,
			AmountBurnedNanos:             3,
			PaymentPlacedNanos:            0,
			PaymentCanceledNanos:          31,
			PaymentRejectedNanos:          19,
			RevenueConfirmedNanos:         0,
			RevenueFulfilledNanos:         6,
			RevenueRefundedNanos:          17,
			// Commissions go down because a refund nullifies the commissions.
			// See comment in block_view for why.
			CommissionsNanos:     1,
			RevenuePositiveNanos: 0,
			MerchantScore:        big.NewInt(24),
		}, me1.Stats)
	}

	// Refunding a fulfilled order should work. Score should go down because
	// the commissions are deducted from the score.
	refundOrder(m1Pub, m2Pub, m1Priv, orderID7)
	{
		// Verify the order fields. Merchant score should improve.
		orderID := orderID7
		currentEntry := DbGetOrderEntryForOrderID(db, orderID)
		require.NotNil(currentEntry)
		originalPayment := uint64(7)
		commissionNanos, _, err := _computeCommissionsAndRevenueFromPayment(
			originalPayment, params.CommissionBasisPoints)
		require.NoError(err)
		pk := m2Pub
		message := buyerMessage7
		merchantID := merchantID1
		blockHeight := uint32(5)
		require.Equal(orderID, currentEntry.orderID)
		require.Equal(uint64(commissionNanos), currentEntry.AmountLockedNanos)
		require.Equal(pk, PkToStringTestnet(currentEntry.BuyerPk))
		require.Equal(merchantID, currentEntry.MerchantID)
		require.Less(currentEntry.Pos, uint64(10))
		require.Equal(OrderStateRefunded, currentEntry.State)
		require.Equal(message, string(currentEntry.BuyerMessage))
		require.Equal(uint32(blockHeight), currentEntry.ConfirmationBlockHeight)
		require.Equal(uint32(blockHeight), currentEntry.LastModifiedBlock)
		require.Equal("", string(currentEntry.RejectReason))
		require.Equal(uint64(originalPayment), currentEntry.PaymentAmountNanos)
		require.Equal("", string(currentEntry.ReviewText))
		// 1 = commissions * 6 = multiplier
		require.Equal(big.NewInt(0), currentEntry.MerchantScoreImpact)
		require.Equal(uint64(1), commissionNanos)

		// Dig up the MerchantEntry and check that the stats have now changed.
		me1 := DbGetMerchantEntryForMerchantID(db, merchantID1)
		require.Equal(&MerchantStats{
			LastRejectedOrderHeight:       blockHeight,
			LastCanceledOrderHeight:       blockHeight,
			LastConfirmedOrderHeight:      blockHeight,
			LastPlacedOrderHeight:         blockHeight,
			LastPositiveReviewOrderHeight: blockHeight,
			LastNegativeReviewOrderHeight: blockHeight,
			LastFulfilledOrderHeight:      blockHeight,
			LastRefundedOrderHeight:       blockHeight,
			AmountBurnedNanos:             3,
			PaymentPlacedNanos:            0,
			PaymentCanceledNanos:          31,
			PaymentRejectedNanos:          19,
			RevenueConfirmedNanos:         0,
			RevenueFulfilledNanos:         0,
			RevenueRefundedNanos:          23,
			// Commissions go down because a refund nullifies the commissions.
			// See comment in block_view for why.
			CommissionsNanos:     0,
			RevenuePositiveNanos: 0,
			// This is good because it's the merchant's score if you only count
			// what she burned at the beginning.
			MerchantScore: big.NewInt(18),
		}, me1.Stats)

		//_, _, orderEntriesX, err := DbGetOrdersForMerchantID(db, merchantID1, true)
		//require.NoError(err)
		//for _, ee := range orderEntriesX {
		//c, r, err := _computeCommissionsAndRevenueFromPayment(ee.PaymentAmountNanos, params)
		//require.NoError(err)
		//fmt.Println(ee.State, c, r)
		//}
		//spew.Dump(orderEntriesX)
	}

	// ===================================================================================
	// Do some PrivateMessage transactions
	// ===================================================================================
	tstamp1 := uint64(time.Now().UnixNano())
	message1 := string(append([]byte("message1: "), RandomBytes(100)...))
	tstamp2 := uint64(time.Now().UnixNano())
	message2 := string(append([]byte("message2: "), RandomBytes(100)...))
	tstamp3 := uint64(time.Now().UnixNano())
	message3 := string(append([]byte("message3: "), RandomBytes(100)...))
	tstamp4 := uint64(time.Now().UnixNano())
	message4 := string(append([]byte("message4: "), RandomBytes(100)...))
	message5 := string(append([]byte("message5: "), RandomBytes(100)...))

	// Message where the sender is the recipient should fail.
	_, _, _, err = _privateMessage(
		t, chain, db, params, 10 /*feeRateNanosPerKB*/, m0Pub,
		m0Pub, m0Priv, "test" /*unencryptedMessageText*/, tstamp1)
	require.Error(err)
	require.Contains(err.Error(), RuleErrorPrivateMessageSenderPublicKeyEqualsRecipientPublicKey)

	// Message with length too long should fail.
	badMessage := string(append([]byte("badMessage: "), RandomBytes(MaxPrivateMessageLengthBytes)...))
	_, _, _, err = _privateMessage(
		t, chain, db, params, 0 /*feeRateNanosPerKB*/, m0Pub,
		m1Pub, m0Priv, badMessage /*unencryptedMessageText*/, tstamp1)
	require.Error(err)
	require.Contains(err.Error(), RuleErrorPrivateMessageEncryptedTextLengthExceedsMax)

	// Zero tstamp should fail.
	_, _, _, err = _privateMessage(
		t, chain, db, params, 0 /*feeRateNanosPerKB*/, m0Pub,
		m1Pub, m0Priv, message1 /*unencryptedMessageText*/, 0)
	require.Error(err)
	require.Contains(err.Error(), RuleErrorPrivateMessageTstampIsZero)

	// m0 -> m1: message1, tstamp1
	privateMessage(
		m0Pub, m1Pub, m0Priv, message1, tstamp1, 0 /*feeRateNanosPerKB*/)

	// Duplicating (m0, tstamp1) should fail.
	_, _, _, err = _privateMessage(
		t, chain, db, params, 0 /*feeRateNanosPerKB*/, m0Pub,
		m1Pub, m0Priv, message1 /*unencryptedMessageText*/, tstamp1)
	require.Error(err)
	require.Contains(err.Error(), RuleErrorPrivateMessageExistsWithSenderPublicKeyTstampTuple)

	// Duplicating (m1, tstamp1) should fail.
	_, _, _, err = _privateMessage(
		t, chain, db, params, 0 /*feeRateNanosPerKB*/, m1Pub,
		m0Pub, m1Priv, message1 /*unencryptedMessageText*/, tstamp1)
	require.Error(err)
	require.Contains(err.Error(), RuleErrorPrivateMessageExistsWithSenderPublicKeyTstampTuple)

	// Duplicating (m0, tstamp1) with a different sender should still fail.
	_, _, _, err = _privateMessage(
		t, chain, db, params, 0 /*feeRateNanosPerKB*/, m2Pub,
		m0Pub, m2Priv, message1 /*unencryptedMessageText*/, tstamp1)
	require.Error(err)
	require.Contains(err.Error(), RuleErrorPrivateMessageExistsWithRecipientPublicKeyTstampTuple)

	// Duplicating (m1, tstamp1) with a different sender should still fail.
	_, _, _, err = _privateMessage(
		t, chain, db, params, 0 /*feeRateNanosPerKB*/, m2Pub,
		m1Pub, m2Priv, message1 /*unencryptedMessageText*/, tstamp1)
	require.Error(err)
	require.Contains(err.Error(), RuleErrorPrivateMessageExistsWithRecipientPublicKeyTstampTuple)

	// m2 -> m1: message2, tstamp2
	privateMessage(
		m2Pub, m1Pub, m2Priv, message2, tstamp2, 10 /*feeRateNanosPerKB*/)

	// m3 -> m1: message3, tstamp3
	privateMessage(
		m3Pub, m1Pub, m3Priv, message3, tstamp3, 10 /*feeRateNanosPerKB*/)

	// m2 -> m1: message4Str, tstamp4
	privateMessage(
		m1Pub, m2Pub, m1Priv, message4, tstamp4, 10 /*feeRateNanosPerKB*/)

	// m2 -> m3: message5Str, tstamp1
	// Using tstamp1 should be OK since the message is between two new users.
	privateMessage(
		m2Pub, m3Pub, m2Priv, message5, tstamp1, 10 /*feeRateNanosPerKB*/)

	// Verify that the messages are as we expect them in the db.
	// 1: m0 m1
	// 2: m2 m1
	// 3: m3 m1
	// 4: m1 m2
	// 5: m2 m3
	// => m0: 1
	// 		m1: 4
	//    m2: 3
	//    m3: 2
	{
		messages, err := DbGetMessageEntriesForPublicKey(db, _strToPk(t, m0Pub))
		require.NoError(err)
		require.Equal(1, len(messages))
		messageEntry := messages[0]
		require.Equal(messageEntry.SenderPublicKey, _strToPk(t, m0Pub))
		require.Equal(messageEntry.RecipientPublicKey, _strToPk(t, m1Pub))
		require.Equal(messageEntry.TstampNanos, tstamp1)
		require.Equal(messageEntry.isDeleted, false)
		priv, _ := btcec.PrivKeyFromBytes(btcec.S256(), _strToPk(t, m1Priv))
		decryptedBytes, err := DecryptBytesWithPrivateKey(messageEntry.EncryptedText, priv.ToECDSA())
		require.NoError(err)
		require.Equal(message1, string(decryptedBytes))
	}
	{
		messages, err := DbGetMessageEntriesForPublicKey(db, _strToPk(t, m1Pub))
		require.NoError(err)
		require.Equal(4, len(messages))
	}
	{
		messages, err := DbGetMessageEntriesForPublicKey(db, _strToPk(t, m2Pub))
		require.NoError(err)
		require.Equal(3, len(messages))
	}
	{
		messages, err := DbGetMessageEntriesForPublicKey(db, _strToPk(t, m3Pub))
		require.NoError(err)
		require.Equal(2, len(messages))
	}

	// ===================================================================================
	// Finish it off with some transactions
	// ===================================================================================
	registerOrTransfer("", senderPkString, m0Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m0Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m0Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m0Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m0Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m0Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m1Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m1Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m1Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m1Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m1Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m1Pub, senderPrivString)
	registerOrTransfer("", m0Pub, m1Pub, m0Priv)
	registerOrTransfer("", m1Pub, m0Pub, m1Priv)
	registerOrTransfer("", m1Pub, m0Pub, m1Priv)
	registerOrTransfer("", m0Pub, m1Pub, m0Priv)
	registerOrTransfer("", m1Pub, m0Pub, m1Priv)
	registerOrTransfer("", m0Pub, m1Pub, m0Priv)
	registerOrTransfer("", m1Pub, m0Pub, m1Priv)
	registerOrTransfer("", m0Pub, m1Pub, m0Priv)
	registerOrTransfer("", m1Pub, m0Pub, m1Priv)
	registerOrTransfer("", m1Pub, m0Pub, m1Priv)
	registerOrTransfer("", m0Pub, m1Pub, m0Priv)
	registerOrTransfer("", m0Pub, m1Pub, m0Priv)
	registerOrTransfer("", m0Pub, m1Pub, m0Priv)

	_checkOrders2 := func() {
		// <OrderID -> OrderEntry> mapping.
		// _PrefixOrderIDToOrderEntry
		orderEntries, err := DbGetAllOrderEntries(db)
		require.NoError(err)
		require.Equal(9, len(orderEntries))
	}
	_checkOrders2()

	// Check the top merchants are as expected.
	{
		topMerchantIDs, topMerchantScores, topMerchantEntries, err :=
			DbGetBlockchainTopMerchants(db, math.MaxUint64, false /*noMerchantEntries*/)
		require.NoError(err)
		_, _, _ = topMerchantIDs, topMerchantScores, topMerchantEntries
	}

	// Roll back all of the above using the utxoOps from each.
	for ii := 0; ii < len(txnOps); ii++ {
		backwardIter := len(txnOps) - 1 - ii
		currentOps := txnOps[backwardIter]
		currentTxn := txns[backwardIter]
		fmt.Printf("Disconnecting transaction with type %v index %d (going backwards)\n", currentTxn.TxnMeta.GetTxnType(), backwardIter)

		if backwardIter == 25 {
			_checkOrders1()
		}
		if backwardIter == 20 {
			{
				me0 := DbGetMerchantEntryForMerchantID(db, merchantID0)
				require.Equal(uint64(34), me0.Stats.PaymentPlacedNanos)
				require.Equal(uint64(0), me0.Stats.PaymentCanceledNanos)
			}
			{
				me1 := DbGetMerchantEntryForMerchantID(db, merchantID1)
				require.Equal(uint64(31), me1.Stats.PaymentPlacedNanos)
				require.Equal(uint64(0), me1.Stats.PaymentCanceledNanos)
			}
		}
		if backwardIter == 12 {
			amountBurnedNanos := int64(3)
			multiplier := int64(6)
			{
				me0 := DbGetMerchantEntryForMerchantID(db, merchantID0)
				require.Equal(&MerchantStats{
					AmountBurnedNanos: uint64(amountBurnedNanos),
					MerchantScore:     big.NewInt(amountBurnedNanos * multiplier),
				}, me0.Stats)
			}
			{
				me1 := DbGetMerchantEntryForMerchantID(db, merchantID1)
				require.Equal(&MerchantStats{
					AmountBurnedNanos: uint64(amountBurnedNanos),
					MerchantScore:     big.NewInt(amountBurnedNanos * multiplier),
				}, me1.Stats)
			}
		}

		utxoView, err := NewUtxoView(db, params, nil)
		require.NoError(err)

		currentHash := currentTxn.Hash()
		err = utxoView.DisconnectTransaction(currentTxn, currentHash, currentOps, savedHeight)
		require.NoError(err)

		require.NoError(utxoView.FlushToDb())

		// After disconnecting, the balances should be restored to what they
		// were before this transaction was applied.
		require.Equal(expectedSenderBalances[backwardIter], _getBalance(t, chain, nil, senderPkString))
		require.Equal(expectedRecipientBalances[backwardIter], _getBalance(t, chain, nil, recipientPkString))

		if backwardIter == 39 {
			// Dig up the MerchantEntry and check that the stats are as they were
			// before the first order confirmation.
			me1 := DbGetMerchantEntryForMerchantID(db, merchantID1)
			require.Equal(uint64(27), me1.Stats.PaymentPlacedNanos)
			require.Equal(uint64(31), me1.Stats.PaymentCanceledNanos)
			require.Equal(uint64(19), me1.Stats.PaymentRejectedNanos)
			// Burn = 3, multiplier = 6
			multiplier := ComputeImpactMultiple(5,
				uint32(params.MerchantScoreHalfLife/params.TimeBetweenBlocks))
			require.Equal(big.NewInt(3*multiplier.Int64()), me1.Stats.MerchantScore)
		}
	}

	// Verify that all the messages have been deleted.
	{
		messages, err := DbGetMessageEntriesForPublicKey(db, _strToPk(t, m0Pub))
		require.NoError(err)
		require.Equal(0, len(messages))
	}
	{
		messages, err := DbGetMessageEntriesForPublicKey(db, _strToPk(t, m1Pub))
		require.NoError(err)
		require.Equal(0, len(messages))
	}
	{
		messages, err := DbGetMessageEntriesForPublicKey(db, _strToPk(t, m2Pub))
		require.NoError(err)
		require.Equal(0, len(messages))
	}
	{
		messages, err := DbGetMessageEntriesForPublicKey(db, _strToPk(t, m3Pub))
		require.NoError(err)
		require.Equal(0, len(messages))
	}

	// Verify all the mappings are now gone from the db.
	{
		merchantIDs, _ := _enumerateKeysForPrefix(db, _PrefixMerchantIDOrderIndex)
		require.Equal(0, len(merchantIDs))
		merchantIDs, _ = _enumerateKeysForPrefix(db, _PrefixBuyerPubKeyOrderIndex)
		require.Equal(0, len(merchantIDs))

		// Get the OrderIDs for the BuyerPk and check them.
		// <pk || lastModified || orderID>
		lastModifiedHeightsForBuyer, orderIDsForBuyer, orderEntriesForBuyer, err := DbGetOrdersForBuyerPublicKey(
			db, senderPkBytes, true /*fetchEntries*/)
		require.NoError(err)
		require.Equal(0, len(lastModifiedHeightsForBuyer))
		require.Equal(0, len(orderIDsForBuyer))
		require.Equal(0, len(orderEntriesForBuyer))

		// Get the OrderIDs for the MerchantID and check them.
		// <merchantID || lastModified || orderID>
		lastModifiedHeightsForMerchant, orderIDsForMerchant, orderEntriesForMerchant, err := DbGetOrdersForMerchantID(
			db, merchantID0, true /*fetchEntries*/)
		require.NoError(err)
		require.Equal(0, len(lastModifiedHeightsForMerchant))
		require.Equal(0, len(orderIDsForMerchant))
		require.Equal(0, len(orderEntriesForMerchant))

		// <pos -> OrderID>
		positions, orderIDPositions := _enumerateKeysForPrefix(db, _PrefixPosToOrderID)
		require.Equal(0, len(positions))
		require.Equal(0, len(orderIDPositions))

		// GetNumOrderEntriesWithTxn
		require.Equal(uint64(0), GetNumOrderEntries(db))
	}

	// Apply all the transactions to a mempool object and make sure we don't get any
	// errors. Verify the balances align as we go.
	for ii, tx := range txns {
		// See comment above on this transaction.
		fmt.Printf("Adding txn %d of type %v to mempool\n", ii, tx.TxnMeta.GetTxnType())

		require.Equal(expectedSenderBalances[ii], _getBalance(t, chain, mempool, senderPkString))
		require.Equal(expectedRecipientBalances[ii], _getBalance(t, chain, mempool, recipientPkString))

		_, err := mempool.ProcessTransaction(tx, false, false, 0, true)
		require.NoError(err, "Problem adding transaction %d to mempool: %v", ii, tx)
	}

	// Apply all the transactions to a view and flush the view to the db.
	utxoView, err := NewUtxoView(db, params, nil)
	require.NoError(err)
	for ii, txn := range txns {
		fmt.Printf("Adding txn %v of type %v to UtxoView\n", ii, txn.TxnMeta.GetTxnType())

		// Always use height+1 for validation since it's assumed the transaction will
		// get mined into the next block.
		txHash := txn.Hash()
		blockHeight := chain.blockTip().Height + 1
		_, _, _, _, err :=
			utxoView.ConnectTransaction(txn, txHash, blockHeight, true /*verifySignature*/, true /*verifyMerchantMerkleRoot*/)
		require.NoError(err)
	}
	// Flush the utxoView after having added all the transactions.
	require.NoError(utxoView.FlushToDb())

	// Check the top merchants are as expected.
	{
		topMerchantIDs, topMerchantScores, topMerchantEntries, err :=
			DbGetBlockchainTopMerchants(db, math.MaxUint64, false /*noMerchantEntries*/)
		require.NoError(err)
		_, _, _ = topMerchantIDs, topMerchantScores, topMerchantEntries
	}

	// Check that the state of the db after the flush is the same as when we added each
	// transaction individually.
	_checkOrders2()

	// Disonnect the transactions from a single view in the same way as above
	// i.e. without flushing each time.
	utxoView2, err := NewUtxoView(db, params, nil)
	require.NoError(err)
	for ii := 0; ii < len(txnOps); ii++ {
		backwardIter := len(txnOps) - 1 - ii
		fmt.Printf("Disconnecting transaction with index %d (going backwards)\n", backwardIter)
		currentOps := txnOps[backwardIter]
		currentTxn := txns[backwardIter]

		if backwardIter == 20 {
			{
				me0 := utxoView2._getMerchantEntryForMerchantID(merchantID0)
				require.Equal(uint64(34), me0.Stats.PaymentPlacedNanos)
				require.Equal(uint64(0), me0.Stats.PaymentCanceledNanos)
			}
			{
				me1 := utxoView2._getMerchantEntryForMerchantID(merchantID1)
				require.Equal(uint64(31), me1.Stats.PaymentPlacedNanos)
				require.Equal(uint64(0), me1.Stats.PaymentCanceledNanos)
			}
		}
		if backwardIter == 12 {
			amountBurnedNanos := int64(3)
			multiplier := int64(6)
			{
				me0 := utxoView2._getMerchantEntryForMerchantID(merchantID0)
				require.Equal(&MerchantStats{
					AmountBurnedNanos: uint64(amountBurnedNanos),
					MerchantScore:     big.NewInt(amountBurnedNanos * multiplier),
				}, me0.Stats)
			}
			{
				me1 := utxoView2._getMerchantEntryForMerchantID(merchantID1)
				require.Equal(&MerchantStats{
					AmountBurnedNanos: uint64(amountBurnedNanos),
					MerchantScore:     big.NewInt(amountBurnedNanos * multiplier),
				}, me1.Stats)
			}
		}

		currentHash := currentTxn.Hash()
		err = utxoView2.DisconnectTransaction(currentTxn, currentHash, currentOps, savedHeight)
		require.NoError(err)

		if backwardIter == 39 {
			// Dig up the MerchantEntry and check that the stats are as they were
			// before the first order confirmation.
			me1 := utxoView2._getMerchantEntryForMerchantID(merchantID1)
			require.Equal(uint64(27), me1.Stats.PaymentPlacedNanos)
			require.Equal(uint64(31), me1.Stats.PaymentCanceledNanos)
			require.Equal(uint64(19), me1.Stats.PaymentRejectedNanos)
			// Burn = 3, multiplier = 6
			multiplier := ComputeImpactMultiple(5,
				uint32(params.MerchantScoreHalfLife/params.TimeBetweenBlocks))
			require.Equal(big.NewInt(3*multiplier.Int64()), me1.Stats.MerchantScore)
		}
	}
	require.NoError(utxoView2.FlushToDb())
	require.Equal(expectedSenderBalances[0], _getBalance(t, chain, nil, senderPkString))
	require.Equal(expectedRecipientBalances[0], _getBalance(t, chain, nil, recipientPkString))

	// Verify that all the messages have been deleted.
	{
		messages, err := DbGetMessageEntriesForPublicKey(db, _strToPk(t, m0Pub))
		require.NoError(err)
		require.Equal(0, len(messages))
	}
	{
		messages, err := DbGetMessageEntriesForPublicKey(db, _strToPk(t, m1Pub))
		require.NoError(err)
		require.Equal(0, len(messages))
	}
	{
		messages, err := DbGetMessageEntriesForPublicKey(db, _strToPk(t, m2Pub))
		require.NoError(err)
		require.Equal(0, len(messages))
	}
	{
		messages, err := DbGetMessageEntriesForPublicKey(db, _strToPk(t, m3Pub))
		require.NoError(err)
		require.Equal(0, len(messages))
	}

	// Verify all the mappings are now gone from the db.
	{
		merchantIDs, _ := _enumerateKeysForPrefix(db, _PrefixMerchantIDOrderIndex)
		require.Equal(0, len(merchantIDs))
		merchantIDs, _ = _enumerateKeysForPrefix(db, _PrefixBuyerPubKeyOrderIndex)
		require.Equal(0, len(merchantIDs))

		// Get the OrderIDs for the BuyerPk and check them.
		// <pk || lastModified || orderID>
		lastModifiedHeightsForBuyer, orderIDsForBuyer, orderEntriesForBuyer, err := DbGetOrdersForBuyerPublicKey(
			db, senderPkBytes, true /*fetchEntries*/)
		require.NoError(err)
		require.Equal(0, len(lastModifiedHeightsForBuyer))
		require.Equal(0, len(orderIDsForBuyer))
		require.Equal(0, len(orderEntriesForBuyer))

		// Get the OrderIDs for the MerchantID and check them.
		// <merchantID || lastModified || orderID>
		lastModifiedHeightsForMerchant, orderIDsForMerchant, orderEntriesForMerchant, err := DbGetOrdersForMerchantID(
			db, merchantID0, true /*fetchEntries*/)
		require.NoError(err)
		require.Equal(0, len(lastModifiedHeightsForMerchant))
		require.Equal(0, len(orderIDsForMerchant))
		require.Equal(0, len(orderEntriesForMerchant))

		// <pos -> OrderID>
		positions, orderIDPositions := _enumerateKeysForPrefix(db, _PrefixPosToOrderID)
		require.Equal(0, len(positions))
		require.Equal(0, len(orderIDPositions))

		// GetNumOrderEntriesWithTxn
		require.Equal(uint64(0), GetNumOrderEntries(db))
	}

	// Try and estimate the fees in a situation where the last block contains just a
	// block reward.
	{
		// Fee should just equal the min passed in because the block has so few transactions.
		require.Equal(int64(0), int64(chain.EstimateDefaultFeeRateNanosPerKB(.1, 0)))
		require.Equal(int64(7), int64(chain.EstimateDefaultFeeRateNanosPerKB(.1, 7)))
		require.Equal(int64(7), int64(chain.EstimateDefaultFeeRateNanosPerKB(0, 7)))
		require.Equal(int64(0), int64(chain.EstimateDefaultFeeRateNanosPerKB(.1, 0)))
		require.Equal(int64(1), int64(chain.EstimateDefaultFeeRateNanosPerKB(.1, 1)))
		require.Equal(int64(1), int64(chain.EstimateDefaultFeeRateNanosPerKB(0, 1)))
	}

	// All the txns should be in the mempool already so mining a block should put
	// all those transactions in it.
	block, err = miner._mineAndProcessSingleBlock(0 /*threadIndex*/)
	require.NoError(err)
	// Add one for the block reward. Now we have a meaty block.
	require.Equal(len(txnOps)+1, len(block.Txns))
	// Estimate the transaction fees of the tip block in various ways.
	{
		// Threshold above what's in the block should return the default fee at all times.
		require.Equal(int64(0), int64(chain.EstimateDefaultFeeRateNanosPerKB(.1, 0)))
		require.Equal(int64(7), int64(chain.EstimateDefaultFeeRateNanosPerKB(.1, 7)))
		// Threshold below what's in the block should return the max of the median
		// and the minfee. This means with a low minfee the value returned should be
		// higher. And with a high minfee the value returned should be equal to the
		// fee.
		require.Equal(int64(7), int64(chain.EstimateDefaultFeeRateNanosPerKB(0, 7)))
		require.Equal(int64(5), int64(chain.EstimateDefaultFeeRateNanosPerKB(0, 0)))
		require.Equal(int64(7), int64(chain.EstimateDefaultFeeRateNanosPerKB(.01, 7)))
		require.Equal(int64(5), int64(chain.EstimateDefaultFeeRateNanosPerKB(.01, 1)))
	}
}

const (
	BitcoinTestnetMnemonic       = "clump donkey smoke"
	BitcoinTestnetDerivationPath = "m/44'/1'/0'/"

	BitcoinTestnetBurnAddress = "ms9ybkD3E685i54ZqW8osN7qg3KnQXZabH"
	BitcoinTestnetBurnPub     = "02bcb72f2dcc0a21aaa31ba792c8bf4a13e3393d7d1b3073afbac613a06dd1d99f"
	BitcoinTestnetBurnPriv    = "cUFfryF4sMvdPzcXMXRVFfK4D5wZzsbZDEqGfBdb7o2MJfE9aoiN"

	BitcoinTestnetAddress1 = "mqsT6WSy5D1xa2GGxsVm1dPGrk7shccwk3"
	BitcoinTestnetPub1     = "02bce3413e2c2eb510208fefd883861f4d65ac494070a76a837196ea663c00f23c"
	BitcoinTestnetPriv1    = "cQ6NjLY85qGNpEr8rsHZRs4USVpYVLUzYiqufVTpw2gvQ3Hrcfdf"

	BitcoinTestnetAddress2 = "mzcT3DXVuEZho8FZS6428Tk8gbyDTeBRyF"
	BitcoinTestnetPub2     = "0368bb82e27246e4fc386eb641fee1ae7bc0b0e0684753a58c64370eab9573ce80"
	BitcoinTestnetPriv2    = "cR2cSmj3pZ51JGjVzmvHiJwAY1m7tb9x8FCesdSkqzBUHayzifM8"

	BitcoinTestnetAddress3 = "myewf7QQJbXhzdx8QUZuxbtqUuD71Dhwy2"
	BitcoinTestnetPub3     = "03da23d9ac943570a2ecf543733c3f39b8037144397b3bd2306e881539170e47d6"
	BitcoinTestnetPriv3    = "cU5PpBsfZbiHfFaCoBVDnCo8wYEUjkr4NxbhnRcSd5qPvG5ofKvN"

	TestDataDir = "./test_data"
)

func _privStringToKeys(t *testing.T, privString string) (*btcec.PrivateKey, *btcec.PublicKey) {
	require := require.New(t)
	result, _, err := Base58CheckDecodePrefix(privString, 1)
	require.NoError(err)
	result = result[:len(result)-1]
	return btcec.PrivKeyFromBytes(btcec.S256(), result)
}

func _readBitcoinExchangeTestData(t *testing.T) (
	_blocks []*wire.MsgBlock, _headers []*wire.BlockHeader, _headerHeights []uint32) {

	require := require.New(t)

	blocks := []*wire.MsgBlock{}
	{
		data, err := ioutil.ReadFile(TestDataDir + "/bitcoin_testnet_blocks_containing_burn.txt")
		require.NoError(err)

		lines := strings.Split(string(data), "\n")
		lines = lines[:len(lines)-1]

		for _, ll := range lines {
			cols := strings.Split(ll, ",")
			blockHash := mustDecodeHexBlockHash(cols[0])
			block := &wire.MsgBlock{}
			blockBytes, err := hex.DecodeString(cols[1])
			require.NoError(err)

			err = block.Deserialize(bytes.NewBuffer(blockBytes))
			require.NoError(err)

			parsedBlockHash := (BlockHash)(block.BlockHash())
			require.Equal(*blockHash, parsedBlockHash)

			blocks = append(blocks, block)
		}
	}

	headers := []*wire.BlockHeader{}
	headerHeights := []uint32{}
	{
		data, err := ioutil.ReadFile(TestDataDir + "/bitcoin_testnet_headers_for_burn.txt")
		require.NoError(err)

		lines := strings.Split(string(data), "\n")
		lines = lines[:len(lines)-1]

		for _, ll := range lines {
			cols := strings.Split(ll, ",")

			// Parse the block height
			blockHeight, err := strconv.Atoi(cols[0])
			require.NoError(err)

			// Parse the header hash
			headerHashBytes, err := hex.DecodeString(cols[1])
			require.NoError(err)
			headerHash := BlockHash{}
			copy(headerHash[:], headerHashBytes[:])

			// Parse the header
			headerBytes, err := hex.DecodeString(cols[2])
			require.NoError(err)
			header := &wire.BlockHeader{}
			header.Deserialize(bytes.NewBuffer(headerBytes))

			// Verify that the header hash matches the hash of the header.
			require.Equal(headerHash, (BlockHash)(header.BlockHash()))

			headers = append(headers, header)
			headerHeights = append(headerHeights, uint32(blockHeight))
		}
	}
	return blocks, headers, headerHeights
}

// FakeTimeSource just returns the same time every time when called. It
// implements AddTimeSample and Offset just to satisfy the interface but
// doesn't actually make use of them.
type FakeTimeSource struct {
	TimeToReturn time.Time
}

func NewFakeTimeSource(timeToReturn time.Time) *FakeTimeSource {
	return &FakeTimeSource{
		TimeToReturn: timeToReturn,
	}
}
func (m *FakeTimeSource) AdjustedTime() time.Time {
	return m.TimeToReturn
}
func (m *FakeTimeSource) AddTimeSample(sourceID string, timeVal time.Time) {
	return
}
func (m *FakeTimeSource) Offset() time.Duration {
	return 0
}

func GetTestBitcoinManager(
	t *testing.T, startHeader *wire.BlockHeader, startHeight uint32, db *badger.DB,
	paramss *UltranetParams, currentTime time.Time, minBurnBlocks uint32,
	headersToApply []*wire.BlockHeader, processFull bool) (
	*BitcoinManager, *FakeTimeSource, *UltranetParams) {

	require := require.New(t)

	// Set the BitcoinExchange-related params to canned values.
	paramsCopy := *paramss
	paramsCopy.BitcoinMinBurnWorkBlocks = minBurnBlocks
	headerHash := (BlockHash)(startHeader.BlockHash())
	paramsCopy.BitcoinStartBlockNode = NewBlockNode(
		nil,         /*ParentNode*/
		&headerHash, /*Hash*/
		startHeight,
		_difficultyBitsToHash(startHeader.Bits),
		// CumWork: We set the work of the start node such that, when added to all of the
		// blocks that follow it, it hurdles the min chain work.
		big.NewInt(0),
		// We are bastardizing the Ultranet header to store Bitcoin information here.
		&MsgUltranetHeader{
			TstampSecs: uint32(startHeader.Timestamp.Unix()),
			Height:     0,
		},
		StatusBitcoinHeaderValidated,
	)

	bitcoinManagerDir, err := ioutil.TempDir("", "bitcoin_manager")
	require.NoError(err)
	fakeTimeSource := NewFakeTimeSource(currentTime)
	testBitcoinManager, err := NewBitcoinManager(
		db, &paramsCopy, fakeTimeSource, bitcoinManagerDir,
		nil /*updateChan*/)
	require.NoError(err)
	testBitcoinManager.ResetBitcoinHeaderIndex()

	for _, hdr := range headersToApply {
		if processFull {
			isMainChain, isOrphan, err := testBitcoinManager.ProcessBitcoinHeaderFull(hdr, &paramsCopy)
			require.NoError(err)
			require.False(isOrphan)
			require.True(isMainChain)
		} else {
			isMainChain, isOrphan, err := testBitcoinManager.ProcessBitcoinHeaderQuick(hdr, &paramsCopy)
			require.NoError(err)
			require.False(isOrphan)
			require.True(isMainChain)
		}
	}

	return testBitcoinManager, fakeTimeSource, &paramsCopy
}

type MedianTimeSource interface {
	// AdjustedTime returns the current time adjusted by the median time
	// offset as calculated from the time samples added by AddTimeSample.
	AdjustedTime() time.Time

	// AddTimeSample adds a time sample that is used when determining the
	// median time of the added samples.
	AddTimeSample(id string, timeVal time.Time)

	// Offset returns the number of seconds to adjust the local clock based
	// upon the median of the time samples added by AddTimeData.
	Offset() time.Duration
}

func TestBitcoinManagerProcessHeadersFull(t *testing.T) {
	require := require.New(t)

	chain, params, db := NewLowDifficultyBlockchain()
	mempool, miner := NewTestMiner(t, chain, params, true /*isSender*/)
	_, _ = mempool, miner
	params.BitcoinMaxTipAge = 3 * time.Hour
	params.BitcoinMinBurnWorkBlocks = uint32(60 * int64(time.Minute) / (10 * int64(time.Minute)))

	// Read in the test Bitcoin blocks and headers.
	bitcoinBlocks, bitcoinHeaders, bitcoinHeaderHeights := _readBitcoinExchangeTestData(t)
	firstBitcoinBurnBlock := bitcoinBlocks[1]
	firstBitcoinBurnBlockHash := firstBitcoinBurnBlock.BlockHash()
	headerIndexOfFirstBurn := -1
	for headerIndex := range bitcoinHeaders {
		if firstBitcoinBurnBlockHash == bitcoinHeaders[headerIndex].BlockHash() {
			headerIndexOfFirstBurn = headerIndex
			break
		}
	}

	timeJustBeforeBurnBlock := time.Unix(firstBitcoinBurnBlock.Header.Timestamp.Unix()-1, 0)
	minBurnBlocks := uint32(2)
	startHeaderIndex := 0
	headersToApply := bitcoinHeaders[1:headerIndexOfFirstBurn]
	// Verify that quick processing behaves as expected.
	{
		bitcoinManager, fakeTimeSource, paramsCopy := GetTestBitcoinManager(
			t, bitcoinHeaders[startHeaderIndex], bitcoinHeaderHeights[startHeaderIndex], db,
			params, timeJustBeforeBurnBlock, minBurnBlocks, headersToApply, false /*processFull*/)
		_, _, _ = bitcoinManager, fakeTimeSource, paramsCopy
		paramsCopy.BitcoinMinChainWorkHex = "0000000000000000000000000000000000000000000000008e207e217e217e22"
		require.True(bitcoinManager.IsCurrent(false /*considerCumWork*/))
		require.False(bitcoinManager.IsCurrent(true /*considerCumWork*/))
		paramsCopy.BitcoinMinChainWorkHex = "0000000000000000000000000000000000000000000000000000000000000001"
		require.False(bitcoinManager.IsCurrent(true /*considerCumWork*/))
	}
	// Verify that full header processing behaves as expected.
	{
		bitcoinManager, fakeTimeSource, paramsCopy := GetTestBitcoinManager(
			t, bitcoinHeaders[startHeaderIndex], bitcoinHeaderHeights[startHeaderIndex], db,
			params, timeJustBeforeBurnBlock, minBurnBlocks, headersToApply, true /*processFull*/)
		_, _, _ = bitcoinManager, fakeTimeSource, paramsCopy
		paramsCopy.BitcoinMinChainWorkHex = "0000000000000000000000000000000000000000000000008e207e217e217e22"
		require.True(bitcoinManager.IsCurrent(false /*considerCumWork*/))
		require.False(bitcoinManager.IsCurrent(true /*considerCumWork*/))
		paramsCopy.BitcoinMinChainWorkHex = "0000000000000000000000000000000000000000000000000000000000000001"
		require.True(bitcoinManager.IsCurrent(true /*considerCumWork*/))
		require.Equal(
			bitcoinManager.bestHeaderChain[len(bitcoinManager.bestHeaderChain)-1].CumWork.Text(16),
			"7e207e217e217e21")
	}
}

func TestBitcoinExchange(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	chain, params, db := NewLowDifficultyBlockchain()
	mempool, miner := NewTestMiner(t, chain, params, true /*isSender*/)
	params.BitcoinMaxTipAge = 3 * time.Hour
	params.BitcoinMinBurnWorkBlocks = uint32(60 * int64(time.Minute) / (10 * int64(time.Minute)))

	// Read in the test Bitcoin blocks and headers.
	bitcoinBlocks, bitcoinHeaders, bitcoinHeaderHeights := _readBitcoinExchangeTestData(t)

	// Extract BitcoinExchange transactions from the test Bitcoin blocks.
	bitcoinExchangeTxns := []*MsgUltranetTxn{}
	for _, block := range bitcoinBlocks {
		currentBurnTxns, err :=
			ExtractBitcoinExchangeTransactionsFromBitcoinBlock(
				block, BitcoinTestnetBurnAddress, params)
		require.NoError(err)
		bitcoinExchangeTxns = append(bitcoinExchangeTxns, currentBurnTxns...)
	}

	// Verify that Bitcoin burn transactions are properly extracted from Bitcoin blocks
	// and the their burn amounts are computed correctly.
	require.Equal(9, len(bitcoinExchangeTxns))
	expectedBitcoinBurnAmounts := []int64{
		10000,
		12500,
		41000,
		20000,
		15000,
		50000,
		15000,
		20482,
		2490,
	}
	blockIndexesForTransactions := []int{1, 1, 1, 1, 1, 1, 1, 3, 3}
	for ii, bitcoinExchangeTxn := range bitcoinExchangeTxns {
		txnMeta := bitcoinExchangeTxn.TxnMeta.(*BitcoinExchangeMetadata)
		burnTxn := txnMeta.BitcoinTransaction
		burnOutput, err := _computeBitcoinBurnOutput(
			burnTxn, BitcoinTestnetBurnAddress, params.BitcoinBtcdParams)
		require.NoError(err)
		assert.Equalf(expectedBitcoinBurnAmounts[ii], burnOutput,
			"Bitcoin burn amount for burn txn %d doesn't line up with "+
				"what is expected", ii)

		// Sanity-check that all the Bitcoin transaction hashes line up.
		{
			hash1 := (BlockHash)(txnMeta.BitcoinTransaction.TxHash())
			hash2 := *txnMeta.BitcoinTransactionHash
			require.Equalf(
				hash1, hash2,
				"Bitcoin transaction hashes do not line up: %v %v %d", &hash1, &hash2, ii)
		}

		// Sanity-check that the Bitcoin block hashes line up.
		blockIndex := blockIndexesForTransactions[ii]
		blockForTxn := bitcoinBlocks[blockIndex]
		{
			hash1 := (BlockHash)(blockForTxn.BlockHash())
			hash2 := *txnMeta.BitcoinBlockHash
			require.Equalf(
				hash1, hash2,
				"Bitcoin block hash for txn does not line up with block hash: %v %v %d", &hash1, &hash2, ii)
		}

		// Sanity-check that the Merkle root lines up with what's in the block.
		{
			hash1 := (BlockHash)(blockForTxn.Header.MerkleRoot)
			hash2 := *txnMeta.BitcoinMerkleRoot
			require.Equalf(
				hash1, hash2,
				"Bitcoin merkle root for txn does not line up with block hash: %v %v %d", &hash1, &hash2, ii)
		}

		// Verify that the merkle proof checks out.
		{
			merkleProofIsValid := merkletree.VerifyProof(
				txnMeta.BitcoinTransactionHash[:], txnMeta.BitcoinMerkleProof, txnMeta.BitcoinMerkleRoot[:])
			require.Truef(
				merkleProofIsValid, "Problem verifying merkle proof for burn txn %d", ii)
		}

		// Verify that using the wrong Merkle root doesn't work.
		{
			badBlock := bitcoinBlocks[blockIndex-1]
			badMerkleRoot := badBlock.Header.MerkleRoot[:]
			merkleProofIsValid := merkletree.VerifyProof(
				txnMeta.BitcoinTransactionHash[:], txnMeta.BitcoinMerkleProof, badMerkleRoot)
			require.Falsef(
				merkleProofIsValid, "Bad Merkle root was actually verified for burn txn %d", ii)
		}

		// Verify that serializing and deserializing work for this transaction.
		bb, err := bitcoinExchangeTxn.ToBytes(false /*preSignature*/)
		require.NoError(err)
		parsedBitcoinExchangeTxn := &MsgUltranetTxn{}
		parsedBitcoinExchangeTxn.FromBytes(bb)
		require.Equal(bitcoinExchangeTxn, parsedBitcoinExchangeTxn)
	}

	// Find the header in our header list corresponding to the first test block,
	// which contains the first Bitcoin
	firstBitcoinBurnBlock := bitcoinBlocks[1]
	firstBitcoinBurnBlockHash := firstBitcoinBurnBlock.BlockHash()
	headerIndexOfFirstBurn := -1
	for headerIndex := range bitcoinHeaders {
		if firstBitcoinBurnBlockHash == bitcoinHeaders[headerIndex].BlockHash() {
			headerIndexOfFirstBurn = headerIndex
			break
		}
	}
	require.Greater(headerIndexOfFirstBurn, 0)

	// Create a Bitcoinmanager that is current whose tip corresponds to the block
	// just before the block containing the first Bitcoin burn transaction.
	timeJustBeforeBurnBlock := time.Unix(firstBitcoinBurnBlock.Header.Timestamp.Unix()-1, 0)
	minBurnBlocks := uint32(2)
	startHeaderIndex := 0
	headersToApply := bitcoinHeaders[1:headerIndexOfFirstBurn]
	bitcoinManager, fakeTimeSource, paramsCopy := GetTestBitcoinManager(
		t, bitcoinHeaders[startHeaderIndex], bitcoinHeaderHeights[startHeaderIndex], db,
		params, timeJustBeforeBurnBlock, minBurnBlocks, headersToApply, false /*processFull*/)
	_, _, _ = bitcoinManager, fakeTimeSource, paramsCopy
	require.True(bitcoinManager.IsCurrent(false /*considerCumWork*/))

	// Update some of the params to make them reflect what we've hacked into
	// the bitcoinManager.
	paramsCopy.BitcoinBurnAddress = BitcoinTestnetBurnAddress
	chain.bitcoinManager = bitcoinManager
	chain.params = paramsCopy

	// Verify that the OldestTimeCurrentBitcoinBlock is where it should be.
	{
		oldestTimeCurrentNode := bitcoinManager.GetOldestTimeCurrentBlock()
		require.NotNil(oldestTimeCurrentNode)
		require.True(bitcoinManager._isCurrentNode(
			oldestTimeCurrentNode, false /*considerCumWork*/))
		require.False(bitcoinManager._isCurrentNode(
			oldestTimeCurrentNode.Parent, false /*considerCumWork*/))
		t1 := timeJustBeforeBurnBlock.Unix() - int64(oldestTimeCurrentNode.Parent.Header.TstampSecs)
		t2 := timeJustBeforeBurnBlock.Unix() - int64(oldestTimeCurrentNode.Header.TstampSecs)
		maxTipAgeSecs := int64(paramsCopy.BitcoinMaxTipAge.Seconds())
		require.Less(maxTipAgeSecs, t1)
		require.Greater(maxTipAgeSecs, t2)
	}

	// Validating the first Bitcoin burn transaction should fail because the block
	// corresponding to it is not yet in the BitcoinManager.
	burnTxn1 := bitcoinExchangeTxns[0]
	txHash1 := burnTxn1.Hash()
	burnTxn2 := bitcoinExchangeTxns[1]

	{
		utxoView, err := NewUtxoView(db, paramsCopy, bitcoinManager)
		blockHeight := chain.blockTip().Height + 1
		_, _, _, _, err =
			utxoView.ConnectTransaction(burnTxn1, txHash1, blockHeight, true /*verifySignature*/, true /*verifyMerchantMerkleRoot*/)
		require.Error(err)
		require.Contains(err.Error(), RuleErrorBitcoinExchangeBlockHashNotFoundInMainBitcoinChain)
	}

	// The mempool should store the transaction but not actually process it yet.
	{
		txDescs, err := mempool.processTransaction(
			burnTxn1, true /*allowOrphan*/, true /*rateLimit*/, 0 /*peerID*/, true /*verifySignatures*/)
		require.NoError(err)
		require.Equal(0, len(txDescs))
		require.Equal(1, len(mempool.immatureBitcoinTxns))
	}

	// Process the Bitcoin block containing the first set of burn transactions.
	bitcoinManager.ProcessBitcoinHeaderQuick(
		bitcoinHeaders[headerIndexOfFirstBurn], paramsCopy)
	require.Equal(bitcoinManager.HeaderTip().Hash[:], firstBitcoinBurnBlockHash[:])
	firstBitcoinBurnNode := bitcoinManager.HeaderTip()

	// Validating the first Bitcoin burn transaction should fail because there is not
	// enough work built on it yet. Note that it is not a RuleError because we don't
	// want to mark the block this transaction appears in as invalid when this happens.
	{
		utxoView, err := NewUtxoView(db, paramsCopy, bitcoinManager)
		blockHeight := chain.blockTip().Height + 1
		_, _, _, _, err =
			utxoView.ConnectTransaction(burnTxn1, txHash1, blockHeight, true /*verifySignature*/, true /*verifyMerchantMerkleRoot*/)
		require.Error(err)
		// TODO: I know I'm a bad person for using string matching. Fix this later.
		require.Contains(err.Error(), "MinBitcoinBurnWork")
	}

	// The mempool should now be able to process the transaction it processed before
	// if we call its update function.
	{
		txDescsAdded := mempool.UpdateAfterBitcoinManagerNotification(
			true /*allowOrphan*/, true /*rateLimit*/, true /*verifySignatures*/)
		require.Equal(1, len(txDescsAdded))
		require.Equal(0, len(mempool.immatureBitcoinTxns))
	}

	// According to the mempool, the balance of the user whose public key created
	// the Bitcoin burn transaction should now have some Ultra. 10,000 satoshis convert
	// to 1Ultra at the starting price and then get hit by a .999 bp fee.
	pkBytes1, _ := hex.DecodeString(BitcoinTestnetPub1)
	pkBytes2, _ := hex.DecodeString(BitcoinTestnetPub2)
	pkBytes3, _ := hex.DecodeString(BitcoinTestnetPub3)
	{
		utxoEntries, err := chain.GetSpendableUtxosForPublicKey(pkBytes1, mempool)
		require.NoError(err)

		require.Equal(1, len(utxoEntries))
		require.Equal(int64(999000000), int64(utxoEntries[0].AmountNanos))
	}

	// The mempool should be able to process a burn transaction directly.
	{
		txDescsAdded, err := mempool.processTransaction(
			burnTxn2, true /*allowOrphan*/, true /*rateLimit*/, 0, /*peerID*/
			true /*verifySignatures*/)
		require.NoError(err)
		require.Equal(1, len(txDescsAdded))
		require.Equal(0, len(mempool.immatureBitcoinTxns))
	}

	// According to the mempool, the balances should have updated. 12,500 satoshis
	// convert to 1.25 Ultra at the starting price and then get hit with a 10 bp fee.
	{
		utxoEntries, err := chain.GetSpendableUtxosForPublicKey(pkBytes3, mempool)
		require.NoError(err)

		require.Equal(1, len(utxoEntries))
		require.Equal(int64(1248750000), int64(utxoEntries[0].AmountNanos))
	}

	// If the mempool is not consulted, the balances should be zero.
	{
		utxoEntries, err := chain.GetSpendableUtxosForPublicKey(pkBytes3, nil)
		require.NoError(err)
		require.Equal(0, len(utxoEntries))
	}

	// Now add blocks to the BitcoinManager until the block containing the first
	// burn transactions is just after the oldestTimeCurrentBlock.
	nextHeaderIndex := headerIndexOfFirstBurn + 1
	{
		timeWhereBurnBlockIsJustBeforeOldestTimeCurrentBlock := time.Unix(
			int64(firstBitcoinBurnNode.Header.TstampSecs)+
				int64(paramsCopy.BitcoinMaxTipAge.Seconds())+1, 0)
		fakeTimeSource.TimeToReturn = timeWhereBurnBlockIsJustBeforeOldestTimeCurrentBlock
		for bitcoinHeaders[nextHeaderIndex].Timestamp.Before(
			timeWhereBurnBlockIsJustBeforeOldestTimeCurrentBlock) {

			bitcoinManager.ProcessBitcoinHeaderQuick(
				bitcoinHeaders[nextHeaderIndex], paramsCopy)
			nextHeaderIndex++
		}
	}

	// At this point, the block containing the first burn transaction should be
	// just after the oldest time-current block.
	{
		oldestTimeCurrentNode := bitcoinManager.GetOldestTimeCurrentBlock()
		require.Equal(oldestTimeCurrentNode.Parent.Hash[:], firstBitcoinBurnBlockHash[:])
		require.Equal(int64(0), bitcoinManager.GetBitcoinBurnWorkBlocks(oldestTimeCurrentNode.Height))
	}

	// Verify that the amount of work on a transaction that is in the first burn
	// block is equal to one (because the burn block is right after the oldest
	// time-current node).
	require.Equal(int64(-2), bitcoinManager.GetBitcoinBurnWorkBlocks(firstBitcoinBurnNode.Height+3))
	require.Equal(int64(1), bitcoinManager.GetBitcoinBurnWorkBlocks(firstBitcoinBurnNode.Height))

	// Verify that adding the transaction to the UtxoView still fails because there is
	// not enough work on the burn block yet.
	{
		utxoView, err := NewUtxoView(db, paramsCopy, bitcoinManager)
		blockHeight := chain.blockTip().Height + 1
		_, _, _, _, err =
			utxoView.ConnectTransaction(burnTxn1, txHash1, blockHeight, true /*verifySignature*/, true /*verifyMerchantMerkleRoot*/)
		require.Error(err)
		// TODO: I know I'm a bad person for using string matching. Fix this later.
		require.Contains(err.Error(), "MinBitcoinBurnWork")
	}

	// Now push the burn block so that it is four blocks behind the oldest time-current
	// block.
	{
		timeWhereBurnBlockIsWellBehindOldestTimeCurrentBlock := time.Unix(
			bitcoinHeaders[headerIndexOfFirstBurn+8].Timestamp.Unix()+
				int64(paramsCopy.BitcoinMaxTipAge.Seconds())+1, 0)
		fakeTimeSource.TimeToReturn = timeWhereBurnBlockIsWellBehindOldestTimeCurrentBlock
		for bitcoinHeaders[nextHeaderIndex].Timestamp.Before(
			timeWhereBurnBlockIsWellBehindOldestTimeCurrentBlock) {

			bitcoinManager.ProcessBitcoinHeaderQuick(
				bitcoinHeaders[nextHeaderIndex], paramsCopy)
			nextHeaderIndex++
		}
	}

	// Verify that there are 9 blocks between the block containing the first burn
	// transaction and the oldest time-current block.
	require.Equal(int64(9), bitcoinManager.GetBitcoinBurnWorkBlocks(firstBitcoinBurnNode.Height))

	// The UtxoView should accept all of the burn transactions now that their blocks
	// have enough work built on them.

	// Applying all the txns to the UtxoView should work.
	utxoOpsList := [][]*UtxoOperation{}
	{
		utxoView, err := NewUtxoView(db, paramsCopy, bitcoinManager)
		require.NoError(err)
		for ii, burnTxn := range bitcoinExchangeTxns {
			blockHeight := chain.blockTip().Height + 1
			utxoOps, totalInput, totalOutput, fees, err :=
				utxoView.ConnectTransaction(burnTxn, burnTxn.Hash(), blockHeight, true /*verifySignature*/, true /*verifyMerchantMerkleRoot*/)
			require.NoError(err)

			require.Equal(2, len(utxoOps))
			require.Equal(int64(totalInput), expectedBitcoinBurnAmounts[ii]*100000)
			require.Equal(int64(fees), expectedBitcoinBurnAmounts[ii]*100000*int64(paramsCopy.BitcoinExchangeFeeBasisPoints)/10000)
			require.Equal(int64(fees), int64(totalInput-totalOutput))

			utxoOpsList = append(utxoOpsList, utxoOps)
		}

		// Flushing the UtxoView should work.
		utxoView.FlushToDb()
	}

	// The balances according to the db after the flush should be correct.
	{
		utxoEntries, err := chain.GetSpendableUtxosForPublicKey(pkBytes1, nil)
		require.NoError(err)
		require.Equal(5, len(utxoEntries))
		totalBalance := uint64(0)
		for _, utxoEntry := range utxoEntries {
			totalBalance += utxoEntry.AmountNanos
		}
		// Note the 10bp fee.
		require.Equal(int64(102972*100000*.999), int64(totalBalance))
	}
	{
		utxoEntries, err := chain.GetSpendableUtxosForPublicKey(pkBytes2, nil)
		require.NoError(err)
		require.Equal(1, len(utxoEntries))
		// Note the 10bp fee.
		require.Equal(int64(15000*100000*.999), int64(utxoEntries[0].AmountNanos))
	}
	{
		utxoEntries, err := chain.GetSpendableUtxosForPublicKey(pkBytes3, nil)
		require.NoError(err)
		require.Equal(3, len(utxoEntries))
		totalBalance := uint64(0)
		for _, utxoEntry := range utxoEntries {
			totalBalance += utxoEntry.AmountNanos
		}
		// Note the 10bp fee.
		require.Equal(int64(68500*100000*.999), int64(totalBalance))
	}

	// Spending from the outputs created by a burn should work.
	ultranetPub1 := Base58CheckEncode(pkBytes1, false /*isPrivate*/, paramsCopy)
	priv1, _ := _privStringToKeys(t, BitcoinTestnetPriv1)
	ultranetPriv1 := Base58CheckEncode(priv1.Serialize(), true /*isPrivate*/, paramsCopy)
	ultranetPub2 := Base58CheckEncode(pkBytes2, false /*isPrivate*/, paramsCopy)
	priv2, _ := _privStringToKeys(t, BitcoinTestnetPriv2)
	ultranetPriv2 := Base58CheckEncode(priv2.Serialize(), true /*isPrivate*/, paramsCopy)
	ultranetPub3 := Base58CheckEncode(pkBytes3, false /*isPrivate*/, paramsCopy)
	priv3, _ := _privStringToKeys(t, BitcoinTestnetPriv3)
	ultranetPriv3 := Base58CheckEncode(priv3.Serialize(), true /*isPrivate*/, paramsCopy)
	{
		currentOps, currentTxn, _ := _doBasicTransferWithViewFlush(
			t, chain, db, params, ultranetPub1, ultranetPub2,
			ultranetPriv1, 100000*100000 /*amount to send*/, 11 /*feerate*/)

		utxoOpsList = append(utxoOpsList, currentOps)
		bitcoinExchangeTxns = append(bitcoinExchangeTxns, currentTxn)
	}
	{
		currentOps, currentTxn, _ := _doBasicTransferWithViewFlush(
			t, chain, db, params, ultranetPub3, ultranetPub1,
			ultranetPriv3, 60000*100000 /*amount to send*/, 11 /*feerate*/)

		utxoOpsList = append(utxoOpsList, currentOps)
		bitcoinExchangeTxns = append(bitcoinExchangeTxns, currentTxn)
	}
	{
		currentOps, currentTxn, _ := _doBasicTransferWithViewFlush(
			t, chain, db, params, ultranetPub2, ultranetPub1,
			ultranetPriv2, 60000*100000 /*amount to send*/, 11 /*feerate*/)

		utxoOpsList = append(utxoOpsList, currentOps)
		bitcoinExchangeTxns = append(bitcoinExchangeTxns, currentTxn)
	}

	// The balances according to the db after the spends above should be correct.
	{
		utxoEntries, err := chain.GetSpendableUtxosForPublicKey(pkBytes1, nil)
		require.NoError(err)
		totalBalance := uint64(0)
		for _, utxoEntry := range utxoEntries {
			totalBalance += utxoEntry.AmountNanos
		}
		require.Equal(int64(12286902797), int64(totalBalance))
	}
	{
		utxoEntries, err := chain.GetSpendableUtxosForPublicKey(pkBytes2, nil)
		require.NoError(err)
		require.Equal(int64(5498499998), int64(utxoEntries[0].AmountNanos))
	}
	{
		utxoEntries, err := chain.GetSpendableUtxosForPublicKey(pkBytes3, nil)
		require.NoError(err)
		totalBalance := uint64(0)
		for _, utxoEntry := range utxoEntries {
			totalBalance += utxoEntry.AmountNanos
		}
		require.Equal(int64(843149998), int64(totalBalance))
	}

	{
		// Rolling back all the transactions should work.
		utxoView, err := NewUtxoView(db, paramsCopy, bitcoinManager)
		require.NoError(err)
		for ii := range bitcoinExchangeTxns {
			index := len(bitcoinExchangeTxns) - 1 - ii
			burnTxn := bitcoinExchangeTxns[index]
			blockHeight := chain.blockTip().Height + 1
			err := utxoView.DisconnectTransaction(burnTxn, burnTxn.Hash(), utxoOpsList[index], blockHeight)
			require.NoError(err)
		}

		// Flushing the UtxoView back to the db after rolling back the
		utxoView.FlushToDb()
	}

	// The balances according to the db after rolling back and flushing everything
	// should be zero.
	{
		utxoEntries, err := chain.GetSpendableUtxosForPublicKey(pkBytes1, nil)
		require.NoError(err)
		require.Equal(0, len(utxoEntries))
	}
	{
		utxoEntries, err := chain.GetSpendableUtxosForPublicKey(pkBytes2, nil)
		require.NoError(err)
		require.Equal(0, len(utxoEntries))
	}
	{
		utxoEntries, err := chain.GetSpendableUtxosForPublicKey(pkBytes3, nil)
		require.NoError(err)
		require.Equal(0, len(utxoEntries))
	}

	// Re-applying all the transactions to the view and rolling back without
	// flushing should be fine.
	utxoOpsList = [][]*UtxoOperation{}
	{
		utxoView, err := NewUtxoView(db, paramsCopy, bitcoinManager)
		require.NoError(err)
		for ii, burnTxn := range bitcoinExchangeTxns {
			blockHeight := chain.blockTip().Height + 1
			utxoOps, totalInput, totalOutput, fees, err :=
				utxoView.ConnectTransaction(burnTxn, burnTxn.Hash(), blockHeight, true /*verifySignature*/, true /*verifyMerchantMerkleRoot*/)
			require.NoError(err)

			if ii < len(expectedBitcoinBurnAmounts) {
				require.Equal(2, len(utxoOps))
				require.Equal(int64(totalInput), expectedBitcoinBurnAmounts[ii]*100000)
				require.Equal(int64(fees), expectedBitcoinBurnAmounts[ii]*100000*int64(paramsCopy.BitcoinExchangeFeeBasisPoints)/10000)
				require.Equal(int64(fees), int64(totalInput-totalOutput))
			}

			utxoOpsList = append(utxoOpsList, utxoOps)
		}

		for ii := range bitcoinExchangeTxns {
			index := len(bitcoinExchangeTxns) - 1 - ii
			burnTxn := bitcoinExchangeTxns[index]
			blockHeight := chain.blockTip().Height + 1
			err := utxoView.DisconnectTransaction(burnTxn, burnTxn.Hash(), utxoOpsList[index], blockHeight)
			require.NoError(err)
		}

		// Flushing the view after applying and rolling back should work.
		utxoView.FlushToDb()
	}

	// The balances according to the db after applying and unapplying all the
	// transactions to a view with a flush at the end should be zero.
	{
		utxoEntries, err := chain.GetSpendableUtxosForPublicKey(pkBytes1, nil)
		require.NoError(err)
		require.Equal(0, len(utxoEntries))
	}
	{
		utxoEntries, err := chain.GetSpendableUtxosForPublicKey(pkBytes2, nil)
		require.NoError(err)
		require.Equal(0, len(utxoEntries))
	}
	{
		utxoEntries, err := chain.GetSpendableUtxosForPublicKey(pkBytes3, nil)
		require.NoError(err)
		require.Equal(0, len(utxoEntries))
	}

	// Running all the transactions through the mempool should work and result
	// in all of them being added.
	{
		for _, burnTxn := range bitcoinExchangeTxns {
			err := mempool.removeTransaction(burnTxn, false /*removeRedeemers*/)
			require.NoError(err)
			txDescsAdded, err := mempool.processTransaction(
				burnTxn, true /*allowOrphan*/, true /*rateLimit*/, 0, /*peerID*/
				true /*verifySignatures*/)
			require.NoError(err)
			require.Equal(1, len(txDescsAdded))
			require.Equal(0, len(mempool.immatureBitcoinTxns))
		}
	}

	// The balances according to the mempool after applying all the transactions
	// should be correct.
	{
		utxoEntries, err := chain.GetSpendableUtxosForPublicKey(pkBytes1, mempool)
		require.NoError(err)
		totalBalance := uint64(0)
		for _, utxoEntry := range utxoEntries {
			totalBalance += utxoEntry.AmountNanos
		}
		require.Equal(int64(12286902797), int64(totalBalance))
	}
	{
		utxoEntries, err := chain.GetSpendableUtxosForPublicKey(pkBytes2, mempool)
		require.NoError(err)
		require.Equal(int64(5498499998), int64(utxoEntries[0].AmountNanos))
	}
	{
		utxoEntries, err := chain.GetSpendableUtxosForPublicKey(pkBytes3, mempool)
		require.NoError(err)
		totalBalance := uint64(0)
		for _, utxoEntry := range utxoEntries {
			totalBalance += utxoEntry.AmountNanos
		}
		require.Equal(int64(843149998), int64(totalBalance))
	}

	// Remove all the transactions from the mempool.
	for _, burnTxn := range bitcoinExchangeTxns {
		err := mempool.removeTransaction(burnTxn, false /*removeRedeemers*/)
		require.NoError(err)
	}

	// The balances should be zero after removing transactions from the mempool.
	{
		utxoEntries, err := chain.GetSpendableUtxosForPublicKey(pkBytes1, mempool)
		require.NoError(err)
		require.Equal(0, len(utxoEntries))
	}
	{
		utxoEntries, err := chain.GetSpendableUtxosForPublicKey(pkBytes2, mempool)
		require.NoError(err)
		require.Equal(0, len(utxoEntries))
	}
	{
		utxoEntries, err := chain.GetSpendableUtxosForPublicKey(pkBytes3, mempool)
		require.NoError(err)
		require.Equal(0, len(utxoEntries))
	}

	// Re-add all of the transactions to the mempool so we can mine them into a block.
	{
		for _, burnTxn := range bitcoinExchangeTxns {
			err := mempool.removeTransaction(burnTxn, false /*removeRedeemers*/)
			require.NoError(err)
			txDescsAdded, err := mempool.processTransaction(
				burnTxn, true /*allowOrphan*/, true /*rateLimit*/, 0, /*peerID*/
				true /*verifySignatures*/)
			require.NoError(err)
			require.Equal(1, len(txDescsAdded))
			require.Equal(0, len(mempool.immatureBitcoinTxns))
		}
	}

	// Mine a block with all the mempool transactions.
	//
	// Set the BitcoinManager to be time-current.
	bitcoinManager.timeSource = NewFakeTimeSource(
		time.Unix(int64(bitcoinManager.HeaderTip().Header.TstampSecs), 0))
	miner.bitcoinManager = bitcoinManager
	params.BitcoinMinBurnWorkBlocks = 0
	// All the txns should be in the mempool already so mining a block should put
	// all those transactions in it. Note we need to mine two blocks since the first
	// one just makes the Ultra chain time-current.
	block, err := miner._mineAndProcessSingleBlock(0 /*threadIndex*/)
	require.NoError(err)
	block, err = miner._mineAndProcessSingleBlock(0 /*threadIndex*/)
	require.NoError(err)
	// Add one for the block reward. Now we have a meaty block.
	require.Equal(len(utxoOpsList)+1, len(block.Txns))
	// Reset the min burn work.
	params.BitcoinMinBurnWorkBlocks = minBurnBlocks

	_, _, _, _, _, _ = db, mempool, miner, bitcoinBlocks, bitcoinHeaders, bitcoinHeaderHeights
}

func TestComputeCommissionsAndRevenue(t *testing.T) {
	require := require.New(t)
	params := &UltranetTestnetParams

	{
		priceNanos := uint64(100)
		commissionsNanos, err := _computeCommissionsFromPriceNanos(priceNanos, params.CommissionBasisPoints)
		require.NoError(err)
		require.Equal(int64(4), int64(commissionsNanos))

		newCommissions, newRevenue, err := _computeCommissionsAndRevenueFromPayment(priceNanos+commissionsNanos, params.CommissionBasisPoints)
		require.NoError(err)
		require.Equal(int64(4), int64(newCommissions))
		require.Equal(int64(100), int64(newRevenue))
	}
	{
		priceNanos := uint64(99)
		commissionsNanos, err := _computeCommissionsFromPriceNanos(priceNanos, params.CommissionBasisPoints)
		require.NoError(err)
		require.Equal(int64(4), int64(commissionsNanos))

		newCommissions, newRevenue, err := _computeCommissionsAndRevenueFromPayment(priceNanos+commissionsNanos, params.CommissionBasisPoints)
		require.NoError(err)
		require.Equal(int64(4), int64(newCommissions))
		require.Equal(int64(99), int64(newRevenue))
	}
	{
		for ii := 0; ii < 1000; ii++ {
			priceNanos := uint64(ii)
			commissionsNanos, err := _computeCommissionsFromPriceNanos(priceNanos, params.CommissionBasisPoints)
			require.NoError(err)

			newCommissions, newRevenue, err := _computeCommissionsAndRevenueFromPayment(priceNanos+commissionsNanos, params.CommissionBasisPoints)
			require.NoError(err)
			require.Equal(int64(commissionsNanos), int64(newCommissions))
			require.Equal(int64(priceNanos), int64(newRevenue))
		}
		for ii := 10; ii < 100000000; ii *= 3 {
			priceNanos := uint64(ii)
			commissionsNanos, err := _computeCommissionsFromPriceNanos(priceNanos, params.CommissionBasisPoints)
			require.NoError(err)

			newCommissions, newRevenue, err := _computeCommissionsAndRevenueFromPayment(priceNanos+commissionsNanos, params.CommissionBasisPoints)
			require.NoError(err)
			require.Equal(int64(commissionsNanos), int64(newCommissions))
			require.Equal(int64(priceNanos), int64(newRevenue))
		}
	}
}
