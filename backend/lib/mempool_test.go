package lib

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func _filterOutBlockRewards(utxoEntries []*UtxoEntry) []*UtxoEntry {
	nonBlockRewardUtxos := []*UtxoEntry{}
	for _, utxoEntry := range utxoEntries {
		if !utxoEntry.IsBlockReward {
			nonBlockRewardUtxos = append(nonBlockRewardUtxos, utxoEntry)
		}
	}
	return nonBlockRewardUtxos
}

const (
	// go run transaction_util.go --manual_entropy_hex=0,1
	senderPkString      = "tUN2QTjWeSbrA9ZhEdvCPCgFVwNh7np3jEdWExWtgZRPBrb1C5TQs1"
	senderPrivString    = "tunT5KBDQhT7CmnBoUBnQ3Dyq8EszvoEqbi1uJdB5qV1veoy3fXtX"
	recipientPkString   = "tUN2Qga7689VUaJ8HKzKRCXCxiFtsEME7DJMmNEqPa5Xytpmm9gzft"
	recipientPrivString = "tunS8hS7ZhcxadnTi3qox3wnVbCBNFJ1hZ8f2niuktWyAZuzivsJA"
)

func _setupFiveBlocks(t *testing.T) (*Blockchain, *UltranetParams, []byte, []byte) {
	require := require.New(t)
	chain, params, db := NewTestBlockchain()
	_ = db

	blockB1 := _hexToBlock(t, blockB1Hex)
	blockB2 := _hexToBlock(t, blockB2Hex)
	blockB3 := _hexToBlock(t, blockB3Hex)
	blockB4 := _hexToBlock(t, blockB4Hex)
	blockB5 := _hexToBlock(t, blockB5Hex)

	// Connect 5 blocks so we have some block reward to spend.
	_shouldConnectBlock(blockB1, t, chain)
	_shouldConnectBlock(blockB2, t, chain)
	_shouldConnectBlock(blockB3, t, chain)
	_shouldConnectBlock(blockB4, t, chain)
	_shouldConnectBlock(blockB5, t, chain)

	// Define a sender and a recipient.
	senderPkBytes, _, err := Base58CheckDecode(senderPkString)
	require.NoError(err)
	recipientPkBytes, _, err := Base58CheckDecode(recipientPkString)
	require.NoError(err)

	return chain, params, senderPkBytes, recipientPkBytes
}

// Create a chain of transactions that is too long for our mempool to
// handle and ensure it gets rejected.
func TestMempoolLongChainOfDependencies(t *testing.T) {
	require := require.New(t)

	chain, _, senderPkBytes, recipientPkBytes := _setupFiveBlocks(t)

	// Create a transaction that sends 1 Ultra to the recipient as its
	// zeroth output.
	txn1 := _assembleBasicTransferTxnFullySigned(t, chain, 1, 0,
		senderPkString, recipientPkString, senderPrivString, nil)

	// Validate this txn.
	mp := NewTxPool(chain, 0 /* rateLimitFeeRateNanosPerKB */, 0 /* minFeeRateNanosPerKB */)
	_, err := mp.processTransaction(txn1, false /*allowOrphan*/, false /*rateLimit*/, 0 /*peerID*/, true /*verifySignatures*/)
	require.NoError(err)

	prevTxn := txn1
	// Create fewer than the maximum number of dependencies allowed by the
	// mempool and make sure all of these transactions are accepted. Then,
	// add one more transaction and make sure it's rejected.
	for ii := 0; ii < MaxTransactionDependenciesToProcess+1; ii++ {
		if ii%100 == 0 {
			fmt.Printf("TestMempoolRateLimit: Processing txn %d\n", ii)
		}
		prevTxnHash := prevTxn.Hash()
		newTxn := &MsgUltranetTxn{
			TxInputs: []*UltranetInput{
				&UltranetInput{
					TxID:  *prevTxnHash,
					Index: 0,
				},
			},
			TxOutputs: []*UltranetOutput{
				&UltranetOutput{
					PublicKey:   recipientPkBytes,
					AmountNanos: 1,
				},
			},
			TxnMeta:   &BasicTransferMetadata{},
			PublicKey: recipientPkBytes,
		}
		//_signTxn(t, newTxn, false [>isSender is false since this is the recipient<])

		_, err := mp.processTransaction(newTxn, false /*allowOrphan*/, false /*rateLimit*/, 0 /*peerID*/, false /*verifySignatures*/)
		if ii < MaxTransactionDependenciesToProcess {
			require.NoErrorf(err, "Error processing txn %d", ii)
		} else {
			require.Error(err, "Transaction %d should error due to too many dependencies", ii)
		}

		prevTxn = newTxn
	}
	_, _ = require, senderPkBytes
}

// Create a chain of transactions with zero fees. Have one public key just
// send 1 Ultra to itself over and over again. Then run all the txns
// through the mempool at once and verify that they are rejected when
// a ratelimit is set.
func TestMempoolRateLimit(t *testing.T) {
	require := require.New(t)

	// Set the LowFeeTxLimitBytesPerMinute very low so that we can trigger
	// rate limiting without having to generate too many transactions. 1000
	// bytes per ten minutes should be about 10 transactions.
	LowFeeTxLimitBytesPerTenMinutes = 1000

	chain, _, senderPkBytes, recipientPkBytes := _setupFiveBlocks(t)

	// Create a new pool object that sets the min fees to zero. This object should
	// accept all of the transactions we're about to create without fail.
	mpNoMinFees := NewTxPool(chain, 0 /* rateLimitFeeRateNanosPerKB */, 0 /* minFeeRateNanosPerKB */)

	// Create a transaction that sends 1 Ultra to the recipient as its
	// zeroth output.
	txn1 := _assembleBasicTransferTxnFullySigned(t, chain, 1, 0,
		senderPkString, recipientPkString, senderPrivString, nil)

	// Validate this txn with the no-fee mempool.
	_, err := mpNoMinFees.processTransaction(txn1, false /*allowOrphan*/, false /*rateLimit*/, 0 /*peerID*/, true /*verifySignatures*/)
	require.NoError(err)

	// If we set a min fee, the transactions should just be immediately rejected
	// if we set rateLimit to true.
	mpWithMinFee := NewTxPool(chain, 0 /* rateLimitFeeRateNanosPerKB */, 100 /* minFeeRateNanosPerKB */)
	_, err = mpWithMinFee.processTransaction(txn1, false /*allowOrphan*/, true /*rateLimit*/, 0 /*peerID*/, false /*verifySignatures*/)
	require.Error(err)
	require.Equal(TxErrorInsufficientFeeMinFee, err)
	// It shoud be accepted if we set rateLimit to false.
	_, err = mpWithMinFee.processTransaction(txn1, false /*allowOrphan*/, false /*rateLimit*/, 0 /*peerID*/, false /*verifySignatures*/)
	require.NoError(err)

	txnsCreated := []*MsgUltranetTxn{txn1}
	prevTxn := txn1
	// Create fewer than the maximum number of dependencies allowed by the
	// mempool to avoid transactions being rejected.
	for ii := 0; ii < 24; ii++ {
		if ii%100 == 0 {
			fmt.Printf("TestMempoolRateLimit: Processing txn %d\n", ii)
		}
		prevTxnHash := prevTxn.Hash()
		newTxn := &MsgUltranetTxn{
			TxInputs: []*UltranetInput{
				&UltranetInput{
					TxID:  *prevTxnHash,
					Index: 0,
				},
			},
			TxOutputs: []*UltranetOutput{
				&UltranetOutput{
					PublicKey:   recipientPkBytes,
					AmountNanos: 1,
				},
			},
			TxnMeta:   &BasicTransferMetadata{},
			PublicKey: recipientPkBytes,
		}
		//_signTxn(t, newTxn, false [>isSender is false since this is the recipient<])

		_, err := mpNoMinFees.processTransaction(newTxn, false /*allowOrphan*/, false /*rateLimit*/, 0 /*peerID*/, false /*verifySignatures*/)
		require.NoErrorf(err, "Error processing txn %d", ii)

		txnsCreated = append(txnsCreated, newTxn)
		prevTxn = newTxn
	}

	// Processing 24 transactions very quickly should cause our rate
	// limit to trigger if it's set even if we don't have a hard min
	// feerate set since 24 transactions should be ~2400 bytes.
	mpWithRateLimit := NewTxPool(chain, 100 /* rateLimitFeeRateNanosPerKB */, 0 /* minFeeRateNanosPerKB */)
	processingErrors := []error{}
	for _, txn := range txnsCreated {
		_, err := mpWithRateLimit.processTransaction(txn, false /*allowOrphan*/, true /*rateLimit*/, 0 /*peerID*/, false /*verifySignatures*/)
		processingErrors = append(processingErrors, err)
	}

	// If we got rate-limited, the first transaction should be error-free.
	firstError := processingErrors[0]
	require.NoError(firstError, "First transaction should not be rate-limited")
	// If we got rate-limited, there should be at least one transaction in
	// the list that has the rate-limited error.
	require.Contains(processingErrors, TxErrorInsufficientFeeRateLimit)

	_, _ = require, senderPkBytes
}

// A chain of transactions one after the other each spending the change
// output of the previous transaction with the same key.
func TestMempoolAugmentedUtxoViewTransactionChain(t *testing.T) {
	require := require.New(t)

	chain, params, senderPkBytes, recipientPkBytes := _setupFiveBlocks(t)

	// Create a transaction that spends very little so that it creates
	// a lot of change.
	txn1 := _assembleBasicTransferTxnFullySigned(t, chain, 1, 0,
		senderPkString, recipientPkString, senderPrivString, nil)

	// There should be two outputs, the second of which should be change to
	// the sender.
	require.Equal(2, len(txn1.TxOutputs))
	changeOutput := txn1.TxOutputs[1]
	require.Equal(senderPkString,
		Base58CheckEncode(changeOutput.PublicKey, false, chain.params))

	// Construct a second transaction that depends on the first. Send 1
	// Ultra to the recipient and set the rest as change.
	txn1Hash := txn1.Hash()
	txn2 := &MsgUltranetTxn{
		// Set the change of the previous transaction as input.
		TxInputs: []*UltranetInput{
			&UltranetInput{
				TxID:  *txn1Hash,
				Index: 1,
			},
		},
		TxOutputs: []*UltranetOutput{
			&UltranetOutput{
				PublicKey:   recipientPkBytes,
				AmountNanos: 1,
			}, &UltranetOutput{
				PublicKey:   senderPkBytes,
				AmountNanos: changeOutput.AmountNanos - 1,
			},
		},
		PublicKey: senderPkBytes,
		TxnMeta:   &BasicTransferMetadata{},
	}
	_signTxn(t, txn2, senderPrivString)

	// Construct a third transaction that depends on the second.
	txn2Hash := txn2.Hash()
	txn3 := &MsgUltranetTxn{
		// Set the change of the previous transaction as input.
		TxInputs: []*UltranetInput{
			&UltranetInput{
				TxID:  *txn2Hash,
				Index: 1,
			},
		},
		TxOutputs: []*UltranetOutput{
			&UltranetOutput{
				PublicKey:   recipientPkBytes,
				AmountNanos: 1,
			}, &UltranetOutput{
				PublicKey:   senderPkBytes,
				AmountNanos: changeOutput.AmountNanos - 2,
			},
		},
		PublicKey: senderPkBytes,
		TxnMeta:   &BasicTransferMetadata{},
	}
	_signTxn(t, txn3, senderPrivString)
	txn3Hash := txn3.Hash()

	// Construct a fourth transaction that spends an output from the recipient's
	// key sending the Ultra back to the sender with some change going back to
	// herself. Make the output come from the first and second transaction above.
	txn4 := &MsgUltranetTxn{
		// Set the change of the previous transaction as input.
		TxInputs: []*UltranetInput{
			&UltranetInput{
				TxID:  *txn1Hash,
				Index: 0,
			},
			&UltranetInput{
				TxID:  *txn2Hash,
				Index: 0,
			},
		},
		TxOutputs: []*UltranetOutput{
			&UltranetOutput{
				PublicKey:   senderPkBytes,
				AmountNanos: 1,
			}, &UltranetOutput{
				PublicKey:   recipientPkBytes,
				AmountNanos: 1,
			},
		},
		PublicKey: recipientPkBytes,
		TxnMeta:   &BasicTransferMetadata{},
	}
	_signTxn(t, txn4, recipientPrivString)
	txn4Hash := txn4.Hash()

	// Create a new pool object. Set the min fees to zero since we're
	// not testing that here.
	mp := NewTxPool(chain, 0 /* rateLimitFeeRateNanosPerKB */, 0 /* minFeeRateNanosPerKB */)

	// Process the first transaction.
	txD1, err := mp.processTransaction(txn1, false /*allowOrphan*/, false /*rateLimit*/, 0 /*peerID*/, true /*verifySignatures*/)
	require.NoError(err)
	{
		// Verify the augmented UtxoView has the change output from the
		// first transaction in it. This output should have the hash of
		// the first transaction with an index of 1.
		utxoView, err := mp.GetAugmentedUtxoViewForPublicKey(senderPkBytes)
		require.NoError(err)
		utxoEntries, err := utxoView.GetUnspentUtxoEntrysForPublicKey(senderPkBytes)
		require.NoError(err)
		// The block reward transactions should be included in the list of
		// outputs spendable by this public key.
		require.LessOrEqual(1, len(utxoEntries))
		nonBlockRewardUtxos := _filterOutBlockRewards(utxoEntries)
		require.Equal(1, len(nonBlockRewardUtxos))
		require.Equal(false, nonBlockRewardUtxos[0].isSpent)
		require.Equal(*txn1Hash, nonBlockRewardUtxos[0].utxoKey.TxID)
	}

	{
		// Verify that the recipient's payment is returned when we do a lookup
		// with her key.
		utxoView, err := mp.GetAugmentedUtxoViewForPublicKey(recipientPkBytes)
		require.NoError(err)
		utxoEntries, err := utxoView.GetUnspentUtxoEntrysForPublicKey(recipientPkBytes)
		require.NoError(err)
		// The number of utxos for the recipient should be exactly 1 since she doesn't
		// get any block rewards.
		require.Equal(1, len(utxoEntries))
		require.Equal(false, utxoEntries[0].isSpent)
		require.Equal(*txn1Hash, utxoEntries[0].utxoKey.TxID)
		require.Equal(uint64(1), utxoEntries[0].AmountNanos)
	}

	// Process the second transaction, which is dependent on the first.
	txD2, err := mp.processTransaction(txn2, false /*allowOrphan*/, false /*rateLimit*/, 0 /*peerID*/, true /*verifySignatures*/)
	require.NoError(err)
	{
		// Verify the augmented UtxoView has the change output from the second
		// transaction in it. The second transaction's output should have replaced
		// the utxo corresponding to the first transaction from before.
		utxoView, err := mp.GetAugmentedUtxoViewForPublicKey(senderPkBytes)
		require.NoError(err)
		utxoEntries, err := utxoView.GetUnspentUtxoEntrysForPublicKey(senderPkBytes)
		require.NoError(err)
		require.LessOrEqual(1, len(utxoEntries))
		nonBlockRewardUtxos := _filterOutBlockRewards(utxoEntries)
		require.Equal(1, len(nonBlockRewardUtxos))
		require.Equal(false, nonBlockRewardUtxos[0].isSpent)
		require.Equal(*txn2Hash, nonBlockRewardUtxos[0].utxoKey.TxID)
	}

	// Process the third transaction, which is dependent on the second.
	txD3, err := mp.processTransaction(txn3, false /*allowOrphan*/, false /*rateLimit*/, 0 /*peerID*/, true /*verifySignatures*/)
	require.NoError(err)
	{
		// Verify the augmented UtxoView has the change output from the third
		// transaction in it. The third transaction's output should have replaced
		// the utxo corresponding to the first transaction from before.
		utxoView, err := mp.GetAugmentedUtxoViewForPublicKey(senderPkBytes)
		require.NoError(err)
		utxoEntries, err := utxoView.GetUnspentUtxoEntrysForPublicKey(senderPkBytes)
		require.NoError(err)
		require.LessOrEqual(1, len(utxoEntries))
		nonBlockRewardUtxos := _filterOutBlockRewards(utxoEntries)
		require.Equal(1, len(nonBlockRewardUtxos))
		require.Equal(false, nonBlockRewardUtxos[0].isSpent)
		require.Equal(*txn3Hash, nonBlockRewardUtxos[0].utxoKey.TxID)
	}

	// Process the fourth transaction, which is dependent on the first and second.
	txD4, err := mp.processTransaction(txn4, false /*allowOrphan*/, false /*rateLimit*/, 0 /*peerID*/, true /*verifySignatures*/)
	require.NoError(err)
	{
		// When we lookup the utxos for the sender we should now have two, one
		// of which should have an amount of exactly 1.
		utxoView, err := mp.GetAugmentedUtxoViewForPublicKey(senderPkBytes)
		require.NoError(err)
		utxoEntries, err := utxoView.GetUnspentUtxoEntrysForPublicKey(senderPkBytes)
		require.NoError(err)
		require.LessOrEqual(2, len(utxoEntries))
		nonBlockRewardUtxos := _filterOutBlockRewards(utxoEntries)
		require.Equal(2, len(nonBlockRewardUtxos))
		// Aggregate the txids and amounts to check them.
		txids := []BlockHash{}
		amounts := []uint64{}
		for ii, utxoEntry := range nonBlockRewardUtxos {
			txids = append(txids, utxoEntry.utxoKey.TxID)
			amounts = append(amounts, utxoEntry.AmountNanos)
			require.Equalf(false, utxoEntry.isSpent, "index: %d", ii)
		}
		require.Contains(txids, *txn3Hash)
		require.Contains(txids, *txn4Hash)
		require.Contains(amounts, uint64(1))
	}

	{
		// Verify that the recipient's payments are returned when we do a lookup
		// with her key.
		utxoView, err := mp.GetAugmentedUtxoViewForPublicKey(recipientPkBytes)
		require.NoError(err)
		utxoEntries, err := utxoView.GetUnspentUtxoEntrysForPublicKey(recipientPkBytes)
		require.NoError(err)
		// She should have exactly 2 utxos at this point from txn3 and txn4.
		// Aggregate the txids and amounts to check them.
		require.Equal(2, len(utxoEntries))
		txids := []BlockHash{}
		for ii, utxoEntry := range utxoEntries {
			txids = append(txids, utxoEntry.utxoKey.TxID)
			require.Equalf(uint64(1), utxoEntry.AmountNanos, "index: %d", ii)
			require.Equalf(false, utxoEntry.isSpent, "index: %d", ii)
		}
		require.Contains(txids, *txn3Hash)
		require.Contains(txids, *txn4Hash)
	}

	_, _, _, _, _ = txD1, txD2, txD3, txD4, params
}
