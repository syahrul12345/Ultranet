package lib

import (
	"fmt"
	"math"
	"math/big"
	"reflect"
	"testing"

	"github.com/btcsuite/btcd/btcec"
	"github.com/dgraph-io/badger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func _getListingBigDelete(
	t *testing.T, pkString string, privString string, merchantID *BlockHash,
	tstamp uint32, index uint32, title string, body string, category string,
	tipComment []byte, isDeleted bool) *MsgUltranetListing {

	require := require.New(t)
	listingMessage := &MsgUltranetListing{
		MerchantID: merchantID,
		PublicKey:  mustBase58CheckDecode(pkString),

		TstampSecs:   tstamp,
		ListingIndex: index,

		Title:    []byte(title),
		Body:     []byte(body),
		Category: []byte(category),

		ThumbnailImage: []byte{2, 3, 31, 2, 3},
		ListingImages:  [][]byte{[]byte{2, 3, 31, 2, 3}, []byte{3, 34, 4, 3}},

		Deleted: isDeleted,

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
		TipComment:  tipComment,

		ShipsTo:   []byte{1, 23, 34, 4},
		ShipsFrom: []byte{34, 43, 3, 4},
		// Sign below.
	}

	privKeyBytes, _, err := Base58CheckDecode(privString)
	require.NoError(err)
	privKey, _ := btcec.PrivKeyFromBytes(btcec.S256(), privKeyBytes)
	require.NoError(err)
	listingBytesNoSignature, err := listingMessage.ToBytes(true /*preSignature*/)
	require.NoError(err)
	listingHashNoSignature := Sha256DoubleHash(listingBytesNoSignature)
	sig, err := privKey.Sign(listingHashNoSignature[:])
	require.NoError(err)
	listingMessage.Signature = sig

	return listingMessage
}

func _getListingBig(
	t *testing.T, pkString string, privString string, merchantID *BlockHash,
	tstamp uint32, index uint32, title string, body string, category string,
	tipComment []byte) *MsgUltranetListing {

	return _getListingBigDelete(t, pkString, privString, merchantID,
		tstamp, index, title, body, category, tipComment, false /*isDeleted*/)
}

func _getListing(
	t *testing.T, pkString string, privString string, merchantID *BlockHash,
	tstamp uint32, index uint32, title string, body string, category string) *MsgUltranetListing {

	return _getListingBig(
		t, pkString, privString, merchantID, tstamp, index, title, body,
		category, []byte{1, 2, 2, 3, 6, 7, 83, 1})
}

func _countNumKeywordListingMappings(db *badger.DB, kwType KeywordType) int {
	dbPrefix := _prefixForKeywordListingSearch(kwType, []byte{})
	keysFound, _ := _enumerateKeysForPrefix(db, dbPrefix)
	return len(keysFound)
}

func _countNumKeywordGlobalMappings(db *badger.DB, kwType KeywordType) int {
	dbPrefix := _keyForGlobalKeywordCount(kwType, []byte{})
	keysFound, _ := _enumerateKeysForPrefix(db, dbPrefix)
	return len(keysFound)
}

// Create a blockchain, register some merchants
func TestListingManager(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	chain, params, db := NewLowDifficultyBlockchain()
	mempool, miner := NewTestMiner(t, chain, params, true /*isSender*/)

	// Set the listing-related params to low values so we can test hitting
	// them.
	params.MaxMerchantsToIndex = 3
	params.MaxListingsPerMerchant = 2
	params.MaxMerchantStorageBytes = 15000 // 15KB
	params.MaxListingSizeBytes = 10000     // 10KB
	params.MaxListingTitleLengthBytes = 100
	params.MaxListingBodyLengthBytes = 100
	params.MaxListingCategoryLengthBytes = 100

	// Mine a few blocks to give the senderPkString some money.
	block, err := miner._mineAndProcessSingleBlock(0 /*threadIndex*/)
	require.NoError(err)
	_, _ = block, mempool
	block, err = miner._mineAndProcessSingleBlock(0 /*threadIndex*/)
	require.NoError(err)

	// Setup some convenience functions for the test.
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
		// If we have a username then this is assumed to be a register merchant txn.
		// In thi scase add to the merchantids, usernames, and publickeys.
		if username != "" {
			merchantID := txns[len(txns)-1].Hash()
			merchantIDs = append(merchantIDs, merchantID)
			usernames = append(usernames, username)
			publicKeys = append(publicKeys, senderPk)
		}
	}

	// Register four merchants, which is one more than what the ListingManager will
	// index.
	m0Pub := "tUN2RExHhcCWqXqT9r7syGupJS6hxrBPDQMssSph6ki1FZLJTczUm4"
	m0Priv := "tunSykM1Si6Wab5mRKBDu7YK5ubpBxr1ciGiiDXmSpMATB12sAawx"
	m1Pub := "tUN2RUx1U7By7i2CZn5sZEEb5jjEHfoyc4Nvk2P9gc6Lf8Bc29xzzB"
	m1Priv := "tunSJ83kV4PNkC7MPEgbmKWNZeJk1mTbjwXUh9oy7kyBLRWsgFjVw"
	m2Pub := "tUN2NazDYX2zmbPMXagebSjHmK6QcybHBGRvFMrHDRgn5Us8YPs1De"
	m2Priv := "tunTBiMhRjKVmeK6bF8kJFQpmxH2UnTweB8zYsvH3bJPjyVMZr5kS"
	m3Pub := "tUN2Q3nYf8KNgZ5q3ftFeEq3fRFpB8CCzXTW5KV4kGrCm4LEvdv67e"
	m3Priv := "tunSRyKa6shh2S6LH3WsFa6jtT42ktUgVcSdZFqTsMBy3KPnHC9kR"
	registerOrTransfer("", senderPkString, m0Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m1Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m2Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m3Pub, senderPrivString)
	registerOrTransfer("m0", m0Pub, "", m0Priv)
	registerOrTransfer("m1", m1Pub, "", m1Priv)
	registerOrTransfer("m2", m2Pub, "", m2Priv)
	registerOrTransfer("m3", m3Pub, "", m3Priv)

	// Give m1 a lower score than the others.
	require.Equal(4, len(merchantIDs))
	merchantID1 := merchantIDs[1]
	merchantEntry1 := DbGetMerchantEntryForMerchantID(db, merchantID1)
	require.NotNil(merchantEntry1)
	newScore := ScoreMinusImpact(merchantEntry1.Stats.MerchantScore, 1, chain.blockTip().Header.Height, params)
	merchantEntry1.Stats.MerchantScore = newScore
	db.Update(func(dbTx *badger.Txn) error {
		require.NoError(DbDeleteUnmodifiedMappingsForMerchantIDWithTxn(dbTx, merchantID1))
		require.NoError(DbPutMappingsForMerchantWithTxn(dbTx, merchantID1, merchantEntry1))
		return nil
	})

	// Create a ListingManager, start it, and call Update(). This should load the
	// data for three of the merchants above into the listing index. Since they all
	// have the same score, it doesn't matter which three get loaded.
	listingManager, err := NewListingManager(db, chain, params)
	require.NoError(err)
	listingManager.Start()
	err = listingManager.Update()
	require.NoError(err)
	// Verify that there are three merchants in the listing index and that m4
	// is not present.
	listingMerchantIDs, listingMerchantScores, listingMerchantEntries, err :=
		DbGetListingTopMerchants(db, math.MaxUint64, false /*noMerchantEntries*/)
	require.NoError(err)
	require.Equal(3, len(listingMerchantIDs))
	require.Contains(listingMerchantIDs, merchantIDs[0])
	require.NotContains(listingMerchantIDs, merchantID1)
	require.Contains(listingMerchantIDs, merchantIDs[2])
	require.Contains(listingMerchantIDs, merchantIDs[3])
	_, _, _ = listingMerchantIDs, listingMerchantScores, listingMerchantEntries
	// The current hash should be equal to the block tip.
	require.Equal(*(chain.blockTip().Hash), *DbGetListingBlockHash(db))
	// There should be a merchant info for each merchant with zero for numBytes
	for ii, mid := range listingMerchantIDs {
		info := DbGetListingMerchantIDInfo(db, mid)
		require.Equal(uint64(0), info.NumBytes, "NumBytes for listing merchant %d should be 0", ii)
	}

	// Create listings for each merchant and process them.
	m0Listing0 := _getListing(
		t, m0Pub, m0Priv, merchantIDs[0], 0 /*tstamp*/, 0, /*index*/
		"this is title0_0 m0Title ok01 01293", "hello from body0_0 m0Body 9823", "woo UPPER category 0")
	m2Listing0 := _getListing(
		t, m2Pub, m2Priv, merchantIDs[2], 0 /*tstamp*/, 0, /*index*/
		"this is Title2_0 m2Title ok 123", "hello from m2Body Body2_0", "woo UPPER category 0")
	m3Listing0 := _getListingBig(
		t, m3Pub, m3Priv, merchantIDs[3], 0 /*tstamp*/, 0, /*index*/
		"this is Title3_0 m3Title ok", "hello from Hey\000there Body3_0 m3Body 12", "woo UPPER category 0",
		make([]byte, params.MaxListingSizeBytes-1000))
	require.NoError(listingManager.ProcessListing(m0Listing0, true /*verifySignatures*/))
	require.NoError(listingManager.ProcessListing(m2Listing0, true /*verifySignatures*/))
	require.NoError(listingManager.ProcessListing(m3Listing0, true /*verifySignatures*/))

	// Create two more listings for merchant0. Adding the third should fail due
	// to it having an index too high. See above for MaxListingsPerMerchant = 2.
	m0Listing1 := _getListing(
		t, m0Pub, m0Priv, merchantIDs[0], 0 /*tstamp*/, 1, /*index*/
		"this is Title0_0 m0Title ok", "m0Body hello from Body0_0 m0Body alksdj m0Body", "woo Hey\000therecat category_0_0")
	m0Listing2 := _getListing(
		t, m0Pub, m0Priv, merchantIDs[0], 0 /*tstamp*/, 2, /*index*/
		"this is Title0_0 m0Title ok alskdj", "hello from Body0_0 m0Body", "woo category_0_0")
	require.NoError(listingManager.ProcessListing(m0Listing1, true /*verifySignatures*/))
	err = listingManager.ProcessListing(m0Listing2, true /*verifySignatures*/)
	require.Error(err)
	require.Contains(err.Error(), ListingErrorInvalidListingIndex)

	// Replacing a listing without a newer tstamp should fail.
	err = listingManager.ProcessListing(m0Listing0, true /*verifySignatures*/)
	require.Error(err)
	require.Contains(err.Error(), ListingErrorMoreRecentListingWithSameIndexExists)

	// Replacing a listing with a newer timestamp should succeed.
	m0Listing0Replacement := _getListing(
		t, m0Pub, m0Priv, merchantIDs[0], 1 /*tstamp*/, 0, /*index*/
		"this is Title0_0 m0Title ok", "hello from Body0_0 m0Body", "woo category_0_0")
	require.NoError(listingManager.ProcessListing(m0Listing0Replacement, true /*verifySignatures*/))

	// Check that the size consumed for m0 is accurate.
	{
		m0StorageBytes := uint64(0)
		bb, _ := m0Listing0Replacement.ToBytes(false)
		m0StorageBytes += uint64(len(bb))
		bb, _ = m0Listing1.ToBytes(false)
		m0StorageBytes += uint64(len(bb))
		m0info := DbGetListingMerchantIDInfo(db, merchantIDs[0])

		require.Equal(m0StorageBytes, m0info.NumBytes)
	}

	// A listing with a bad signature should fail even if there's room for it.
	// Non-matching public key.
	m2Listing1 := _getListing(
		t, m1Pub, m1Priv, merchantIDs[2], 1 /*tstamp*/, 1, /*index*/
		"this is Title2_0 m2Title ok 123", "hello from body2_0 m2body", "woo category_2_0 123")
	err = listingManager.ProcessListing(m2Listing1, true /*verifySignatures*/)
	require.Error(err)
	require.Contains(err.Error(), ListingErrorMerchantPublicKeyDoesNotMatch)
	// Matching public key but bad signature.
	m2Listing1 = _getListing(
		t, m2Pub, m1Priv, merchantIDs[2], 1 /*tstamp*/, 1, /*index*/
		"this is Title2_0 m2Title ok 123", "hello from body2_0 m2body", "woo category_2_0 123")
	err = listingManager.ProcessListing(m2Listing1, true /*verifySignatures*/)
	require.Error(err)
	require.Contains(err.Error(), ListingErrorSignatureNotValid)
	// Should work if we're not checking signatures.
	require.NoError(listingManager.ProcessListing(m2Listing1, false /*verifySignatures*/))

	// Adding a listing that exceeds the size should error.
	m3Listing1Large := _getListingBig(
		t, m3Pub, m3Priv, merchantIDs[3], 1 /*tstamp*/, 1, /*index*/
		"this is Title2_0 m3Title ok 123", "hello from body2_0 m3body", "woo category_2_0 123",
		make([]byte, params.MaxListingSizeBytes))
	// Should fail if it's adding to the size.
	err = listingManager.ProcessListing(m3Listing1Large, true /*verifySignatures*/)
	require.Error(err)
	require.Contains(err.Error(), ListingErrorListingExceedsMaxSize)
	// Adding too many small listings should also fail.
	m3Listing1Large = _getListingBig(
		t, m3Pub, m3Priv, merchantIDs[3], 1 /*tstamp*/, 1, /*index*/
		"this is Title2_0 m3Title ok 123", "hello from body2_0 m3body", "woo category_2_0 123",
		make([]byte, params.MaxListingSizeBytes-1000))
	err = listingManager.ProcessListing(m3Listing1Large, true /*verifySignatures*/)
	require.Error(err)
	require.Contains(err.Error(), ListingErrorAddingListingWouldCauseMaxMerchantStorageToBeEceeded)

	// At this point, we should have the following listings in our db:
	// - m0Listing0Replacement
	// - m0Listing1
	// - m2Listing0
	// - m2Listing1
	// - m3Listing0

	// Check that some keywords exist.
	{
		// Keyword should be in all titles.
		currentKeyword := []byte("this\000")
		kwMerchantIDs, kwListingIndexes, kwNumOccurrences, err := DbGetListingIDsContainingKeyword(db, TitleKeyword, currentKeyword)
		_ = kwListingIndexes
		require.NoError(err)
		require.Equal(5, len(kwMerchantIDs))
		require.Contains(kwMerchantIDs, merchantIDs[0])
		require.NotContains(kwMerchantIDs, merchantIDs[1])
		require.Contains(kwMerchantIDs, merchantIDs[2])
		require.Contains(kwMerchantIDs, merchantIDs[3])

		require.Equal(5, len(kwNumOccurrences))
		require.Equal(uint64(1), kwNumOccurrences[0])
		require.Equal(uint64(1), kwNumOccurrences[1])
		require.Equal(uint64(1), kwNumOccurrences[2])
		require.Equal(uint64(1), kwNumOccurrences[3])
		require.Equal(uint64(1), kwNumOccurrences[4])

		// Check that total count is in-line.
		require.Equal(uint64(5), DbGetGlobalKeywordCountForKeywordType(db, TitleKeyword, currentKeyword))
	}
	{
		// Keyword should be in all bodies.
		currentKeyword := []byte("hello\000")
		kwMerchantIDs, kwListingIndexes, kwNumOccurrences, err := DbGetListingIDsContainingKeyword(db, BodyKeyword, currentKeyword)
		_ = kwListingIndexes
		require.NoError(err)
		require.Equal(5, len(kwMerchantIDs))
		require.Contains(kwMerchantIDs, merchantIDs[0])
		require.NotContains(kwMerchantIDs, merchantIDs[1])
		require.Contains(kwMerchantIDs, merchantIDs[2])
		require.Contains(kwMerchantIDs, merchantIDs[3])

		require.Equal(5, len(kwNumOccurrences))
		require.Equal(uint64(1), kwNumOccurrences[0])
		require.Equal(uint64(1), kwNumOccurrences[1])
		require.Equal(uint64(1), kwNumOccurrences[2])
		require.Equal(uint64(1), kwNumOccurrences[3])
		require.Equal(uint64(1), kwNumOccurrences[4])

		// Check that total count is in-line.
		require.Equal(uint64(5), DbGetGlobalKeywordCountForKeywordType(db, BodyKeyword, currentKeyword))
	}
	{
		// Keyword present in category should work because we index it
		// as part of the body.
		currentKeyword := []byte("woo\000")
		kwMerchantIDs, kwListingIndexes, kwNumOccurrences, err := DbGetListingIDsContainingKeyword(db, BodyKeyword, currentKeyword)
		_ = kwListingIndexes
		require.NoError(err)
		require.Equal(5, len(kwMerchantIDs))
		require.Contains(kwMerchantIDs, merchantIDs[0])
		require.NotContains(kwMerchantIDs, merchantIDs[1])
		require.Contains(kwMerchantIDs, merchantIDs[2])
		require.Contains(kwMerchantIDs, merchantIDs[3])

		require.Equal(5, len(kwNumOccurrences))
		require.Equal(uint64(1), kwNumOccurrences[0])
		require.Equal(uint64(1), kwNumOccurrences[1])
		require.Equal(uint64(1), kwNumOccurrences[2])
		require.Equal(uint64(1), kwNumOccurrences[3])
		require.Equal(uint64(1), kwNumOccurrences[4])

		// Check that total count is in-line.
		require.Equal(uint64(5), DbGetGlobalKeywordCountForKeywordType(db, BodyKeyword, currentKeyword))
	}
	{
		// Keyword present in title for subset of listings should work.
		currentKeyword := []byte("m0title\000")
		kwMerchantIDs, kwListingIndexes, kwNumOccurrences, err := DbGetListingIDsContainingKeyword(db, TitleKeyword, currentKeyword)
		require.NoError(err)
		require.Equal(2, len(kwMerchantIDs))
		require.Equal(kwMerchantIDs, []*BlockHash{merchantIDs[0], merchantIDs[0]})

		require.Equal(2, len(kwListingIndexes))
		require.Equal(kwListingIndexes, []uint32{0, 1})

		require.Equal(2, len(kwNumOccurrences))
		require.Equal(kwNumOccurrences, []uint64{1, 1})

		// Check that total count is in-line.
		require.Equal(uint64(2), DbGetGlobalKeywordCountForKeywordType(db, TitleKeyword, currentKeyword))
	}
	{
		// Keyword present in body for subset of listings should work with multiple occurrences.
		kwMerchantIDs, kwListingIndexes, kwNumOccurrences, err := DbGetListingIDsContainingKeyword(db, BodyKeyword, []byte("m0body\000"))
		require.NoError(err)
		require.Equal(2, len(kwMerchantIDs))
		require.Equal(kwMerchantIDs, []*BlockHash{merchantIDs[0], merchantIDs[0]})

		require.Equal(2, len(kwListingIndexes))
		require.Equal(kwListingIndexes, []uint32{0, 1})

		require.Equal(2, len(kwNumOccurrences))
		require.Equal(kwNumOccurrences, []uint64{1, 3})
	}
	{
		// Keyword containing null character should be escaped.
		kwMerchantIDs, kwListingIndexes, kwNumOccurrences, err := DbGetListingIDsContainingKeyword(db, BodyKeyword, []byte("hey0there\000"))
		require.NoError(err)
		require.Equal(1, len(kwMerchantIDs))
		require.Equal(kwMerchantIDs, []*BlockHash{merchantIDs[3]})

		require.Equal(1, len(kwListingIndexes))
		require.Equal(kwListingIndexes, []uint32{0})

		require.Equal(1, len(kwNumOccurrences))
		require.Equal(kwNumOccurrences, []uint64{1})
	}
	{
		// Keyword containing null character in category should be escaped.
		kwMerchantIDs, kwListingIndexes, kwNumOccurrences, err := DbGetListingIDsContainingKeyword(db, BodyKeyword, []byte("hey0therecat\000"))
		require.NoError(err)
		require.Equal(1, len(kwMerchantIDs))
		require.Equal(kwMerchantIDs, []*BlockHash{merchantIDs[0]})

		require.Equal(1, len(kwListingIndexes))
		require.Equal(kwListingIndexes, []uint32{1})

		require.Equal(1, len(kwNumOccurrences))
		require.Equal(kwNumOccurrences, []uint64{1})
	}
	{
		// Search for category that has whitespace in it should work because
		// we don't split category on whitespace.
		kwMerchantIDs, kwListingIndexes, kwNumOccurrences, err := DbGetListingIDsContainingKeyword(db, CategoryKeyword, []byte("woo upper category 0\000"))
		require.NoError(err)
		// Only 2 because m0's listing with index 0 was replaced
		require.Equal(2, len(kwMerchantIDs))
		require.Contains(kwMerchantIDs, merchantIDs[2])
		require.Contains(kwMerchantIDs, merchantIDs[3])

		require.Equal(2, len(kwListingIndexes))
		require.Equal(kwListingIndexes, []uint32{0, 0})

		require.Equal(2, len(kwNumOccurrences))
		require.Equal(kwNumOccurrences, []uint64{1, 1})
	}
	{
		// Search for category with null character and whitespace in it should work because
		// we don't split category on whitespace.
		currentKeyword := []byte("woo hey0therecat category_0_0\000")
		kwMerchantIDs, kwListingIndexes, kwNumOccurrences, err := DbGetListingIDsContainingKeyword(db, CategoryKeyword, currentKeyword)
		require.NoError(err)
		// Only 2 because m0's listing with index 0 was replaced
		require.Equal(1, len(kwMerchantIDs))
		require.Contains(kwMerchantIDs, merchantIDs[0])

		require.Equal(1, len(kwListingIndexes))
		require.Equal(kwListingIndexes, []uint32{1})

		require.Equal(1, len(kwNumOccurrences))
		require.Equal(kwNumOccurrences, []uint64{1})

		// Check that total count is in-line.
		require.Equal(uint64(1), DbGetGlobalKeywordCountForKeywordType(db, CategoryKeyword, currentKeyword))
	}

	// This should get all category/title/body keywords in total.
	require.Equal(5, _countNumKeywordListingMappings(db, CategoryKeyword))
	require.Less(0, _countNumKeywordListingMappings(db, TitleKeyword))
	require.Less(0, _countNumKeywordListingMappings(db, BodyKeyword))
	// Because m20 and m30 have the same category.
	require.Equal(4, _countNumKeywordGlobalMappings(db, CategoryKeyword))
	require.Less(0, _countNumKeywordGlobalMappings(db, TitleKeyword))
	require.Less(0, _countNumKeywordGlobalMappings(db, BodyKeyword))

	// Check the top categories.
	topCats, counts, err := DbGetListingTopCategories(db, math.MaxUint64)
	require.NoError(err)
	require.Equal(4, len(topCats))
	require.Equal("woo upper category 0\000", string(topCats[0]))
	require.Equal([]uint64{2, 1, 1, 1}, counts)

	// Verify that the zeroth listing for m0 was actually stored.
	{
		listingMessage := DbGetListingMessage(db, merchantIDs[0], 0)
		require.NotNil(listingMessage)
		require.True(reflect.DeepEqual(listingMessage, m0Listing0Replacement))
	}
	// Verify m2Listing0 was actually stored
	{
		listingMessage := DbGetListingMessage(db, merchantIDs[2], 0)
		require.NotNil(listingMessage)
		require.True(reflect.DeepEqual(listingMessage, m2Listing0))
	}

	// Verify all the listing hashes are present in the db.
	{
		keysFound, _ := _enumerateKeysForPrefix(
			db, _PrefixListingHashToMerchantIDListingIndexTstampSecs)
		require.Equal(5, len(keysFound))
	}

	// Roll back all of the above using the utxoOps from each transaction.
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

	// Mine a block to force the ListingManager to actually do work next time
	// we call Update()
	block, err = miner._mineAndProcessSingleBlock(0 /*threadIndex*/)
	require.NoError(err)

	// Now call Update() on the ListingManager again. This should result in the
	// deletion of all of the mappings in the db.
	err = listingManager.Update()
	require.NoError(err)
	// Check that all of the mappings have been erased.
	{
		// Check the hash has been updated.
		hash, err := block.Hash()
		require.NoError(err)
		require.Equal(*hash, *DbGetListingBlockHash(db))
		// Check there are no merchantids in the <count | merchantid> mapping
		listingMerchantIDs, listingMerchantScores, listingMerchantEntries, err :=
			DbGetListingTopMerchants(db, math.MaxUint64, false /*noMerchantEntries*/)
		require.NoError(err)
		require.Equal(0, len(listingMerchantIDs))
		require.Equal(0, len(listingMerchantScores))
		require.Equal(0, len(listingMerchantEntries))
		// Check there are no merchantids in the <merchantID> -> info mapping
		info0 := DbGetListingMerchantIDInfo(db, merchantIDs[0])
		require.Nil(info0)
		info2 := DbGetListingMerchantIDInfo(db, merchantIDs[2])
		require.Nil(info2)
		info3 := DbGetListingMerchantIDInfo(db, merchantIDs[3])
		require.Nil(info3)
		// Check there is no listing data stored.
		listing00 := DbGetListingMessage(db, merchantIDs[0], 0)
		require.Nil(listing00)
		listing01 := DbGetListingMessage(db, merchantIDs[0], 1)
		require.Nil(listing01)
		listing20 := DbGetListingMessage(db, merchantIDs[2], 0)
		require.Nil(listing20)
		listing21 := DbGetListingMessage(db, merchantIDs[2], 1)
		require.Nil(listing21)
		listing30 := DbGetListingMessage(db, merchantIDs[3], 0)
		require.Nil(listing30)
		// Check there are no keyword mappings left.
		require.Equal(0, _countNumKeywordListingMappings(db, CategoryKeyword))
		require.Equal(0, _countNumKeywordListingMappings(db, TitleKeyword))
		require.Equal(0, _countNumKeywordListingMappings(db, BodyKeyword))
		require.Equal(0, _countNumKeywordGlobalMappings(db, CategoryKeyword))
		require.Equal(0, _countNumKeywordGlobalMappings(db, TitleKeyword))
		require.Equal(0, _countNumKeywordGlobalMappings(db, BodyKeyword))
		// Do one last special check for the top categories.
		topCats, counts, err := DbGetListingTopCategories(db, math.MaxUint64)
		require.NoError(err)
		require.Equal(0, len(topCats))
		require.Equal(0, len(counts))
		// Verify all the listing hashes were deleted from the db.
		{
			keysFound, _ := _enumerateKeysForPrefix(
				db, _PrefixListingHashToMerchantIDListingIndexTstampSecs)
			require.Equal(0, len(keysFound))
		}
	}
}

func TestListingManagerDeleteListings(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	chain, params, db := NewLowDifficultyBlockchain()
	mempool, miner := NewTestMiner(t, chain, params, true /*isSender*/)

	// Set the listing-related params to low values so we can test hitting
	// them.
	params.MaxMerchantsToIndex = 3
	params.MaxListingsPerMerchant = 4
	params.MaxMerchantStorageBytes = 15000 // 15KB
	params.MaxListingSizeBytes = 10000     // 10KB
	params.MaxListingTitleLengthBytes = 100
	params.MaxListingBodyLengthBytes = 100
	params.MaxListingCategoryLengthBytes = 100

	// Mine a few blocks to give the senderPkString some money.
	block, err := miner._mineAndProcessSingleBlock(0 /*threadIndex*/)
	require.NoError(err)
	_, _ = block, mempool
	block, err = miner._mineAndProcessSingleBlock(0 /*threadIndex*/)
	require.NoError(err)

	// Setup some convenience functions for the test.
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
		// If we have a username then this is assumed to be a register merchant txn.
		// In thi scase add to the merchantids, usernames, and publickeys.
		if username != "" {
			merchantID := txns[len(txns)-1].Hash()
			merchantIDs = append(merchantIDs, merchantID)
			usernames = append(usernames, username)
			publicKeys = append(publicKeys, senderPk)
		}
	}

	// Register four merchants, which is one more than what the ListingManager will
	// index.
	m0Pub := "tUN2RExHhcCWqXqT9r7syGupJS6hxrBPDQMssSph6ki1FZLJTczUm4"
	m0Priv := "tunSykM1Si6Wab5mRKBDu7YK5ubpBxr1ciGiiDXmSpMATB12sAawx"
	m1Pub := "tUN2RUx1U7By7i2CZn5sZEEb5jjEHfoyc4Nvk2P9gc6Lf8Bc29xzzB"
	m1Priv := "tunSJ83kV4PNkC7MPEgbmKWNZeJk1mTbjwXUh9oy7kyBLRWsgFjVw"
	m2Pub := "tUN2NazDYX2zmbPMXagebSjHmK6QcybHBGRvFMrHDRgn5Us8YPs1De"
	m2Priv := "tunTBiMhRjKVmeK6bF8kJFQpmxH2UnTweB8zYsvH3bJPjyVMZr5kS"
	m3Pub := "tUN2Q3nYf8KNgZ5q3ftFeEq3fRFpB8CCzXTW5KV4kGrCm4LEvdv67e"
	m3Priv := "tunSRyKa6shh2S6LH3WsFa6jtT42ktUgVcSdZFqTsMBy3KPnHC9kR"
	registerOrTransfer("", senderPkString, m0Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m1Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m2Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m3Pub, senderPrivString)
	registerOrTransfer("m0", m0Pub, "", m0Priv)
	registerOrTransfer("m1", m1Pub, "", m1Priv)
	registerOrTransfer("m2", m2Pub, "", m2Priv)
	registerOrTransfer("m3", m3Pub, "", m3Priv)

	// Give m1 a lower score than the others.
	require.Equal(4, len(merchantIDs))
	merchantID1 := merchantIDs[1]
	merchantEntry1 := DbGetMerchantEntryForMerchantID(db, merchantID1)
	require.NotNil(merchantEntry1)
	newScore := ScoreMinusImpact(merchantEntry1.Stats.MerchantScore, 1, chain.blockTip().Header.Height, params)
	merchantEntry1.Stats.MerchantScore = newScore
	db.Update(func(dbTx *badger.Txn) error {
		require.NoError(DbDeleteUnmodifiedMappingsForMerchantIDWithTxn(dbTx, merchantID1))
		require.NoError(DbPutMappingsForMerchantWithTxn(dbTx, merchantID1, merchantEntry1))
		return nil
	})

	// Create a ListingManager, start it, and call Update(). This should load the
	// data for three of the merchants above into the listing index. Since they all
	// have the same score, it doesn't matter which three get loaded.
	listingManager, err := NewListingManager(db, chain, params)
	require.NoError(err)
	listingManager.Start()
	err = listingManager.Update()
	require.NoError(err)
	// Verify that there are three merchants in the listing index and that m4
	// is not present.
	listingMerchantIDs, listingMerchantScores, listingMerchantEntries, err :=
		DbGetListingTopMerchants(db, math.MaxUint64, false /*noMerchantEntries*/)
	require.NoError(err)
	require.Equal(3, len(listingMerchantIDs))
	require.Contains(listingMerchantIDs, merchantIDs[0])
	require.NotContains(listingMerchantIDs, merchantID1)
	require.Contains(listingMerchantIDs, merchantIDs[2])
	require.Contains(listingMerchantIDs, merchantIDs[3])
	_, _, _ = listingMerchantIDs, listingMerchantScores, listingMerchantEntries
	// The current hash should be equal to the block tip.
	require.Equal(*(chain.blockTip().Hash), *DbGetListingBlockHash(db))
	// There should be a merchant info for each merchant with zero for numBytes
	for ii, mid := range listingMerchantIDs {
		info := DbGetListingMerchantIDInfo(db, mid)
		require.Equal(uint64(0), info.NumBytes, "NumBytes for listing merchant %d should be 0", ii)
	}

	// Create listings for each merchant and process them.
	m0Listing0 := _getListing(
		t, m0Pub, m0Priv, merchantIDs[0], 0 /*tstamp*/, 0, /*index*/
		"this is title0_0 m0Title ok01 01293", "hello from body0_0 m0Body 9823", "woo UPPER category 0")
	m2Listing0 := _getListing(
		t, m2Pub, m2Priv, merchantIDs[2], 0 /*tstamp*/, 0, /*index*/
		"this is Title2_0 m2Title ok 123", "hello from m2Body Body2_0", "woo UPPER category 0")
	m3Listing0 := _getListingBig(
		t, m3Pub, m3Priv, merchantIDs[3], 0 /*tstamp*/, 0, /*index*/
		"this is Title3_0 m3Title ok", "hello from Hey\000there Body3_0 m3Body 12", "woo UPPER category 0",
		make([]byte, params.MaxListingSizeBytes-1000))
	require.NoError(listingManager.ProcessListing(m0Listing0, true /*verifySignatures*/))
	require.NoError(listingManager.ProcessListing(m2Listing0, true /*verifySignatures*/))
	require.NoError(listingManager.ProcessListing(m3Listing0, true /*verifySignatures*/))

	// Create two more listings for merchant0.
	m0Listing1 := _getListing(
		t, m0Pub, m0Priv, merchantIDs[0], 0 /*tstamp*/, 1, /*index*/
		"this is Title0_0 m0Title ok", "m0Body hello from Body0_0 m0Body alksdj m0Body", "woo Hey\000therecat category_0_0")
	require.NoError(listingManager.ProcessListing(m0Listing1, true /*verifySignatures*/))

	// Replacing a listing without a newer tstamp should fail.
	err = listingManager.ProcessListing(m0Listing0, true /*verifySignatures*/)
	require.Error(err)
	require.Contains(err.Error(), ListingErrorMoreRecentListingWithSameIndexExists)

	// Replacing a listing with a newer timestamp should succeed.
	m0Listing0Replacement := _getListing(
		t, m0Pub, m0Priv, merchantIDs[0], 1 /*tstamp*/, 0, /*index*/
		"this is Title0_0 m0Title ok", "hello from Body0_0 m0Body", "woo category_0_0")
	require.NoError(listingManager.ProcessListing(m0Listing0Replacement, true /*verifySignatures*/))

	// Check that the size consumed for m0 is accurate.
	{
		m0StorageBytes := uint64(0)
		bb, _ := m0Listing0Replacement.ToBytes(false)
		m0StorageBytes += uint64(len(bb))
		bb, _ = m0Listing1.ToBytes(false)
		m0StorageBytes += uint64(len(bb))
		m0info := DbGetListingMerchantIDInfo(db, merchantIDs[0])

		require.Equal(m0StorageBytes, m0info.NumBytes)
	}

	// A listing with a bad signature should fail even if there's room for it.
	// Non-matching public key.
	m2Listing1 := _getListing(
		t, m1Pub, m1Priv, merchantIDs[2], 1 /*tstamp*/, 1, /*index*/
		"this is Title2_0 m2Title ok 123", "hello from body2_0 m2body", "woo category_2_0 123")
	err = listingManager.ProcessListing(m2Listing1, true /*verifySignatures*/)
	require.Error(err)
	require.Contains(err.Error(), ListingErrorMerchantPublicKeyDoesNotMatch)
	// Matching public key but bad signature.
	m2Listing1 = _getListing(
		t, m2Pub, m1Priv, merchantIDs[2], 1 /*tstamp*/, 1, /*index*/
		"this is Title2_0 m2Title ok 123", "hello from body2_0 m2body", "woo category_2_0 123")
	err = listingManager.ProcessListing(m2Listing1, true /*verifySignatures*/)
	require.Error(err)
	require.Contains(err.Error(), ListingErrorSignatureNotValid)
	// Should work if we're not checking signatures.
	require.NoError(listingManager.ProcessListing(m2Listing1, false /*verifySignatures*/))

	// Adding a listing that exceeds the size should error.
	m3Listing1Large := _getListingBig(
		t, m3Pub, m3Priv, merchantIDs[3], 1 /*tstamp*/, 1, /*index*/
		"this is Title2_0 m3Title ok 123", "hello from body2_0 m3body", "woo category_2_0 123",
		make([]byte, params.MaxListingSizeBytes))
	// Should fail if it's adding to the size.
	err = listingManager.ProcessListing(m3Listing1Large, true /*verifySignatures*/)
	require.Error(err)
	require.Contains(err.Error(), ListingErrorListingExceedsMaxSize)
	// Adding too many small listings should also fail.
	m3Listing1Large = _getListingBig(
		t, m3Pub, m3Priv, merchantIDs[3], 1 /*tstamp*/, 1, /*index*/
		"this is Title2_0 m3Title ok 123", "hello from body2_0 m3body", "woo category_2_0 123",
		make([]byte, params.MaxListingSizeBytes-1000))
	err = listingManager.ProcessListing(m3Listing1Large, true /*verifySignatures*/)
	require.Error(err)
	require.Contains(err.Error(), ListingErrorAddingListingWouldCauseMaxMerchantStorageToBeEceeded)

	// At this point, we should have the following listings in our db:
	// - m0Listing0Replacement
	// - m0Listing1
	// - m2Listing0
	// - m2Listing1
	// - m3Listing0

	// Verify that the zeroth listing for m0 was actually stored.
	{
		listingMessage := DbGetListingMessage(db, merchantIDs[0], 0)
		require.NotNil(listingMessage)
		require.True(reflect.DeepEqual(listingMessage, m0Listing0Replacement))
	}
	// Verify m2Listing0 was actually stored
	{
		listingMessage := DbGetListingMessage(db, merchantIDs[2], 0)
		require.NotNil(listingMessage)
		require.True(reflect.DeepEqual(listingMessage, m2Listing0))
	}

	// Verify all the listing hashes are present in the db.
	{
		keysFound, _ := _enumerateKeysForPrefix(
			db, _PrefixListingHashToMerchantIDListingIndexTstampSecs)
		require.Equal(5, len(keysFound))
	}

	// Deleting m0Listing1 should fail with an old stamp.
	{
		m0Listing1Deleted := _getListingBigDelete(
			t, m0Pub, m0Priv, merchantIDs[0], 0 /*tstamp*/, 1, /*index*/
			"", "", "", []byte{}, true /*isDeleted*/)
		err = listingManager.ProcessListing(m0Listing1Deleted, true /*verifySignatures*/)
		require.Error(err)
		require.Contains(err.Error(), ListingErrorMoreRecentListingWithSameIndexExists)
	}
	// Deleting m0Listing1 for the first time should work.
	{
		m0Listing1Deleted := _getListingBigDelete(
			t, m0Pub, m0Priv, merchantIDs[0], 3 /*tstamp*/, 1, /*index*/
			"", "", "", []byte{}, true /*isDeleted*/)
		err = listingManager.ProcessListing(m0Listing1Deleted, true /*verifySignatures*/)
		require.NoError(err)
		// Fetch m0Listing1 and make sure it's deleted.
		expectedListingMessage := DbGetListingMessage(db, merchantIDs[0], 1)
		require.Nil(expectedListingMessage)
	}
	// Deleting m0Listing1 again should work but still result in a nil listing.
	{
		m0Listing1DeletedAgain := _getListingBigDelete(
			t, m0Pub, m0Priv, merchantIDs[0], 4 /*tstamp*/, 1, /*index*/
			"", "", "", []byte{}, true /*isDeleted*/)
		err = listingManager.ProcessListing(m0Listing1DeletedAgain, true /*verifySignatures*/)
		require.NoError(err)
		// Fetch m0Listing1Again and make sure it's deleted.
		expectedListingMessage := DbGetListingMessage(db, merchantIDs[0], 1)
		require.Nil(expectedListingMessage)
	}
	// Deleting a non-existent listing should work but there should be nothing
	// added to the db.
	{
		m0Listing3Deleted := _getListingBigDelete(
			t, m0Pub, m0Priv, merchantIDs[0], 0 /*tstamp*/, 3, /*index*/
			"", "", "", []byte{}, true /*isDeleted*/)
		err = listingManager.ProcessListing(m0Listing3Deleted, true /*verifySignatures*/)
		require.NoError(err)
		// Fetch m0Listing3 and make sure it's deleted.
		expectedListingMessage := DbGetListingMessage(db, merchantIDs[0], 3)
		require.Nil(expectedListingMessage)
	}
	// Un-deleting m0Listing1 with an older timestamp should succeed. This is a known
	// issue with a TODO in ProcessListing discussing it. If you're here because you
	// fixed this issue, good job.
	{
		m0Listing1Undeleted := _getListingBigDelete(
			t, m0Pub, m0Priv, merchantIDs[0], 0 /*tstamp*/, 1, /*index*/
			"woo", "hoo", "hoooooo", []byte("woooooo"), false /*isDeleted*/)
		err = listingManager.ProcessListing(m0Listing1Undeleted, true /*verifySignatures*/)
		require.NoError(err)
		expectedListingMessage := DbGetListingMessage(db, merchantIDs[0], 1)
		require.Equal(expectedListingMessage, m0Listing1Undeleted)
	}
	// Re-delete m0Listing1
	{
		m0Listing1Deleted := _getListingBigDelete(
			t, m0Pub, m0Priv, merchantIDs[0], 3 /*tstamp*/, 1, /*index*/
			"", "", "", []byte{}, true /*isDeleted*/)
		err = listingManager.ProcessListing(m0Listing1Deleted, true /*verifySignatures*/)
		require.NoError(err)
		// Fetch m0Listing1 and make sure it's deleted.
		expectedListingMessage := DbGetListingMessage(db, merchantIDs[0], 1)
		require.Nil(expectedListingMessage)
	}
	// Undeleting m0Listing1 properly should work
	{
		m0Listing1Undeleted := _getListingBigDelete(
			t, m0Pub, m0Priv, merchantIDs[0], 5 /*tstamp*/, 1, /*index*/
			"woo", "hoo", "hoooo", []byte("tip"), false /*isDeleted*/)
		// Should fail if it's adding to the size.
		err = listingManager.ProcessListing(m0Listing1Undeleted, true /*verifySignatures*/)
		require.NoError(err)
		// Fetch m0Listing1 and make sure it's deleted.
		expectedListingMessage := DbGetListingMessage(db, merchantIDs[0], 1)
		require.NotNil(expectedListingMessage)
		require.False(expectedListingMessage.Deleted)
		require.True(reflect.DeepEqual(expectedListingMessage, m0Listing1Undeleted))
	}

	// Deleting all the other listings should work.
	// - m0Listing0Replacement
	// - m0Listing1
	// - m2Listing0
	// - m2Listing1
	// - m3Listing0
	deleteListingAndCheck := func(pub string, priv string, merchantid *BlockHash, index uint32) {
		listingDeleted := _getListingBigDelete(
			t, pub, priv, merchantid, 10 /*tstamp*/, index, /*index*/
			"", "", "", []byte{}, true /*isDeleted*/)
		err = listingManager.ProcessListing(listingDeleted, true /*verifySignatures*/)
		require.NoError(err)
		expectedListingMessage := DbGetListingMessage(db, merchantid, index)
		require.Nil(expectedListingMessage)
	}
	// m0Listing0Replacement
	deleteListingAndCheck(m0Pub, m0Priv, merchantIDs[0], 0)
	deleteListingAndCheck(m0Pub, m0Priv, merchantIDs[0], 1)
	// m2Listing0
	deleteListingAndCheck(m2Pub, m2Priv, merchantIDs[2], 0)
	// - m2Listing1
	deleteListingAndCheck(m2Pub, m2Priv, merchantIDs[2], 1)
	// - m3Listing0
	deleteListingAndCheck(m3Pub, m3Priv, merchantIDs[3], 0)

	// After deleting all the listings, the merchant info should show the total
	// number of bytes to be zero for all three merchants.
	m0info := DbGetListingMerchantIDInfo(db, merchantIDs[0])
	require.NotNil(m0info)
	require.Equal(uint64(0), m0info.NumBytes)

	m2info := DbGetListingMerchantIDInfo(db, merchantIDs[2])
	require.NotNil(m2info)
	require.Equal(uint64(0), m2info.NumBytes)

	m3info := DbGetListingMerchantIDInfo(db, merchantIDs[3])
	require.NotNil(m3info)
	require.Equal(uint64(0), m3info.NumBytes)

	// Roll back all of the above using the utxoOps from each transaction.
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

	// Mine a block to force the ListingManager to actually do work next time
	// we call Update()
	block, err = miner._mineAndProcessSingleBlock(0 /*threadIndex*/)
	require.NoError(err)

	// Now call Update() on the ListingManager again. This should result in the
	// deletion of all of the mappings in the db.
	err = listingManager.Update()
	require.NoError(err)
	// Check that all of the mappings have been erased.
	{
		// Check the hash has been updated.
		hash, err := block.Hash()
		require.NoError(err)
		require.Equal(*hash, *DbGetListingBlockHash(db))
		// Check there are no merchantids in the <count | merchantid> mapping
		listingMerchantIDs, listingMerchantScores, listingMerchantEntries, err :=
			DbGetListingTopMerchants(db, math.MaxUint64, false /*noMerchantEntries*/)
		require.NoError(err)
		require.Equal(0, len(listingMerchantIDs))
		require.Equal(0, len(listingMerchantScores))
		require.Equal(0, len(listingMerchantEntries))
		// Check there are no merchantids in the <merchantID> -> info mapping
		info0 := DbGetListingMerchantIDInfo(db, merchantIDs[0])
		require.Nil(info0)
		info2 := DbGetListingMerchantIDInfo(db, merchantIDs[2])
		require.Nil(info2)
		info3 := DbGetListingMerchantIDInfo(db, merchantIDs[3])
		require.Nil(info3)
		// Check there is no listing data stored.
		listing00 := DbGetListingMessage(db, merchantIDs[0], 0)
		require.Nil(listing00)
		listing01 := DbGetListingMessage(db, merchantIDs[0], 1)
		require.Nil(listing01)
		listing20 := DbGetListingMessage(db, merchantIDs[2], 0)
		require.Nil(listing20)
		listing21 := DbGetListingMessage(db, merchantIDs[2], 1)
		require.Nil(listing21)
		listing30 := DbGetListingMessage(db, merchantIDs[3], 0)
		require.Nil(listing30)
		// Check there are no keyword mappings left.
		require.Equal(0, _countNumKeywordListingMappings(db, CategoryKeyword))
		require.Equal(0, _countNumKeywordListingMappings(db, TitleKeyword))
		require.Equal(0, _countNumKeywordListingMappings(db, BodyKeyword))
		require.Equal(0, _countNumKeywordGlobalMappings(db, CategoryKeyword))
		require.Equal(0, _countNumKeywordGlobalMappings(db, TitleKeyword))
		require.Equal(0, _countNumKeywordGlobalMappings(db, BodyKeyword))
		// Do one last special check for the top categories.
		topCats, counts, err := DbGetListingTopCategories(db, math.MaxUint64)
		require.NoError(err)
		require.Equal(0, len(topCats))
		require.Equal(0, len(counts))
		// Verify all the listing hashes were deleted from the db.
		{
			keysFound, _ := _enumerateKeysForPrefix(
				db, _PrefixListingHashToMerchantIDListingIndexTstampSecs)
			require.Equal(0, len(keysFound))
		}
	}
}

func _setMerchantScore(t *testing.T, chain *Blockchain, params *UltranetParams, db *badger.DB, merchantID *BlockHash, scoreArg int64) {
	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	merchantEntry := DbGetMerchantEntryForMerchantID(db, merchantID)
	require.NotNil(merchantEntry)
	newScore := ScorePlusImpact(big.NewInt(0), scoreArg, chain.blockTip().Header.Height, params)
	merchantEntry.Stats.MerchantScore = newScore
	db.Update(func(dbTx *badger.Txn) error {
		require.NoError(DbDeleteUnmodifiedMappingsForMerchantIDWithTxn(dbTx, merchantID))
		require.NoError(DbPutMappingsForMerchantWithTxn(dbTx, merchantID, merchantEntry))
		return nil
	})

}

// Create a blockchain, register some merchants
func TestFrontendListingSearch(t *testing.T) {
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

	// Mine a few blocks to give the senderPkString some money.
	block, err := miner._mineAndProcessSingleBlock(0 /*threadIndex*/)
	require.NoError(err)
	_, _ = block, mempool
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

	// Register four merchants, which is one more than what the ListingManager will
	// index.
	m0Pub := "tUN2RExHhcCWqXqT9r7syGupJS6hxrBPDQMssSph6ki1FZLJTczUm4"
	m0Priv := "tunSykM1Si6Wab5mRKBDu7YK5ubpBxr1ciGiiDXmSpMATB12sAawx"
	m1Pub := "tUN2RUx1U7By7i2CZn5sZEEb5jjEHfoyc4Nvk2P9gc6Lf8Bc29xzzB"
	m1Priv := "tunSJ83kV4PNkC7MPEgbmKWNZeJk1mTbjwXUh9oy7kyBLRWsgFjVw"
	m2Pub := "tUN2NazDYX2zmbPMXagebSjHmK6QcybHBGRvFMrHDRgn5Us8YPs1De"
	m2Priv := "tunTBiMhRjKVmeK6bF8kJFQpmxH2UnTweB8zYsvH3bJPjyVMZr5kS"
	m3Pub := "tUN2Q3nYf8KNgZ5q3ftFeEq3fRFpB8CCzXTW5KV4kGrCm4LEvdv67e"
	m3Priv := "tunSRyKa6shh2S6LH3WsFa6jtT42ktUgVcSdZFqTsMBy3KPnHC9kR"
	registerOrTransfer("", senderPkString, m0Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m0Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m1Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m2Pub, senderPrivString)
	registerOrTransfer("", senderPkString, m3Pub, senderPrivString)
	registerOrTransfer("m0", m0Pub, "", m0Priv)
	merchantID0 := txns[len(txns)-1].Hash()
	registerOrTransfer("m1", m1Pub, "", m1Priv)
	merchantID1 := txns[len(txns)-1].Hash()
	registerOrTransfer("m2", m2Pub, "", m2Priv)
	merchantID2 := txns[len(txns)-1].Hash()
	registerOrTransfer("m3", m3Pub, "", m3Priv)
	merchantID3 := txns[len(txns)-1].Hash()

	// Give each  merchant a custom score so they rank differently.
	_setMerchantScore(t, chain, params, db, merchantID0, 300)
	_setMerchantScore(t, chain, params, db, merchantID1, -100)
	_setMerchantScore(t, chain, params, db, merchantID2, 200)
	_setMerchantScore(t, chain, params, db, merchantID3, 0)

	// Create a ListingManager, start it, and call Update(). This should load the
	// data for three of the merchants above into the listing index. Since they all
	// have the same score, it doesn't matter which three get loaded.
	listingManager, err := NewListingManager(db, chain, params)
	require.NoError(err)
	listingManager.Start()
	err = listingManager.Update()
	require.NoError(err)

	// Ensure GetTopMerchants returns the merchants in proper sorted order
	{
		topMerchantIDs, scores, _, err := DbGetListingTopMerchants(db, 4, false /*noMerchantEntries*/)
		require.NoError(err)
		require.Equal(4, len(topMerchantIDs))
		require.Equal(4, len(scores))
		require.Equal(topMerchantIDs, []*BlockHash{merchantID0, merchantID2, merchantID3, merchantID1})
		require.Equal(scores[0], big.NewInt(300))
		require.Equal(scores[1], big.NewInt(200))
		require.True(scores[2].Cmp(big.NewInt(0)) == 0)
		require.Equal(scores[3], big.NewInt(-100))
	}

	// If we update the top merchants without calling Update() on the listingManager then the
	// top merchants should not change.
	{
		expectedSenderBalances = append(expectedSenderBalances, _getBalance(t, chain, nil, senderPkString))
		expectedRecipientBalances = append(expectedRecipientBalances, _getBalance(t, chain, nil, recipientPkString))

		tmpOps, tmpTxn, _, err := _doUpdateMerchantWithViewFlush(t, chain, db,
			params, m0Pub, m0Priv,
			merchantID0, "", "asdf", "", 7, 3)
		require.NoError(err)
		txnOps = append(txnOps, tmpOps)
		txns = append(txns, tmpTxn)

		// Verify that everything in the database is updated for the merchant.
		merchantEntry := DbGetMerchantEntryForMerchantID(db, merchantIDs[0])
		require.NotNil(merchantEntry)
		require.Equal("asdf", string(merchantEntry.Username))
		require.Equal(m0Pub, PkToStringTestnet(merchantEntry.PublicKey))
		require.Equal("i mean she's the best ", string(merchantEntry.Description))
		require.False(merchantEntry.isDeleted)
	}
	{
		// This should error since we haven't called Update() on the listing manager
		// yet.
		_, _, _, err := _getTopMerchantsForDbPrefix(
			db, true /*useListingDB*/, math.MaxUint64,
			false /*noMerchantEntries*/, true /*errorIfInconsistentMerchantEntryFound*/)
		require.Error(err)
		require.Contains(err.Error(), "computed score")
	}

	// After calling Update() on the ListingManager, the score for the MerchantEntry
	// should be consistent with what's in the listing DB. Mine a block so that an update
	// actually happens.
	block, err = miner._mineAndProcessSingleBlock(0 /*threadIndex*/)
	require.NoError(err)
	err = listingManager.Update()
	require.NoError(err)
	{
		// This should error since we haven't called Update() on the listing manager
		// yet.
		_, _, _, err := _getTopMerchantsForDbPrefix(
			db, true /*useListingDB*/, math.MaxUint64,
			false /*noMerchantEntries*/, true /*errorIfInconsistentMerchantEntryFound*/)
		require.NoError(err)
	}

	// Create listings for each merchant and process them.
	m0Listing0 := _getListing(
		t, m0Pub, m0Priv, merchantIDs[0], 0 /*tstamp*/, 0, /*index*/
		"m00 single_title all_title  multi_title1 multi_title2 title_1 title_2 body_1", "hello single_body title_body_mix multi_body1 multi_body2 from body0_0 m0Body 9823 body_1", "this is Category 0")
	m0Listing1 := _getListing(
		t, m0Pub, m0Priv, merchantIDs[0], 2 /*tstamp*/, 1, /*index*/
		"m01 all_title multi_title1 title_1 title_2", "hello from body0_0 m0Body 9823 multi_body1", "this is Category 1")
	m0Listing2 := _getListing(
		t, m0Pub, m0Priv, merchantIDs[0], 8 /*tstamp*/, 2, /*index*/
		"m02 all_title multi_title1", "hello from body0_0 m0Body 9823 multi_body1 body_1 body_2", "this is Category 0")
	m0Listing3 := _getListing(
		t, m0Pub, m0Priv, merchantIDs[0], 9 /*tstamp*/, 3, /*index*/
		"m03 all_title multi_title1", "hello from body0_0 m0Body 9823 multi_body1 body_1 body_2", "this is Category 0")
	m0Listing4 := _getListing(
		t, m0Pub, m0Priv, merchantIDs[0], 10 /*tstamp*/, 4, /*index*/
		"m04 all_title multi_title1 title_1 title_2", "hello from body0_0 m0Body 9823 multi_body1", "this is Category 0")
	m1Listing0 := _getListing(
		t, m1Pub, m1Priv, merchantIDs[1], 4 /*tstamp*/, 0, /*index*/
		"m10 all_title multi_title1 multi_title2 title_1 title_2 body_1", "hello from body0_0 m0Body 9823 multi_body1 multi_body2 body_1", "this is Category 0")
	m1Listing1 := _getListing(
		t, m1Pub, m1Priv, merchantIDs[1], 3 /*tstamp*/, 1, /*index*/
		"m11 all_title single_title title_body_mix multi_title1 multi_title2", "hello single_body from body0_0 m0Body 9823 multi_body1 multi_body2 body_1", "this is Category 1")
	m2Listing0 := _getListing(
		t, m2Pub, m2Priv, merchantIDs[2], 5 /*tstamp*/, 0, /*index*/
		"m20 all_title single_title this is Title2_0 m2Title ok 123", "hello from title_body_mix  single_body m2Body Body2_0 body_1 body_2", "this is Category 0")
	m2Listing1 := _getListing(
		t, m2Pub, m2Priv, merchantIDs[2], 1 /*tstamp*/, 1, /*index*/
		"m21 all_title this is Title2_0 m2Title ok 123 multi_title1 multi_title2 ", "hello from m2Body Body2_0 multi_body1 multi_body2 body_1", "this is Category 0")
	m3Listing0 := _getListing(
		t, m3Pub, m3Priv, merchantIDs[3], 6 /*tstamp*/, 0, /*index*/
		"m30 all_title this is Title3_0 m3Title ok multi_title2 title_1 title_2", "hello from Hey\000there Body3_0 m3Body 12 multi_body2", "this is Category 0")
	m3Listing1 := _getListing(
		t, m3Pub, m3Priv, merchantIDs[3], 7 /*tstamp*/, 1, /*index*/
		"m31 all_title single_title this is Title3_0 m3Title ok multi_title1 multi_title2", "hello from Hey\000there single_body Body3_0 title_body_mix m3Body 12 multi_body1 multi_body2 body_1", "this is Category 1")
	require.NoError(listingManager.ProcessListing(m0Listing0, true /*verifySignatures*/))
	require.NoError(listingManager.ProcessListing(m0Listing1, true /*verifySignatures*/))
	require.NoError(listingManager.ProcessListing(m0Listing2, true /*verifySignatures*/))
	require.NoError(listingManager.ProcessListing(m0Listing3, true /*verifySignatures*/))
	require.NoError(listingManager.ProcessListing(m0Listing4, true /*verifySignatures*/))
	require.NoError(listingManager.ProcessListing(m1Listing0, true /*verifySignatures*/))
	require.NoError(listingManager.ProcessListing(m1Listing1, true /*verifySignatures*/))
	require.NoError(listingManager.ProcessListing(m2Listing0, true /*verifySignatures*/))
	require.NoError(listingManager.ProcessListing(m2Listing1, true /*verifySignatures*/))
	require.NoError(listingManager.ProcessListing(m3Listing0, true /*verifySignatures*/))
	require.NoError(listingManager.ProcessListing(m3Listing1, true /*verifySignatures*/))

	{
		listings, err := _findListingsForCriteria(
			db, params, PkToStringTestnet(merchantID0[:]) /*merchantID*/, -1 /*listingIndex*/, "", /*keyword*/
			false /*categoryQuery*/)
		require.NoError(err)
		require.Equal(5, len(listings))
		require.Contains(listings, m0Listing0)
		require.Contains(listings, m0Listing1)
		require.Contains(listings, m0Listing2)
		require.Contains(listings, m0Listing3)
		require.Contains(listings, m0Listing4)
	}
	{
		listings, err := _findListingsForCriteria(
			db, params, PkToStringTestnet(merchantID0[:]) /*merchantID*/, 0 /*listingIndex*/, "", /*keyword*/
			false /*categoryQuery*/)
		require.NoError(err)
		require.Equal(1, len(listings))
		require.Contains(listings, m0Listing0)
	}
	// Calling the function with no query should return the listings in a particular
	// order based on the scores of the merchants (with some randomness).
	{
		listings, err := _findListingsForCriteria(
			db, params, "" /*merchantID*/, -1 /*listingIndex*/, "", /*keyword*/
			false /*categoryQuery*/)
		require.NoError(err)
		require.Equal(11, len(listings))
		// Use Contains because listings are randomized within a single merchant.
		require.Contains([]*MsgUltranetListing{m0Listing0, m0Listing1, m0Listing2, m0Listing3, m0Listing4}, listings[0])
		require.Contains([]*MsgUltranetListing{m2Listing0, m2Listing1}, listings[1])
		require.Contains([]*MsgUltranetListing{m0Listing0, m0Listing1, m0Listing2, m0Listing3, m0Listing4}, listings[2])
		require.Contains([]*MsgUltranetListing{m2Listing0, m2Listing1}, listings[3])
		require.Contains([]*MsgUltranetListing{m3Listing0, m3Listing1, m0Listing0, m0Listing1, m0Listing2, m0Listing3, m0Listing4}, listings[4])
		require.Contains([]*MsgUltranetListing{m3Listing0, m3Listing1, m0Listing0, m0Listing1, m0Listing2, m0Listing3, m0Listing4}, listings[5])
		require.Contains([]*MsgUltranetListing{m3Listing0, m3Listing1, m0Listing0, m0Listing1, m0Listing2, m0Listing3, m0Listing4}, listings[6])
		require.Contains([]*MsgUltranetListing{m3Listing0, m3Listing1, m0Listing0, m0Listing1, m0Listing2, m0Listing3, m0Listing4}, listings[7])
		require.Contains([]*MsgUltranetListing{m3Listing0, m3Listing1, m0Listing0, m0Listing1, m0Listing2, m0Listing3, m0Listing4}, listings[8])
		require.Contains([]*MsgUltranetListing{m1Listing0, m1Listing1}, listings[9])
		require.Contains([]*MsgUltranetListing{m1Listing0, m1Listing1}, listings[10])
	}
	// If listings match a category then they should be sorted based on the
	// merchant score.
	{
		listings, err := _findListingsForCriteria(
			db, params, "" /*merchantID*/, -1 /*listingIndex*/, "this is Category 0", /*keyword*/
			true /*categoryQuery*/)
		require.NoError(err)
		require.Equal(8, len(listings))
		// Even with decay m0 and m2 listings should dominate the first few listings.
		require.Contains([]*MsgUltranetListing{m0Listing0, m0Listing2, m0Listing3, m0Listing4}, listings[0])
		require.Contains([]*MsgUltranetListing{m2Listing0, m2Listing1}, listings[1])
		require.Contains([]*MsgUltranetListing{m0Listing0, m0Listing2, m0Listing3, m0Listing4}, listings[2])
		require.Contains([]*MsgUltranetListing{m2Listing0, m2Listing1}, listings[3])
		require.Contains([]*MsgUltranetListing{m0Listing0, m0Listing2, m0Listing3, m0Listing4}, listings[4])

		// m0 and m3 have a score of zero at this point due to decay.
		require.Contains([]*MsgUltranetListing{m3Listing0, m3Listing1, m0Listing0, m0Listing2, m0Listing3, m0Listing4}, listings[5])
		require.Contains([]*MsgUltranetListing{m3Listing0, m3Listing1, m0Listing0, m0Listing2, m0Listing3, m0Listing4}, listings[6])

		// m1 is negative ans should appear last regardless of decay.
		require.Contains([]*MsgUltranetListing{m1Listing0}, listings[7])
	}
	// A keyword that returns multiple listings for each merchant should bias away from
	// showing only listings from the top merchant at the highest rank (i.e. it should
	// interleave listings from different merchants if the listings have the same relevance).
	{
		listings, err := _findListingsForCriteria(
			db, params, "" /*merchantID*/, -1 /*listingIndex*/, "all_title", /*keyword*/
			false /*categoryQuery*/)
		require.NoError(err)
		require.Equal(11, len(listings))
		// Result should be exactly the same as with no keyword specified since all the
		// listings are returned.
		require.Contains([]*MsgUltranetListing{m0Listing0, m0Listing1, m0Listing2, m0Listing3, m0Listing4}, listings[0])
		require.Contains([]*MsgUltranetListing{m2Listing0, m2Listing1}, listings[1])
		require.Contains([]*MsgUltranetListing{m0Listing0, m0Listing1, m0Listing2, m0Listing3, m0Listing4}, listings[2])
		require.Contains([]*MsgUltranetListing{m2Listing0, m2Listing1}, listings[3])
		require.Contains([]*MsgUltranetListing{m3Listing0, m3Listing1, m0Listing0, m0Listing1, m0Listing2, m0Listing3, m0Listing4}, listings[4])
		require.Contains([]*MsgUltranetListing{m3Listing0, m3Listing1, m0Listing0, m0Listing1, m0Listing2, m0Listing3, m0Listing4}, listings[5])
		require.Contains([]*MsgUltranetListing{m3Listing0, m3Listing1, m0Listing0, m0Listing1, m0Listing2, m0Listing3, m0Listing4}, listings[6])
		require.Contains([]*MsgUltranetListing{m3Listing0, m3Listing1, m0Listing0, m0Listing1, m0Listing2, m0Listing3, m0Listing4}, listings[7])
		require.Contains([]*MsgUltranetListing{m3Listing0, m3Listing1, m0Listing0, m0Listing1, m0Listing2, m0Listing3, m0Listing4}, listings[8])
		require.Contains([]*MsgUltranetListing{m1Listing0, m1Listing1}, listings[9])
		require.Contains([]*MsgUltranetListing{m1Listing0, m1Listing1}, listings[10])
	}

	// A keyword that is in the title of multiple listings should cause those listings
	// to return in merchant score order.
	{
		listings, err := _findListingsForCriteria(
			db, params, "" /*merchantID*/, -1 /*listingIndex*/, "single_title", /*keyword*/
			false /*categoryQuery*/)
		require.NoError(err)
		require.Equal(4, len(listings))
		require.Equal(listings, []*MsgUltranetListing{m0Listing0, m2Listing0, m3Listing1, m1Listing1})
	}
	// A keyword that is in the body of multiple listings should cause those listings
	// to return in merchant score order.
	{
		listings, err := _findListingsForCriteria(
			db, params, "" /*merchantID*/, -1 /*listingIndex*/, "single_body", /*keyword*/
			false /*categoryQuery*/)
		require.NoError(err)
		require.Equal(4, len(listings))
		require.Equal(listings, []*MsgUltranetListing{m0Listing0, m2Listing0, m3Listing1, m1Listing1})
	}
	// Listings that have a keyword in the title should rank above listigns that have
	// it in the body.
	{
		listings, err := _findListingsForCriteria(
			db, params, "" /*merchantID*/, -1 /*listingIndex*/, "title_body_mix", /*keyword*/
			false /*categoryQuery*/)
		require.NoError(err)
		require.Equal(4, len(listings))
		require.Equal(listings, []*MsgUltranetListing{m1Listing1, m0Listing0, m2Listing0, m3Listing1})
	}

	// Multiple title matches should outrank a single title match.
	{
		listings, err := _findListingsForCriteria(
			db, params, "" /*merchantID*/, -1 /*listingIndex*/, "multi_title1 multi_title2", /*keyword*/
			false /*categoryQuery*/)
		require.NoError(err)
		require.Equal(10, len(listings))
		// These listings should have two title matches, placing them unambiguously
		// above the rest ordered by their merchant score.
		require.Contains([]*MsgUltranetListing{m0Listing0}, listings[0])
		require.Contains([]*MsgUltranetListing{m2Listing1}, listings[1])
		require.Contains([]*MsgUltranetListing{m3Listing1}, listings[2])
		require.Contains([]*MsgUltranetListing{m1Listing0, m1Listing1}, listings[3])
		require.Contains([]*MsgUltranetListing{m1Listing0, m1Listing1}, listings[4])

		// These listings have a single match and a score unambiguously higher than
		// the remaining listings.
		require.Contains([]*MsgUltranetListing{m0Listing1, m0Listing2, m0Listing3, m0Listing4}, listings[5])
		require.Contains([]*MsgUltranetListing{m0Listing1, m0Listing2, m0Listing3, m0Listing4}, listings[6])

		// The remaining listings have a single match with a score of zero.
		require.Contains([]*MsgUltranetListing{m3Listing0, m0Listing1, m0Listing2, m0Listing3, m0Listing4}, listings[7])
		require.Contains([]*MsgUltranetListing{m3Listing0, m0Listing1, m0Listing2, m0Listing3, m0Listing4}, listings[8])
		require.Contains([]*MsgUltranetListing{m3Listing0, m0Listing1, m0Listing2, m0Listing3, m0Listing4}, listings[9])
	}

	// Multiple body matches should outrank a single body match.
	{
		listings, err := _findListingsForCriteria(
			db, params, "" /*merchantID*/, -1 /*listingIndex*/, "multi_body1 multi_body2", /*keyword*/
			false /*categoryQuery*/)
		require.NoError(err)
		require.Equal(10, len(listings))
		// These listings should have two title matches, placing them unambiguously
		// above the rest ordered by their merchant score.
		require.Contains([]*MsgUltranetListing{m0Listing0}, listings[0])
		require.Contains([]*MsgUltranetListing{m2Listing1}, listings[1])
		require.Contains([]*MsgUltranetListing{m3Listing1}, listings[2])
		require.Contains([]*MsgUltranetListing{m1Listing0, m1Listing1}, listings[3])
		require.Contains([]*MsgUltranetListing{m1Listing0, m1Listing1}, listings[4])

		// These listings have a single match and a score unambiguously higher than
		// the remaining listings.
		require.Contains([]*MsgUltranetListing{m0Listing1, m0Listing2, m0Listing3, m0Listing4}, listings[5])
		require.Contains([]*MsgUltranetListing{m0Listing1, m0Listing2, m0Listing3, m0Listing4}, listings[6])

		// The remaining listings have a single match with a score of zero.
		require.Contains([]*MsgUltranetListing{m3Listing0, m0Listing1, m0Listing2, m0Listing3, m0Listing4}, listings[7])
		require.Contains([]*MsgUltranetListing{m3Listing0, m0Listing1, m0Listing2, m0Listing3, m0Listing4}, listings[8])
		require.Contains([]*MsgUltranetListing{m3Listing0, m0Listing1, m0Listing2, m0Listing3, m0Listing4}, listings[9])
	}

	// Alright, now for something truly annoying:
	// - 2 listings with 2 title matches and 1 body match (title_1 title_2 body_1)
	// - 3 listings with 2 title matches only (title_1 title_2)
	// - 3 listings with two body matches (body_1 body_2)
	// - 3 listings with one body match (body_1)
	//
	// The ranking for listings with the same keyword match stats should be by
	// MerchantID.
	{
		listings, err := _findListingsForCriteria(
			db, params, "" /*merchantID*/, -1 /*listingIndex*/, "title_1 title_2 body_1 body_2", /*keyword*/
			false /*categoryQuery*/)
		require.NoError(err)
		// 2 titles matches and 1 body match. Unambiguously the most relevant.
		require.Contains([]*MsgUltranetListing{m0Listing0}, listings[0])
		require.Contains([]*MsgUltranetListing{m1Listing0}, listings[1])

		// 2 title matches. Some ambiguity since 2/3 matches are from m0. Note that
		// both m0 listings beat the m3 listing because the scores are 300 and 30
		// (with 1/10th as the decay factor) vs 0.
		require.Contains([]*MsgUltranetListing{m0Listing1, m0Listing4}, listings[2])
		require.Contains([]*MsgUltranetListing{m0Listing1, m0Listing4}, listings[3])
		require.Contains([]*MsgUltranetListing{m3Listing0}, listings[4])

		// 2 body matches. Some ambiguity since 2/3 matches are from m0.
		require.Contains([]*MsgUltranetListing{m0Listing2, m0Listing3}, listings[5])
		require.Contains([]*MsgUltranetListing{m2Listing0}, listings[6])
		require.Contains([]*MsgUltranetListing{m0Listing2, m0Listing3}, listings[7])

		// The remaining listings have a single match with a score of zero.
		require.Contains([]*MsgUltranetListing{m2Listing1}, listings[8])
		require.Contains([]*MsgUltranetListing{m3Listing1}, listings[9])
		require.Contains([]*MsgUltranetListing{m1Listing1}, listings[10])
	}
}
