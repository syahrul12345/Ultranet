package lib

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/gob"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"math/big"
	"path/filepath"
	"strings"
	"time"

	"github.com/btcsuite/btcd/btcec"
	"github.com/davecgh/go-spew/spew"
	"github.com/dgraph-io/badger"
	"github.com/golang/glog"
	"github.com/pkg/errors"
)

// This file contains all of the functions that interact with the database.

const (
	// badgerDbFolder is the subfolder in the config dir where we
	// store the badgerdb database by default.
	badgerDbFolder = "badgerdb"
)

var (
	// The key prefixes for the key-value database. To store a particular
	// type of data, we create a key prefix and store all those types of
	// data with a key prefixed by that key prefix.
	// Bitcoin does a similar thing that you can see at this link:
	// https://bitcoin.stackexchange.com/questions/28168/what-are-the-keys-used-in-the-blockchain-leveldb-ie-what-are-the-keyvalue-pair

	// The prefix for the block index:
	// Key format: <hash BlockHash>
	// Value format: serialized MsgUltranetBlock
	_PrefixBlockHashToBlock = []byte{0}

	// The prefix for the node index that we use to reconstruct the block tree.
	// Storing the height in big-endian byte order allows us to read in all the
	// blocks in height-sorted order from the db and construct the block tree by connecting
	// nodes to their parents as we go.
	//
	// Key format: <height uint32 (big-endian), hash BlockHash>
	// Value format: serialized BlockNode
	_PrefixHeightHashToNodeInfo        = []byte{1}
	_PrefixBitcoinHeightHashToNodeInfo = []byte{2}

	// We store the hash of the node that is the current tip of the main chain.
	// This key is used to look it up.
	// Value format: BlockHash
	_KeyBestUltranetBlockHash = []byte{3}

	_KeyBestBitcoinHeaderHash = []byte{5}

	// Utxo table.
	// <txid BlockHash, output_index uint64> -> UtxoEntry
	_PrefixUtxoKeyToUtxoEntry = []byte{6}
	// <pos uint64 (big-endian encoded)> -> <txid BlockHash, output_index uint64>
	_PrefixPositionToUtxoKey = []byte{7}
	// <pubKey [33]byte, utxoKey< txid BlockHash, index uint64 >> -> <>
	_PrefixPubKeyUtxoKey = []byte{8}
	// The number of utxo entries in the database.
	_KeyUtxoNumEntries = []byte{9}
	// Utxo operations table.
	// This table contains, for each blockhash on the main chain, the UtxoOperations
	// that were applied by this block. To roll back the block, one must loop through
	// the UtxoOperations for a particular block backwards and invert them.
	//
	// < hash *BlockHash > -> < serialized []UtxoOperation using gob encoding >
	_PrefixBlockHashToUtxoOperations = []byte{10}

	// Merchant table.
	// <username []byte -> (txid where merchant was registered) BlockHash>
	_PrefixUsernameToMerchantID = []byte{11}
	// <pk []byte -> (txid where merchant was registered) BlockHash>
	_PrefixPubKeyToMerchantID = []byte{12}
	// <pos uint64 big-endian encoded -> (txid where merchant was registered) BlockHash>
	_PrefixPosToMerchantID = []byte{13}
	// <(txid where merchant was registered) BlockHash -> MerchantEntry>
	_PrefixMerchantIDToMerchantEntry = []byte{14}
	// <score big-endian BlockHash || merchant_id BlockHash> -> empty
	//
	// Keeping this index allows for a very quick and easy query to fetch the top
	// N merchants by score, which is frequently required. Note that because the
	// key starts with the big-endian encoded score, the entries are sorted by their
	// score. It maps to empty because we don't care about the values, we just iterate
	// over the keys in sorted order (effectively using the db as an on-disk sorter).
	_PrefixScoreMerchantIDIndex = []byte{15}
	// The number of merchant entries currently in the db.
	_KeyMerchantNumEntries = []byte{16}

	// Order table.
	_PrefixPosToOrderID        = []byte{17}
	_PrefixOrderIDToOrderEntry = []byte{18}
	// We keep an index mapping buyer public keys and MerchantIDs to orders sorted by
	// when the orders were last modified. This supports fast querying for the orders
	// associated with a particular buyer public key or MerchantID.
	//
	// The key for this index is as follows:
	// <public key []byte || lastModifiedHeight uint64 big-endian encoded || orderID BlockHash>
	// See _dbKeyForOrderBuyerPubKey and _dbKeyForOrderMerchantPubKey for details.
	//
	// We keep separate indexes for buyer pks and merchant pks, so to get all the orders
	// for a particular pk, two queries are required. Both indexes have the same key
	// format described above.
	_PrefixBuyerPubKeyOrderIndex = []byte{19}
	_PrefixMerchantIDOrderIndex  = []byte{20}
	_KeyOrderNumEntries          = []byte{21}

	// The BlockHash corresponding to the block the ListingsManager most recently
	// processed. This is used to determine whether not an update to the listings
	// data is required or not.
	_KeyListingBlockHash = []byte{22}
	// <MerchantID BlockHash> -> <score BlockHash bigint, numBytesStored uint64>
	_PrefixListingMerchantIDScoreNumBytes = []byte{23}
	// <score BlockHash bigint | merchantID BlockHash> -> <nothing>
	_PrefixListingScoreMerchantID = []byte{24}
	// <merchantID BlockHash | listingIndex uint64 big-endian> -> MsgUltranetListing
	_PrefixListingMerchantIDListingIndexToListingMessage = []byte{25}
	// We use a null byte as a separator character and escape null bytes in the
	// keyword by replacing them with the character '0'. This allows for searches
	// like finding all the listings for a keyword using the keyword with a null
	// byte after it as the prefix for the seek.
	//
	// <keyword []byte | byte(0) | ListingID> -> numOccurrencesOfKeywordInListing uint64
	_PrefixListingTitleKeywordListingIDToCount = []byte{26}
	// <keyword []byte> -> numListingsContainingKeyword uint64
	// This is useful when processing a query so that keywords that are present in a
	// lot of listings can be down-weighted in terms of importance.
	_PrefixListingTitleKeywordToListingCount = []byte{27}
	// Same as above but for body instead of title.
	_PrefixListingBodyKeywordListingIDToCount = []byte{28}
	_PrefixListingBodyKeywordToListingCount   = []byte{29}
	// Same as above but for category instead of title/body.
	_PrefixListingCategoryKeywordListingIDToCount = []byte{30}
	_PrefixListingCategoryKeywordToListingCount   = []byte{31}
	// For category we store an extra mapping so we can compute the top categories
	// and display them to the user by their counts. This mapping is:
	// <numListingsContainingCategory uint64 bigint | category keyword escaped and null-terminated> -> <>
	_PrefixListingCountCategory = []byte{32}
	// For each listing, we store a mapping from its hash to its listing id,
	// which consists of merchantID, listing index, and tstamp.
	// <hash BlockHash> -> <merchantID BlockHash, listing index uvarint, tstampSecs uvarint>
	_PrefixListingHashToMerchantIDListingIndexTstampSecs = []byte{33}

	// Db keys for storing local user data. This contains information like the
	// current logged in user, encrypted seeds, etc used by the frontend.
	_KeyLocalUserData = []byte{34}

	// The below are mappings related to the validation of BitcoinExchange transactions.
	//
	// The number of nanos that has been purchased thus far.
	_KeyNanosPurchased = []byte{35}
	// The prefix for the Bitcoin TxID map. If a key is set for a TxID that means this
	// particular TxID has been processed as part of a BitcoinExchange transaction. If
	// no key is set for a TxID that means it has not been processed (and thus it can be
	// used to create new nanos).
	// <BitcoinTxID BlockHash> -> <nothing>
	_PrefixBitcoinBurnTxIDs = []byte{36}

	// Messages are indexed by the public key of their senders and receivers. If
	// a message sends from pkFrom to pkTo then there will be two separate entries,
	// one for pkFrom and one for pkTo. The exact format is as follows:
	// <public key (33 bytes) || uint64 big-endian> -> < SenderPublicKey || RecipientPublicKey || EncryptedText >
	_PrefixPublicKeyTimestampToPrivateMessage = []byte{37}

	// TODO: This process is a bit error-prone. We should come up with a test or
	// something to at least catch cases where people have two prefixes with the
	// same ID.
	//
	// NEXT_TAG: 38
)

// A helper function to enumerate all of the values for a particular prefix.
func _enumerateKeysForPrefix(db *badger.DB, dbPrefix []byte) (_keysFound [][]byte, _valsFound [][]byte) {
	keysFound := [][]byte{}
	valsFound := [][]byte{}

	dbErr := db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		nodeIterator := txn.NewIterator(opts)
		defer nodeIterator.Close()
		prefix := dbPrefix
		for nodeIterator.Seek(prefix); nodeIterator.ValidForPrefix(prefix); nodeIterator.Next() {
			key := nodeIterator.Item().Key()
			keyCopy := make([]byte, len(key))
			copy(keyCopy[:], key[:])

			valCopy, err := nodeIterator.Item().ValueCopy(nil)
			if err != nil {
				return err
			}
			keysFound = append(keysFound, keyCopy)
			valsFound = append(valsFound, valCopy)
		}
		return nil
	})
	if dbErr != nil {
		glog.Errorf("_enumerateKeysForPrefix: Problem fetching keys and vlaues from db: %v", dbErr)
		return nil, nil
	}

	return keysFound, valsFound
}

// -------------------------------------------------------------------------------------
// PrivateMessage mapping functions
// <public key (33 bytes) || uint64 big-endian> ->
// 		< SenderPublicKey || RecipientPublicKey || EncryptedText >
// -------------------------------------------------------------------------------------

func _dbKeyForMessageEntry(publicKey []byte, tstampNanos uint64) []byte {
	// Make a copy to avoid multiple calls to this function re-using the same slice.
	prefixCopy := append([]byte{}, _PrefixPublicKeyTimestampToPrivateMessage...)
	key := append(prefixCopy, publicKey...)
	key = append(key, _EncodeUint64(tstampNanos)...)
	return key
}

func _dbSeekPrefixForMessagePublicKey(publicKey []byte) []byte {
	// Make a copy to avoid multiple calls to this function re-using the same slice.
	prefixCopy := append([]byte{}, _PrefixPublicKeyTimestampToPrivateMessage...)
	return append(prefixCopy, publicKey...)
}

// Note that this adds a mapping for the sender *and* the recipient.
func DbPutMessageEntryWithTxn(
	txn *badger.Txn, messageEntry *MessageEntry) error {

	if len(messageEntry.SenderPublicKey) != btcec.PubKeyBytesLenCompressed {
		return fmt.Errorf("DbPutPrivateMessageWithTxn: Sender public key "+
			"length %d != %d", len(messageEntry.SenderPublicKey), btcec.PubKeyBytesLenCompressed)
	}
	if len(messageEntry.RecipientPublicKey) != btcec.PubKeyBytesLenCompressed {
		return fmt.Errorf("DbPutPrivateMessageWithTxn: Recipient public key "+
			"length %d != %d", len(messageEntry.RecipientPublicKey), btcec.PubKeyBytesLenCompressed)
	}
	messageData := &MessageEntry{
		SenderPublicKey:    messageEntry.SenderPublicKey,
		RecipientPublicKey: messageEntry.RecipientPublicKey,
		EncryptedText:      messageEntry.EncryptedText,
		TstampNanos:        messageEntry.TstampNanos,
	}

	messageDataBuf := bytes.NewBuffer([]byte{})
	gob.NewEncoder(messageDataBuf).Encode(messageData)

	if err := txn.Set(_dbKeyForMessageEntry(
		messageEntry.SenderPublicKey, messageEntry.TstampNanos), messageDataBuf.Bytes()); err != nil {

		return errors.Wrapf(err, "DbPutPrivateMessageWithTxn: Problem adding mapping for sender: ")
	}
	if err := txn.Set(_dbKeyForMessageEntry(
		messageEntry.RecipientPublicKey, messageEntry.TstampNanos), messageDataBuf.Bytes()); err != nil {

		return errors.Wrapf(err, "DbPutPrivateMessageWithTxn: Problem adding mapping for recipient: ")
	}

	return nil
}

func DbPutMessageEntry(handle *badger.DB, messageEntry *MessageEntry) error {

	return handle.Update(func(txn *badger.Txn) error {
		return DbPutMessageEntryWithTxn(txn, messageEntry)
	})
}

func DbGetMessageEntryWithTxn(
	txn *badger.Txn, publicKey []byte, tstampNanos uint64) *MessageEntry {

	key := _dbKeyForMessageEntry(publicKey, tstampNanos)
	privateMessageObj := &MessageEntry{}
	privateMessageItem, err := txn.Get(key)
	if err != nil {
		return nil
	}
	err = privateMessageItem.Value(func(valBytes []byte) error {
		return gob.NewDecoder(bytes.NewReader(valBytes)).Decode(privateMessageObj)
	})
	if err != nil {
		glog.Errorf("DbGetMessageEntryWithTxn: Problem reading "+
			"MessageEntry for public key %s with tstampnanos %d",
			PkToStringMainnet(publicKey), tstampNanos)
		return nil
	}
	return privateMessageObj
}

func DbGetMessageEntry(db *badger.DB, publicKey []byte, tstampNanos uint64) *MessageEntry {
	var ret *MessageEntry
	db.View(func(txn *badger.Txn) error {
		ret = DbGetMessageEntryWithTxn(txn, publicKey, tstampNanos)
		return nil
	})
	return ret
}

// Note this deletes the message for the sender *and* receiver since a mapping
// should exist for each.
func DbDeleteMessageEntryMappingsWithTxn(
	txn *badger.Txn, publicKey []byte, tstampNanos uint64) error {

	// First pull up the mapping that texists for the public key passed in.
	// If one doesn't exist then there's nothing to do.
	existingMessage := DbGetMessageEntryWithTxn(txn, publicKey, tstampNanos)
	if existingMessage == nil {
		return nil
	}

	// When a message exists, delete the mapping for the sender and receiver.
	if err := txn.Delete(_dbKeyForMessageEntry(existingMessage.SenderPublicKey, tstampNanos)); err != nil {
		return errors.Wrapf(err, "DbDeleteMessageEntryMappingsWithTxn: Deleting "+
			"sender mapping for public key %s and tstamp %d failed",
			PkToStringMainnet(existingMessage.SenderPublicKey), tstampNanos)
	}
	if err := txn.Delete(_dbKeyForMessageEntry(existingMessage.RecipientPublicKey, tstampNanos)); err != nil {
		return errors.Wrapf(err, "DbDeleteMessageEntryMappingsWithTxn: Deleting "+
			"recipient mapping for public key %s and tstamp %d failed",
			PkToStringMainnet(existingMessage.RecipientPublicKey), tstampNanos)
	}

	return nil
}

func DbDeleteMessageEntryMappings(handle *badger.DB, publicKey []byte, tstampNanos uint64) error {
	return handle.Update(func(txn *badger.Txn) error {
		return DbDeleteMessageEntryMappingsWithTxn(txn, publicKey, tstampNanos)
	})
}

func DbGetMessageEntriesForPublicKey(handle *badger.DB, publicKey []byte) (
	_privateMessages []*MessageEntry, _err error) {

	// Setting the prefix to a tstamp of zero should return all the messages
	// for the public key in sorted order since 0 << the minimum timestamp in
	// the db.
	prefix := _dbSeekPrefixForMessagePublicKey(publicKey)
	_, valuesFound := _enumerateKeysForPrefix(handle, prefix)

	privateMessages := []*MessageEntry{}
	for _, valBytes := range valuesFound {
		privateMessageObj := &MessageEntry{}
		if err := gob.NewDecoder(bytes.NewReader(valBytes)).Decode(privateMessageObj); err != nil {
			return nil, errors.Wrapf(
				err, "DbGetMessageEntriesForPublicKey: Problem decoding value: ")
		}

		privateMessages = append(privateMessages, privateMessageObj)
	}

	return privateMessages, nil
}

// -------------------------------------------------------------------------------------
// BitcoinBurnTxID mapping functions
// <BitcoinBurnTxID BlockHash> -> <>
// -------------------------------------------------------------------------------------

func _keyForBitcoinBurnTxID(bitcoinBurnTxID *BlockHash) []byte {
	// Make a copy to avoid multiple calls to this function re-using the same
	// underlying array.
	prefixCopy := append([]byte{}, _PrefixBitcoinBurnTxIDs...)
	return append(prefixCopy, bitcoinBurnTxID[:]...)
}

func DbPutBitcoinBurnTxIDWithTxn(txn *badger.Txn, bitcoinBurnTxID *BlockHash) error {
	return txn.Set(_keyForBitcoinBurnTxID(bitcoinBurnTxID), []byte{})
}

func DbExistsBitcoinBurnTxIDWithTxn(txn *badger.Txn, bitcoinBurnTxID *BlockHash) bool {
	// We don't care about the value because we're just checking to see if the key exists.
	if _, err := txn.Get(_keyForBitcoinBurnTxID(bitcoinBurnTxID)); err != nil {
		return false
	}
	return true
}

func DbExistsBitcoinBurnTxID(db *badger.DB, bitcoinBurnTxID *BlockHash) bool {
	var exists bool
	db.View(func(txn *badger.Txn) error {
		exists = DbExistsBitcoinBurnTxIDWithTxn(txn, bitcoinBurnTxID)
		return nil
	})
	return exists
}

func DbDeleteBitcoinBurnTxIDWithTxn(txn *badger.Txn, bitcoinBurnTxID *BlockHash) error {
	return txn.Delete(_keyForBitcoinBurnTxID(bitcoinBurnTxID))
}

func DbGetAllBitcoinBurnTxIDs(handle *badger.DB) (_bitcoinBurnTxIDs []*BlockHash) {
	keysFound, _ := _enumerateKeysForPrefix(handle, _PrefixBitcoinBurnTxIDs)
	bitcoinBurnTxIDs := []*BlockHash{}
	for _, key := range keysFound {
		bbtxid := &BlockHash{}
		copy(bbtxid[:], key[1:])
		bitcoinBurnTxIDs = append(bitcoinBurnTxIDs, bbtxid)
	}

	return bitcoinBurnTxIDs
}

// =======================================================================================
// Listing code start
// TODO: Break into its own file?
// =======================================================================================

// -------------------------------------------------------------------------------------
// Helpers
// -------------------------------------------------------------------------------------

type ListingID struct {
	MerchantID   BlockHash
	ListingIndex uint32
}

func _getBlockHashForPrefixWithTxn(txn *badger.Txn, prefix []byte) *BlockHash {
	var ret BlockHash
	bhItem, err := txn.Get(prefix)
	if err != nil {
		return nil
	}
	_, err = bhItem.ValueCopy(ret[:])
	if err != nil {
		return nil
	}

	return &ret
}

func _getBlockHashForPrefix(handle *badger.DB, prefix []byte) *BlockHash {
	var ret *BlockHash
	err := handle.View(func(txn *badger.Txn) error {
		ret = _getBlockHashForPrefixWithTxn(txn, prefix)
		return nil
	})
	if err != nil {
		return nil
	}
	return ret
}

const (
	// Use a generous size for the maximum keyword length just to keep things sane.
	// Note that even if we didn't do this, we still shouldn't
	// have any problems around our keyword index getting too large becuase:
	// 1) The total number of merchants we index is restricted.
	// 2) The total amount of listing data per merchant is restricted (e.g. to ~5MB
	//    per merchant).
	// 3) The size of our index is directly proportional to:
	//    - (number of merchants allowed) * (average listing data per merchant)
	//    which is a quantity that is hard upper-bounded by the protocol.
	MaxKeywordLengthBytes = 120
)

// Takes the input text as a byte slice and does the following:
// - Escapes all null characters in the text into '0' (that is, the string "0").
// - Splits the text on whitespace.
// - Counts up all the unique strings.
// - Null-terminates all of the unique strings (meaning there should be precisely
//   one null byte at the end of the string and nowhere else thanks to the escaping
//   in the first step).
// - Returns all the now-null-termianted strings along with their counts.
func _computeKeywordsFromTextWithEscapingAndNullTermination(
	text []byte, keywordType KeywordType) (
	_nullTerminatedEscapedKeywords [][]byte, _keywordCounts []uint64) {

	// Replace all null characters with the text string "0" since we
	// null-terminate strings when we store them in the db. This should
	// be OK to do in both unicode and non-unicode strings
	// since the null character has the same encoding in both and since
	// null characters generally don't exist in unicode strings other than
	// the single unique character NUL, which is what we want to escape here.
	// See link below for more info on how the null character interacts with
	// unicode:
	// - https://stackoverflow.com/questions/6907297/can-utf-8-contain-zero-byte
	escapedString := strings.ReplaceAll(strings.ToLower(string(text)), "\000", "0")

	// When we're dealing with a category, we don't split it on whitespace like
	// we would for a title or body, but we still need to escape the text and
	// null terminate it, which we do later. When we're not dealing with a category
	// we split on white space.
	kwCounts := make(map[string]uint64)
	if keywordType == CategoryKeyword {
		kwCounts[escapedString] = 1
	} else {
		escapedKeywords := strings.Fields(escapedString)
		// Split on \\s+ basically and count up all the unique strings. Note they
		// should all be free of null characters because of the above.
		for _, sKeyword := range escapedKeywords {
			if _, exists := kwCounts[sKeyword]; !exists {
				kwCounts[sKeyword] = uint64(0)
			}
			// At this point there must be a count for the keyword thanks to the above.
			count, _ := kwCounts[sKeyword]
			kwCounts[sKeyword] = count + 1
		}
	}

	// Convert all the keywords to byte slices and null-terminate them.
	nullTerminatedEscapedKeywordBytes := [][]byte{}
	counts := []uint64{}
	for escapedKeywordString, count := range kwCounts {
		kwBytes := append([]byte(escapedKeywordString), byte(0))
		// If a keyword is too long, don't index it.
		if len(kwBytes) > MaxKeywordLengthBytes {
			continue
		}
		nullTerminatedEscapedKeywordBytes = append(nullTerminatedEscapedKeywordBytes, kwBytes)
		counts = append(counts, count)
	}

	return nullTerminatedEscapedKeywordBytes, counts
}

// -------------------------------------------------------------------------------------
// ListingBlockHash
// <_KeyListingBlockHash> -> <currentHash BlockHash>
// -------------------------------------------------------------------------------------

func DbGetListingBlockHashWithTxn(txn *badger.Txn) *BlockHash {
	return _getBlockHashForPrefixWithTxn(txn, _KeyListingBlockHash)
}

func DbGetListingBlockHash(handle *badger.DB) *BlockHash {
	return _getBlockHashForPrefix(handle, _KeyListingBlockHash)
}

func DbPutListingBlockHashWithTxn(txn *badger.Txn, bh *BlockHash) error {
	return txn.Set(_KeyListingBlockHash, bh[:])
}

func DbPutListingBlockHash(handle *badger.DB, bh *BlockHash) error {
	return handle.View(func(txn *badger.Txn) error {
		return DbPutListingBlockHashWithTxn(txn, bh)
	})
}

// -------------------------------------------------------------------------------------
// MerchantID Info
// <merchantID> -> <score, numBytes>
// -------------------------------------------------------------------------------------

type ListingMerchantIDInfo struct {
	Score    *big.Int
	NumBytes uint64
}

func _keyForListingMerchantIDInfo(merchantID *BlockHash) []byte {
	// Make a copy to avoid multiple calls to this function re-using the same
	// underlying array.
	prefixCopy := append([]byte{}, _PrefixListingMerchantIDScoreNumBytes...)
	return append(prefixCopy, merchantID[:]...)
}

func DbGetListingMerchantIDInfoWithTxn(txn *badger.Txn, merchantID *BlockHash) (
	_info *ListingMerchantIDInfo) {

	key := _keyForListingMerchantIDInfo(merchantID)
	infoObj := &ListingMerchantIDInfo{}
	infoItem, err := txn.Get(key)
	if err != nil {
		return nil
	}
	err = infoItem.Value(func(valBytes []byte) error {
		return gob.NewDecoder(bytes.NewReader(valBytes)).Decode(infoObj)
	})
	if err != nil {
		glog.Errorf("DbGetListingMerchantIDInfoWithTxn: Problem reading "+
			"ListingMerchantIDInfo for merchantID %v; should never happen: %v", merchantID, err)
		return nil
	}
	return infoObj
}

func DbGetListingMerchantIDInfo(handle *badger.DB, merchantID *BlockHash) (
	_info *ListingMerchantIDInfo) {
	var info *ListingMerchantIDInfo
	err := handle.View(func(txn *badger.Txn) error {
		info = DbGetListingMerchantIDInfoWithTxn(txn, merchantID)
		return nil
	})
	if err != nil {
		return nil
	}
	return info
}

func DbPutListingMerchantIDInfoWithTxn(txn *badger.Txn, merchantID *BlockHash, infoObj *ListingMerchantIDInfo) error {
	key := _keyForListingMerchantIDInfo(merchantID)

	infoBuf := bytes.NewBuffer([]byte{})
	gob.NewEncoder(infoBuf).Encode(infoObj)
	return txn.Set(key, infoBuf.Bytes())
}

func DbDeleteMerchantIDInfoWithTxn(txn *badger.Txn, merchantID *BlockHash) error {
	return txn.Delete(_keyForListingMerchantIDInfo(merchantID))
}

// -------------------------------------------------------------------------------------
// MerchantID score index
// <score (big-endian BlockHash) | merchantID> -> <>
// -------------------------------------------------------------------------------------

func _keyForListingScoreMerchantIDIndex(score *big.Int, merchantID *BlockHash) []byte {
	suffix := append(MerchantScoreToHash(score)[:], merchantID[:]...)
	// Make a copy to avoid multiple calls to this function re-using the same
	// underlying array.
	prefixCopy := append([]byte{}, _PrefixListingScoreMerchantID...)
	return append(prefixCopy, suffix...)
}

func DbPutListingScoreMerchantIDIndexWithTxn(txn *badger.Txn, score *big.Int, merchantID *BlockHash) error {
	return txn.Set(_keyForListingScoreMerchantIDIndex(score, merchantID), []byte{})
}

func DbExistsListingScoreMerchantIDWithTxn(txn *badger.Txn, score *big.Int, merchantID *BlockHash) bool {
	// We don't care about the value because we're just checking to see if the key exists.
	if _, err := txn.Get(_keyForListingScoreMerchantIDIndex(score, merchantID)); err != nil {
		return false
	}
	return true
}

func DbDeleteScoreMerchantIDIndexWithTxn(txn *badger.Txn, score *big.Int, merchantID *BlockHash) error {
	return txn.Delete(_keyForListingScoreMerchantIDIndex(score, merchantID))
}

func DbGetAllMerchantEntries(handle *badger.DB) (_merchantIDs []*BlockHash, _valsFound []*MerchantEntry) {
	keysFound, valsFound := _enumerateKeysForPrefix(handle, _PrefixMerchantIDToMerchantEntry)
	merchantIDs := []*BlockHash{}
	merchantEntries := []*MerchantEntry{}
	for _, key := range keysFound {
		mid := &BlockHash{}
		copy(mid[:], key[1:])
		merchantIDs = append(merchantIDs, mid)
	}
	for ii, val := range valsFound {
		merchantEntry, err := _DecodeMerchantEntry(val)
		if err != nil {
			glog.Errorf("_dumMerchantEntries: Problem decoding merchantID %d: %v", ii, err)
		}
		merchantEntry.merchantID = merchantIDs[ii]
		merchantEntries = append(merchantEntries, merchantEntry)
	}

	return merchantIDs, merchantEntries
}

// DbGetListingTopMerchants gets the top merchants according to the listing db. Note
// this is in contrast with DbGetBlockchainTopMerchants, which gets the top merchants according
// to the blockchain. Normally the blockchain's top merchants will be a block or two
// ahead of the listing's version, since in general merchants are processed in a block
// and then the listing index is instructed to update its view based on what merchants
// were added or removed.
func DbGetListingTopMerchants(handle *badger.DB, numMerchantsToFetch uint64, noMerchantEntries bool) (
	_merchantIDs []*BlockHash, _scores []*big.Int, _merchantEntries []*MerchantEntry, _err error) {

	return _getTopMerchantsForDbPrefix(handle, true, /*useListingDB*/
		numMerchantsToFetch, noMerchantEntries, false /*errorIfInconsistentMerchantEntryFound*/)
}

// -------------------------------------------------------------------------------------
// Listing data
// <merchantID BlockHash | listingIndex uint64 big-endian> -> <MsgUltranetListing>
// -------------------------------------------------------------------------------------

func _keyForListingMessage(merchantID *BlockHash, listingIndex uint32) []byte {
	ret := append([]byte{}, _PrefixListingMerchantIDListingIndexToListingMessage...)
	ret = append(ret, merchantID[:]...)
	ret = append(ret, _EncodeUint64(uint64(listingIndex))...)
	return ret
}

func DbGetListingMessageWithTxn(txn *badger.Txn, merchantID *BlockHash, listingIndex uint32) *MsgUltranetListing {
	key := _keyForListingMessage(merchantID, listingIndex)
	listingMessage := &MsgUltranetListing{}
	listingItem, err := txn.Get(key)
	if err != nil {
		return nil
	}
	err = listingItem.Value(func(valBytes []byte) error {
		return listingMessage.FromBytes(valBytes)
	})
	if err != nil {
		glog.Errorf("DbGetListingMessageWithTxn: Problem reading "+
			"MsgUltranetListing for merchantID %v, index: %d; should never happen: %v",
			merchantID, listingIndex, err)
		return nil
	}
	return listingMessage
}

func DbGetListingMessage(handle *badger.DB, merchantID *BlockHash, listingIndex uint32) *MsgUltranetListing {
	var listingMessage *MsgUltranetListing
	handle.View(func(txn *badger.Txn) error {
		listingMessage = DbGetListingMessageWithTxn(txn, merchantID, listingIndex)
		return nil
	})
	return listingMessage

}

func DbPutListingMessageWithTxn(txn *badger.Txn, listingMessage *MsgUltranetListing) error {
	key := _keyForListingMessage(listingMessage.MerchantID, listingMessage.ListingIndex)
	messageBytes, err := listingMessage.ToBytes(false /*preSignature*/)
	if err != nil {
		return fmt.Errorf("DbPutListingMessageWithTxn: Problem serializing listing %v: %v", listingMessage, err)
	}
	return txn.Set(key, messageBytes)
}

func DbDeleteListingMessageWithTxn(txn *badger.Txn, merchantID *BlockHash, listingIndex uint32) error {
	key := _keyForListingMessage(merchantID, listingIndex)
	return txn.Delete(key)
}

// -------------------------------------------------------------------------------------
// {Title, Body, Category} keyword index
// <keyword []byte | byte(0) | merchantID | listingIndex big-endian> -> <numOccurrences uvarint>
// <keyword []byte> -> count uvarint
//
// Note that we escape all null bytes in the tite as char('0') when processing keywords
// so that they can be uniquely stored as null-termianted strings.
// -------------------------------------------------------------------------------------

type KeywordType uint8

const (
	// KeywordType ...
	TitleKeyword KeywordType = 0
	// BodyKeyword ...
	BodyKeyword KeywordType = 1
	// CategoryKeyword ...
	CategoryKeyword KeywordType = 2
)

func _dbGetKeywordCountForKeyWithTxn(txn *badger.Txn, key []byte) uint64 {
	count := uint64(0)

	countItem, err := txn.Get(key)
	if err != nil {
		// If the mapping doesn't exist, return zero. We don't distinguish between
		// the mapping not existing and the mapping existing with zero.
		return 0
	}
	err = countItem.Value(func(valBytes []byte) error {
		convertedCount, numBytes := Uvarint(valBytes)
		if numBytes <= 0 {
			count = 0
		}
		count = convertedCount
		return nil
	})
	if err != nil {
		return 0
	}
	return count
}

func _keyForListingKeywordNumOccurrences(
	keywordType KeywordType, escapedNullTerminatedKeyword []byte,
	merchantID *BlockHash, listingIndex uint32) []byte {

	var dbPrefix []byte
	switch keywordType {
	case TitleKeyword:
		dbPrefix = append([]byte{}, _PrefixListingTitleKeywordListingIDToCount...)
	case BodyKeyword:
		dbPrefix = append([]byte{}, _PrefixListingBodyKeywordListingIDToCount...)
	case CategoryKeyword:
		dbPrefix = append([]byte{}, _PrefixListingCategoryKeywordListingIDToCount...)
	default:
		glog.Errorf("_keyForListingKeywordNumOccurrences: Unrecognized KeywordType %d; returning nil key", keywordType)
		return nil
	}

	retBytes := dbPrefix
	retBytes = append(retBytes, escapedNullTerminatedKeyword...)
	retBytes = append(retBytes, merchantID[:]...)
	retBytes = append(retBytes, _EncodeUint64(uint64(listingIndex))...)
	return retBytes
}

func _prefixForKeywordListingSearch(
	keywordType KeywordType, escapedNullTerminatedKeyword []byte) []byte {

	var dbPrefix []byte
	switch keywordType {
	case TitleKeyword:
		dbPrefix = _PrefixListingTitleKeywordListingIDToCount
	case BodyKeyword:
		dbPrefix = _PrefixListingBodyKeywordListingIDToCount
	case CategoryKeyword:
		dbPrefix = _PrefixListingCategoryKeywordListingIDToCount
	default:
		glog.Errorf("_keyForListingKeywordNumOccurrences: Unrecognized KeywordType %d; returning nil key", keywordType)
		return nil
	}

	retBytes := dbPrefix
	retBytes = append(retBytes, escapedNullTerminatedKeyword...)
	return retBytes
}

func _keyForGlobalKeywordCount(keywordType KeywordType, escapedNullTerminatedKeyword []byte) []byte {
	var dbPrefix []byte
	switch keywordType {
	case TitleKeyword:
		dbPrefix = _PrefixListingTitleKeywordToListingCount
	case BodyKeyword:
		dbPrefix = _PrefixListingBodyKeywordToListingCount
	case CategoryKeyword:
		dbPrefix = _PrefixListingCategoryKeywordToListingCount
	default:
		glog.Errorf("_keyForListingKeywordNumOccurrences: Unrecognized KeywordType %d; returning nil key", keywordType)
		return nil
	}

	return append(dbPrefix, escapedNullTerminatedKeyword...)
}

// GetListingKeywordNumOccurrences
func DbGetListingKeywordNumOccurrencesForKeywordTypeWithTxn(
	txn *badger.Txn, keywordType KeywordType, escapedNullTerminatedKeyword []byte,
	merchantID *BlockHash, listingIndex uint32) uint64 {

	key := _keyForListingKeywordNumOccurrences(keywordType, escapedNullTerminatedKeyword, merchantID, listingIndex)
	return _dbGetKeywordCountForKeyWithTxn(txn, key)
}

// PutListingKeywordNumOccurrences
func DbPutListingKeywordNumOccurrencesForKeywordTypeWithTxn(
	txn *badger.Txn, keywordType KeywordType, escapedNullTerminatedKeyword []byte,
	merchantID *BlockHash, listingIndex uint32, count uint64) error {

	key := _keyForListingKeywordNumOccurrences(
		keywordType, escapedNullTerminatedKeyword, merchantID, listingIndex)
	return txn.Set(key, UintToBuf(count))
}

// RemoveListingKeywordNumOccurrences
func DbDeleteListingKeywordNumOccurrencesForKeywordTypeWithTxn(
	txn *badger.Txn, keywordType KeywordType, escapedNullTerminatedKeyword []byte,
	merchantID *BlockHash, listingIndex uint32) error {

	key := _keyForListingKeywordNumOccurrences(
		keywordType, escapedNullTerminatedKeyword, merchantID, listingIndex)
	return txn.Delete(key)
}

func DbGetGlobalKeywordCountForKeywordType(db *badger.DB, keywordType KeywordType, escapedNullTerminatedKeyword []byte) uint64 {
	var ret uint64
	db.View(func(txn *badger.Txn) error {
		ret = DbGetGlobalKeywordCountForKeywordTypeWithTxn(txn, keywordType, escapedNullTerminatedKeyword)
		return nil
	})
	return ret
}

// GetGlobalKeywordCount
func DbGetGlobalKeywordCountForKeywordTypeWithTxn(
	txn *badger.Txn, keywordType KeywordType, escapedNullTerminatedKeyword []byte) uint64 {

	key := _keyForGlobalKeywordCount(keywordType, escapedNullTerminatedKeyword)
	return _dbGetKeywordCountForKeyWithTxn(txn, key)
}

// PutBlobalKeywordCount
func DbPutGlobalKeywordCountForKeywordTypeWithTxn(
	txn *badger.Txn, keywordType KeywordType, escapedNullTerminatedKeyword []byte, count uint64) error {

	key := _keyForGlobalKeywordCount(keywordType, escapedNullTerminatedKeyword)
	return txn.Set(key, UintToBuf(count))
}

// RemoveBlobalKeyword
func DbDeleteGlobalKeywordCountForKeywordTypeWithTxn(
	txn *badger.Txn, keywordType KeywordType, escapedNullTerminatedKeyword []byte) error {

	key := _keyForGlobalKeywordCount(keywordType, escapedNullTerminatedKeyword)
	return txn.Delete(key)
}

func DbGetListingIDsContainingKeyword(
	handle *badger.DB, keywordType KeywordType, escapedNullTerminatedKeyword []byte) (
	_merchantIDs []*BlockHash, _listingIndexes []uint32, _numOccurrences []uint64, _err error) {

	merchantIDs := []*BlockHash{}
	listingIndexes := []uint32{}
	numOccurrences := []uint64{}

	dbErr := handle.View(func(txn *badger.Txn) error {
		var err error
		merchantIDs, listingIndexes, numOccurrences, err =
			DbGetListingIDsContainingKeywordWithTxn(txn, keywordType, escapedNullTerminatedKeyword)
		if err != nil {
			return err
		}
		return nil
	})
	if dbErr != nil {
		return nil, nil, nil, dbErr
	}

	return merchantIDs, listingIndexes, numOccurrences, nil
}

func DbGetListingIDsContainingKeywordWithTxn(
	txn *badger.Txn, keywordType KeywordType, escapedNullTerminatedKeyword []byte) (
	_merchantIDs []*BlockHash, _listingIndexes []uint32, _numOccurrences []uint64, _err error) {

	merchantIDs := []*BlockHash{}
	listingIndexes := []uint32{}
	numOccurrences := []uint64{}

	opts := badger.DefaultIteratorOptions
	nodeIterator := txn.NewIterator(opts)
	defer nodeIterator.Close()
	prefix := _prefixForKeywordListingSearch(keywordType, escapedNullTerminatedKeyword)
	for nodeIterator.Seek(prefix); nodeIterator.ValidForPrefix(prefix); nodeIterator.Next() {
		// Strip the prefix off the key. What's left should be the merchantID and the
		// listingIndex encoded as a big-endian uint64.
		listingIDKey := nodeIterator.Item().Key()
		listingIDBytes := listingIDKey[len(prefix):]
		// The size of the key should be equal to the size of a blockhash plus the size
		// of a uint64.
		uint64BytesLen := 8
		if len(listingIDBytes) != (uint64BytesLen + HashSizeBytes) {
			return nil, nil, nil, fmt.Errorf("DbGetListingIDsContainingKeywordWithTxn: Problem reading "+
				"<keyword, merchantID, listingIndex> mapping; remaining key size %d is too "+
				"short %d", len(listingIDBytes), uint64BytesLen+HashSizeBytes)
		}

		merchantID := &BlockHash{}
		copy(merchantID[:], listingIDBytes[:HashSizeBytes])
		listingIndexBytes := listingIDBytes[HashSizeBytes:]
		listingIndexVal := uint32(_DecodeUint64(listingIndexBytes))

		// Try and extract the number of occurrences from the message.
		var numOccurrencesVal uint64
		err := nodeIterator.Item().Value(func(valBytes []byte) error {
			var numBytesRead int
			numOccurrencesVal, numBytesRead = Uvarint(valBytes)
			if numBytesRead <= 0 {
				return fmt.Errorf("DbGetListingIDsContainingKeywordWithTxn: "+
					"value %#v as uvarint for merchantID %v and listingIndex %d",
					valBytes, merchantID, listingIndexVal)
			}
			return nil
		})
		if err != nil {
			return nil, nil, nil, err
		}

		merchantIDs = append(merchantIDs, merchantID)
		listingIndexes = append(listingIndexes, listingIndexVal)
		numOccurrences = append(numOccurrences, numOccurrencesVal)
	}

	return merchantIDs, listingIndexes, numOccurrences, nil
}

// -------------------------------------------------------------------------------------
// Category count index
// <count uint64 big-endian | category> -> <numListings uvarint>
//
// We store this extra index for categories so that the top categories and the number
// of listings for each category can be shown to the user.
//
// Note that we escape all null bytes in the tite as char('0') when processing categories.
// -------------------------------------------------------------------------------------

func _keyForCategoryCount(dbPrefix []byte, escapedNullTerminatedCategory []byte, count uint64) []byte {
	countKey := append(_EncodeUint64(count), escapedNullTerminatedCategory...)
	return append(dbPrefix, countKey...)
}

func DbGetListingTopCategories(handle *badger.DB, numCategories uint64) (
	_categories [][]byte, _counts []uint64, _err error) {
	dbPrefixx := append([]byte{}, _PrefixListingCountCategory...)

	countsFetched := []uint64{}
	categoriesFetched := [][]byte{}

	err := handle.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions

		opts.PrefetchValues = false

		// Go in reverse order since a larger count is better.
		opts.Reverse = true

		it := txn.NewIterator(opts)
		defer it.Close()
		// Since we iterate backwards, the prefix must be bigger than all possible
		// counts that could actually exist. We use eight bytes since the count is
		// encoded as a 64-bit big-endian byte slice, which will be eight bytes long.
		maxBigEndianUint64Bytes := []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
		prefix := append(dbPrefixx, maxBigEndianUint64Bytes...)
		for it.Seek(prefix); it.ValidForPrefix(dbPrefixx); it.Next() {
			countKey := it.Item().Key()

			// Strip the prefix off the score key and check its length. If it contains
			// a big-endian uint64 then it should be at least eight bytes.
			countKey = countKey[1:]
			uint64BytesLen := len(maxBigEndianUint64Bytes)
			if len(countKey) < uint64BytesLen {
				return fmt.Errorf("DbGetListingTopCategories: Invalid category key "+
					"length %d should be at least %d", len(countKey), uint64BytesLen)
			}

			countVal := _DecodeUint64(countKey[:uint64BytesLen])

			// Appended to the count should be the keyword so extract it here.
			categoryVal := make([]byte, len(countKey[uint64BytesLen:]))
			copy(categoryVal[:], countKey[uint64BytesLen:])

			if uint64(len(countsFetched)) == numCategories {
				return nil
			}
			countsFetched = append(countsFetched, countVal)
			categoriesFetched = append(categoriesFetched, categoryVal)
		}
		return nil
	})
	if err != nil {
		return nil, nil, err
	}

	// Return the categories fetched along with their counts.
	return categoriesFetched, countsFetched, nil
}

func DbExistsListingCategoryCountWithTxn(txn *badger.Txn, escapedNullTerminatedCategory []byte, count uint64) bool {
	key := _keyForCategoryCount(_PrefixListingCountCategory, escapedNullTerminatedCategory, count)
	_, err := txn.Get(key)
	if err != nil {
		return false
	}
	return true
}

func DbPutListingCategoryCountWithTxn(txn *badger.Txn, escapedNullTerminatedCategory []byte, count uint64) error {
	key := _keyForCategoryCount(_PrefixListingCountCategory, escapedNullTerminatedCategory, count)
	return txn.Set(key, []byte{})
}

func DbDeleteListingCategoryCountWithTxn(txn *badger.Txn, escapedNullTerminatedCategory []byte, count uint64) error {
	key := _keyForCategoryCount(_PrefixListingCountCategory, escapedNullTerminatedCategory, count)
	return txn.Delete(key)
}

// -------------------------------------------------------------------------------------
// Add/Remove all mappings associated with a MerchantID
//
// Uses all of the above.
// -------------------------------------------------------------------------------------

func DbGetListingsForMerchantID(handle *badger.DB, merchantID *BlockHash, fetchListings bool) (
	_listingIndices []uint32, _listings []*MsgUltranetListing, _err error) {

	listingIndices := []uint32{}
	listingMessages := []*MsgUltranetListing{}
	dbErr := handle.View(func(txn *badger.Txn) error {
		var err error
		listingIndices, listingMessages, err = DbGetListingsForMerchantIDWithTxn(txn, merchantID, fetchListings)
		return err
	})
	if dbErr != nil {
		return nil, nil, dbErr
	}
	return listingIndices, listingMessages, nil
}

func DbGetListingsForMerchantIDWithTxn(txn *badger.Txn, merchantID *BlockHash, fetchListings bool) (
	_listingIndices []uint32, _listings []*MsgUltranetListing, _err error) {

	listingIndicesFound := []uint32{}
	listingMessagesFound := []*MsgUltranetListing{}

	opts := badger.DefaultIteratorOptions
	opts.PrefetchValues = fetchListings
	nodeIterator := txn.NewIterator(opts)
	defer nodeIterator.Close()
	prefixCopy := append([]byte{}, _PrefixListingMerchantIDListingIndexToListingMessage...)
	prefix := append(prefixCopy, merchantID[:]...)
	for nodeIterator.Seek(prefix); nodeIterator.ValidForPrefix(prefix); nodeIterator.Next() {
		// Strip the prefix off the key. What's left should be the listingIndex encoded
		// as a big-endian uint64.
		merchantIDKey := nodeIterator.Item().Key()
		listingIndexBytes := merchantIDKey[len(prefix):]
		// The size of the utxo key bytes should be equal to the size of a
		// standard hash (the txid) plus the size of a uint32.
		uint64BytesLen := 8
		if len(listingIndexBytes) != uint64BytesLen {
			return nil, nil, fmt.Errorf("DbGetListingIndicesForMerchantIDWithTxn: Problem reading "+
				"<merchantID, listingIndex> mapping; key size %d "+
				"is not equal to (prefix_byte=%d + HashSizeBytes=%d + len(uint64Bytes)=%d)=%d. "+
				"Key found: %#v", len(merchantIDKey), len(_PrefixListingMerchantIDListingIndexToListingMessage),
				HashSizeBytes, uint64BytesLen,
				len(_PrefixListingMerchantIDListingIndexToListingMessage)+HashSizeBytes+uint64BytesLen,
				merchantIDKey)
		}
		// Try and convert the listingIndex bytes into a uint32.
		listingIndexVal := uint32(_DecodeUint64(listingIndexBytes))
		listingIndicesFound = append(listingIndicesFound, listingIndexVal)

		// Try and extract the value message if required.
		if fetchListings {
			listingMessage := &MsgUltranetListing{}
			err := nodeIterator.Item().Value(func(valBytes []byte) error {
				return listingMessage.FromBytes(valBytes)
			})
			if err != nil {
				return nil, nil, errors.Wrapf(err, "DbGetListingIndicesForMerchantIDWithTxn: "+
					"Problem decoding MsgUltranetListing value for MerchantID %v, listingIndex %d, "+
					"key: %#v", merchantID, listingIndexVal, merchantIDKey)
			}
			listingMessagesFound = append(listingMessagesFound, listingMessage)
		}
	}

	return listingIndicesFound, listingMessagesFound, nil
}

func _removeMappingsForKeywords(txn *badger.Txn, merchantID *BlockHash,
	listingIndex uint32, text []byte, kwType KeywordType) error {

	// Compute all of the keywords. If we're dealing with a category we treat it
	// as one keyword (i.e. we don't split it on whitespace).
	escapedNullTerminatedKeywords, keywordCounts :=
		_computeKeywordsFromTextWithEscapingAndNullTermination(text, kwType)

	// For each keyword, sanity check that its mapping exists in the db for this
	// listing and then delete it.
	for ii := range escapedNullTerminatedKeywords {
		keyword := escapedNullTerminatedKeywords[ii]
		numOccurrences := keywordCounts[ii]
		dbNumOccurrences := DbGetListingKeywordNumOccurrencesForKeywordTypeWithTxn(
			txn, kwType, keyword, merchantID, listingIndex)
		// Sanity-check that the number of occurrences according to the db is
		// in-line with the number of occurrences in the listing fetched.
		if numOccurrences != dbNumOccurrences {
			return fmt.Errorf("_removeMappingsForKeywords: Number of "+
				"occurrences for keyword %s found in listing %d is not equal to number "+
				"of occurrences recorded in the db %d; this should never happen", string(keyword),
				numOccurrences, dbNumOccurrences)
		}

		// Now that we've finished our sanity-checking, delete the keyword from
		// the mapping for this listing.
		err := DbDeleteListingKeywordNumOccurrencesForKeywordTypeWithTxn(
			txn, kwType, keyword, merchantID, listingIndex)
		if err != nil {
			return errors.Wrapf(err, "_removeMappingsForKeywords: Problem deleting "+
				"listing keyword %s for merchantID %v listingIndex %v type %v: ",
				string(keyword), merchantID, listingIndex, kwType)
		}

		// Since we are removing this listing, subtract one from the global
		// <keyword> -> numListingsContainingKeyword map. Sanity-check that
		// this doesn't cause us to go negative.
		numListingsContainingKeyword :=
			DbGetGlobalKeywordCountForKeywordTypeWithTxn(txn, kwType, keyword)
		if numListingsContainingKeyword == 0 {
			return fmt.Errorf("_removeMappingsForKeywords: Number of "+
				"listings containing keyword %s according to the db is zero even "+
				"though we have a listing in the db containing this keyword; this "+
				"should never happen", string(keyword))
		}
		// This should over-write the previous value.
		DbPutGlobalKeywordCountForKeywordTypeWithTxn(
			txn, kwType, keyword, numListingsContainingKeyword-1)
		// If the value happens to be zero, just remove the mapping completely to
		// free up space and keep things clean.
		if (numListingsContainingKeyword - 1) == 0 {
			DbDeleteGlobalKeywordCountForKeywordTypeWithTxn(txn, kwType, keyword)
		}

		if kwType == CategoryKeyword {
			// If we're dealing with a category keyword, we have to do one more step
			// because we store a mapping that indexes them by count:
			// - <numListingsContainingCategory | category> -> <>
			//
			// Look up the mapping with the current value to sanity-check that it exists.
			if !DbExistsListingCategoryCountWithTxn(txn, keyword, numListingsContainingKeyword) {
				return fmt.Errorf("_removeMappingsForKeywords: Category %s does not have "+
					"mapping <count=%d|keyword=%s> even though a ( <category> -> <count> ) entry "+
					"was found; this should never happen", string(keyword),
					numListingsContainingKeyword, string(keyword))
			}

			// Delete the existing mapping and create a new mapping decremented by one to
			// reflect that this listing is being removed.
			err = DbDeleteListingCategoryCountWithTxn(txn, keyword, numListingsContainingKeyword)
			if err != nil {
				return errors.Wrapf(err, "_removeMappingsForKeywords: Problem deleting "+
					"listing category count for category %s for merchantID %v listingIndex %v type %v: ",
					string(keyword), merchantID, listingIndex, kwType)
			}
			// Only re-add a mapping if the number of listings with this category is still
			// above zero.
			if (numListingsContainingKeyword - 1) > 0 {
				err = DbPutListingCategoryCountWithTxn(txn, keyword, numListingsContainingKeyword-1)
				if err != nil {
					return errors.Wrapf(err, "_removeMappingsForKeywords: Problem putting "+
						"listing category count for category %s for merchantID %v listingIndex %v type %v: ",
						string(keyword), merchantID, listingIndex, kwType)
				}
			}
		}
	}

	// At this point all of the keywords in the text and their associated mappings
	// should be removed from the db.
	return nil
}

func DbDeleteMappingsForSingleListingWithTxn(
	txn *badger.Txn, merchantID *BlockHash, listingIndex uint32) error {
	// Verify that a <merchantID | listingIndex> -> MsgUltranetListing mapping
	// exists. This is a redundant sanity check.
	//
	// TODO: This method doesn't need to be so pedantic about only removing mappings
	// only if the listing already exists, but doing it this way will help us catch
	// errors initially.
	listingMessage := DbGetListingMessageWithTxn(txn, merchantID, listingIndex)
	if listingMessage == nil {
		return fmt.Errorf("DbDeleteMappingsForSingleListingWithTxn: Sanity check "+
			"failed for <merchantID %v, listingIndex: %d>; found listing %v when "+
			"seeking but did not find the same listing when getting: ",
			merchantID, listingMessage.ListingIndex, listingMessage)
	}

	// After sanity-checking, delete the <merchantID | listingIndex> -> MsgUltranetListing
	// mapping.
	if err := DbDeleteListingMessageWithTxn(txn, merchantID, listingMessage.ListingIndex); err != nil {
		return errors.Wrapf(err, "DbDeleteMappingsForSingleListingWithTxn: Problem "+
			"deleting listing %v: ", listingMessage)
	}

	// Compute the size of the listing being deleted.
	listingBytes, err := listingMessage.ToBytes(false /*preSignature*/)
	if err != nil {
		return errors.Wrapf(err, "DbDeleteMappingsForSingleListingWithTxn: Problem serializing "+
			"listing %v: ", listingMessage)
	}
	listingSizeBytes := len(listingBytes)

	// Update the <merchantID> -> <score, numBytes> mapping to reflect that the
	// listing has been deleted.
	merchantInfo := DbGetListingMerchantIDInfoWithTxn(txn, merchantID)
	if merchantInfo == nil {
		return fmt.Errorf("DbDeleteMappingsForSingleListingWithTxn: ListingMerchantIDInfo "+
			"does not exist for merchantID %v even though listing exists: ", merchantID)
	}
	if merchantInfo.NumBytes < uint64(listingSizeBytes) {
		return fmt.Errorf("DbDeleteMappingsForSingleListingWithTxn: Deleting ListingMerchantIDInfo "+
			"with size %d for merchantID %v would make total size %d negative; this "+
			"should never happen: ", listingSizeBytes, merchantID, merchantInfo.NumBytes)
	}
	merchantInfo.NumBytes -= uint64(listingSizeBytes)
	// Should over-write the previous value.
	DbPutListingMerchantIDInfoWithTxn(txn, merchantID, merchantInfo)

	// Remove the title keyword mappings from the db.
	err = _removeMappingsForKeywords(
		txn, merchantID, listingIndex, listingMessage.Title, TitleKeyword)
	if err != nil {
		return fmt.Errorf("DbDeleteMappingsForSingleListingWithTxn: Problem deleting "+
			"Title keywords for listing %v: ", listingMessage)
	}

	// Remove the body keyword mappings from the db. We add the category to the
	// body so that it will be split and indexed as part of that corpus and so we
	// need to remove it here.
	bodyCopy := append([]byte{}, listingMessage.Body...)
	bodyWithCategory := append(bodyCopy, []byte(" ")...)
	bodyWithCategory = append(bodyWithCategory, listingMessage.Category...)
	err = _removeMappingsForKeywords(
		txn, merchantID, listingIndex, bodyWithCategory, BodyKeyword)
	if err != nil {
		return fmt.Errorf("DbDeleteMappingsForSingleListingWithTxn: Problem deleting "+
			"Body keywords for listing %v: ", listingMessage)
	}

	// Remove the category keyword mappings from the db.
	err = _removeMappingsForKeywords(
		txn, merchantID, listingIndex, listingMessage.Category, CategoryKeyword)
	if err != nil {
		return fmt.Errorf("DbDeleteMappingsForSingleListingWithTxn: Problem deleting "+
			"Category keywords for listing %v: ", listingMessage)
	}

	// Remove mapping from the listing's hash to its basic information.
	// Verify that it exists before deleting as a sanity-check.
	hash := listingMessage.Hash()
	if hash == nil {
		return fmt.Errorf("DbDeleteMappingsForSingleListingWithTxn: Problem "+
			"computing hash for listing %v: ", listingMessage)
	}
	oldHashIndexValue := DbGetMappingForListingHashIndexWithTxn(txn, hash)
	if oldHashIndexValue == nil {
		return fmt.Errorf("DbDeleteMappingsForSingleListingWithTxn: Trying to delete "+
			"hash index value for listing but hash %v doesn't exist even though "+
			"listing does; this should never happen %v: ", hash, listingMessage)
	}
	if err := DbDeleteMappingForListingHashIndexWithTxn(txn, listingMessage); err != nil {
		return errors.Wrapf(err, "DbDeleteMappingsForSingleListingWithTxn: Problem deleting "+
			"hash index mapping for listing %v: ", listingMessage)
	}

	// If we get here, all the mappings should have been removed successfully and all
	// of our sanity checks should have passed.
	return nil
}

func _addMappingsForKeywords(txn *badger.Txn, merchantID *BlockHash,
	listingIndex uint32, text []byte, kwType KeywordType) error {

	// Compute all of the keywords. If we're dealing with a category we treat it
	// as one keyword (i.e. we don't split it on whitespace).
	escapedNullTerminatedKeywords, keywordCounts :=
		_computeKeywordsFromTextWithEscapingAndNullTermination(text, kwType)

	// For each keyword, sanity check that its mapping does not exist in the db for this
	// listing and then add it.
	for ii := range escapedNullTerminatedKeywords {
		keyword := escapedNullTerminatedKeywords[ii]
		numOccurrences := keywordCounts[ii]
		dbNumOccurrences := DbGetListingKeywordNumOccurrencesForKeywordTypeWithTxn(
			txn, kwType, keyword, merchantID, listingIndex)
		// Sanity-check that the number of occurrences according to the db is zero since
		// this keyword shouldn't exist for this listing yet.
		if dbNumOccurrences != 0 {
			return fmt.Errorf("_addMappingsForKeywords: Number of "+
				"occurrences for keyword %s found in db is %d even though it should "+
				"be zero because this listing has never been added; this should never happen",
				string(keyword), dbNumOccurrences)
		}

		// Now that we've finished our sanity-checking, add the keyword to
		// the mapping for this listing.
		err := DbPutListingKeywordNumOccurrencesForKeywordTypeWithTxn(
			txn, kwType, keyword, merchantID, listingIndex, numOccurrences)
		if err != nil {
			return errors.Wrapf(err, "_addMappingsForKeywords: Problem deleting "+
				"listing keyword %s for merchantID %v listingIndex %v type %v: ",
				string(keyword), merchantID, listingIndex, kwType)
		}

		// Since we are adding this listing, add to the global
		// <keyword> -> numListingsContainingKeyword map. Note numListingsContainingKeyword
		// will be zero if no mapping yet exists in the db for this keyword.
		numListingsContainingKeyword :=
			DbGetGlobalKeywordCountForKeywordTypeWithTxn(txn, kwType, keyword)
		// This should over-write the previous value if one exists.
		DbPutGlobalKeywordCountForKeywordTypeWithTxn(
			txn, kwType, keyword, numListingsContainingKeyword+1)

		if kwType == CategoryKeyword {
			// If we're dealing with a category keyword, we have to do one more step
			// because we store a mapping that indexes them by count:
			// - <numListingsContainingCategory | category> -> <>

			// Delete the existing mapping and create a new mapping incremented by one to
			// reflect that this listing is being removed.
			err = DbDeleteListingCategoryCountWithTxn(txn, keyword, numListingsContainingKeyword)
			if err != nil {
				return errors.Wrapf(err, "_addMappingsForKeywords: Problem deleting "+
					"listing category count for category %s for merchantID %v listingIndex %v type %v: ",
					string(keyword), merchantID, listingIndex, kwType)
			}
			err = DbPutListingCategoryCountWithTxn(txn, keyword, numListingsContainingKeyword+1)
			if err != nil {
				return errors.Wrapf(err, "_addMappingsForKeywords: Problem putting "+
					"listing category count for category %s for merchantID %v listingIndex %v type %v: ",
					string(keyword), merchantID, listingIndex, kwType)
			}
		}
	}

	// At this point all of the keywords in the text and their associated mappings
	// should be removed from the db.
	return nil
}

type ListingHashIndexValue struct {
	MerchantID   *BlockHash
	ListingIndex uint32
	TstampSecs   uint32
}

func _keyForListingHashIndexWithHash(listingHash *BlockHash) []byte {
	if listingHash == nil {
		return append([]byte{}, _PrefixListingHashToMerchantIDListingIndexTstampSecs...)
	}
	prefixCopy := append([]byte{}, _PrefixListingHashToMerchantIDListingIndexTstampSecs...)
	return append(prefixCopy, listingHash[:]...)
}

func _keyForListingHashIndexWithMessage(listingMessage *MsgUltranetListing) ([]byte, error) {
	listingHash := listingMessage.Hash()
	if listingHash == nil {
		return nil, fmt.Errorf("_keyForListingHasIndex: Problem computing "+
			"hash for listing message %v: ", listingMessage)
	}
	return _keyForListingHashIndexWithHash(listingHash), nil
}

func DbGetAllListingHashes(db *badger.DB) ([]*BlockHash, error) {
	dbPrefix := _keyForListingHashIndexWithHash(nil)

	hashesFound := []*BlockHash{}

	err := db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.PrefetchValues = false
		nodeIterator := txn.NewIterator(opts)
		defer nodeIterator.Close()
		prefix := dbPrefix
		for nodeIterator.Seek(prefix); nodeIterator.ValidForPrefix(prefix); nodeIterator.Next() {
			key := nodeIterator.Item().Key()
			// Strip off the db prefix.
			key = key[len(dbPrefix):]
			// The remainder of the key should be HashSizeBytes since it's just
			// a block hash.
			if len(key) != HashSizeBytes {
				return fmt.Errorf("DbGetAllListingHashes: Key found with length %d not "+
					"equal to %d", len(key), HashSizeBytes)
			}

			hash := BlockHash{}
			copy(hash[:], key[:])

			hashesFound = append(hashesFound, &hash)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	return hashesFound, nil
}

func DbGetMappingForListingHashIndex(db *badger.DB, listingHash *BlockHash) *ListingHashIndexValue {
	var ret *ListingHashIndexValue
	err := db.View(func(txn *badger.Txn) error {
		ret = DbGetMappingForListingHashIndexWithTxn(txn, listingHash)
		return nil
	})
	if err != nil {
		return nil
	}
	return ret
}

func DbGetMappingForListingHashIndexWithTxn(txn *badger.Txn, listingHash *BlockHash) *ListingHashIndexValue {
	key := _keyForListingHashIndexWithHash(listingHash)
	item, err := txn.Get(key)
	if err != nil {
		return nil
	}
	ret := &ListingHashIndexValue{}
	err = item.Value(func(valBytes []byte) error {
		if err := gob.NewDecoder(bytes.NewReader(valBytes)).Decode(ret); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return nil
	}
	return ret
}

func DbPutMappingForListingHashIndexWithTxn(txn *badger.Txn, listingMessage *MsgUltranetListing) error {
	key, err := _keyForListingHashIndexWithMessage(listingMessage)
	if err != nil {
		return errors.Wrapf(err, "DbPutMappingForListingHashIndexWithTxn: ")
	}
	valueObj := &ListingHashIndexValue{
		MerchantID:   listingMessage.MerchantID,
		ListingIndex: listingMessage.ListingIndex,
		TstampSecs:   listingMessage.TstampSecs,
	}
	valueBuf := bytes.NewBuffer([]byte{})
	gob.NewEncoder(valueBuf).Encode(valueObj)
	return txn.Set(key, valueBuf.Bytes())
}

func DbDeleteMappingForListingHashIndexWithTxn(txn *badger.Txn, listingMessage *MsgUltranetListing) error {
	key, err := _keyForListingHashIndexWithMessage(listingMessage)
	if err != nil {
		return errors.Wrapf(err, "DbDeleteMappingForListingHashIndexWithTxn: ")
	}
	return txn.Delete(key)
}

func DbPutMappingsForSingleListingWithTxn(txn *badger.Txn, listingMessage *MsgUltranetListing) error {
	// Verify that a <merchantID | score> -> info mapping exists. If this doesn't exist
	// it menas the merchant has not been initialized and/or is not authorized to have
	// any listings.
	merchantInfo := DbGetListingMerchantIDInfoWithTxn(txn, listingMessage.MerchantID)
	if merchantInfo == nil {
		return fmt.Errorf("DbPutMappingsForSingleListingWithTxn: Missing "+
			"merchant info (score, numBytes) for merchantID %v",
			listingMessage.MerchantID)
	}
	// Sanity-check to make sure that there is no <merchantID | listingIndex> mapping
	// for this listing already. We do not over-write listings in this function.
	dbListingMessage := DbGetListingMessageWithTxn(
		txn, listingMessage.MerchantID, listingMessage.ListingIndex)
	if dbListingMessage != nil {
		return fmt.Errorf("DbPutMappingsForSingleListingWithTxn: Listing with "+
			"merchantID %v and listingIndex %d already exists: %v",
			listingMessage.MerchantID, listingMessage.ListingIndex, dbListingMessage)
	}

	// Update the merchant info to reflect the increase in size due to the addition of
	// this new listing. Note we don't check whether this would make the total number
	// of bytes too large here to keep the API simple so the caller should be careful.
	// This should over-write the previous value.
	listingBytes, err := listingMessage.ToBytes(false /*preSignature*/)
	if err != nil {
		return errors.Wrapf(err, "DbPutMappingsForSingleListingWithTxn: Problem "+
			"serializing listing %v: ", listingMessage)
	}
	merchantInfo.NumBytes += uint64(len(listingBytes))
	err = DbPutListingMerchantIDInfoWithTxn(txn, listingMessage.MerchantID, merchantInfo)
	if err != nil {
		return errors.Wrapf(err, "DbPutMappingsForSingleListingWithTxn: Problem "+
			"adding merchant info %v to db for MerchantID %v: ",
			merchantInfo, listingMessage.MerchantID)
	}

	// Add the listing itself to the db under the
	// <merchantID | listingIndex> -> MsgUltranetListing map.
	if err := DbPutListingMessageWithTxn(txn, listingMessage); err != nil {
		return errors.Wrapf(err, "DbPutMappingsForSingleListingWithTxn: Problem "+
			"adding listing data to db for listing %v: ", listingMessage)
	}

	// Add the title keyword mappings from the db.
	err = _addMappingsForKeywords(
		txn, listingMessage.MerchantID, listingMessage.ListingIndex,
		listingMessage.Title, TitleKeyword)
	if err != nil {
		return fmt.Errorf("DbPutMappingsForSingleListingWithTxn: Problem adding "+
			"Title keywords for listing %v: ", listingMessage)
	}

	// Add the body keyword mappings to the db. We add the category to the
	// body so that it will be split and indexed as part of that corpus.
	bodyWithCategory := append(listingMessage.Body, []byte(" ")...)
	bodyWithCategory = append(bodyWithCategory, listingMessage.Category...)
	err = _addMappingsForKeywords(
		txn, listingMessage.MerchantID, listingMessage.ListingIndex, bodyWithCategory, BodyKeyword)
	if err != nil {
		return fmt.Errorf("DbPutMappingsForSingleListingWithTxn: Problem adding "+
			"Body keywords for listing %v: ", listingMessage)
	}

	// Remove the category keyword mappings from the db.
	err = _addMappingsForKeywords(
		txn, listingMessage.MerchantID, listingMessage.ListingIndex, listingMessage.Category, CategoryKeyword)
	if err != nil {
		return fmt.Errorf("DbPutMappingsForSingleListingWithTxn: Problem adding "+
			"Category keywords for listing %v: ", listingMessage)
	}

	// Add a mapping from the listing's hash to its basic information.
	if err := DbPutMappingForListingHashIndexWithTxn(txn, listingMessage); err != nil {
		return fmt.Errorf("DbPutMappingsForSingleListingWithTxn: Problem adding "+
			"hash index mapping for listing %v: ", listingMessage)
	}

	// At this point we should be confident that all of the mappings have been added
	// for the listing and that various sanity checks have all passed.
	return nil
}

func DbUpdateListingScoreMappingForMerchantIDWithTxn(txn *badger.Txn, merchantID *BlockHash, newMerchantScore *big.Int) error {
	// Delete the old mappings for the merchant.
	previousMerchantInfo, err := DbDeleteMerchantMappingsInListingIndexWithTxn(txn, merchantID)
	if err != nil {
		return errors.Wrapf(err, "DbUpdateListingScoreMappingForMerchantIDWithTxn: Problem "+
			"deleting merchant mappings: ")
	}

	// Now that the old score mappings for the merchant have been deleted, add
	// the new score mappings.
	previousMerchantInfo.Score = newMerchantScore
	err = DbPutMerchantMappingsInListingIndexWithTxn(
		txn, merchantID, previousMerchantInfo)
	if err != nil {
		return errors.Wrapf(err, "DbUpdateListingScoreMappingForMerchantIDWithTxn: "+
			"Problem putting merchant info for merchantID %v and merchantInfo %v",
			merchantID, previousMerchantInfo)
	}

	return nil
}

func DbDeleteMerchantMappingsInListingIndexWithTxn(txn *badger.Txn, merchantID *BlockHash) (
	_previousMerchantInfo *ListingMerchantIDInfo, _err error) {

	// Get the info mapping from the db. If there isn't one then this merchant doesn't
	// exist in the listing index. Return an error in this case.
	previousMerchantInfo := DbGetListingMerchantIDInfoWithTxn(txn, merchantID)
	if previousMerchantInfo == nil {
		return nil, fmt.Errorf("DbDeleteMerchantMappingsInListingIndexWithTxn: "+
			"ListingMerchantIDInfo does not exist for merchantID %v", merchantID)
	}
	// Delete the <merchantID> -> ListingMerchantIDInfo mapping from the db.
	if err := DbDeleteMerchantIDInfoWithTxn(txn, merchantID); err != nil {
		return nil, errors.Wrapf(err, "DbDeleteMerchantMappingsInListingIndexWithTxn: "+
			"Problem deleting ListingMerchantIDInfo for merchantID %v", merchantID)
	}
	// Sanity-check that a <score | merchantID> -> <> mapping exists in the db for
	// the merchant.
	if !DbExistsListingScoreMerchantIDWithTxn(txn, previousMerchantInfo.Score, merchantID) {
		return nil, fmt.Errorf("DbDeleteMerchantMappingsInListingIndexWithTxn: "+
			"Missing <score | merchantID> mapping for merchantID %v with score %v",
			merchantID, previousMerchantInfo.Score)
	}
	// Delete the mapping now that we've sanity-checked that it exists.
	if err := DbDeleteScoreMerchantIDIndexWithTxn(txn, previousMerchantInfo.Score, merchantID); err != nil {
		return nil, errors.Wrapf(err, "DbDeleteMerchantMappingsInListingIndexWithTxn: "+
			"Problem deleting <score | merchantID> mapping for merchantID %v with score %v",
			merchantID, previousMerchantInfo.Score)
	}

	return previousMerchantInfo, nil
}

func DbDeleteAllListingMappingsForMerchantIDWithTxn(txn *badger.Txn, merchantID *BlockHash) error {
	// Find all the listings associated with this MerchantID.
	_, listingsForMerchant, err := DbGetListingsForMerchantIDWithTxn(txn, merchantID, true /*fetchListings*/)
	if err != nil {
		return errors.Wrapf(err, "DbDeleteAllListingMappingsForMerchantIDWithTxn: Problem "+
			"fetching listings for MerchantID %v: ", merchantID)
	}

	// Iterate through the listings and delete the mappings for each one from the db.
	for _, listingMessage := range listingsForMerchant {
		err := DbDeleteMappingsForSingleListingWithTxn(txn, merchantID, listingMessage.ListingIndex)
		if err != nil {
			return errors.Wrapf(err, "DbDeleteAllListingMappingsForMerchantIDWithTxn: Problem "+
				"deleting mappings for listing %v: ", listingMessage)
		}
	}
	// At this point, all of the listing-specific mappings such as the
	// <merchantID | listingIndex> -> MsgUltranetListing mapping, among others, should
	// be gone.

	// Delete all of the merchant mappings:
	// - <merchantID> -> ListingIDInfo
	// - <score | merchantID> -> <>
	previousMerchantInfo, err := DbDeleteMerchantMappingsInListingIndexWithTxn(txn, merchantID)
	if err != nil {
		return errors.Wrapf(err, "DbDeleteAllListingMappingsForMerchantIDWithTxn: Problem "+
			"deleting merchant mappings: ")
	}

	// At this point, the numBytes stored in the previousMerchantInfo should be zero because
	// we deleted all of the merchant's listings. Sanity-check that here.
	if previousMerchantInfo.NumBytes != 0 {
		return fmt.Errorf("DbDeleteAllListingMappingsForMerchantIDWithTxn: "+
			"Merchant with merchantID %v has NumBytes=%d != 0 even though we've deleted "+
			"all of her listings; this should never happen", merchantID, previousMerchantInfo.NumBytes)
	}

	// At this point, all of the mappings for this merchantID and all of the mappings
	// of its associated listings should be expunged from the database (with various
	// sanity checks all having passed).
	return nil
}

func DbPutMerchantMappingsInListingIndexWithTxn(
	txn *badger.Txn, merchantID *BlockHash, merchantInfo *ListingMerchantIDInfo) error {

	// Verify that the merchant isn't already in the db. Return an error in this
	// case.
	existingMerchantInfo := DbGetListingMerchantIDInfoWithTxn(txn, merchantID)
	if existingMerchantInfo != nil {
		return fmt.Errorf("DbPutMerchantMappingsInListingIndexWithTxn: "+
			"ListingMerchantIDInfoMerchantInfo already exists for merchant with "+
			"merchantID %v: %v", merchantID, existingMerchantInfo)
	}
	// Same goes for the <score | merchantID> index.
	if DbExistsListingScoreMerchantIDWithTxn(txn, merchantInfo.Score, merchantID) {
		return fmt.Errorf("DbPutMerchantMappingsInListingIndexWithTxn: "+
			"mapping in <score | merchantID> index already exists for merchant with "+
			"merchantID %v and score %v", merchantID, merchantInfo.Score)
	}
	// At this point, we are confident no mappings already exist for this merchant and
	// so we're not dirupting anything.

	// Add an info mapping for the merchant.
	err := DbPutListingMerchantIDInfoWithTxn(txn, merchantID, merchantInfo)
	if err != nil {
		return errors.Wrapf(err, "DbPutMerchantMappingsInListingIndexWithTxn: Problem adding "+
			"info mapping for merchant to listing index: ")
	}
	// Add a <score | merchantID> mapping for the merchant.
	err = DbPutListingScoreMerchantIDIndexWithTxn(txn, merchantInfo.Score, merchantID)
	if err != nil {
		return errors.Wrapf(err, "DbPutMerchantMappingsInListingIndexWithTxn: Problem adding "+
			"<score | merchantID> mapping for merchant to listing index: ")
	}

	// If we get here, we've added all the mappings we need to for the merchant.
	return nil
}

// =======================================================================================
// Listing code end
// =======================================================================================

// GetBadgerDbPath returns the path where we store the badgerdb data.
func GetBadgerDbPath(dataDir string) string {
	return filepath.Join(dataDir, badgerDbFolder)
}

func DbPutLocalUserDataWithTxn(userData *LocalUserData, txn *badger.Txn) error {
	userDataBuf := bytes.NewBuffer([]byte{})
	err := gob.NewEncoder(userDataBuf).Encode(userData)
	if err != nil {
		// TODO: Fix a bug where nil map values break serialization. This happens,
		// for example, when loading an account from a seed that had placed an
		// order encrypted with the merchant key
		scs := spew.ConfigState{DisableMethods: true, Indent: "\t"}
		fmt.Println("Dumping unserializable user object for debugging: ", scs.Sdump(userData))
		glog.Errorf("DbPutLocalUserDataWithTxn: Problem encoding user data: %v", err)
	}

	return txn.Set(_KeyLocalUserData, userDataBuf.Bytes())
}
func DbPutLocalUserData(userData *LocalUserData, handle *badger.DB) error {
	return handle.Update(func(txn *badger.Txn) error {
		return DbPutLocalUserDataWithTxn(userData, txn)
	})
}

func DbGetLocalUserDataWithTxn(txn *badger.Txn) *LocalUserData {
	var userData LocalUserData
	userDataItem, err := txn.Get(_KeyLocalUserData)
	if err != nil {
		return nil
	}
	err = userDataItem.Value(func(valBytes []byte) error {
		if err := gob.NewDecoder(bytes.NewReader(valBytes)).Decode(&userData); err != nil {
			glog.Errorf("DbGetLocalUserDataWithTxn: Problem decoding user data: %v", err)
		}
		return nil
	})
	if err != nil {
		return nil
	}
	return &userData
}
func DbGetLocalUserData(handle *badger.DB) *LocalUserData {
	var userData *LocalUserData
	handle.View(func(txn *badger.Txn) error {
		userData = DbGetLocalUserDataWithTxn(txn)
		return nil
	})
	return userData
}

// Basically returns a score byte slice that just has 0xFF set for all of its indices.
// This function is needed because when iterating backward using a prefix in badger,
// the prefix must be strictly greater than all of the keys you want to iterate over
// or else some keys will be skipped. See this bug for more detail:
// - https://github.com/dgraph-io/badger/issues/436
func _GetScoreIndexPrefixForBackwardIteration(dbPrefix []byte) []byte {
	maxScoreBytes := make([]byte, HashSizeBytes)
	for ii := 0; ii < len(maxScoreBytes); ii++ {
		maxScoreBytes[ii] = 0xFF
	}
	return append(dbPrefix, maxScoreBytes...)
}

func _EncodeUint64(num uint64) []byte {
	numBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(numBytes, num)
	return numBytes
}

func _DecodeUint64(scoreBytes []byte) uint64 {
	return binary.BigEndian.Uint64(scoreBytes)
}

func _getTopMerchantsForDbPrefix(
	handle *badger.DB, useListingDB bool, numMerchantsToFetch uint64, noMerchantEntries bool, errorIfInconsistentMerchantEntryFound bool) (
	_merchantIDs []*BlockHash, _scores []*big.Int, _merchantEntries []*MerchantEntry, _err error) {

	dbPrefix := _PrefixScoreMerchantIDIndex
	if useListingDB {
		dbPrefix = _PrefixListingScoreMerchantID
	}

	scoresFetched := []*big.Int{}
	merchantIDsFetched := []*BlockHash{}

	// The score key is the concatenation of two block hashes.
	scoreKeyLen := 2 * HashSizeBytes

	err := handle.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.PrefetchValues = false

		// Go in reverse order since a larger score is better.
		opts.Reverse = true

		it := txn.NewIterator(opts)
		defer it.Close()
		prefix := _GetScoreIndexPrefixForBackwardIteration(dbPrefix)
		for it.Seek(prefix); it.ValidForPrefix(dbPrefix); it.Next() {
			scoreKey := it.Item().Key()

			// Strip the prefix off the score key and check its length.
			scoreKey = scoreKey[1:]
			if len(scoreKey) != scoreKeyLen {
				return fmt.Errorf("_getTopMerchantsForDbPrefix: Invalid score length %d should be %d", len(scoreKey), scoreKeyLen)
			}

			scoreHash := BlockHash{}
			copy(scoreHash[:], scoreKey[:HashSizeBytes])
			scoresFetched = append(scoresFetched, MerchantScoreFromHash(&scoreHash))

			merchantID := BlockHash{}
			copy(merchantID[:], scoreKey[HashSizeBytes:])
			merchantIDsFetched = append(merchantIDsFetched, &merchantID)

			if uint64(len(scoresFetched)) == numMerchantsToFetch {
				return nil
			}
		}
		return nil
	})
	if err != nil {
		return nil, nil, nil, err
	}

	// At this point, scoresFetched and merchantIDsFetched should be populated
	// with <= numMerchantsToFetched entries. They should also be the same size.
	if len(scoresFetched) != len(merchantIDsFetched) {
		return nil, nil, nil, fmt.Errorf("_getTopMerchantsForDbPrefix: Fetched %d scores != to %d "+
			"merchantIDs", len(scoresFetched), len(merchantIDsFetched))
	}

	// Only return ids if that's all the caller wants.
	if noMerchantEntries {
		return merchantIDsFetched, scoresFetched, nil, nil
	}

	// For each merchantID fetch the corresponding MerchantEntry and set its
	// merchantID.
	merchantEntriesFetched := []*MerchantEntry{}
	err = handle.View(func(txn *badger.Txn) error {
		for merchantIndex, merchantID := range merchantIDsFetched {
			merchantEntry := DbGetMerchantEntryForMerchantIDWithTxn(txn, merchantID)
			if merchantEntry == nil {
				return fmt.Errorf("_getTopMerchantsForDbPrefix: Found merchantID %v in score index "+
					"but missing corresponding entry in <merchantID -> entry> index; useListingDB: %v",
					merchantID, useListingDB)
			}
			if err != nil {
				return err
			}
			// Only perform the score check if we're fetching from the blockchain DB. The
			// listing DB can be out of sync with the entries and that's OK.
			scoreFetched := scoresFetched[merchantIndex]
			if errorIfInconsistentMerchantEntryFound && merchantEntry.Stats.MerchantScore.Cmp(scoreFetched) != 0 {
				return fmt.Errorf("_getTopMerchantsForDbPrefix: Found merchantID %v in score index "+
					"but merchant's computed score %d is not equal to fetched score %d; useListingDB: %v",
					merchantID, merchantEntry.Stats.MerchantScore, scoreFetched, useListingDB)
			}
			merchantEntry.merchantID = merchantID
			merchantEntriesFetched = append(merchantEntriesFetched, merchantEntry)
		}

		return nil
	})
	if err != nil {
		return nil, nil, nil, err
	}

	return merchantIDsFetched, scoresFetched, merchantEntriesFetched, nil
}

// DbGetBlockchainTopMerchants ...
func DbGetBlockchainTopMerchants(handle *badger.DB, numMerchantsToFetch uint64, noMerchantEntries bool) (
	_merchantIDs []*BlockHash, _scores []*big.Int, _merchantEntries []*MerchantEntry, _err error) {

	return _getTopMerchantsForDbPrefix(handle, false /*useListingDB*/, numMerchantsToFetch,
		noMerchantEntries, false /*errorIfInconsistentMerchantEntryFound*/)
}

// DbGetAllOrderEntries ...
func DbGetAllOrderEntries(db *badger.DB) ([]*OrderEntry, error) {
	orderIDBytes, orderEntryBytes := _enumerateKeysForPrefix(db, _PrefixOrderIDToOrderEntry)

	orderEntries := []*OrderEntry{}
	for ii := range orderEntryBytes {
		currentEntry, err := _DecodeOrderEntry(orderEntryBytes[ii])
		if err != nil {
			return nil, errors.Wrapf(err, "DbGetAllOrderEntries: Problem decoding OrderEntry: ")
		}
		currentOrderID := BlockHash{}
		// Strip the prefix before copying.
		copy(currentOrderID[:], orderIDBytes[ii][1:])
		currentEntry.orderID = &currentOrderID
		orderEntries = append(orderEntries, currentEntry)
	}

	return orderEntries, nil
}

// DbPutNanosPurchasedWithTxn ...
func DbPutNanosPurchasedWithTxn(txn *badger.Txn, nanosPurchased uint64) error {
	return txn.Set(_KeyNanosPurchased, _EncodeUint64(nanosPurchased))
}

// DbGetNanosPurchasedWithTxn ...
func DbGetNanosPurchasedWithTxn(txn *badger.Txn) uint64 {
	nanosPurchasedItem, err := txn.Get(_KeyNanosPurchased)
	if err != nil {
		return 0
	}
	nanosPurchasedBuf, err := nanosPurchasedItem.ValueCopy(nil)
	if err != nil {
		return 0
	}

	return _DecodeUint64(nanosPurchasedBuf)
}

// DbGetNanosPurchased ...
func DbGetNanosPurchased(handle *badger.DB) uint64 {
	var nanosPurchased uint64
	handle.View(func(txn *badger.Txn) error {
		nanosPurchased = DbGetNanosPurchasedWithTxn(txn)
		return nil
	})

	return nanosPurchased
}

// PutNumOrderEntriesWithTxn ...
func PutNumOrderEntriesWithTxn(txn *badger.Txn, numOrderEntries uint64) error {
	return txn.Set(_KeyOrderNumEntries, _EncodeUint64(numOrderEntries))
}

// GetNumOrderEntriesWithTxn ...
func GetNumOrderEntriesWithTxn(txn *badger.Txn) uint64 {
	orderEntryItem, err := txn.Get(_KeyOrderNumEntries)
	if err != nil {
		return 0
	}
	numEntryBuf, err := orderEntryItem.ValueCopy(nil)
	if err != nil {
		return 0
	}

	return _DecodeUint64(numEntryBuf)
}

// GetNumOrderEntries ...
func GetNumOrderEntries(handle *badger.DB) uint64 {
	var numOrderEntries uint64
	handle.View(func(txn *badger.Txn) error {
		numOrderEntries = GetNumOrderEntriesWithTxn(txn)
		return nil
	})

	return numOrderEntries
}

func _EncodeOrderEntry(orderEntry *OrderEntry) []byte {
	orderEntryBuf := bytes.NewBuffer([]byte{})
	gob.NewEncoder(orderEntryBuf).Encode(orderEntry)
	return orderEntryBuf.Bytes()
}

func _DecodeOrderEntry(data []byte) (*OrderEntry, error) {
	orderEntry := OrderEntry{}
	if err := gob.NewDecoder(bytes.NewReader(data)).Decode(&orderEntry); err != nil {
		return nil, err
	}
	return &orderEntry, nil
}

// PutOrderEntryForOrderIDWithTxn ...
func PutOrderEntryForOrderIDWithTxn(txn *badger.Txn, orderID *BlockHash, orderEntry *OrderEntry) error {
	return txn.Set(append(append([]byte{}, _PrefixOrderIDToOrderEntry...), orderID[:]...), _EncodeOrderEntry(orderEntry))
}

// PutOrderIDForPosWithTxn ...
func PutOrderIDForPosWithTxn(txn *badger.Txn, orderID *BlockHash, pos uint64) error {
	return txn.Set(_DbKeyForOrderEntryPos(pos), orderID[:])
}

// DeleteOrderEntryForOrderIDWithTxn ...
func DeleteOrderEntryForOrderIDWithTxn(txn *badger.Txn, orderID *BlockHash) error {
	return txn.Delete(append(append([]byte{}, _PrefixOrderIDToOrderEntry...), orderID[:]...))
}

// DeleteOrderIDForPosWithTxn ...
func DeleteOrderIDForPosWithTxn(txn *badger.Txn, pos uint64) error {
	return txn.Delete(_DbKeyForOrderEntryPos(pos))
}

// GetOrderEntryForOrderIDWithTxn ...
func GetOrderEntryForOrderIDWithTxn(txn *badger.Txn, orderID *BlockHash) *OrderEntry {
	var orderEntry *OrderEntry
	orderEntryItem, err := txn.Get(append(append([]byte{}, _PrefixOrderIDToOrderEntry...), orderID[:]...))
	if err != nil {
		return nil
	}
	dbErr := orderEntryItem.Value(func(valBytes []byte) error {
		orderEntry, err = _DecodeOrderEntry(valBytes)
		return err
	})
	if dbErr != nil {
		return nil
	}
	return orderEntry
}

// DbGetOrderEntryForOrderID ...
func DbGetOrderEntryForOrderID(handle *badger.DB, orderID *BlockHash) *OrderEntry {
	var orderEntry *OrderEntry
	handle.View(func(txn *badger.Txn) error {
		orderEntry = GetOrderEntryForOrderIDWithTxn(txn, orderID)
		return nil
	})
	if orderEntry != nil {
		orderEntry.orderID = orderID
	}

	return orderEntry
}

// GetOrderIDForPosWithTxn ...
func GetOrderIDForPosWithTxn(txn *badger.Txn, pos uint64) *BlockHash {
	var orderID BlockHash
	orderIDItem, err := txn.Get(_DbKeyForOrderEntryPos(pos))
	if err != nil {
		return nil
	}
	_, err = orderIDItem.ValueCopy(orderID[:])
	if err != nil {
		return nil
	}

	return &orderID
}

// GetOrderIDForPos ...
func GetOrderIDForPos(handle *badger.DB, pos uint64) *BlockHash {
	var orderID *BlockHash
	handle.View(func(txn *badger.Txn) error {
		orderID = GetOrderIDForPosWithTxn(txn, pos)
		return nil
	})

	return orderID
}

func _dbKeyForOrderMerchantID(orderEntry *OrderEntry, orderID *BlockHash) []byte {
	keyRet := append([]byte{}, _PrefixMerchantIDOrderIndex...)
	keyRet = append(keyRet, orderEntry.MerchantID[:]...)
	keyRet = append(keyRet, _EncodeUint64(uint64(orderEntry.LastModifiedBlock))...)
	keyRet = append(keyRet, orderID[:]...)

	return keyRet
}

func _dbKeyForOrderBuyerPubKey(orderEntry *OrderEntry, orderID *BlockHash) []byte {
	keyRet := append([]byte{}, _PrefixBuyerPubKeyOrderIndex...)
	keyRet = append(keyRet, orderEntry.BuyerPk...)
	keyRet = append(keyRet, _EncodeUint64(uint64(orderEntry.LastModifiedBlock))...)
	keyRet = append(keyRet, orderID[:]...)

	return keyRet
}

func DbGetOrdersForMerchantID(handle *badger.DB, merchantID *BlockHash, fetchEntries bool) (
	_lastModifiedHeights []uint32, _orderIDs []*BlockHash, _orderEntries []*OrderEntry, _err error) {

	lastModifiedHeights := []uint32{}
	orderIDs := []*BlockHash{}

	dbPrefix := append(append([]byte{}, _PrefixMerchantIDOrderIndex...), merchantID[:]...)
	keysFound, _ := _enumerateKeysForPrefix(handle, dbPrefix)
	for _, kf := range keysFound {
		uint64BytesLen := 8
		minKeySize := 1 + HashSizeBytes + uint64BytesLen + HashSizeBytes
		if len(kf) < minKeySize {
			return nil, nil, nil, fmt.Errorf("DbGetOrdersForMerchantID: Key length %d "+
				"not greater than minimum size %d", len(kf), minKeySize)
		}

		// Decode the last modified block height.
		lastBlockHeightBytes := kf[1+HashSizeBytes : len(kf)-HashSizeBytes+1]
		lastBlockHeight := _DecodeUint64(lastBlockHeightBytes)

		orderIDBytes := kf[1+HashSizeBytes+uint64BytesLen:]
		orderID := BlockHash{}
		copy(orderID[:], orderIDBytes)

		lastModifiedHeights = append(lastModifiedHeights, uint32(lastBlockHeight))
		orderIDs = append(orderIDs, &orderID)
	}

	if !fetchEntries {
		return lastModifiedHeights, orderIDs, nil, nil
	}

	orderEntries := []*OrderEntry{}
	for _, orderID := range orderIDs {
		orderEntry := DbGetOrderEntryForOrderID(handle, orderID)
		if orderEntry == nil {
			return nil, nil, nil, fmt.Errorf("DbGetOrdersForMerchantID: "+
				"OrderID %v does not have corresponding entry", orderID)
		}
		orderEntry.orderID = orderID
		orderEntries = append(orderEntries, orderEntry)
	}

	return lastModifiedHeights, orderIDs, orderEntries, nil

}

func DbGetOrdersForBuyerPublicKey(handle *badger.DB, buyerPk []byte, fetchEntries bool) (
	_lastModifiedHeights []uint32, _orderIDs []*BlockHash, _orderEntries []*OrderEntry, _err error) {

	lastModifiedHeights := []uint32{}
	orderIDs := []*BlockHash{}

	dbPrefix := append(append([]byte{}, _PrefixBuyerPubKeyOrderIndex...), buyerPk...)
	keysFound, _ := _enumerateKeysForPrefix(handle, dbPrefix)
	for _, kf := range keysFound {
		uint64BytesLen := 8
		minKeySize := 1 + btcec.PubKeyBytesLenCompressed + uint64BytesLen + HashSizeBytes
		if len(kf) < minKeySize {
			return nil, nil, nil, fmt.Errorf("DbGetOrdersForBuyerPublicKey: Key length %d "+
				"not greater than minimum size %d", len(kf), minKeySize)
		}

		// Decode the last modified block height.
		lastBlockHeightBytes := kf[1+btcec.PubKeyBytesLenCompressed : len(kf)-HashSizeBytes+1]
		lastBlockHeight := _DecodeUint64(lastBlockHeightBytes)

		orderIDBytes := kf[1+btcec.PubKeyBytesLenCompressed+uint64BytesLen:]
		orderID := BlockHash{}
		copy(orderID[:], orderIDBytes)

		lastModifiedHeights = append(lastModifiedHeights, uint32(lastBlockHeight))
		orderIDs = append(orderIDs, &orderID)
	}

	if !fetchEntries {
		return lastModifiedHeights, orderIDs, nil, nil
	}

	orderEntries := []*OrderEntry{}
	for _, orderID := range orderIDs {
		orderEntry := DbGetOrderEntryForOrderID(handle, orderID)
		if orderEntry == nil {
			return nil, nil, nil, fmt.Errorf("DbGetOrdersForBuyerPublicKey: "+
				"OrderID %v does not have corresponding entry", orderID)
		}
		orderEntry.orderID = orderID
		orderEntries = append(orderEntries, orderEntry)
	}

	return lastModifiedHeights, orderIDs, orderEntries, nil
}

// DeletePubKeyMappingsForOrderWithTxn ...
func DeletePubKeyMappingsForOrderWithTxn(txn *badger.Txn, orderEntry *OrderEntry, orderID *BlockHash) error {
	if err := txn.Delete(_dbKeyForOrderBuyerPubKey(orderEntry, orderID)); err != nil {
		return err
	}

	if err := txn.Delete(_dbKeyForOrderMerchantID(orderEntry, orderID)); err != nil {
		return err
	}

	return nil
}

// DeleteUnmodifiedMappingsForOrderWithTxn ...
func DeleteUnmodifiedMappingsForOrderWithTxn(txn *badger.Txn, orderID *BlockHash) error {
	// Get the entry associated with the order.
	orderEntry := GetOrderEntryForOrderIDWithTxn(txn, orderID)
	// If there's no oderEntry then there's nothing to delete.
	if orderEntry == nil {
		return nil
	}

	// Delete the <pk || lastModified || orderID> mappings for this order.
	DeletePubKeyMappingsForOrderWithTxn(txn, orderEntry, orderID)

	// Delete the <orderID -> entry> mapping.
	if err := DeleteOrderEntryForOrderIDWithTxn(txn, orderID); err != nil {
		return err
	}

	// Get the <pos -> orderID> mapping associated with this entry. If it matches
	// the orderID we're deleting then delete the mapping. Otherwise we can assume
	// it has been modified and therefore should remain untouched.
	posOrderID := GetOrderIDForPosWithTxn(txn, orderEntry.Pos)
	if posOrderID != nil && *posOrderID == *orderID {
		if err := DeleteOrderIDForPosWithTxn(txn, orderEntry.Pos); err != nil {
			return err
		}
	}

	return nil
}

// PutPubKeyMappingsForOrderWithTxn ...
func PutPubKeyMappingsForOrderWithTxn(txn *badger.Txn, orderEntry *OrderEntry, orderID *BlockHash) error {
	if err := txn.Set(_dbKeyForOrderBuyerPubKey(orderEntry, orderID), []byte{}); err != nil {
		return err
	}
	if err := txn.Set(_dbKeyForOrderMerchantID(orderEntry, orderID), []byte{}); err != nil {
		return err
	}
	return nil
}

// PutMappingsForOrderWithTxn ...
func PutMappingsForOrderWithTxn(txn *badger.Txn, orderID *BlockHash, orderEntry *OrderEntry) error {
	// Put the <OrderID -> OrderEntry> mapping.
	if err := PutOrderEntryForOrderIDWithTxn(txn, orderID, orderEntry); err != nil {
		return nil
	}

	// Put the <pk || lastModified || orderID> mappings for this order.
	PutPubKeyMappingsForOrderWithTxn(txn, orderEntry, orderID)

	// Put the <pos -> OrderID> mapping.
	if err := PutOrderIDForPosWithTxn(txn, orderID, orderEntry.Pos); err != nil {
		return err
	}

	return nil
}

// PutUtxoNumEntriesWithTxn ...
func PutUtxoNumEntriesWithTxn(txn *badger.Txn, newNumEntries uint64) error {
	return txn.Set(_KeyUtxoNumEntries, _EncodeUint64(newNumEntries))
}

// GetUtxoNumEntriesWithTxn ...
func GetUtxoNumEntriesWithTxn(txn *badger.Txn) uint64 {
	indexItem, err := txn.Get(_KeyUtxoNumEntries)
	if err != nil {
		return 0
	}
	// Get the current index.
	indexBytes, err := indexItem.ValueCopy(nil)
	if err != nil {
		return 0
	}
	numEntries := _DecodeUint64(indexBytes)

	return numEntries
}

// GetUtxoNumEntries ...
func GetUtxoNumEntries(handle *badger.DB) uint64 {
	var numEntries uint64
	handle.View(func(txn *badger.Txn) error {
		numEntries = GetUtxoNumEntriesWithTxn(txn)

		return nil
	})

	return numEntries
}

func _SerializeUtxoKey(utxoKey *UtxoKey) []byte {
	indexBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(indexBytes, utxoKey.Index)
	return append(utxoKey.TxID[:], indexBytes...)

}

func _DbKeyForUtxoKey(utxoKey *UtxoKey) []byte {
	return append(append([]byte{}, _PrefixUtxoKeyToUtxoEntry...), _SerializeUtxoKey(utxoKey)...)
}

// Implements the reverse of _DbKeyForUtxoKey. This doesn't error-check
// and caller should make sure they're passing a properly-sized key to
// this function.
func _UtxoKeyFromDbKey(utxoDbKey []byte) *UtxoKey {
	// Read in the TxID, which is at the beginning.
	txIDBytes := utxoDbKey[:HashSizeBytes]
	txID := BlockHash{}
	copy(txID[:], txIDBytes)
	// Read in the index, which is encoded as a bigint at the end.
	indexBytes := utxoDbKey[HashSizeBytes:]
	indexValue := binary.BigEndian.Uint32(indexBytes)
	return &UtxoKey{
		Index: indexValue,
		TxID:  txID,
	}
}

func _DbBufForUtxoEntry(utxoEntry *UtxoEntry) []byte {
	utxoEntryBuf := bytes.NewBuffer([]byte{})
	gob.NewEncoder(utxoEntryBuf).Encode(utxoEntry)
	return utxoEntryBuf.Bytes()
}

// PutUtxoEntryForUtxoKeyWithTxn ...
func PutUtxoEntryForUtxoKeyWithTxn(txn *badger.Txn, utxoKey *UtxoKey, utxoEntry *UtxoEntry) error {
	return txn.Set(_DbKeyForUtxoKey(utxoKey), _DbBufForUtxoEntry(utxoEntry))
}

// DbGetUtxoEntryForUtxoKeyWithTxn ...
func DbGetUtxoEntryForUtxoKeyWithTxn(txn *badger.Txn, utxoKey *UtxoKey) *UtxoEntry {
	var ret UtxoEntry
	utxoDbKey := _DbKeyForUtxoKey(utxoKey)
	item, err := txn.Get(utxoDbKey)
	if err != nil {
		return nil
	}

	err = item.Value(func(valBytes []byte) error {
		// TODO: Storing with gob is very slow due to reflection. Would be
		// better if we serialized/deserialized manually.
		if err := gob.NewDecoder(bytes.NewReader(valBytes)).Decode(&ret); err != nil {
			return err
		}

		return nil
	})

	if err != nil {
		return nil
	}

	return &ret
}

// DbGetUtxoEntryForUtxoKey ...
func DbGetUtxoEntryForUtxoKey(handle *badger.DB, utxoKey *UtxoKey) *UtxoEntry {
	var ret *UtxoEntry
	handle.View(func(txn *badger.Txn) error {
		ret = DbGetUtxoEntryForUtxoKeyWithTxn(txn, utxoKey)
		return nil
	})

	return ret
}

func _DbKeyForUtxoPos(pos uint64) []byte {
	return append(append([]byte{}, _PrefixPositionToUtxoKey...), _EncodeUint64(pos)...)
}

// DeleteUtxoEntryForKeyWithTxn ...
func DeleteUtxoEntryForKeyWithTxn(txn *badger.Txn, utxoKey *UtxoKey) error {
	return txn.Delete(_DbKeyForUtxoKey(utxoKey))
}

// DeletePubKeyUtxoKeyMappingWithTxn ...
func DeletePubKeyUtxoKeyMappingWithTxn(txn *badger.Txn, publicKey []byte, utxoKey *UtxoKey) error {
	if len(publicKey) != btcec.PubKeyBytesLenCompressed {
		return fmt.Errorf("DeletePubKeyUtxoKeyMappingWithTxn: Public key has improper length %d != %d", len(publicKey), btcec.PubKeyBytesLenCompressed)
	}

	keyToDelete := append(append([]byte{}, _PrefixPubKeyUtxoKey...), publicKey...)
	keyToDelete = append(keyToDelete, _SerializeUtxoKey(utxoKey)...)

	return txn.Delete(keyToDelete)
}

// DeleteUtxoKeyAtPositionWithTxn ...
func DeleteUtxoKeyAtPositionWithTxn(txn *badger.Txn, pos uint64) error {
	return txn.Delete(_DbKeyForUtxoPos(pos))
}

// DbBufForUtxoKey ...
func DbBufForUtxoKey(utxoKey *UtxoKey) []byte {
	utxoKeyBuf := bytes.NewBuffer([]byte{})
	gob.NewEncoder(utxoKeyBuf).Encode(utxoKey)
	return utxoKeyBuf.Bytes()
}

// PutUtxoKeyAtPositionWithTxn ...
func PutUtxoKeyAtPositionWithTxn(txn *badger.Txn, pos uint64, utxoKey *UtxoKey) error {
	return txn.Set(_DbKeyForUtxoPos(pos), DbBufForUtxoKey(utxoKey))
}

// PutPubKeyUtxoKeyWithTxn ...
func PutPubKeyUtxoKeyWithTxn(txn *badger.Txn, publicKey []byte, utxoKey *UtxoKey) error {
	if len(publicKey) != btcec.PubKeyBytesLenCompressed {
		return fmt.Errorf("PutPubKeyUtxoKeyWithTxn: Public key has improper length %d != %d", len(publicKey), btcec.PubKeyBytesLenCompressed)
	}

	keyToAdd := append(append([]byte{}, _PrefixPubKeyUtxoKey...), publicKey...)
	keyToAdd = append(keyToAdd, _SerializeUtxoKey(utxoKey)...)

	return txn.Set(keyToAdd, []byte{})
}

// DbGetUtxosForPubKey finds the UtxoEntry's corresponding to the public
// key passed in. It also attaches the UtxoKeys to the UtxoEntry's it
// returns for easy access.
func DbGetUtxosForPubKey(publicKey []byte, handle *badger.DB) ([]*UtxoEntry, error) {
	// Verify the length of the public key.
	if len(publicKey) != btcec.PubKeyBytesLenCompressed {
		return nil, fmt.Errorf("DbGetUtxosForPubKey: Public key has improper "+
			"length %d != %d", len(publicKey), btcec.PubKeyBytesLenCompressed)
	}
	// Look up the utxo keys for this public key.
	utxoEntriesFound := []*UtxoEntry{}
	err := handle.View(func(txn *badger.Txn) error {
		// Start by looping through to find all the UtxoKeys.
		utxoKeysFound := []*UtxoKey{}
		opts := badger.DefaultIteratorOptions
		nodeIterator := txn.NewIterator(opts)
		defer nodeIterator.Close()
		prefix := append(append([]byte{}, _PrefixPubKeyUtxoKey...), publicKey...)
		for nodeIterator.Seek(prefix); nodeIterator.ValidForPrefix(prefix); nodeIterator.Next() {
			// Strip the prefix off the key. What's left should be the UtxoKey.
			pkUtxoKey := nodeIterator.Item().Key()
			utxoKeyBytes := pkUtxoKey[len(prefix):]
			// The size of the utxo key bytes should be equal to the size of a
			// standard hash (the txid) plus the size of a uint32.
			if len(utxoKeyBytes) != HashSizeBytes+4 {
				return fmt.Errorf("Problem reading <pk, utxoKey> mapping; key size %d "+
					"is not equal to (prefix_byte=%d + len(publicKey)=%d + len(utxoKey)=%d)=%d. "+
					"Key found: %#v", len(pkUtxoKey), len(_PrefixPubKeyUtxoKey), len(publicKey), HashSizeBytes+4, len(prefix)+HashSizeBytes+4, pkUtxoKey)
			}
			// Try and convert the utxo key bytes into a utxo key.
			utxoKey := _UtxoKeyFromDbKey(utxoKeyBytes)
			if utxoKey == nil {
				return fmt.Errorf("Problem reading <pk, utxoKey> mapping; parsing UtxoKey bytes %#v returned nil", utxoKeyBytes)
			}

			// Now that we have the utxoKey, enqueue it.
			utxoKeysFound = append(utxoKeysFound, utxoKey)
		}

		// Once all the UtxoKeys are found, fetch all the UtxoEntries.
		for ii, _ := range utxoKeysFound {
			foundUtxoKey := utxoKeysFound[ii]
			utxoEntry := DbGetUtxoEntryForUtxoKeyWithTxn(txn, foundUtxoKey)
			if utxoEntry == nil {
				return fmt.Errorf("UtxoEntry for UtxoKey %v was not found", foundUtxoKey)
			}

			// Set a back-reference to the utxo key.
			utxoEntry.utxoKey = foundUtxoKey

			utxoEntriesFound = append(utxoEntriesFound, utxoEntry)
		}

		return nil
	})
	if err != nil {
		return nil, errors.Wrapf(err, "DbGetUtxosForPubKey: ")
	}

	// If there are no errors, return everything we found.
	return utxoEntriesFound, nil
}

// GetAllUtxoKeys gets all the utxos in the db and returns them as a list.
// TODO: This is very inefficiently-written right now.
func GetAllUtxoKeys(handle *badger.DB) []*UtxoKey {
	numUtxos := GetUtxoNumEntries(handle)
	utxos := []*UtxoKey{}
	for ii := uint64(0); ii < numUtxos; ii++ {
		utxos = append(utxos, GetUtxoKeyAtPosition(handle, ii))
	}

	return utxos
}

// GetUtxoKeyAtPositionWithTxn ...
func GetUtxoKeyAtPositionWithTxn(txn *badger.Txn, pos uint64) *UtxoKey {
	item, err := txn.Get(_DbKeyForUtxoPos(pos))
	if err != nil {
		return nil
	}

	var keyRet UtxoKey
	err = item.Value(func(valBytes []byte) error {
		if err := gob.NewDecoder(bytes.NewReader(valBytes)).Decode(&keyRet); err != nil {
			return err
		}

		return nil
	})

	if err != nil {
		return nil
	}

	return &keyRet
}

// GetUtxoKeyAtPosition ...
func GetUtxoKeyAtPosition(handle *badger.DB, pos uint64) *UtxoKey {
	var keyRet *UtxoKey
	handle.View(func(txn *badger.Txn) error {
		keyRet = GetUtxoKeyAtPositionWithTxn(txn, pos)
		return nil
	})

	return keyRet
}

// DbGetAllPubKeyMerchantIDMappings ...
func DbGetAllPubKeyMerchantIDMappings(handle *badger.DB) ([][]byte, []*BlockHash, []*MerchantEntry, error) {
	publicKeys := [][]byte{}
	merchantIDs := []*BlockHash{}
	merchantEntries := []*MerchantEntry{}

	err := handle.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.PrefetchValues = false

		it := txn.NewIterator(opts)
		defer it.Close()
		prefix := _PrefixPubKeyToMerchantID
		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			pubKeyDbKey := it.Item().Key()

			// Strip the prefix off the score key and check its length.
			pubKey := pubKeyDbKey[1:]
			if len(pubKey) != btcec.PubKeyBytesLenCompressed {
				return fmt.Errorf("DbGetAllPubKeyMerchantIDMappings: Invalid pubkey "+
					"length %d should be %d", len(pubKey), btcec.PubKeyBytesLenCompressed)
			}

			merchantID := BlockHash{}
			it.Item().Value(func(val []byte) error {
				if len(val) != HashSizeBytes {
					return fmt.Errorf("DbGetAllPubKeyMerchantIDMappings: Invalid value for pk %v "+
						"length %d should be %d", PkToStringMainnet(pubKey), len(val), HashSizeBytes)
				}
				copy(merchantID[:], val)
				return nil
			})

			// Need to make a copy because thigns change from under us.
			pkCopy := make([]byte, 33)
			copy(pkCopy[:], pubKey)
			publicKeys = append(publicKeys, pkCopy)
			merchantIDs = append(merchantIDs, &merchantID)
		}
		return nil
	})
	if err != nil {
		return nil, nil, nil, err
	}

	for _, merchantID := range merchantIDs {
		merchantEntries = append(merchantEntries, DbGetMerchantEntryForMerchantID(handle, merchantID))
	}

	return publicKeys, merchantIDs, merchantEntries, nil
}

// DbGetAllUsernameMerchantIDMappings ...
func DbGetAllUsernameMerchantIDMappings(handle *badger.DB) ([][]byte, []*BlockHash, []*MerchantEntry, error) {
	usernames := [][]byte{}
	merchantIDs := []*BlockHash{}
	merchantEntries := []*MerchantEntry{}

	err := handle.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.PrefetchValues = false

		it := txn.NewIterator(opts)
		defer it.Close()
		prefix := _PrefixUsernameToMerchantID
		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			usernameDbKey := it.Item().Key()

			// Strip the prefix off the score key and check its length.
			username := usernameDbKey[1:]

			merchantID := BlockHash{}
			it.Item().Value(func(val []byte) error {
				if len(val) != HashSizeBytes {
					return fmt.Errorf("DbGetAllUsernameMerchantIDMappings: Invalid value for username %s "+
						"length %d should be %d", username, len(val), HashSizeBytes)
				}
				copy(merchantID[:], val)
				return nil
			})

			usernameCopy := make([]byte, len(username))
			copy(usernameCopy[:], username[:])
			usernames = append(usernames, usernameCopy)
			merchantIDs = append(merchantIDs, &merchantID)
		}
		return nil
	})
	if err != nil {
		return nil, nil, nil, err
	}

	for _, merchantID := range merchantIDs {
		merchantEntries = append(merchantEntries, DbGetMerchantEntryForMerchantID(handle, merchantID))
	}

	return usernames, merchantIDs, merchantEntries, nil
}

// DeleteUnmodifiedMappingsForUtxoWithTxn ...
func DeleteUnmodifiedMappingsForUtxoWithTxn(txn *badger.Txn, utxoKey *UtxoKey) error {
	// Get the entry for the utxoKey from the db.
	utxoEntry := DbGetUtxoEntryForUtxoKeyWithTxn(txn, utxoKey)
	if utxoEntry == nil {
		// If an entry doesn't exist for this key then there is nothing in the
		// db to delete.
		return nil
	}

	// If the entry exists, delete the <UtxoKey -> UtxoEntry> mapping from the db.
	// It is assumed that the entry corresponding to a key has not been modified
	// and so is OK to delete
	if err := DeleteUtxoEntryForKeyWithTxn(txn, utxoKey); err != nil {
		return err
	}

	// Delete the <pubkey, utxoKey> -> <> mapping.
	if err := DeletePubKeyUtxoKeyMappingWithTxn(txn, utxoEntry.PublicKey, utxoKey); err != nil {
		return err
	}

	// If the <pos -> UtxoKey> mapping for this entry points to the same key that
	// is passed in then delete this mapping as well. Otherwise, it means this
	// pos has been previously modified so leave it unchanged.
	utxoKeyForPos := GetUtxoKeyAtPositionWithTxn(txn, utxoEntry.Pos)
	if utxoKeyForPos != nil && *utxoKeyForPos == *utxoKey {
		if err := DeleteUtxoKeyAtPositionWithTxn(txn, utxoEntry.Pos); err != nil {
			return err
		}
	}

	return nil
}

// PutMappingsForUtxoWithTxn ...
func PutMappingsForUtxoWithTxn(txn *badger.Txn, utxoKey *UtxoKey, utxoEntry *UtxoEntry) error {
	// Put the <utxoKey -> utxoEntry> mapping.
	if err := PutUtxoEntryForUtxoKeyWithTxn(txn, utxoKey, utxoEntry); err != nil {
		return nil
	}

	// Put the <pos -> utxoKey> mapping.
	if err := PutUtxoKeyAtPositionWithTxn(txn, utxoEntry.Pos, utxoKey); err != nil {
		return err
	}

	// Put the <pubkey, utxoKey> -> <> mapping.
	if err := PutPubKeyUtxoKeyWithTxn(txn, utxoEntry.PublicKey, utxoKey); err != nil {
		return err
	}

	return nil
}

// DeleteMerchantScoreWithTxn ...
func DeleteMerchantScoreWithTxn(txn *badger.Txn, merchantScore *big.Int, merchantID *BlockHash) error {
	scoreKey := append(MerchantScoreToHash(merchantScore)[:], merchantID[:]...)
	err := txn.Delete(append(_PrefixScoreMerchantIDIndex, scoreKey...))
	if err != nil {
		return err
	}

	return nil
}

// PutMerchantScoreWithTxn ...
func PutMerchantScoreWithTxn(txn *badger.Txn, newScore *big.Int, merchantID *BlockHash) error {
	// Adding a score for a merchant requires adding an entry for the merchant to the
	// <id -> score> index and to the <score || id -> empty> index.
	scoreKey := append(MerchantScoreToHash(newScore)[:], merchantID[:]...)
	err := txn.Set(append(_PrefixScoreMerchantIDIndex, scoreKey...), []byte{})
	if err != nil {
		return err
	}

	return nil
}

// DbDeleteUnmodifiedMappingsForMerchantIDWithTxn ...
func DbDeleteUnmodifiedMappingsForMerchantIDWithTxn(txn *badger.Txn, merchantID *BlockHash) error {
	// Fetch the merchant entry using the merchantID.
	merchantEntry := DbGetMerchantEntryForMerchantIDWithTxn(txn, merchantID)
	if merchantEntry == nil {
		// If there's no entry then just return as there's nothing to delete.
		return nil
	}

	// Delete the score mapping for this merchant.
	if err := DeleteMerchantScoreWithTxn(txn, merchantEntry.Stats.MerchantScore, merchantID); err != nil {
		return err
	}

	// Delete the pos mapping only if the mapping currently in the db corresponds
	// with this merchantID. If it doesn't that means it's already been updated
	// and we shouldn't touch it. This can happen if, for example, an entry is
	// deleted in the view but not in the db and then a new entry is set in its
	// place. Not doing this check could cause the new entry to get deleted in
	// this instance, which is not the desired behavior.
	merchantIDForPos := GetMerchantIDForPosWithTxn(txn, merchantEntry.Pos)
	if merchantIDForPos != nil && *merchantID == *merchantIDForPos {
		if err := DeletePosToMerchantIDWithTxn(txn, merchantEntry.Pos); err != nil {
			return err
		}
	}

	// Delete the pk mapping. Same logic as above applies.
	merchantIDForPubKey := GetMerchantIDForPubKeyWithTxn(txn, merchantEntry.PublicKey)
	if merchantIDForPubKey != nil && *merchantID == *merchantIDForPubKey {
		if err := DeletePubKeyToMerchantIDWithTxn(txn, merchantEntry.PublicKey); err != nil {
			return err
		}
	}

	// Delete the username mapping. Same logic as above applies.
	merchantIDForUsername := GetMerchantIDForUsernameWithTxn(txn, merchantEntry.Username)
	if merchantIDForUsername != nil && *merchantID == *merchantIDForUsername {
		if err := DeleteUsernameToMerchantIDWithTxn(txn, merchantEntry.Username); err != nil {
			return err
		}
	}

	// Delete the mapping to the merchant entry itself. This doesn't require any
	// extra checking.
	if err := DeleteMerchantEntryForMerchantIDWithTxn(txn, merchantID); err != nil {
		return err
	}

	return nil
}

// DbPutMappingsForMerchantWithTxn ...
func DbPutMappingsForMerchantWithTxn(txn *badger.Txn, merchantID *BlockHash, merchantEntry *MerchantEntry) error {
	// Write the score index mappings.
	if err := PutMerchantScoreWithTxn(txn, merchantEntry.Stats.MerchantScore, merchantID); err != nil {
		return err
	}

	// Write the <merchantID -> entry> mapping.
	if err := PutMerchantEntryForMerchantIDWithTxn(txn, merchantID, merchantEntry); err != nil {
		return err
	}

	// Write the <pk -> merchantID> mappings.
	if err := PutMerchantIDForPubKeyWithTxn(txn, merchantEntry.PublicKey, merchantID); err != nil {
		return err
	}

	// Write the <username -> merchantID> mappings.
	if err := PutMerchantIDForUsernameWithTxn(txn, merchantEntry.Username, merchantID); err != nil {
		return err
	}

	// Write the <pos -> merchantID> mappings.
	if err := PutMerchantIDForPosWithTxn(txn, merchantEntry.Pos, merchantID); err != nil {
		return err
	}

	return nil
}

func _EncodeMerchantEntry(merchantEntry *MerchantEntry) []byte {
	merchantEntryBuf := bytes.NewBuffer([]byte{})
	gob.NewEncoder(merchantEntryBuf).Encode(merchantEntry)
	return merchantEntryBuf.Bytes()
}

func _DecodeMerchantEntry(merchantEntryBytes []byte) (*MerchantEntry, error) {
	var merchantEntry MerchantEntry
	if err := gob.NewDecoder(bytes.NewReader(merchantEntryBytes)).Decode(&merchantEntry); err != nil {
		return nil, err
	}
	return &merchantEntry, nil
}

// PutMerchantEntryForMerchantIDWithTxn ...
func PutMerchantEntryForMerchantIDWithTxn(txn *badger.Txn, merchantID *BlockHash, merchantEntry *MerchantEntry) error {
	return txn.Set(append(append([]byte{}, _PrefixMerchantIDToMerchantEntry...), merchantID[:]...), _EncodeMerchantEntry(merchantEntry))
}

// PutMerchantIDForPosWithTxn ...
func PutMerchantIDForPosWithTxn(txn *badger.Txn, pos uint64, merchantID *BlockHash) error {
	return txn.Set(_DbKeyForMerchantEntryPos(pos), merchantID[:])
}

// PutMerchantIDForPubKeyWithTxn ...
func PutMerchantIDForPubKeyWithTxn(txn *badger.Txn, pk []byte, merchantID *BlockHash) error {
	return txn.Set(append(append([]byte{}, _PrefixPubKeyToMerchantID...), pk...), merchantID[:])
}

// PutMerchantIDForUsernameWithTxn ...
func PutMerchantIDForUsernameWithTxn(txn *badger.Txn, username []byte, merchantID *BlockHash) error {
	return txn.Set(append(append([]byte{}, _PrefixUsernameToMerchantID...), username...), merchantID[:])
}

// PutNumMerchantEntriesWithTxn ...
func PutNumMerchantEntriesWithTxn(txn *badger.Txn, numMerchantEntries uint64) error {
	return txn.Set(_KeyMerchantNumEntries, _EncodeUint64(numMerchantEntries))
}

// DeleteMerchantEntryForMerchantIDWithTxn ...
func DeleteMerchantEntryForMerchantIDWithTxn(txn *badger.Txn, merchantID *BlockHash) error {
	return txn.Delete(append(append([]byte{}, _PrefixMerchantIDToMerchantEntry...), merchantID[:]...))
}

// DeletePubKeyToMerchantIDWithTxn ...
func DeletePubKeyToMerchantIDWithTxn(txn *badger.Txn, pk []byte) error {
	return txn.Delete(append(append([]byte{}, _PrefixPubKeyToMerchantID...), pk...))
}

// DeleteUsernameToMerchantIDWithTxn ...
func DeleteUsernameToMerchantIDWithTxn(txn *badger.Txn, username []byte) error {
	return txn.Delete(append(append([]byte{}, _PrefixUsernameToMerchantID...), username...))
}

// DeletePosToMerchantIDWithTxn ...
func DeletePosToMerchantIDWithTxn(txn *badger.Txn, pos uint64) error {
	return txn.Delete(_DbKeyForMerchantEntryPos(pos))
}

// GetNumMerchantEntriesWithTxn ...
func GetNumMerchantEntriesWithTxn(txn *badger.Txn) uint64 {
	merchantEntryItem, err := txn.Get(_KeyMerchantNumEntries)
	if err != nil {
		return 0
	}
	numEntryBuf, err := merchantEntryItem.ValueCopy(nil)
	if err != nil {
		return 0
	}

	return _DecodeUint64(numEntryBuf)
}

// GetNumMerchantEntries ...
func GetNumMerchantEntries(handle *badger.DB) uint64 {
	var numMerchantEntries uint64
	handle.View(func(txn *badger.Txn) error {
		numMerchantEntries = GetNumMerchantEntriesWithTxn(txn)
		return nil
	})

	return numMerchantEntries
}

// DbGetMerchantEntryForMerchantIDWithTxn ...
func DbGetMerchantEntryForMerchantIDWithTxn(txn *badger.Txn, merchantID *BlockHash) *MerchantEntry {
	var merchantEntry *MerchantEntry
	merchantEntryItem, err := txn.Get(append(append([]byte{}, _PrefixMerchantIDToMerchantEntry...), merchantID[:]...))
	if err != nil {
		// Return nothing if we hit an error.
		//glog.Errorf("DbGetMerchantEntryForMerchantIDWithTxn: Problem getting merchant entry for merchantID %v: %v", merchantID, err)
		return nil
	}
	err = merchantEntryItem.Value(func(valBytes []byte) error {
		merchantEntry, err = _DecodeMerchantEntry(valBytes)
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		// Return nothing if we hit an error.
		glog.Errorf("DbGetMerchantEntryForMerchantIDWithTxn: Problem decoding MerchantEntry for MerchantID %v: %v", merchantID, err)
		return nil
	}

	return merchantEntry
}

// DbGetMerchantEntryForMerchantID ...
func DbGetMerchantEntryForMerchantID(handle *badger.DB, merchantID *BlockHash) *MerchantEntry {
	var merchantEntry *MerchantEntry
	handle.View(func(txn *badger.Txn) error {
		merchantEntry = DbGetMerchantEntryForMerchantIDWithTxn(txn, merchantID)
		return nil
	})
	if merchantEntry != nil {
		merchantEntry.merchantID = merchantID
	}

	return merchantEntry
}

// GetMerchantIDForPosWithTxn ...
func GetMerchantIDForPosWithTxn(txn *badger.Txn, pos uint64) *BlockHash {
	var merchantID BlockHash
	merchantIDItem, err := txn.Get(_DbKeyForMerchantEntryPos(pos))
	if err != nil {
		return nil
	}
	_, err = merchantIDItem.ValueCopy(merchantID[:])
	if err != nil {
		return nil
	}
	return &merchantID
}

// GetMerchantIDForPos ...
func GetMerchantIDForPos(handle *badger.DB, pos uint64) *BlockHash {
	var merchantID *BlockHash
	handle.View(func(txn *badger.Txn) error {
		merchantID = GetMerchantIDForPosWithTxn(txn, pos)
		return nil
	})

	return merchantID
}

// GetMerchantIDForUsernameWithTxn ...
func GetMerchantIDForUsernameWithTxn(txn *badger.Txn, username []byte) *BlockHash {
	var bh BlockHash
	blockHashItem, err := txn.Get(append(append([]byte{}, _PrefixUsernameToMerchantID...), username...))
	if err != nil {
		return nil
	}
	_, err = blockHashItem.ValueCopy(bh[:])
	if err != nil {
		return nil
	}

	return &bh
}

// GetMerchantIDForUsername ...
func GetMerchantIDForUsername(handle *badger.DB, username []byte) *BlockHash {
	var bh *BlockHash
	err := handle.View(func(txn *badger.Txn) error {
		bh = GetMerchantIDForUsernameWithTxn(txn, username)
		return nil
	})
	if err != nil {
		return nil
	}

	return bh
}

// GetMerchantIDForPubKeyWithTxn ...
func GetMerchantIDForPubKeyWithTxn(txn *badger.Txn, pk []byte) *BlockHash {
	var bh BlockHash
	blockHashItem, err := txn.Get(append(append([]byte{}, _PrefixPubKeyToMerchantID...), pk...))
	if err != nil {
		return nil
	}
	_, err = blockHashItem.ValueCopy(bh[:])
	if err != nil {
		return nil
	}

	return &bh
}

// GetMerchantIDForPubKey ...
func DbGetMerchantIDForPubKey(handle *badger.DB, pk []byte) *BlockHash {
	var bh *BlockHash
	err := handle.View(func(txn *badger.Txn) error {
		bh = GetMerchantIDForPubKeyWithTxn(txn, pk)
		return nil
	})
	if err != nil {
		return nil
	}

	return bh
}

func _DecodeUtxoOperations(data []byte) ([][]*UtxoOperation, error) {
	ret := [][]*UtxoOperation{}
	if err := gob.NewDecoder(bytes.NewReader(data)).Decode(&ret); err != nil {
		return nil, err
	}
	return ret, nil
}

func _EncodeUtxoOperations(utxoOp [][]*UtxoOperation) []byte {
	opBuf := bytes.NewBuffer([]byte{})
	gob.NewEncoder(opBuf).Encode(utxoOp)
	return opBuf.Bytes()
}

func _DbKeyForUtxoOps(blockHash *BlockHash) []byte {
	return append(append([]byte{}, _PrefixBlockHashToUtxoOperations...), blockHash[:]...)
}

// GetUtxoOperationsForBlockWithTxn ...
func GetUtxoOperationsForBlockWithTxn(txn *badger.Txn, blockHash *BlockHash) ([][]*UtxoOperation, error) {
	var retOps [][]*UtxoOperation
	utxoOpsItem, err := txn.Get(_DbKeyForUtxoOps(blockHash))
	if err != nil {
		return nil, err
	}
	err = utxoOpsItem.Value(func(valBytes []byte) error {
		retOps, err = _DecodeUtxoOperations(valBytes)
		if err != nil {
			return err
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	return retOps, err
}

// GetUtxoOperationsForBlock ...
func GetUtxoOperationsForBlock(handle *badger.DB, blockHash *BlockHash) ([][]*UtxoOperation, error) {
	var ops [][]*UtxoOperation
	err := handle.View(func(txn *badger.Txn) error {
		var err error
		ops, err = GetUtxoOperationsForBlockWithTxn(txn, blockHash)
		return err
	})

	return ops, err
}

// PutUtxoOperationsForBlockWithTxn ...
func PutUtxoOperationsForBlockWithTxn(txn *badger.Txn, blockHash *BlockHash, utxoOpsForBlock [][]*UtxoOperation) error {
	return txn.Set(_DbKeyForUtxoOps(blockHash), _EncodeUtxoOperations(utxoOpsForBlock))
}

// DeleteUtxoOperationsForBlockWithTxn ...
func DeleteUtxoOperationsForBlockWithTxn(txn *badger.Txn, blockHash *BlockHash) error {
	return txn.Delete(_DbKeyForUtxoOps(blockHash))
}

func _DbKeyForOrderEntryPos(pos uint64) []byte {
	posBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(posBytes, pos)
	return append(append([]byte{}, _PrefixPosToOrderID...), posBytes...)

}

func _DbKeyForMerchantEntryPos(pos uint64) []byte {
	posBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(posBytes, pos)
	return append(append([]byte{}, _PrefixPosToMerchantID...), posBytes...)

}

// SerializeBlockNode ...
func SerializeBlockNode(blockNode *BlockNode) ([]byte, error) {
	data := []byte{}

	// Hash
	if blockNode.Hash == nil {
		return nil, fmt.Errorf("SerializeBlockNode: Hash cannot be nil")
	}
	data = append(data, blockNode.Hash[:]...)

	// Height
	data = append(data, UintToBuf(uint64(blockNode.Height))...)

	// DifficultyTarget
	if blockNode.DifficultyTarget == nil {
		return nil, fmt.Errorf("SerializeBlockNode: DifficultyTarget cannot be nil")
	}
	data = append(data, blockNode.DifficultyTarget[:]...)

	// CumWork
	data = append(data, BigintToHash(blockNode.CumWork)[:]...)

	// Header
	serializedHeader, err := blockNode.Header.ToBytes(false)
	if err != nil {
		return nil, errors.Wrapf(err, "SerializeBlockNode: Problem serializing header")
	}
	data = append(data, IntToBuf(int64(len(serializedHeader)))...)
	data = append(data, serializedHeader...)

	// Status
	// It's assumed this field is one byte long.
	data = append(data, UintToBuf(uint64(blockNode.Status))...)

	return data, nil
}

// DeserializeBlockNode ...
func DeserializeBlockNode(data []byte) (*BlockNode, error) {
	blockNode := NewBlockNode(
		nil,          // Parent
		&BlockHash{}, // Hash
		0,            // Height
		&BlockHash{}, // DifficultyTarget
		nil,          // CumWork
		nil,          // Header
		StatusNone,   // Status

	)

	rr := bytes.NewReader(data)

	// Hash
	_, err := io.ReadFull(rr, blockNode.Hash[:])
	if err != nil {
		return nil, errors.Wrapf(err, "DeserializeBlockNode: Problem decoding Hash")
	}

	// Height
	height, err := ReadUvarint(rr)
	if err != nil {
		return nil, errors.Wrapf(err, "DeserializeBlockNode: Problem decoding Height")
	}
	blockNode.Height = uint32(height)

	// DifficultyTarget
	_, err = io.ReadFull(rr, blockNode.DifficultyTarget[:])
	if err != nil {
		return nil, errors.Wrapf(err, "DeserializeBlockNode: Problem decoding DifficultyTarget")
	}

	// CumWork
	tmp := BlockHash{}
	_, err = io.ReadFull(rr, tmp[:])
	if err != nil {
		return nil, errors.Wrapf(err, "DeserializeBlockNode: Problem decoding CumWork")
	}
	blockNode.CumWork = HashToBigint(&tmp)

	// Header
	payloadLen, err := ReadVarint(rr)
	if err != nil {
		return nil, errors.Wrapf(err, "DeserializeBlockNode: Problem decoding Header length")
	}
	headerBytes := make([]byte, payloadLen)
	_, err = io.ReadFull(rr, headerBytes[:])
	if err != nil {
		return nil, errors.Wrapf(err, "DeserializeBlockNode: Problem reading Header bytes")
	}
	blockNode.Header = NewMessage(MsgTypeHeader).(*MsgUltranetHeader)
	err = blockNode.Header.FromBytes(headerBytes)
	if err != nil {
		return nil, errors.Wrapf(err, "DeserializeBlockNode: Problem parsing Header bytes")
	}

	// Status
	status, err := ReadUvarint(rr)
	if err != nil {
		return nil, errors.Wrapf(err, "DeserializeBlockNode: Problem decoding Status")
	}
	blockNode.Status = BlockStatus(uint32(status))

	return blockNode, nil
}

type ChainType uint8

const (
	ChainTypeUltranetBlock = iota
	ChainTypeBitcoinHeader
)

func _prefixForChainType(chainType ChainType) []byte {
	var prefix []byte
	switch chainType {
	case ChainTypeUltranetBlock:
		prefix = _KeyBestUltranetBlockHash
	case ChainTypeBitcoinHeader:
		prefix = _KeyBestBitcoinHeaderHash
	default:
		glog.Errorf("_prefixForChainType: Unknown ChainType %d; this should never happen", chainType)
		return nil
	}

	return prefix
}

// DbGetBestHash ...
func DbGetBestHash(handle *badger.DB, chainType ChainType) *BlockHash {
	prefix := _prefixForChainType(chainType)
	if len(prefix) == 0 {
		glog.Errorf("DbGetBestHash: Problem getting prefix for ChainType: %d", chainType)
		return nil
	}
	return _getBlockHashForPrefix(handle, prefix)
}

// PutBestHashWithTxn ...
func PutBestHashWithTxn(txn *badger.Txn, bh *BlockHash, chainType ChainType) error {
	prefix := _prefixForChainType(chainType)
	if len(prefix) == 0 {
		glog.Errorf("PutBestHashWithTxn: Problem getting prefix for ChainType: %d", chainType)
		return nil
	}
	return txn.Set(prefix, bh[:])
}

// PutBestHash ...
func PutBestHash(bh *BlockHash, handle *badger.DB, chainType ChainType) error {
	return handle.Update(func(txn *badger.Txn) error {
		return PutBestHashWithTxn(txn, bh, chainType)
	})
}

func _blockHashToBlockKey(blockHash *BlockHash) []byte {
	return append(append([]byte{}, _PrefixBlockHashToBlock...), blockHash[:]...)
}

// GetBlock ...
func GetBlock(blockHash *BlockHash, handle *badger.DB) (*MsgUltranetBlock, error) {
	hashKey := _blockHashToBlockKey(blockHash)
	var blockRet *MsgUltranetBlock
	err := handle.View(func(txn *badger.Txn) error {
		item, err := txn.Get(hashKey)
		if err != nil {
			return err
		}

		err = item.Value(func(valBytes []byte) error {
			ret := NewMessage(MsgTypeBlock).(*MsgUltranetBlock)
			if err := ret.FromBytes(valBytes); err != nil {
				return err
			}
			blockRet = ret

			return nil
		})

		if err != nil {
			return err
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	return blockRet, nil
}

// PutBlockWithTxn ...
func PutBlockWithTxn(txn *badger.Txn, ultranetBlock *MsgUltranetBlock) error {
	if ultranetBlock.Header == nil {
		return fmt.Errorf("PutBlockWithTxn: Header was nil in block %v", ultranetBlock)
	}
	blockHash, err := ultranetBlock.Header.Hash()
	if err != nil {
		return errors.Wrapf(err, "PutBlockWithTxn: Problem hashing header: ")
	}
	blockKey := _blockHashToBlockKey(blockHash)
	data, err := ultranetBlock.ToBytes(false)
	if err != nil {
		return err
	}
	// First check to see if the block is already in the db.
	if _, err := txn.Get(blockKey); err == nil {
		// err == nil means the block already exists in the db so
		// no need to store it.
		return nil
	}
	// If the block is not in the db then set it.
	if err := txn.Set(blockKey, data); err != nil {
		return err
	}
	return nil
}

// PutBlock ...
func PutBlock(ultranetBlock *MsgUltranetBlock, handle *badger.DB) error {
	err := handle.Update(func(txn *badger.Txn) error {
		return PutBlockWithTxn(txn, ultranetBlock)
	})
	if err != nil {
		return err
	}

	return nil
}

func _heightHashToNodeIndexPrefix(bitcoinNodes bool) []byte {
	prefix := append([]byte{}, _PrefixHeightHashToNodeInfo...)
	if bitcoinNodes {
		prefix = append([]byte{}, _PrefixBitcoinHeightHashToNodeInfo...)
	}

	return prefix
}

func _heightHashToNodeIndexKey(height uint32, hash *BlockHash, bitcoinNodes bool) []byte {
	prefix := _heightHashToNodeIndexPrefix(bitcoinNodes)

	heightBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(heightBytes[:], height)
	key := append(prefix, heightBytes[:]...)
	key = append(key, hash[:]...)

	return key
}

// GetHeightHashToNodeInfoWithTxn ...
func GetHeightHashToNodeInfoWithTxn(
	txn *badger.Txn, height uint32, hash *BlockHash, bitcoinNodes bool) *BlockNode {

	key := _heightHashToNodeIndexKey(height, hash, bitcoinNodes)
	nodeValue, err := txn.Get(key)
	if err != nil {
		return nil
	}
	var blockNode *BlockNode
	nodeValue.Value(func(nodeBytes []byte) error {
		blockNode, err = DeserializeBlockNode(nodeBytes)
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return nil
	}
	return blockNode
}

// GetHeightHashToNodeInfo ...
func GetHeightHashToNodeInfo(
	handle *badger.DB, height uint32, hash *BlockHash, bitcoinNodes bool) *BlockNode {

	var blockNode *BlockNode
	handle.View(func(txn *badger.Txn) error {
		blockNode = GetHeightHashToNodeInfoWithTxn(txn, height, hash, bitcoinNodes)
		return nil
	})
	return blockNode
}

// PutHeightHashToNodeInfoWithTxn ...
func PutHeightHashToNodeInfoWithTxn(txn *badger.Txn, node *BlockNode, bitcoinNodes bool) error {

	key := _heightHashToNodeIndexKey(node.Height, node.Hash, bitcoinNodes)
	serializedNode, err := SerializeBlockNode(node)
	if err != nil {
		return errors.Wrapf(err, "PutHeightHashToNodeInfoWithTxn: Problem serializing node")
	}

	if err := txn.Set(key, serializedNode); err != nil {
		return err
	}
	return nil
}

// PutHeightHashToNodeInfo ...
func PutHeightHashToNodeInfo(node *BlockNode, handle *badger.DB, bitcoinNodes bool) error {
	err := handle.Update(func(txn *badger.Txn) error {
		return PutHeightHashToNodeInfoWithTxn(txn, node, bitcoinNodes)
	})

	if err != nil {
		return err
	}

	return nil
}

// DbDeleteHeightHashToNodeInfoWithTxn ...
func DbDeleteHeightHashToNodeInfoWithTxn(
	node *BlockNode, txn *badger.Txn, bitcoinNodes bool) error {

	return txn.Delete(_heightHashToNodeIndexKey(node.Height, node.Hash, bitcoinNodes))
}

// DbBulkDeleteHeightHashToNodeInfo ...
func DbBulkDeleteHeightHashToNodeInfo(
	nodes []*BlockNode, handle *badger.DB, bitcoinNodes bool) error {

	err := handle.Update(func(txn *badger.Txn) error {
		for _, nn := range nodes {
			if err := DbDeleteHeightHashToNodeInfoWithTxn(nn, txn, bitcoinNodes); err != nil {
				return err
			}
		}
		return nil
	})

	if err != nil {
		return err
	}

	return nil
}

// InitDbWithGenesisBlock initializes the database to contain only the genesis
// block.
func InitDbWithUltranetGenesisBlock(params *UltranetParams, handle *badger.DB) error {
	// Construct a node for the genesis block. Its height is zero and it has
	// no parents. Its difficulty should be set to the initial
	// difficulty specified in the parameters and it should be assumed to be
	// valid and stored by the end of this function.
	genesisBlock := params.GenesisBlock
	diffTarget := NewBlockHash(params.MinDifficultyTargetHex)
	blockHash := NewBlockHash(params.GenesisBlockHashHex)
	genesisNode := NewBlockNode(
		nil, // Parent
		blockHash,
		0, // Height
		diffTarget,
		BytesToBigint(ExpectedWorkForBlockHash(diffTarget)[:]), // CumWork
		genesisBlock.Header, // Header
		StatusHeaderValidated|StatusBlockProcessed|StatusBlockStored|StatusBlockValidated, // Status
	)

	// Set the fields in the db to reflect the current state of our chain.
	//
	// Set the best hash to the genesis block in the db since its the only node
	// we're currently aware of. Set it for both the header chain and the block
	// chain.
	if err := PutBestHash(blockHash, handle, ChainTypeUltranetBlock); err != nil {
		return errors.Wrapf(err, "InitDbWithGenesisBlock: Problem putting genesis block hash into db for block chain")
	}
	// Add the genesis block to the (hash -> block) index.
	if err := PutBlock(genesisBlock, handle); err != nil {
		return errors.Wrapf(err, "InitDbWithGenesisBlock: Problem putting genesis block into db")
	}
	// Add the genesis block to the (height, hash -> node info) index in the db.
	if err := PutHeightHashToNodeInfo(genesisNode, handle, false /*bitcoinNodes*/); err != nil {
		return errors.Wrapf(err, "InitDbWithGenesisBlock: Problem putting (height, hash -> node) in db")
	}

	return nil
}

// GetBlockIndex ...
func GetBlockIndex(handle *badger.DB, bitcoinNodes bool) (map[BlockHash]*BlockNode, error) {
	blockIndex := make(map[BlockHash]*BlockNode)

	prefix := _heightHashToNodeIndexPrefix(bitcoinNodes)

	err := handle.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		nodeIterator := txn.NewIterator(opts)
		defer nodeIterator.Close()
		for nodeIterator.Seek(prefix); nodeIterator.ValidForPrefix(prefix); nodeIterator.Next() {
			var blockNode *BlockNode

			// Don't bother checking the key. We assume that the key lines up
			// with what we've stored in the value in terms of (height, block hash).
			item := nodeIterator.Item()
			err := item.Value(func(blockNodeBytes []byte) error {
				// Deserialize the block node.
				var err error
				// TODO: There is room for optimization here by pre-allocating a
				// contiguous list of block nodes and then populating that list
				// rather than having each blockNode be a stand-alone allocation.
				blockNode, err = DeserializeBlockNode(blockNodeBytes)
				if err != nil {
					return err
				}
				return nil
			})
			if err != nil {
				return err
			}

			// If we got hear it means we read a blockNode successfully. Store it
			// into our node index.
			blockIndex[*blockNode.Hash] = blockNode

			// Find the parent of this block, which should already have been read
			// in and connect it. Skip the genesis block, which has height 0. Also
			// skip the block if its PrevBlockHash is empty, which will be true for
			// the BitcoinStartBlockNode.
			//
			// TODO: There is room for optimization here by keeping a reference to
			// the last node we've iterated over and checking if that node is the
			// parent. Doing this would avoid an expensive hashmap check to get
			// the parent by its block hash.
			if blockNode.Height == 0 || (*blockNode.Header.PrevBlockHash == BlockHash{}) {
				continue
			}
			if parent, ok := blockIndex[*blockNode.Header.PrevBlockHash]; ok {
				// We found the parent node so connect it.
				blockNode.Parent = parent
			} else {
				// In this case we didn't find the parent so error. There shouldn't
				// be any orphans in our block index.
				return fmt.Errorf("GetBlockIndex: Could not find parent for blockNode: %+v", blockNode)
			}
		}
		return nil
	})
	if err != nil {
		return nil, errors.Wrapf(err, "GetBlockIndex: Problem reading block index from db")
	}

	return blockIndex, nil
}

// GetBestChain ...
func GetBestChain(tipNode *BlockNode, blockIndex map[BlockHash]*BlockNode) ([]*BlockNode, error) {
	reversedBestChain := []*BlockNode{}
	for tipNode != nil {
		if (tipNode.Status&StatusBlockValidated) == 0 &&
			(tipNode.Status&StatusBitcoinHeaderValidated) == 0 {

			return nil, fmt.Errorf("GetBestChain: Invalid node found in main chain: %+v", tipNode)
		}

		reversedBestChain = append(reversedBestChain, tipNode)
		tipNode = tipNode.Parent
	}

	bestChain := make([]*BlockNode, len(reversedBestChain))
	for ii := 0; ii < len(reversedBestChain); ii++ {
		bestChain[ii] = reversedBestChain[len(reversedBestChain)-1-ii]
	}

	return bestChain, nil
}

// RandomBytes returns a []byte with random values.
func RandomBytes(numBytes int32) []byte {
	randomBytes := make([]byte, numBytes)
	_, err := rand.Read(randomBytes)
	if err != nil {
		glog.Errorf("Problem reading random bytes: %v", err)
	}
	return randomBytes
}

// RandomBytesHex returns a hex string representing numBytes of
// entropy.
func RandomBytesHex(numBytes int32) string {
	return hex.EncodeToString(RandomBytes(numBytes))
}

// RandInt64 returns a random 64-bit int.
func RandInt64(max int64) int64 {
	val, err := rand.Int(rand.Reader, big.NewInt(math.MaxInt64))
	if err != nil {
		glog.Errorf("Problem generating random int64: %v", err)
	}
	return val.Int64()
}

// RandInt32 returns a random 32-bit int.
func RandInt32(max int32) int32 {
	val, err := rand.Int(rand.Reader, big.NewInt(math.MaxInt32))
	if err != nil {
		glog.Errorf("Problem generating random int32: %v", err)
	}
	if val.Int64() > math.MaxInt32 {
		glog.Errorf("Generated a random number out of range: %d (max: %d)", val.Int64(), math.MaxInt32)
	}
	// This cast is OK since we initialized the number to be
	// < MaxInt32 above.
	return int32(val.Int64())
}

// PPrintJSON prints a JSON object but pretty.
func PPrintJSON(xx interface{}) {
	yy, _ := json.MarshalIndent(xx, "", "  ")
	log.Println(string(yy))
}

// BlocksPerDuration ...
func BlocksPerDuration(duration time.Duration, timeBetweenBlocks time.Duration) uint32 {
	return uint32(int64(duration) / int64(timeBetweenBlocks))
}

// PkToString ...
func PkToString(pk []byte, params *UltranetParams) string {
	return Base58CheckEncode(pk, false, params)
}

// PkToStringMainnet ...
func PkToStringMainnet(pk []byte) string {
	return Base58CheckEncode(pk, false, &UltranetMainnetParams)
}

// PkToStringTestnet ...
func PkToStringTestnet(pk []byte) string {
	return Base58CheckEncode(pk, false, &UltranetTestnetParams)
}

func main() {
	/*
		// TODO: Turn this memory testing code into a real utility.

		capacity := 10000000

		testList := make([]example.Test, 0, capacity)
		// Hack to avoid compiler warning...
		_ = proto.Int32(123)

		mm1 := new(runtime.MemStats)
		mm2 := new(runtime.MemStats)
		// First call to ReadMemStats. Code to test goes below.
		runtime.ReadMemStats(mm1)

		for ii := 0; ii < capacity; ii++ {
			// Comment this in and comment the below out to test proto3 memory usage.
			//testList = append(testList, example.Test{Type: 123})
			// Comment this in and comment the above out to test proto2 memory usage.
			testList = append(testList, example.Test{Type: proto.Int32(123)})
		}

		// Second call to ReadMemStats. Code to test goes above.
		runtime.ReadMemStats(mm2)

		// Print the amount of memory that was allocated between runs of ReadMemStats,
		// subtracting off a baseline that is used to actually call ReadMemStats.
		fmt.Println(
			"TotalAlloc: ", mm2.TotalAlloc-mm1.TotalAlloc-2048,
			"Mallocs: ", mm2.Mallocs-mm1.Mallocs-4,
			"HeapAlloc: ", mm2.HeapAlloc-mm1.HeapAlloc-2048,
			"StackInUse: ", mm2.StackInuse-mm1.StackInuse-32768)
	*/
}
