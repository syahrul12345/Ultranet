package lib

import (
	"bytes"
	"fmt"
	"math"
	"math/big"

	"github.com/btcsuite/btcd/btcec"
	"github.com/dgraph-io/badger"
	"github.com/golang/glog"
	"github.com/pkg/errors"
	"github.com/sasha-s/go-deadlock"
)

// listing_manager.go contains all of the logic for updating merchant listings.
// Note that the listing db is disjoint from the blockchain. A good place to
// start to understand this file is Update().

// ListingManager ...
type ListingManager struct {
	ListingLock deadlock.RWMutex

	Handle     *badger.DB
	Params     *UltranetParams
	blockchain *Blockchain
}

// NewListingManager returns a new ListingManager.
// Note that the ListingIndex will not be initialized until Start() is called.
func NewListingManager(_handle *badger.DB, _blockchain *Blockchain, _params *UltranetParams) (*ListingManager, error) {
	listingView := ListingManager{
		Handle:     _handle,
		Params:     _params,
		blockchain: _blockchain,
	}

	return &listingView, nil
}

// Stop stops the ListingManager
// TODO: We should probably clean up any goroutines that we kicked off here. It
// doesn't matter right now though because Stop() is only called when everything
// is being shut down.
func (lv *ListingManager) Stop() {
}

// Start starts the ListingManager
func (lv *ListingManager) Start() error {
	// Note that we don't run Update() in start because we're not sure if the blockchain
	// is in-sync yet. Once it is, the Server is responsible for calling it initially
	// and whenever a new block is connected to keep the data structure up-to-date.
	return nil
}

func _merchantIDListToMap(merchantIDList []*BlockHash) map[BlockHash]bool {
	ret := make(map[BlockHash]bool)
	for _, hash := range merchantIDList {
		ret[*hash] = true
	}
	return ret
}

// Does the leg-work for the Update() function. Assumes the blockchain's ChainLock
// is held for reading and the ListingLock is held for writing.
func (lv *ListingManager) update() error {
	// If the current block tip is equal to the block hash at which the listing index
	// was last updated then there's nothing to do. If the listing index hash is nil
	// it means this is the first time we're running update, which means the listing
	// db should be completely empty.
	listingIndexHash := DbGetListingBlockHash(lv.Handle)
	tipHash := lv.blockchain.blockTip().Hash
	if listingIndexHash != nil && *listingIndexHash == *tipHash {
		glog.Tracef("ListingManager.update: No need to update listing index because "+
			"listing index hash %v is equal to block tip %v", listingIndexHash, tipHash)
		return nil
	}

	// Fetch the MerchantIDs according to the listing index. This is our starting point
	// for the update. We don't limit the number of MerchantIDs that we fetch from the
	// listing index because it should already be limited at the point where we insert
	// into it.
	listingMerchantIDs, listingMerchantScores, _, err := DbGetListingTopMerchants(
		lv.Handle, math.MaxUint64, true /*noMerchantEntries*/)
	if err != nil {
		return errors.Wrapf(err, "Problem fetching MerchantIDs and scores from the listing index: ")
	}
	// If we have too many MerchantIDs in the listing index then we've vioated an invariant.
	// Log an error but don't stop executing.
	if uint64(len(listingMerchantIDs)) > lv.Params.MaxMerchantsToIndex {
		glog.Errorf("ListingManager.update: Number of MerchantIDs in ListingManager "+
			"db is %d, which exceeds the max allowed %d. This should never happen, but "+
			"we're going to ignore this error and move on",
			len(listingMerchantIDs), lv.Params.MaxMerchantsToIndex)
	}
	// Create a mapping from the listing merchantIDs to the scores for use later.
	listingMerchantIDsToScores := make(map[BlockHash]*big.Int)
	for ii := range listingMerchantIDs {
		merchantID := listingMerchantIDs[ii]
		score := listingMerchantScores[ii]

		listingMerchantIDsToScores[*merchantID] = score
	}

	// Fetch the MerchantIDs according to the blockchain. This will be our source of
	// truth or our "endpoint" that we want to update the index toward during this update.
	blockchainMerchantIDs, blockchainMerchantScores, _, err := DbGetBlockchainTopMerchants(
		lv.Handle, lv.Params.MaxMerchantsToIndex, true /*noMerchantEntries*/)
	// Create a mapping from the blockchain's merchantIDs to the merchant scores
	// for use later.
	blockchainMerchantIDsToScores := make(map[BlockHash]*big.Int)
	for ii := range blockchainMerchantIDs {
		merchantID := blockchainMerchantIDs[ii]
		score := blockchainMerchantScores[ii]

		blockchainMerchantIDsToScores[*merchantID] = score
	}

	// In a single database transaction, update the listing index state.
	dbError := lv.Handle.Update(func(txn *badger.Txn) error {
		// If a merchantID is in the listing db but not in the blockchain db,
		// remove its mappings from the listing index completely. If a merchantID
		// is in the listing db and in the blockchain db but has a different score
		// in the blockchain db, then update the score in the listing db.
		for listingMerchantIDIter, listingScore := range listingMerchantIDsToScores {
			// Note: We're being a little paranoid here and making a copy of the MerchantID
			// just in case the function is saving a reference.
			listingMerchantID := listingMerchantIDIter

			// If we don't find the MerchantID in the blockchain db then delete all of its
			// mappings from the listing db.
			blockchainScore, isIDInBlockchainDB := blockchainMerchantIDsToScores[listingMerchantID]
			if !isIDInBlockchainDB {
				err := DbDeleteAllListingMappingsForMerchantIDWithTxn(txn, &listingMerchantID)
				if err != nil {
					return errors.Wrapf(err, "ListingManager.update: Problem removing mappings "+
						"for MerchantID %v: ", listingMerchantID)
				}
				continue
			}

			// If the score in the listing index is the same as the score in the
			// blockchain index, no need to update anything.
			if listingScore.Cmp(blockchainScore) == 0 {
				continue
			}

			// If we get here then the merchant exists in the blockchain db and the listing
			// db but its score is different in each. Update the score in the listing db to
			// be equal to the score in the blockchain db, which is our source of truth.
			err := DbUpdateListingScoreMappingForMerchantIDWithTxn(
				txn, &listingMerchantID, blockchainScore)
			if err != nil {
				return errors.Wrapf(err, "ListingManager.update: Problem updating score "+
					"for MerchantID %v: ", listingMerchantID)
			}
		}

		// If a merchantID is in the blockchain db but not in the listing db then create
		// mappings for it in the listing db.
		for blockchainMerchantIDIter, blockchainScore := range blockchainMerchantIDsToScores {
			// Note: We are being a little paranoid and making a copy of the iterator in case
			// anything below decides to take a reference.
			blockchainMerchantID := blockchainMerchantIDIter

			_, isIDInListingDB := listingMerchantIDsToScores[blockchainMerchantIDIter]
			if !isIDInListingDB {

				err := DbPutMerchantMappingsInListingIndexWithTxn(
					txn, &blockchainMerchantID, &ListingMerchantIDInfo{
						Score:    blockchainScore,
						NumBytes: 0,
					})
				if err != nil {
					return errors.Wrapf(err, "ListingManager.update: Problem initializing "+
						"merchant mappings in listing index: ")
				}
			}
		}

		// Once we've updated all of the merchant mappings, advance our pointer to the
		// block tip, which is the point at which our listing index now corresponds to.
		if err := DbPutListingBlockHashWithTxn(txn, tipHash); err != nil {
			return errors.Wrapf(err, "ListingManager.update: Problem updating tip hash: ")
		}

		return nil
	})
	if dbError != nil {
		return dbError
	}

	// At this point, the listing index should be in-sync with the blockchain in terms
	// of who the top merchants are and what their scores are. We should also have run
	// various sanity checks on the listing index, all of which must have passed.
	return nil
}

// Update holds the blockchain's ChainLock for reading and the ListingManager's
// ListingLock for writing. Broadly, there are two parts of the database that
// concern us in this function:
// - The blockchain's data, which tells us who the top merchants are and is
//   protected by the ChainLock. This function just reads this data in order
//   to determine who the top merchants are, which is why the ChainLock is only
//   acquired for reads.
// - The listings data, which organizes all of the information around the listings
//   for the top merchant. This second part is managed independently of the
//   blockchain, other than the fact that the listings for whom we storee listings
//   is determined based on their score as determined by the blockchain. This
//   listings component of the data we're interested in in this function is what
//   is protected by the ListingLock and it is what we update in this function.
//
// The purpose of this function is to "sync" the listings data up with the blockchain's
// data in terms of who the top merchants are and what their scores are. This ensures
// that when listings come in we are only indexing them for the merchants who are
// worthy based on their score.
func (lv *ListingManager) Update() error {
	// Hold the ChainLock for reading
	lv.blockchain.ChainLock.RLock()
	defer lv.blockchain.ChainLock.RUnlock()
	// Hold the ListingLock for writing
	lv.ListingLock.Lock()
	defer lv.ListingLock.Unlock()

	return lv.update()
}

// ValidateListing does various checks to make sure the fields of the passed-in
// listing follow various rules and that the passed-in listing can be added to the
// db (potentially after removing a pre-existing listing with the same index).
func (lv *ListingManager) ValidateListing(
	listingMessage *MsgUltranetListing, verifySignatures bool) (_err error) {

	// If the listing index is out of range then reject the listing.
	if listingMessage.ListingIndex >= lv.Params.MaxListingsPerMerchant {
		return ListingErrorInvalidListingIndex
	}

	// Fetch the info for this merchant. If we can't find it then it means the merchant
	// who posted this listing is not authorized to post listings and we should error.
	merchantInfo := DbGetListingMerchantIDInfo(lv.Handle, listingMessage.MerchantID)
	if merchantInfo == nil {
		return ListingErrorNotTopMerchantUnauthorizedToPostListing
	}

	// Get the MerchantEntry for the merchant so we can check her public key. Note
	// that the MerchantEntry being looked up may have a different score than what's
	// in the Listing DB because the Blockchain DB has since updated it.
	//
	// TODO: This is technically under the blockchain's database and isn't protected
	// by the ListingLock, which means we could
	// be exposing ourselves to a minor race condition if the caller isn't holding
	// the ChainLock. That said, I think the worst that will happen is that the
	// blockchain will remove a merchant or something before the listing index is
	// able to update and we'll just error here rather than above. As such, it
	// doesn't seem necessary to acquire the ChainLock to protect this.
	merchantEntry := DbGetMerchantEntryForMerchantID(
		lv.Handle, listingMessage.MerchantID)
	if merchantEntry == nil {
		return ListingErrorMerchantEntryNotFoundForMerchantID
	}

	// Check that the public key of the merchant matches up with what's
	// set in the listing.
	if !bytes.Equal(merchantEntry.PublicKey, listingMessage.PublicKey) {
		return ListingErrorMerchantPublicKeyDoesNotMatch
	}

	// Check that this listing is later than any prior listing we had in this slot.
	prevListingNumBytes := uint64(0)
	prevListing := DbGetListingMessage(
		lv.Handle, listingMessage.MerchantID, listingMessage.ListingIndex)
	if prevListing != nil {
		// Verify that the timestamp of the previous listing is stricly less than the
		// timestamp of the listing being added.
		if listingMessage.TstampSecs <= prevListing.TstampSecs {
			return ListingErrorMoreRecentListingWithSameIndexExists
		}

		// Serialize the previous listing and compute its size so we can make sure
		// replacing it won't cause us to exceed the maximum storage for the merchant.
		prevBytes, err := prevListing.ToBytes(false /*preSignature*/)
		if err != nil {
			return errors.Wrapf(err,
				"ValidateListing: Problem serializing prior listing to bytes %v", prevListing)
		}
		prevListingNumBytes = uint64(len(prevBytes))
	}

	// Sanity-check to make sure the number of bytes according to the db is not less
	// than the number of bytes in a listing currently stored.
	if merchantInfo.NumBytes < prevListingNumBytes {
		return fmt.Errorf("ValidateListing: Number of bytes according to db %d is "+
			"less than previous listing serialized size %d for merchantID %v and "+
			"listingIndex %d; this should never happen",
			merchantInfo.NumBytes, prevListingNumBytes, listingMessage.MerchantID,
			listingMessage.ListingIndex)
	}

	// Ensure that adding the passed-in listing would not cause the maximum merchant
	// storage to be exceeded for this merchant.
	listingBytes, err := listingMessage.ToBytes(false /*preSignature*/)
	if err != nil {
		return ListingErrorCouldNotSerializeListingToBytes
	}
	listingNumBytes := uint64(len(listingBytes))
	// If the listing is greater than the maximum number of bytes allowed for a listing
	// then reject it.
	if listingNumBytes > lv.Params.MaxListingSizeBytes {
		return ListingErrorListingExceedsMaxSize
	}
	// Avoid overflow when adding listing size to total bytes. Shouldn't be possible but
	// only the paranoid survive.
	if listingNumBytes > math.MaxUint64-merchantInfo.NumBytes {
		return fmt.Errorf("ValidateListing: Listing size %d would cause overflow "+
			"when added with size in merchant info %d",
			listingNumBytes, merchantInfo.NumBytes)
	}
	// Should not underflow because we checked that the previous listing size does not
	// exceed the size stored in the info.
	merchantStorageAfter := merchantInfo.NumBytes - prevListingNumBytes + listingNumBytes
	if merchantStorageAfter > lv.Params.MaxMerchantStorageBytes {
		return ListingErrorAddingListingWouldCauseMaxMerchantStorageToBeEceeded
	}

	// Verify the signature of the listing if it's desired.
	if verifySignatures {
		// Compute a hash of the passed-in listing without its signature present.
		listingBytesNoSignature, err := listingMessage.ToBytes(true /*preSignature*/)
		if err != nil {
			return ListingErrorCouldNotSerializeTransactionWithoutSignature
		}
		listingPubKeyParsed, err := btcec.ParsePubKey(listingMessage.PublicKey, btcec.S256())
		if err != nil {
			return ListingErrorCouldNotParsePublicKey
		}
		listingHashNoSignature := Sha256DoubleHash(listingBytesNoSignature)
		if listingMessage.Signature == nil || !listingMessage.Signature.Verify(listingHashNoSignature[:], listingPubKeyParsed) {
			return ListingErrorSignatureNotValid
		}
	}

	// Verify that individual fields don't exceed their limits. We just check the
	// fields that we'll be indexing on for now.
	if uint64(len(listingMessage.Title)) > lv.Params.MaxListingTitleLengthBytes {
		return ListingErrorTitleTooLong
	}
	if uint64(len(listingMessage.Body)) > lv.Params.MaxListingBodyLengthBytes {
		return ListingErrorBodyTooLong
	}
	if uint64(len(listingMessage.Category)) > lv.Params.MaxListingCategoryLengthBytes {
		return ListingErrorCategoryTooLong
	}
	// If other fields are too long the frontend will just cut them off. The fact
	// that the merchant has not exceeded the max listing size, which is checked below,
	// is sufficient to ensure there won't be serious problems serving this listing.

	// If the listing has Deleted=true then we do some abbreviated validation. Note
	// that a listing can have Deleted=true even if there's no pre-existing listing
	// to delete. As such, at this point there is nothing more to check for a deleted
	// listing.
	if listingMessage.Deleted {
		return nil
	}

	// In addition to the above, make sure the fields have non-zero length. This is
	// mainly cosmetic, since zero-length fields look bad to users and serve no purpose
	// in general.
	if uint64(len(listingMessage.Title)) == 0 {
		return ListingErrorTitleTooShort
	}
	if uint64(len(listingMessage.Body)) == 0 {
		return ListingErrorBodyTooShort
	}
	if uint64(len(listingMessage.Category)) == 0 {
		return ListingErrorCategoryTooShort
	}
	if uint64(len(listingMessage.UnitNameSingular)) == 0 {
		return ListingErrorUnitNameSingularTooShort
	}
	if uint64(len(listingMessage.UnitNamePlural)) == 0 {
		return ListingErrorUnitNamePluralTooShort
	}

	if len(listingMessage.ThumbnailImage) == 0 {
		return ListingErrorThumbnailRequired
	}

	if len(listingMessage.ListingImages) == 0 {
		return ListingErrorAtLeastOneImageRequired
	}

	// Ensure that the min quantity and the max quantity are not in conflict.
	if listingMessage.MinQuantity != 0 && listingMessage.MaxQuantity != 0 &&
		listingMessage.MinQuantity > listingMessage.MaxQuantity {
		return ListingErrorQuantityConflict
	}

	// At this point, we are confident that removing the previous listing, if one exists,
	// and adding the passed-in listing in its place is a good idea.
	return nil
}

// ProcessListing holds only the ListingManager's ListingLock. It does not need the
// blockchain's ChainLock becuase it only reads the ListingManager's index, for which
// holding the ListingLock is sufficient to guarantee safety. Note this is in contrast
// with Update(), which must effectively "sync" the top merchants between the blockchain's
// database and the ListingManager's index, requiring the holding of both locks to
// avoid changes being made to the blockchain database during execution of the function.
//
// TODO: Add per-merchant rate limiting on listing posting. Make it a configurable flag
// that is set to very high by default so nobody has issues early on. Not doing this
// makes it so that one merchant who publishes gratuitously will negatively impact other
// merchants.
func (lv *ListingManager) ProcessListing(
	listingMessage *MsgUltranetListing, verifySignatures bool) error {

	// Hold the ListingLock for writing
	lv.ListingLock.Lock()
	defer lv.ListingLock.Unlock()

	// Validate the listing. This ensures that the passed-in listing can be added at
	// the index it specifies, and that any pre-existing listing that already exists
	// at that index can be replaced by it.
	err := lv.ValidateListing(listingMessage, verifySignatures)
	if err != nil {
		return errors.Wrapf(err, "ProcessListing: Problem validating listing: ")
	}

	// Once the passed-in listing is validated, remove the mappings for any prior
	// listing and add the mappings for the passed-in listing to the db.
	dbError := lv.Handle.Update(func(txn *badger.Txn) error {
		// If a previous listing exists, remove all of its mappings from the db. This
		// should update the merchant storage accordingly.
		prevListing := DbGetListingMessageWithTxn(
			txn, listingMessage.MerchantID, listingMessage.ListingIndex)
		if prevListing != nil {
			err = DbDeleteMappingsForSingleListingWithTxn(
				txn, prevListing.MerchantID, prevListing.ListingIndex)
			if err != nil {
				return errors.Wrapf(err, "ProcessListing: Problem removing previous listing: ")
			}
		}
		// Only add the new listing if it has Deleted = false.
		//
		// TODO: Right now the way we handle deletion is we allow any listing message
		// with Deleted=true to wipe out a listing's data as long as it's greater than
		// the current timestamp. The problem with this is that once a listing's data
		// is wiped out, someone can theoretically replay any old listing that had
		// Deleted=false immediately afterward to undo the operation. This is annoying
		// but not a security threat, and an easy workaround for a merchant is simply
		// to fill that slot with a real listing (even if it's just a copy of another
		// listing that will work).
		// ... The above being said ...
		// The right way to do this that eliminates the need
		// for this workaround is to store the timestamp of the last listing update for
		// all listings, even if the last update is a deletion. This makes the replay attack fail
		// because the attacker cannot produce a listing message with a higher timestamp
		// than the deletion. The reason why I didn't do this is making this change would
		// require changing a bunch of code and, since it's really just an annoying edge
		// case with a workaround and not a security threat, I was too lazy. But someone
		// shoud make this change eventually.
		if !listingMessage.Deleted {
			err = DbPutMappingsForSingleListingWithTxn(txn, listingMessage)
			if err != nil {
				return errors.Wrapf(err, "ProcessListing: Problem putting listing mappings: ")
			}
		}

		// As a sanity-check, verify that the number of bytes of merchant storage does not
		// exceed the max after this operation (should be guaranteed since validation checks
		// this).
		newInfoTmp := DbGetListingMerchantIDInfoWithTxn(txn, listingMessage.MerchantID)
		if newInfoTmp.NumBytes > lv.Params.MaxMerchantStorageBytes {
			return fmt.Errorf("ProcessListing: Size according to the db after updating "+
				"listing %d exceeds the maximum size %d; this should never happen",
				newInfoTmp.NumBytes, lv.Params.MaxMerchantStorageBytes)
		}

		return nil
	})
	if dbError != nil {
		return dbError
	}

	// At this point we should have removed all mappings from any previous listing
	// with the same index and we should have added all-new mappings for the passed-in
	// listing.
	return nil
}

func (lv *ListingManager) NewListingIndexForMerchantID(merchantID *BlockHash) (uint32, error) {
	lv.ListingLock.RLock()
	defer lv.ListingLock.RUnlock()

	listingIndices, _, err := DbGetListingsForMerchantID(lv.Handle, merchantID, false /*fetchListings*/)
	if err != nil {
		return 0, errors.Wrapf(err, "NewListingIndexForMerchantID: Problem fetching existing listing indices: ")
	}
	listingIndicesMap := make(map[uint32]bool)
	for _, index := range listingIndices {
		listingIndicesMap[index] = true
	}
	for ii := uint32(0); ii < lv.Params.MaxListingsPerMerchant; ii++ {
		if _, exists := listingIndicesMap[ii]; !exists {
			return ii, nil
		}
	}

	return 0, fmt.Errorf("NewListingIndexForMerchantID: All %d listing slots are "+
		"currently taken; merchant must delete a listing in order to be able to "+
		"create a new one", lv.Params.MaxListingsPerMerchant)
}

func (lv *ListingManager) HasHash(listingHash *BlockHash) bool {
	lv.ListingLock.RLock()
	defer lv.ListingLock.RUnlock()

	val := DbGetMappingForListingHashIndex(lv.Handle, listingHash)
	if val != nil {
		return true
	}
	return false
}

func (lv *ListingManager) GetListingForHash(listingHash *BlockHash) *MsgUltranetListing {
	lv.ListingLock.RLock()
	defer lv.ListingLock.RUnlock()

	listingHashIndexValue := DbGetMappingForListingHashIndex(lv.Handle, listingHash)
	if listingHashIndexValue == nil {
		return nil
	}
	return DbGetListingMessage(lv.Handle, listingHashIndexValue.MerchantID, listingHashIndexValue.ListingIndex)
}

func (lv *ListingManager) GetAllListingHashes() ([]*BlockHash, error) {
	hashes, err := DbGetAllListingHashes(lv.Handle)
	if err != nil {
		return nil, err
	}
	return hashes, nil
}
