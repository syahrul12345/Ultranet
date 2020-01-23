package lib

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"

	mathrand "math/rand"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil/base58"
	"github.com/btcsuite/btcutil/hdkeychain"
	"github.com/dgraph-io/badger"
	"github.com/golang/glog"
	deadlock "github.com/sasha-s/go-deadlock"
	"golang.org/x/crypto/pbkdf2"
)

// TODO: frontend_utils and frontend_server were actually supposed to be one big file.
// The only reason I broke them up is because vim-go refused to give me error-checks
// once the file exceeded a certain size. I chopped it kindof randomly in the middle,
// so if we want to keep it as two files going forward, we should clean up
// what goes where. A good place to start is probably InitRoutes() in frontend_server.go
// to see what all the functions that are exposed are.

// FrontendServer provides the interface between the web UI and the blockchain.
// In particular, it exposes a JSON API that can be used to do everything the
// frontend cares about, from posting listings to purchasing Ultra with Bitcoin.
type FrontendServer struct {
	backendServer        *Server
	listingManager       *ListingManager
	blockchain           *Blockchain
	Params               *UltranetParams
	SharedSecret         string
	JSONPort             uint16
	MinFeeRateNanosPerKB uint64

	// This lock should be held when reading or writing any of the data
	// fields below. One could argue that a single giant lock on the entire
	// data structure is inefficient, but since the FE very rarely calls
	// multiple things at once, doing it this way ensures the integrity of
	// everything below without really hurting performance in practice.
	DataLock deadlock.RWMutex

	UserData *LocalUserData

	// This map is stored strictly in memory and contains a mapping from
	// public keys to passwords for passwords that the user has entered
	// since the app was started. After the user enters her password on
	// startup or during login, it is stored in this map and is used for
	// signatures. When the app is closed, this map is erased so no trace
	// of the user's password is left on the machine. This striked a nice
	// balance between security and ease of use. Namely it doesn't store the
	// password on disk and doesn't require the user to enter the password
	// on every transaction.
	PublicKeyToPasswordMap map[string]string

	// Mapping from an image ID to JPEG image bytes. Note that when this is
	// non-empty, it is expected that the 0th element is the thumbnail.
	DraftImages      []*DraftImage
	NextDraftImageID uint64
}

// NewFrontendServer ...
func NewFrontendServer(_backendServer *Server, _listingManager *ListingManager,
	_blockchain *Blockchain, params *UltranetParams, sharedSecret string,
	jsonPort uint16, _minFeeRateNanosPerKB uint64) (*FrontendServer, error) {

	fes := &FrontendServer{
		// TODO: It would be great if we could eliminate the dependency on
		// the backendServer. Right now it's here because it was the easiest
		// way to give the FrontendServer the ability to add transactions
		// to the mempool and relay them to peers.
		backendServer:        _backendServer,
		blockchain:           _blockchain,
		listingManager:       _listingManager,
		Params:               params,
		SharedSecret:         sharedSecret,
		JSONPort:             jsonPort,
		MinFeeRateNanosPerKB: _minFeeRateNanosPerKB,
		DraftImages:          []*DraftImage{},
		// The ImageID is just a counter. It starts at 1 because an image thumbnail
		// always takes the ID of 0.
		NextDraftImageID: 1,

		PublicKeyToPasswordMap: make(map[string]string),
	}

	return fes, nil
}

type SeedInfo struct {
	// Seed-related fields
	HasPassword      bool
	EncryptedSeedHex string
	PwSaltHex        string
	Pbkdf2Iterations uint32
	// A string encoding of a pay-to-pubkey-hash Bitcoin address.
	// The user is expected to deposit BTC into this address so that
	// it can be burned in exchange for Ultra. The private key for this
	// address can always be generated from the seed (or the encrypted
	// seed params above and the password). Its derivation path is
	// m/44'/0'/0'/0/0 and should therefore correspond to the first
	// address you'd get if you typed the seed into most standard
	// Bitcoin wallets.
	BtcDepositAddress string
	// Because we generate the public and private keys using Bitcoin's
	// HD-wallet protocol, we need to maintain whether we're using the
	// testnet or mainnet parameters.
	IsTestnet bool
}

type BitcoinBroadcastInfo struct {
	BitcoinTxn *wire.MsgTx
	// This fields indicates whether or not we have seen this transaction in an
	// API response yet. It is not safe to allow a user to call the BurnBitcoin
	// endpoint until all transactions that the user has created have been
	// registered by the API. Not abiding by this would cause double-spends
	// to be created because the UTXOs would not be properly accounted for as
	// having been used in this transaction.
	ApiResponseReturned bool
	// When this Bitcoin transaction was created. If enough time has passed and
	// we still haven't heard back from the API then we allow other transactions
	// to process, even if we haven't heard back about this particular transaction.
	TimeCreated time.Time
}

type TransactionInfo struct {
	TotalInputNanos   uint64
	SpendAmountNanos  uint64
	ChangeAmountNanos uint64
	FeeNanos          uint64
	TxIDBase58Check   string

	// These are Base58Check encoded
	RecipientPublicKeys   []string
	RecipientAmountsNanos []uint64

	TransactionHex string

	// TODO: Not including the transaction because it causes encoding to
	// fail due to the presence of an interface for TxnMeta.
	//Transaction    *MsgUltranetTxn

	// Unix timestamp (seconds since epoch).
	TimeAdded int64
}

type LocalState struct {
	// We keep a mapping of the BuyerMessages we have sent to merchants
	// since we can't actually decrypt them.
	OrderIDToBuyerMessage map[string]*BuyerMessage
	OrderIDToRejectReason map[string]string

	// These are Bitcoin transactions that we need to broadcast for
	// the user. It maps TxID string to Bitcoin transactions.
	BitcoinTxnsToBroadcast map[string]*BitcoinBroadcastInfo

	// A map of transactions that the user has sent.
	// TODO: Currently this only includes transactions that originated on the
	// SendUltra endpoint. We should augment this at some point to include
	// transactions from other sources. Right now it's too costly to trawl
	// the blockchain to find all transactions that belong to a user.
	// The map key is the TxID in Base58Check encoding.
	OutgoingTransactions map[string]*TransactionInfo

	// Maps <public key, tstamp> to decrypted text so we can show the user
	// her messages in decrypted form.
	MessageKeyToDecryptedText map[string]string
	// A mapping from user public keys to nicknames that the user has assigned
	// for these users.
	PublicKeyToNickname map[string]string
	// This list contains all of the contacts the user has messaged with ordered
	// such that the contact who messaged most recently is first.
	OrderedContactsWithMessages []*MessageContactResponse

	// Whether or not the miner is currently paused.
	IsMinerPaused bool
}

type OrderEntryResponse struct {
	OrderIDBase58Check string

	BuyerPublicKeyBase58Check string
	MerchantIDBase58Check     string

	PaymentAmountNanos  uint64
	ReferrerAmountNanos uint64
	RevenueNanos        uint64
	CommissionNanos     uint64
	AmountLockedNanos   uint64

	// Break the revenue into the revenue and the tip separately for
	// display purposes.
	MerchantTipRevenue        float64
	MerchantRevenueWithoutTip float64

	BuyerPricePerItem    float64
	MerchantPricePerItem float64

	Pos uint64

	BuyerMessage *BuyerMessage

	State string

	ReviewType string
	ReviewText string

	// May be encrypted
	RejectReason string

	MerchantScoreImpact float64

	// Whether or not the user in question is the buyer or the merchant.
	IsBuyer bool

	ConfirmedAtTstampSecs    int64
	LastModifiedAtTstampSecs int64
	MerchantEntry            *MerchantEntryResponse
	ListingMessage           *SingleListingResponse

	IsActionRequired bool
	PossibleActions  []string
}

type MessageEntryResponse struct {
	SenderPublicKeyBase58Check    string
	RecipientPublicKeyBase58Check string

	// We attempt to decrypt all messages using the user's private key. If we
	// can't then we set an error message instead.
	DecryptedText string

	TstampNanos uint64

	// Whether or not the user is the sender of the message.
	IsSender bool
}

type MessageContactResponse struct {
	PublicKeyBase58Check string
	// Can be set to empty string in which case the public key should be
	// used to identify them.
	Nickname string
	Messages []*MessageEntryResponse

	// The number of messages this user has read from this contact. This is
	// used to show a notification badge for unread messages.
	NumMessagesRead int64
}

type UtxoResponse struct {
	AmountNanos          uint64
	PublicKeyBase58Check string
	BlockHeight          uint32
	IsBlockReward        bool

	Pos uint64

	TxIDBase58Check string
	Index           uint32
}

// User ...
type User struct {
	Username string
	// The public key for the user is computed from the seed using the exact
	// paramters used to generate the BTC deposit address below. Because
	// of this, the Ultra private and public key pair is also the key
	// pair corresponding to the BTC address above. We store this same
	// key in base58 format above for convenience in communicating with
	// the FE.
	PublicKeyBase58Check string

	// The public key of the user who referred this user to the platform. If
	// no public key was set then we send the referrer commission to the
	// merchant as a tip.
	//
	// TODO: This is useful to have initially for bootstrapping but we should
	// remove it in the long run since it's easily gameable. In particular, someone
	// can just enter their own public key if they know what they're doing and once
	// this practice becomes widespread that will be a good time to get rid of this
	// logic.
	ReferrerPublicKeyBase58Check string

	// If the user is a merchant, then we will have a MerchantEntryResponse
	// set up for her.
	MerchantEntry *MerchantEntryResponse

	// If the user is a merchant, we may or may not have listings for her.
	Listings []*SingleListingResponse

	SeedInfo *SeedInfo

	LocalState *LocalState

	Orders []*OrderEntryResponse

	Utxos        []*UtxoResponse
	BalanceNanos uint64

	BitcoinAPIResponse *BlockCypherAPIFullAddressResponse
}

func (uu *User) String() string {
	return fmt.Sprintf("< Username: %s, Public Key: %s, Balance: %d >",
		uu.Username, uu.PublicKeyBase58Check, uu.BalanceNanos)
}

// LocalUserData ...
type LocalUserData struct {
	LoggedInUser *User   `json:"loggedInUser"`
	UserList     []*User `json:"userList"`
}

func (ll *LocalUserData) String() string {
	loggedInUserStrings := []string{}
	for _, user := range ll.UserList {
		loggedInUserStrings = append(loggedInUserStrings, user.String())
	}
	return fmt.Sprintf("\nLoggedInUser:\n\t%v \nUserList:\n\t%v", ll.LoggedInUser, strings.Join(loggedInUserStrings, "\n\t"))
}

// FEProductTypes ...
var FEProductTypes = map[string]ProductType{
	"delivered": ProductTypeDelivered,
	"instant":   ProductTypeInstant,
}

// DraftImage ...
type DraftImage struct {
	ID    uint64
	Image []byte
}

// Route ...
type Route struct {
	Name        string
	Method      []string
	Pattern     string
	HandlerFunc http.HandlerFunc
	CheckSecret bool
}

// FrontendRoutes ...

// Index ...
func (fes *FrontendServer) Index(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, "Your Ultra node is running!\n")
}

type TopCategory struct {
	Category string
	Count    int64
}

type TopCategoriesResponse struct {
	TopCategories []*TopCategory
}

// GetTopCategories ...
func (fes *FrontendServer) GetTopCategories(ww http.ResponseWriter, req *http.Request) {
	// All of the following locks are OK to acquire in precisely this order. Any
	// other order could result in deadlock.
	//
	// Grab the DataLock for reading.
	fes.DataLock.RLock()
	defer fes.DataLock.RUnlock()
	// Lock the blockchain for reading.
	fes.blockchain.ChainLock.RLock()
	defer fes.blockchain.ChainLock.RUnlock()
	// Lock the listing db for reading.
	fes.listingManager.ListingLock.RLock()
	defer fes.listingManager.ListingLock.RUnlock()

	categories, counts, err := DbGetListingTopCategories(
		fes.blockchain.db, MaxTopCategoriesToReturn)

	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetTopCategories: fetching top categories "+
			"from db: %v", err))
		return
	}

	res := TopCategoriesResponse{
		TopCategories: []*TopCategory{},
	}
	for index := range categories {
		// Strip the null terminator from the category returned.
		currentCategory := categories[index]
		if len(currentCategory) == 0 {
			continue
		}
		currentCategory = currentCategory[:len(currentCategory)-1]

		res.TopCategories = append(res.TopCategories, &TopCategory{
			Category: string(currentCategory),
			Count:    int64(counts[index]),
		})
	}

	if err := json.NewEncoder(ww).Encode(res); err != nil {
		glog.Error(errors.Wrapf(err, "GetTopCategories: Problem serializing object to "+
			"JSON: %v\n Request: %v", res, req))
	}
}

func (fes *FrontendServer) MerchantEntryToResponse(
	merchantEntry *MerchantEntry, merchantRank int64) *MerchantEntryResponse {

	ff, _ := new(big.Float).SetInt(merchantEntry.Stats.MerchantScore).Float64()
	return &MerchantEntryResponse{
		Username:              string(merchantEntry.Username),
		Description:           string(merchantEntry.Description),
		PublicKeyBase58Check:  PkToString(merchantEntry.PublicKey, fes.Params),
		MerchantIDBase58Check: PkToString(merchantEntry.merchantID[:], fes.Params),
		Stats:                 merchantEntry.Stats,
		TotalSalesNanos: merchantEntry.Stats.RevenueConfirmedNanos +
			merchantEntry.Stats.RevenueFulfilledNanos +
			merchantEntry.Stats.RevenueNeutralNanos +
			merchantEntry.Stats.RevenuePositiveNanos +
			merchantEntry.Stats.RevenueNegativeNanos,
		MerchantScore: ff,
		MerchantRank:  merchantRank,
	}
}

type MerchantEntryResponse struct {
	Username              string
	Description           string
	PublicKeyBase58Check  string
	MerchantIDBase58Check string
	Stats                 *MerchantStats
	TotalSalesNanos       uint64
	MerchantScore         float64
	MerchantRank          int64
}

// GetTopMerchantsResponse ...
type GetTopMerchantsResponse struct {
	TopMerchants         []*MerchantEntryResponse
	CurrentScoreMultiple float64
}

func (fes *FrontendServer) _getTopMerchantResponse() (*GetTopMerchantsResponse, error) {
	// Use the merchant index from the listing table (DbGetListingTopMerchants rather than
	// DbGetBlockchainTopMerchants) because those are the merchants for whom we've actually
	// indexed listings (though the two shouldn't differ substantially in general).
	topMerchantIDs, topMerchantScores, topMerchantEntries, err := DbGetListingTopMerchants(
		fes.blockchain.db, fes.Params.MaxMerchantsToIndex, false /*noMerchantEntries*/)
	if err != nil {
		return nil, errors.Wrapf(err, "_getTopMerchantResponse: Problem fetching top "+
			"merchants from db: ")
	}
	_, _ = topMerchantIDs, topMerchantScores

	// Compute the score multiple so we can return it.
	halfLifeBlocks := BlocksPerDuration(
		fes.Params.MerchantScoreHalfLife, fes.Params.TimeBetweenBlocks)
	blockTip := fes.blockchain.blockTip()
	scoreMultipleBigint := ComputeImpactMultiple(blockTip.Height, halfLifeBlocks)
	scoreMultipleFloat, _ := new(big.Float).SetInt(scoreMultipleBigint).Float64()

	res := GetTopMerchantsResponse{
		TopMerchants:         []*MerchantEntryResponse{},
		CurrentScoreMultiple: scoreMultipleFloat,
	}
	for ii, merchantEntry := range topMerchantEntries {
		res.TopMerchants = append(
			res.TopMerchants,
			fes.MerchantEntryToResponse(merchantEntry, int64(ii)))
	}

	return &res, nil
}

// GetTopMerchants ...
func (fes *FrontendServer) GetTopMerchants(ww http.ResponseWriter, rr *http.Request) {
	// All of the following locks are OK to acquire in precisely this order. Any
	// other order could result in deadlock.
	//
	// Grab the DataLock for reading.
	fes.DataLock.RLock()
	defer fes.DataLock.RUnlock()
	// Lock the blockchain for reading.
	fes.blockchain.ChainLock.RLock()
	defer fes.blockchain.ChainLock.RUnlock()
	// Lock the listing db for reading.
	fes.listingManager.ListingLock.RLock()
	defer fes.listingManager.ListingLock.RUnlock()

	res, err := fes._getTopMerchantResponse()
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetTopMerchants: Problem getting top merchants: "))
		return
	}

	if err := json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetTopMerchants: Problem serializing object to "+
			"JSON: %v\n Request: %v, Error: %v", res, rr, err))
		return
	}
}

type GetExchangeRateResponse struct {
	SatoshisPerUltraExchangeRate uint64
	NanosLeftInTranche           uint64
}

func (fes *FrontendServer) GetExchangeRate(ww http.ResponseWriter, rr *http.Request) {
	// Get the nanos left in the tranche and the current rate of exchange.
	nanosLeftInTranche, satoshisPerUnit := GetSatoshisPerUnitExchangeRate(fes.blockchain.db)

	res := &GetExchangeRateResponse{
		SatoshisPerUltraExchangeRate: satoshisPerUnit,
		NanosLeftInTranche:           nanosLeftInTranche,
	}

	if err := json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetExchangeRate: Problem serializing object to "+
			"JSON: %v\n Request: %v, Error: %v", res, rr, err))
		return
	}
}

// GetUsersResponse ...
type GetUsersResponse struct {
	UserData                 *LocalUserData `json:"userData"`
	DefaultFeeRateNanosPerKB uint64
}

// GetUsers ...
func (fes *FrontendServer) GetUsers(ww http.ResponseWriter, rr *http.Request) {
	// We lock the whole function since we access the UserData directly.
	fes.DataLock.Lock()
	defer fes.DataLock.Unlock()

	// Compute a default fee rate.
	// TODO: The median threshold should be a flag.
	defaultFeeRateNanosPerKB := fes.blockchain.EstimateDefaultFeeRateNanosPerKB(
		.1, fes.MinFeeRateNanosPerKB)

	// Update all user information before returning.
	fes.updateUsers()
	res := GetUsersResponse{
		UserData:                 fes.UserData,
		DefaultFeeRateNanosPerKB: defaultFeeRateNanosPerKB,
	}

	if err := json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetUsers: Problem serializing object to "+
			"JSON: %v\n Request: %v, Error: %v", res, rr, err))
		return
	}
}

func _listingsForListingIDs(handle *badger.DB, listingIDsArg []ListingID) []*MsgUltranetListing {
	listingMessages := []*MsgUltranetListing{}
	for _, listingID := range listingIDsArg {
		msg := DbGetListingMessage(handle, &listingID.MerchantID, listingID.ListingIndex)
		if msg != nil {
			listingMessages = append(listingMessages, msg)
		}
	}
	return listingMessages
}

func _getListingIDsSortedByScore(listingScoreByID map[ListingID]*big.Int) (_listingIDsSorted []ListingID) {
	// Now that we've organized all of the listings by an exponentially-decaying
	// merchant score, organize them into a sorted slice.
	listingIDsSorted := []ListingID{}
	for listingID := range listingScoreByID {
		listingIDsSorted = append(listingIDsSorted, listingID)
	}
	sort.Slice(listingIDsSorted, func(ii, jj int) bool {
		iiMerchantScore, _ := listingScoreByID[listingIDsSorted[ii]]
		jjMerchantScore, _ := listingScoreByID[listingIDsSorted[jj]]
		return (iiMerchantScore.Cmp(jjMerchantScore) > 0)
	})
	return listingIDsSorted
}

func _sortByMerchantScore(listingIDsArg []ListingID, merchantScoreByID map[BlockHash]*big.Int) []ListingID {
	// For each ListingID, set its score equal to that of the corresponding
	// MerchantID with an exponential decay. Add the mapping to the
	// listingScoreByID map.
	//
	// For each MerchantID, track the number of listings we have for this MerchantID
	// already. For each one we add, we exponentially decay the score so that a
	// dominant merchant won't just completely eclipse listings from less dominant
	// merchants if they have many listings in the same category.
	listingScoreByID := make(map[ListingID]*big.Int)
	numListingsPerMerchantID := make(map[BlockHash]uint64)
	for _, listingID := range listingIDsArg {
		numListings, exists := numListingsPerMerchantID[listingID.MerchantID]
		if !exists {
			numListings = 0
		}
		numListingsPerMerchantID[listingID.MerchantID] = numListings + 1

		merchantScoreForListing, exists := merchantScoreByID[listingID.MerchantID]
		if !exists {
			// If this happens, log an error but don't stop the show.
			glog.Error("Found listing with ListingID %v that doesn't have " +
				"a score for its merchant; this should never happen")
			listingScoreByID[listingID] = big.NewInt(0)
			continue
		}
		listingScoreByID[listingID] = _adjustScore(merchantScoreForListing, numListings)
	}

	// Get the ListingIDs sorted by their score.
	return _getListingIDsSortedByScore(listingScoreByID)
}

func _findCategoryListings(
	handle *badger.DB, searchQuery string, merchantScoreByID map[BlockHash]*big.Int) ([]*MsgUltranetListing, error) {

	categoryKeywords, _ := _computeKeywordsFromTextWithEscapingAndNullTermination(
		[]byte(searchQuery), CategoryKeyword)
	// Generally, there should just be one category keyword since the category
	// isn't split on whitespace but iterate in a loop nonetheless.
	uniqueListingIDs := make(map[ListingID]bool)
	for _, categoryKW := range categoryKeywords {
		// For each category, find the merchantIDs and listingIndexes that match
		// the category and add them to the map of unique listing ids.
		merchantIDs, listingIndexes, _, err := DbGetListingIDsContainingKeyword(
			handle, CategoryKeyword, categoryKW)
		if err != nil {
			return nil, errors.Wrapf(err, "GetListings: Problem looking up listings "+
				"for CategoryKeyword %s", string(categoryKW))
		}

		for ii := range merchantIDs {
			listingID := ListingID{
				MerchantID:   *merchantIDs[ii],
				ListingIndex: listingIndexes[ii],
			}
			uniqueListingIDs[listingID] = true
		}
	}
	// Now that we have all the ListingIDs, sort them according to an exponentially
	// decayed merchant score.

	// Gather the ListingIDs up into a slice.
	listingIDSlice := []ListingID{}
	for listingID := range uniqueListingIDs {
		listingIDSlice = append(listingIDSlice, listingID)
	}

	// Sort the listings based on an exponentially decayed merchant score.
	sortedListingIDs := _sortByMerchantScore(listingIDSlice, merchantScoreByID)

	// Get the listings for the ids passed.
	return _listingsForListingIDs(handle, sortedListingIDs), nil
}

func _augmentListingsFound(handle *badger.DB, listingScoreByID map[ListingID]uint64, searchQuery string, kwType KeywordType) error {
	// For each title match a listing gets ten points. For each body match it gets
	// one point.
	scoreIncreasePerMatch := uint64(10)
	if kwType == BodyKeyword {
		scoreIncreasePerMatch = 1
	}

	// Get the keywords for the query.
	keywords, _ := _computeKeywordsFromTextWithEscapingAndNullTermination(
		[]byte(searchQuery), kwType)

	// For each keyword, find all the listings that match. For each listing
	// that matches, add scoreIncreasePerMatch to its score.
	for _, kw := range keywords {
		// Get the ListingIDs that match this keyword
		merchantIDs, listingIndexes, _, err := DbGetListingIDsContainingKeyword(handle, kwType, kw)
		if err != nil {
			return errors.Wrapf(err, "GetListings: Problem looking up listings "+
				"matching keyword %s", string(kw))
		}

		// For each ListingID we found, increase its score by scoreIncreasePerMatch.
		for ii := range merchantIDs {
			// Construct the ListingID
			listingID := ListingID{
				MerchantID:   *merchantIDs[ii],
				ListingIndex: listingIndexes[ii],
			}
			// Update the score for the listing.
			listingScore, exists := listingScoreByID[listingID]
			if !exists {
				listingScore = 0
			}
			listingScore += scoreIncreasePerMatch
			listingScoreByID[listingID] = listingScore
		}
	}

	return nil
}

func _adjustScore(merchantScore *big.Int, listingNum uint64) *big.Int {
	multiplier := big.NewInt(0).Exp(big.NewInt(10), big.NewInt(int64(listingNum)), nil)
	// Divide scores if they're positive.
	listingScore := big.NewInt(0).Div(merchantScore, multiplier)
	// Multiply scores if they're negative.
	if merchantScore.Cmp(big.NewInt(0)) < 0 {
		listingScore = big.NewInt(0).Mul(merchantScore, multiplier)
	}
	return listingScore
}

// DataLock, ChainLock, and ListingLock must all be held for reading
// before calling this funcion.
func _findListingsForCriteria(
	handle *badger.DB, params *UltranetParams, merchantIDBase58Check string,
	listingIndex int, searchQuery string, categoryQuery bool) ([]*MsgUltranetListing, error) {

	// If a merchantID is present, that takes priority over a searchQuery being present.
	// The searchQuery will be ignored in this case.
	if merchantIDBase58Check != "" {
		// Convert the merchantID to bytes
		merchantIDBytes, _, err := Base58CheckDecode(merchantIDBase58Check)
		if err != nil {
			return nil, errors.Wrapf(err, "GetListings: Problem converting MerchantID %s to bytes: ", merchantIDBase58Check)
		}
		merchantID := &BlockHash{}
		copy(merchantID[:], merchantIDBytes[:])

		// If the listingIndex is negative, return all listings for this merchant.
		// Otherwise, return a specific listing.
		if listingIndex < 0 {
			_, listings, err := DbGetListingsForMerchantID(handle, merchantID, true /*fetchListings*/)
			if err != nil {
				return nil, errors.Wrapf(err, "GetListings: Problem fetching listings for MerchantID %v: ", merchantID)
			}
			// Sort the listings by their timestamp before returning them.
			sort.Slice(listings, func(ii, jj int) bool {
				return listings[ii].TstampSecs > listings[jj].TstampSecs
			})
			return listings, nil
		}
		listingMessage := DbGetListingMessage(handle, merchantID, uint32(listingIndex))
		if listingMessage != nil {
			return []*MsgUltranetListing{listingMessage}, nil
		}

		// If we had a merchantID but haven't returned by the end of this block
		// then we can assume no listings were found for this criteria.
		return nil, nil
	}

	// Regardless of what the query is, we'll need the merchantIDs organized by
	// their score.
	merchantScoreByID := make(map[BlockHash]*big.Int)
	topMerchantIDs, topMerchantScores, _, err := DbGetListingTopMerchants(
		handle, params.MaxMerchantsToIndex, false /*noMerchantEntries*/)
	if err != nil {
		return nil, errors.Wrapf(err, "GetListings: Problem looking up top merchants")
	}
	for ii := range topMerchantIDs {
		merchantScoreByID[*topMerchantIDs[ii]] = topMerchantScores[ii]
	}
	// Compute a slice containing the merchantIDs sorted by their score.
	merchantIDsSorted := []*BlockHash{}
	for merchantIDIter := range merchantScoreByID {
		merchantID := &BlockHash{}
		copy(merchantID[:], merchantIDIter[:])
		merchantIDsSorted = append(merchantIDsSorted, merchantID)
	}
	sort.Slice(merchantIDsSorted, func(ii, jj int) bool {
		iiMerchantScore, _ := merchantScoreByID[*merchantIDsSorted[ii]]
		jjMerchantScore, _ := merchantScoreByID[*merchantIDsSorted[jj]]
		return (iiMerchantScore.Cmp(jjMerchantScore) > 0)
	})

	// If we get here without a searchQuery set, then we return some listings from
	// the top merchants as "featured listings".
	if searchQuery == "" {
		listingScoreByID := make(map[ListingID]*big.Int)
		for _, merchantID := range merchantIDsSorted {
			listingIndices, _, err := DbGetListingsForMerchantID(handle, merchantID, false /*fetchListings*/)
			if err != nil {
				return nil, errors.Wrapf(err, "GetListings: Problem looking up listings for MerchantID %v", merchantID)
			}
			// Shuffle the listingIndices slice for fun. We're allowed to have fun, right?
			mathrand.Seed(time.Now().UnixNano())
			mathrand.Shuffle(len(listingIndices), func(i, j int) {
				listingIndices[i], listingIndices[j] = listingIndices[j], listingIndices[i]
			})
			// For each randomly-selected listing, give it an exponentially decaying score
			// that is a function of the merchant's overall score. This way we basically have
			// one listing from each of the top merchants being shown.
			merchantScore, _ := merchantScoreByID[*merchantID]
			for ii, listingIndex := range listingIndices {
				listingID := ListingID{
					MerchantID:   *merchantID,
					ListingIndex: listingIndex,
				}
				listingScoreByID[listingID] = _adjustScore(merchantScore, uint64(ii))
			}
		}

		// Get the ListingIDs sorted by their score.
		listingIDsSorted := _getListingIDsSortedByScore(listingScoreByID)

		// Get the listings for the ids passed.
		return _listingsForListingIDs(handle, listingIDsSorted), nil
	}

	// If we're here it means we have a searchQuery that is not the empty string
	// and so we are actually querying for listings that match the query.

	// If the query is based on a category, we do a simpler return of all listings
	// that exactly match the category.
	if categoryQuery {
		return _findCategoryListings(handle, searchQuery, merchantScoreByID)
	}

	// If we're not doing a category query, we find all listings that have
	// matches in their title and body (note that the body includes a split
	// version of the category).
	//
	// Because we want a title match to count a lot more than a body match,
	// we organize all the matching listings by a score, which corresponds to
	// ten points per title keyword matched and one point per body keyword
	// match. Then we sort the listings by this score, breaking ties using
	// the merchant score.
	listingScoreByID := make(map[ListingID]uint64)
	err = _augmentListingsFound(handle, listingScoreByID, searchQuery, TitleKeyword)
	if err != nil {
		return nil, errors.Wrapf(err, "Problem finding listings with title match: ")
	}
	err = _augmentListingsFound(handle, listingScoreByID, searchQuery, BodyKeyword)
	if err != nil {
		return nil, errors.Wrapf(err, "Problem finding body with title match: ")
	}

	// At this point, listingScoreByID should contain all listings with some kind
	// of match and their corresponding keyword points. Create and sort a slice of the
	// ListingIDs by this score.
	listingIDsSortedByKeywordScore := []ListingID{}
	for listingID := range listingScoreByID {
		listingIDsSortedByKeywordScore = append(listingIDsSortedByKeywordScore, listingID)
	}
	sort.Slice(listingIDsSortedByKeywordScore, func(ii, jj int) bool {
		iiListingScore, _ := listingScoreByID[listingIDsSortedByKeywordScore[ii]]
		jjListingScore, _ := listingScoreByID[listingIDsSortedByKeywordScore[jj]]

		return iiListingScore > jjListingScore
	})
	// Once listings are sorted by their keyword score, we do one more pass to sort
	// listings that have the same keyword score by the score of their merchant. We
	// do this in the same way we do it for categories, where merchant scores are
	// exponentially decayed for each listing within a particular listing score group.
	// This ensures that if a merchant submits many duplicate listings that match
	// a keyword, we will still show the user a variety of listings from multiple
	// merchants in the top results.
	if len(listingIDsSortedByKeywordScore) == 0 {
		return []*MsgUltranetListing{}, nil
	}
	startIndex := 0
	currentIndex := 1
	listingIDsWithVariety := []ListingID{}
	for {
		// The current group we're processing consists of all the elements from the
		// start index to the current index.
		currentGroup := listingIDsSortedByKeywordScore[startIndex:currentIndex]

		// If we're at the end then process the listings in the current group and break.
		if currentIndex == len(listingIDsSortedByKeywordScore) {
			listingIDsWithVariety = append(
				listingIDsWithVariety,
				_sortByMerchantScore(currentGroup, merchantScoreByID)...)
			break
		}

		// If the score at the current index isn't equal to the current score we're
		// processing then process the group. Adjust the start index accodringly.
		startElem := listingIDsSortedByKeywordScore[startIndex]
		startElemScore, _ := listingScoreByID[startElem]
		currentElem := listingIDsSortedByKeywordScore[currentIndex]
		currentElemScore, _ := listingScoreByID[currentElem]
		if startElemScore != currentElemScore {
			// Process the current group, adding it to our final output slice.
			listingIDsWithVariety = append(
				listingIDsWithVariety,
				_sortByMerchantScore(currentGroup, merchantScoreByID)...)

			// Updating the start index means we will no longer consider the
			// elements we just processed above.
			startIndex = currentIndex
		}

		currentIndex++
	}

	return _listingsForListingIDs(handle, listingIDsWithVariety), nil
}

// GetListingsRequest ...
type GetListingsRequest struct {
	ListingIndex int
	SearchQuery  string

	// The type of query being performed.
	QueryType string

	AdjustPriceForCommissions bool
}

type SingleListingResponse struct {
	MerchantIDBase58Check string
	PublicKeyBase58Check  string

	TstampSecs uint32
	Deleted    bool

	ListingIndex int32

	Title             string
	Body              string
	Category          string
	PricePerUnitNanos uint64
	UnitNameSingular  string
	UnitNamePlural    string
	MinQuantity       uint64
	MaxQuantity       uint64
	ProductType       string
	RequiredFields    []string
	OptionalFields    []string
	TipComment        string

	ShipsTo   string
	ShipsFrom string
	NumImages int

	MerchantEntry *MerchantEntryResponse
}

// GetListingsResponse ...
type GetListingsResponse struct {
	Listings []*SingleListingResponse
}

// fetchMerchantEntries makes it so that each listing has the full MerchantEntry
// corresponding to its MerchantIDBase58Check. Note that the reason it is an
// option is because fetching merchant entries is expensive and unnecessary in
// certain circumstances.
func (fes *FrontendServer) _getListingResponsesForCriteria(
	merchantIDFound string, listingIndex int, searchQuery string, categoryQuery bool,
	fetchMerchantEntries bool, adjustPriceForCommissions bool) (
	[]*SingleListingResponse, error) {

	// We should have filled in a merchantID at this point if it's possible so now
	// execute the query given the full criteria.
	// If we have a merchantID at this point, the lookup is restriced to listings
	// just for this merchant.
	listings, err := _findListingsForCriteria(fes.blockchain.db, fes.Params, merchantIDFound,
		listingIndex, searchQuery, categoryQuery)
	if err != nil {
		return nil, fmt.Errorf("GetListings: Problem executing search query: %v", err)
	}

	// Get the top merchants so we can attach them to the listings.
	topMerchantMapp := make(map[string]*MerchantEntryResponse)
	if fetchMerchantEntries {
		topMerchantRes, err := fes._getTopMerchantResponse()
		if err != nil {
			return nil, fmt.Errorf("GetListings: Problem getting top merchants "+
				"to attach to listings: %v", err)
		}
		// Organize them into a map by their merchantID
		for _, merchant := range topMerchantRes.TopMerchants {
			topMerchantMapp[merchant.MerchantIDBase58Check] = merchant
		}
	}

	listingsRet := []*SingleListingResponse{}
	for _, listingMessage := range listings {
		requiredFields := []string{}
		optionalFields := []string{}
		for _, rf := range listingMessage.RequiredFields {
			if rf.IsRequired {
				requiredFields = append(requiredFields, string(rf.Label))
			} else {
				optionalFields = append(optionalFields, string(rf.Label))
			}
		}

		// Look up the MerchantEntryResponse for this listing. If one doesn't exist
		// then log an error and continue.
		merchantIDBase58Check := PkToString(listingMessage.MerchantID[:], fes.Params)
		var merchantEntryRes *MerchantEntryResponse
		if fetchMerchantEntries {
			merchantEntryExists := false
			merchantEntryRes, merchantEntryExists = topMerchantMapp[merchantIDBase58Check]
			if !merchantEntryExists {
				glog.Errorf("GetListings: Missing MerchantEntry for listing: (%v, %d)",
					merchantIDBase58Check, listingMessage.ListingIndex)
				continue
			}
		}

		// Only add the commissions if it was requested in the arguments.
		var commissionsNanos uint64
		if adjustPriceForCommissions {
			// Here we compute the sum of the normal commissions plus the amount that
			// should go to the referrer. The referrer amount will either go to the
			// referrer if the user has one set or else it will be sent to the merchant
			// as a tip.
			//
			// TODO: Remove this referrer logic after the product has matured.
			var err error
			commissionsNanos, err = _computeCommissionsFromPriceNanos(
				listingMessage.PricePerUnitNanos, fes.Params.CommissionBasisPoints+fes.Params.ReferrerCommissionBasisPoints)
			if err != nil {
				return nil, fmt.Errorf("GetListings: Problem computing "+
					"commissions from price %d: %v", listingMessage.PricePerUnitNanos, err)
			}
		}

		listingsRet = append(listingsRet, &SingleListingResponse{
			MerchantIDBase58Check: merchantIDBase58Check,
			PublicKeyBase58Check:  PkToString(listingMessage.PublicKey, fes.Params),

			TstampSecs: listingMessage.TstampSecs,
			Deleted:    listingMessage.Deleted,

			ListingIndex: int32(listingMessage.ListingIndex),

			Title:    string(listingMessage.Title),
			Body:     string(listingMessage.Body),
			Category: string(listingMessage.Category),
			// Potentially add in the commissions so the user sees the "all-in"
			// price per unit and pays the merchant accordingly.
			PricePerUnitNanos: listingMessage.PricePerUnitNanos + commissionsNanos,
			UnitNameSingular:  string(listingMessage.UnitNameSingular),
			UnitNamePlural:    string(listingMessage.UnitNamePlural),
			MinQuantity:       listingMessage.MinQuantity,
			MaxQuantity:       listingMessage.MaxQuantity,
			ProductType:       listingMessage.ProductType.String(),
			RequiredFields:    requiredFields,
			OptionalFields:    optionalFields,
			TipComment:        string(listingMessage.TipComment),

			ShipsTo:   string(listingMessage.ShipsTo),
			ShipsFrom: string(listingMessage.ShipsFrom),
			NumImages: len(listingMessage.ListingImages),

			MerchantEntry: merchantEntryRes,
		})
	}

	return listingsRet, nil
}

// GetListings ...
func (fes *FrontendServer) GetListings(ww http.ResponseWriter, req *http.Request) {
	// All of the following locks are OK to acquire in precisely this order. Any
	// other order could result in deadlock.
	//
	// Grab the DataLock for reading.
	fes.DataLock.RLock()
	defer fes.DataLock.RUnlock()
	// Lock the blockchain for reading.
	fes.blockchain.ChainLock.RLock()
	defer fes.blockchain.ChainLock.RUnlock()
	// Lock the listing db for reading.
	fes.listingManager.ListingLock.RLock()
	defer fes.listingManager.ListingLock.RUnlock()

	// If the node is still syncing return an error so that an alternative node can be
	// used to fetch listings.
	if fes.blockchain.isSyncing() {
		_AddBadRequestError(ww, fmt.Sprintf("GetListings: Node cannot serve listings "+
			"because it is in state %v", fes.blockchain.chainState()))
		return
	}

	// Decode the request data.
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	getListingsRequest := GetListingsRequest{}
	if err := decoder.Decode(&getListingsRequest); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetListings: Problem parsing request body: %v", err))
		return
	}

	queryTypes := make(map[string]bool)
	queryTypes["merchant_id"] = true
	queryTypes["username"] = true
	queryTypes["public_key"] = true
	queryTypes["category"] = true
	//queryTypes["title"] = true
	//queryTypes["body"] = true
	queryTypes["title_and_body"] = true
	queryTypes["single_listing"] = true
	queryTypes["featured"] = true

	if _, allowedQuery := queryTypes[getListingsRequest.QueryType]; !allowedQuery {
		_AddBadRequestError(ww, fmt.Sprintf("GetListings: QueryType %s is not allowed. "+
			"Allowed query types: %v", getListingsRequest.QueryType, queryTypes))
		return
	}

	var listingsRet []*SingleListingResponse
	var err error
	switch getListingsRequest.QueryType {
	case "merchant_id":
		if getListingsRequest.SearchQuery == "" {
			_AddBadRequestError(ww, fmt.Sprintf("MerchantIDBase58Check is required with "+
				"queryType merchant_id"))
			return
		}
		listingsRet, err = fes._getListingResponsesForCriteria(
			getListingsRequest.SearchQuery,
			-1,                            /*listingIndex: -1 => fetch all listings for this merchant*/
			"",                            /*searchQuery: empty => fetch all listings for this merchant*/
			false /*categoryQuery*/, true, /*fetchMerchantEntries*/
			getListingsRequest.AdjustPriceForCommissions /*adjustPriceForCommissions*/)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("GetListings: Problem fetching listings "+
				"with criteria: %v", err))
			return
		}

	case "username":
		// In this case we use the username to look up a MerchantID and use the latter
		// to fetch listings.
		if getListingsRequest.SearchQuery == "" {
			_AddBadRequestError(ww, fmt.Sprintf("Username is required with "+
				"queryType usename"))
			return
		}
		// Find the merchantID. If it's nil, return an error.

		usernames, hashes, merchants, err := DbGetAllUsernameMerchantIDMappings(fes.blockchain.db)
		fmt.Println(len(usernames), len(hashes), len(merchants), err)

		merchantID := GetMerchantIDForUsername(fes.blockchain.db, []byte(getListingsRequest.SearchQuery))
		if merchantID == nil {
			_AddBadRequestError(ww, fmt.Sprintf("GetListings: Could not find merchantID "+
				"for username %s", getListingsRequest.SearchQuery))
			return
		}
		// Convert the MerchantID to string to compare it to what was passed in.
		merchantIDBase58Check := Base58CheckEncode(merchantID[:], false /*isPrivate*/, fes.Params)
		// Do the query using the MerchantID.
		listingsRet, err = fes._getListingResponsesForCriteria(
			merchantIDBase58Check,
			-1,                            /*listingIndex: -1 => fetch all listings for this username*/
			"",                            /*searchQuery: empty => fetch all listings for this username*/
			false /*categoryQuery*/, true, /*fetchMerchantEntries*/
			getListingsRequest.AdjustPriceForCommissions /*adjustPriceForCommissions*/)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("GetListings: Problem fetching listings "+
				"with criteria: %v", err))
			return
		}

	case "public_key":
		// In this case we use the public key to look up a MerchantID and use the latter
		// to fetch listings.
		if getListingsRequest.SearchQuery == "" {
			_AddBadRequestError(ww, fmt.Sprintf("PublicKeyBase58Check is required with "+
				"queryType public_key"))
			return
		}
		// Convert the public key to bytes
		publicKeyBytes, _, err := Base58CheckDecode(getListingsRequest.SearchQuery)
		if err != nil || len(publicKeyBytes) != btcec.PubKeyBytesLenCompressed {
			_AddBadRequestError(ww, fmt.Sprintf("GetListings: Problem computing PublicKey bytes from base58 %+v", err))
			return
		}
		// Find the merchantID. If it's nil, return an error.
		merchantID := DbGetMerchantIDForPubKey(fes.blockchain.db, publicKeyBytes)
		if merchantID == nil {
			_AddBadRequestError(ww, fmt.Sprintf("GetListings: Could not find merchantID "+
				"for public key %s", getListingsRequest.SearchQuery))
			return
		}
		// Convert the MerchantID to string to compare it to what was passed in.
		merchantIDBase58Check := Base58CheckEncode(merchantID[:], false /*isPrivate*/, fes.Params)
		// Do the query using the MerchantID.
		listingsRet, err = fes._getListingResponsesForCriteria(
			merchantIDBase58Check,
			-1,                            /*listingIndex: -1 => fetch all listings for this public key*/
			"",                            /*searchQuery: empty => fetch all listings for this public key*/
			false /*categoryQuery*/, true, /*fetchMerchantEntries*/
			getListingsRequest.AdjustPriceForCommissions /*adjustPriceForCommissions*/)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("GetListings: Problem fetching listings "+
				"with criteria: %v", err))
			return
		}

	case "category":
		// In this case the query is straightforward. We simply use the category
		// to do the lookup.
		listingsRet, err = fes._getListingResponsesForCriteria(
			"",
			-1,                             /*listingIndex: -1 => fetch all listings for this category*/
			getListingsRequest.SearchQuery, /*searchQuery: this is the category we're querying*/
			true,                           /*categoryQuery: true because this is a category query*/
			true,                           /*fetchMerchantEntries*/
			getListingsRequest.AdjustPriceForCommissions /*adjustPriceForCommissions*/)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("GetListings: Problem fetching listings "+
				"with criteria: %v", err))
			return
		}

	case "title_and_body":
		// In this case the query is straightforward. We simply use the category
		// to do the lookup.
		listingsRet, err = fes._getListingResponsesForCriteria(
			"",                             /*merchantIDBase58Check: empty => fetch all listings that match the query*/
			-1,                             /*listingIndex: -1 => fetch all listings that match*/
			getListingsRequest.SearchQuery, /*searchQuery: this is the query we're using*/
			false,                          /*categoryQuery: false because this queries the title+body index*/
			true,                           /*fetchMerchantEntries*/
			getListingsRequest.AdjustPriceForCommissions /*adjustPriceForCommissions*/)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("GetListings: Problem fetching listings "+
				"with criteria: %v", err))
			return
		}

	case "single_listing":
		if getListingsRequest.SearchQuery == "" {
			_AddBadRequestError(ww, fmt.Sprintf("MerchantIDBase58Check is required with "+
				"queryType single_listing"))
			return
		}
		if getListingsRequest.ListingIndex < 0 ||
			uint32(getListingsRequest.ListingIndex) >= fes.Params.MaxListingsPerMerchant {

			_AddBadRequestError(ww, fmt.Sprintf("ListingIndex must be >= 0 and <= %d when "+
				"querying single_listing", fes.Params.MaxListingsPerMerchant))
			return
		}

		// In this case the query is straightforward. We simply use the category
		// to do the lookup.
		listingsRet, err = fes._getListingResponsesForCriteria(
			getListingsRequest.SearchQuery,
			getListingsRequest.ListingIndex,
			"",    /*searchQuery: empty because we're querying a specific listing*/
			false, /*categoryQuery: false because this queries for a specific listing*/
			true,  /*fetchMerchantEntries*/
			getListingsRequest.AdjustPriceForCommissions /*adjustPriceForCommissions*/)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("GetListings: Problem fetching listings "+
				"with criteria: %v", err))
			return
		}

	case "featured":
		// In this case the query is straightforward. We simply use the category
		// to do the lookup.
		listingsRet, err = fes._getListingResponsesForCriteria(
			"",    /*merchantIDBase58Check: empty because we're querying featured listings*/
			-1,    /*listingIndex: empty because we're querying featured listings*/
			"",    /*searchQuery: empty because we're querying featured listings*/
			false, /*categoryQuery: false because this queries for featured listings*/
			true,  /*fetchMerchantEntries*/
			getListingsRequest.AdjustPriceForCommissions /*adjustPriceForCommissions*/)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("GetListings: Problem fetching listings "+
				"with criteria: %v", err))
			return
		}

	default:
		_AddBadRequestError(ww, fmt.Sprintf("GetListings: QueryType %s is allowed "+
			"but not implemented; this should never happen", getListingsRequest.QueryType))
		return
	}

	res := GetListingsResponse{}
	res.Listings = listingsRet
	if err := json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetBlocks: Problem encoding response as JSON: %v", err))
		return
	}
}

// GetBlocksRequest ...
type GetBlocksRequest struct {
	StartBlockHeight int64 `json:"start_block_height"`
	EndBlockHeight   int64 `json:"end_block_height"`
}

// GetBlocksResponse ...
type GetBlocksResponse struct {
	Blocks []*MsgUltranetBlock `json:"blocks"`
}

// GetBlocks ...
func (fes *FrontendServer) GetBlocks(ww http.ResponseWriter, req *http.Request) {
	// Get the start and end index.
	startBlockHeightParams, startBlockHeightExists := req.URL.Query()[StartBlockHeightParam]
	startBlockHeightStr := "0"
	if startBlockHeightExists {
		startBlockHeightStr = startBlockHeightParams[0]
	}
	startBlockHeight, err := strconv.Atoi(startBlockHeightStr)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetBlocks: Problem parsing %s value: %s",
			StartBlockHeightParam, startBlockHeightStr))
		return
	}
	if startBlockHeight < 0 {
		startBlockHeight = 0
	}
	endBlockHeightParams, endBlockHeightExists := req.URL.Query()[EndBlockHeightParam]
	endBlockHeightStr := "-1"
	if endBlockHeightExists {
		endBlockHeightStr = endBlockHeightParams[0]
	}
	endBlockHeight, err := strconv.Atoi(endBlockHeightStr)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetBlocks: Problem parsing %s value: %s",
			EndBlockHeightParam, endBlockHeightStr))
		return
	}

	// Lock the blockchain for reading.
	fes.blockchain.ChainLock.RLock()
	defer fes.blockchain.ChainLock.RUnlock()

	mainChainBlocks := fes.blockchain.bestChainn
	if endBlockHeight < 0 || endBlockHeight > len(mainChainBlocks) {
		endBlockHeight = len(mainChainBlocks)
	}

	blockNodes := []*BlockNode{}
	if len(mainChainBlocks) > 0 && startBlockHeight < endBlockHeight {
		blockNodes = mainChainBlocks[startBlockHeight:endBlockHeight]
	}

	blocks := []*MsgUltranetBlock{}
	for _, nn := range blockNodes {
		blk, err := GetBlock(nn.Hash, fes.blockchain.db)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("GetBlocks: Problem looking up block %v from db: %v", nn, err))
			return
		}
		blocks = append(blocks, blk)
	}

	res := GetBlocksResponse{
		Blocks: blocks,
	}

	if err := json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetBlocks: Problem encoding response as JSON: %v", err))
		return
	}
}

func _AddBadRequestError(ww http.ResponseWriter, errorString string) {
	glog.Error(errorString)
	ww.WriteHeader(http.StatusBadRequest)
	json.NewEncoder(ww).Encode(struct {
		Error string `json:"error"`
	}{Error: errorString})
}

type PublishListingRequest struct {
	PublicKeyBase58Check string `json:"publicKeyBase58Check"`

	TstampSecs uint32 `json:"tstampSecs"`
	Deleted    bool

	ListingIndex int32 `json:"listingIndex"`

	Title             string `json:"title"`
	Body              string `json:"body"`
	Category          string `json:"category"`
	PricePerUnitNanos uint64 `json:"pricePerUnitNanos"`
	UnitNameSingular  string `json:"unitNameSingular"`
	UnitNamePlural    string `json:"unitNamePlural"`
	MinQuantity       uint64 `json:"minQuantity"`
	MaxQuantity       uint64 `json:"maxQuantity"`
	ProductType       string `json:"productType"`
	RequiredFields    []string
	OptionalFields    []string
	TipComment        string `json:"tipComment"`

	ShipsTo   string `json:"shipsTo"`
	ShipsFrom string `json:"shipsFrom"`

	// The password is just used when creating a listing to produce a signature
	// using the logged in user's private key. If the password is already present
	// in our PublicKeyToPasswordMap for this user then it can be omitted from the
	// request.
	Password string
}

type PublishListingResponse struct {
}

// PublishListing ...
func (fes *FrontendServer) PublishListing(ww http.ResponseWriter, req *http.Request) {

	// Note that a subsequent call to ProcessListing will grab a lock internal to
	// the ListingManager as well, but that this should be fine.

	// Decode the request data.
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	listingRequest := PublishListingRequest{}
	if err := decoder.Decode(&listingRequest); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("PublishListing: Problem parsing request body: %v", err))
		return
	}

	// Ensure that a public key is provided in the request.
	if len(listingRequest.PublicKeyBase58Check) == 0 {
		_AddBadRequestError(ww, fmt.Sprintf("PublishListing: Public key is missing from request"))
		return
	}

	// Get the user associated with the public key.
	user := fes.GetUserForPublicKey(listingRequest.PublicKeyBase58Check)
	if user == nil {
		_AddBadRequestError(ww, fmt.Sprintf("PublishListing: Could not find user with "+
			"public key %v", listingRequest.PublicKeyBase58Check))
		return
	}

	// If the user is not a merchant then don't allow her to post a listing.
	// TODO: Should we also deny her if her registration isn't confirmed?
	if user.MerchantEntry == nil {
		_AddBadRequestError(ww, fmt.Sprintf("PublishListing: User found %v is not "+
			"registered as a merchant", user))
		return
	}

	// Convert the MerchantID to bytes.
	merchantIDBytes, _, err := Base58CheckDecode(user.MerchantEntry.MerchantIDBase58Check)
	if err != nil || len(merchantIDBytes) != HashSizeBytes {
		_AddBadRequestError(ww, fmt.Sprintf("PublishListing: Problem computing MerchantID "+
			"bytes from base58 %v", err))
		return
	}
	merchantID := &BlockHash{}
	copy(merchantID[:], merchantIDBytes)

	// If the listing index is set to something improper, error. It should be less
	// than zero or else set to a valid value.
	if listingRequest.ListingIndex > int32(fes.Params.MaxListingsPerMerchant) {
		_AddBadRequestError(ww, fmt.Sprintf("PublishListing: Listing index %d exceeds "+
			"maximum index value %d", listingRequest.ListingIndex, fes.Params.MaxListingsPerMerchant))
		return
	}
	// If the user is creating a new listing then find an index that we can use
	// to assign to this listing. If we can't find one then error.
	if listingRequest.ListingIndex < 0 {
		// Get the ListingIDs currently set for this merchant and see if there is a
		// currently-unused listing index. If not, then error.
		//
		// Note that this will acquire a lock internal to the ListingManager.
		// This is important because we're holding the DataLock at this point,
		// and so care must be taken to avoid acquiring the two locks in the
		// reverse order (or else a deadlock could occur).
		listingIndex, err := fes.listingManager.NewListingIndexForMerchantID(merchantID)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("PublishListing: Problem creating new "+
				"listing; likely that the maximum number of listings has been "+
				"reached: %v", err))
			return
		}
		listingRequest.ListingIndex = int32(listingIndex)
	}
	// At this point the listingData should have a ListingIndex set to a valid
	// value that can be converted to uint32 if needed.

	// If the timestamp is unset, set it to now so the listing will update smoothly.
	if listingRequest.TstampSecs == 0 {
		listingRequest.TstampSecs = uint32(time.Now().Unix())
	}

	// Convert the public key to bytes.
	publicKeyBytes, _, err := Base58CheckDecode(listingRequest.PublicKeyBase58Check)
	if err != nil || len(publicKeyBytes) != btcec.PubKeyBytesLenCompressed {
		_AddBadRequestError(ww, fmt.Sprintf("PublishListing: Problem computing PublicKey bytes from base58 %+v", err))
		return
	}

	// Get the password for the user. If a password is set in the request it will
	// override any password we have stored for the user.
	password := fes.GetPassword(listingRequest.PublicKeyBase58Check, listingRequest.Password)

	// Verify that we can get the private key from the public key specified.
	privKey, _, err := fes.GetPrivateKeyForPublicKey(
		listingRequest.PublicKeyBase58Check, password)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("PublishListing: Problem decrypting private "+
			"key with password %v", err))
		return
	}

	// This function is called to process the listing as long as its valid. It can get hit
	// either as part of the Delete path, in which we don't do as much validation, or in
	// the normal path that follows it.
	signAndProcessListing := func(listingMessage *MsgUltranetListing) {
		listingSignature, err := listingMessage.Sign(privKey)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("PublishListing: Problem signing "+
				"listing message %v", err))
			return
		}
		listingMessage.Signature = listingSignature

		// Run ProcessListing on this message to try and add it to the db.
		// Note that this will acquire a lock internal to the ListingManager.
		// This is important because we're holding the DataLock at this point,
		// and so care must be taken to avoid acquiring the two locks in the
		// reverse order (or else a deadlock could occur).
		if err := fes.listingManager.ProcessListing(listingMessage, true /*verifySignatures*/); err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("PublishListing: Problem processing listing %+v", err))
			return
		}

		// If we get here it means the listing has been successfully processed.
		// Now tell the Server about it so that it can be potentially broadcast
		// to other nodes.
		fes.BroadcastListing(listingMessage)

		// At this point, the listing has been added to our db. As such, we can
		// delete the temporary data we used to create it.
		fes.DraftImages = []*DraftImage{}

		res := PublishListingResponse{}
		if err := json.NewEncoder(ww).Encode(res); err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("PublishListing: Problem encoding response as JSON: %v", err))
			return
		}
	}

	// If the user asked us to delete this listing, short-circuit early and don't run
	// the rest of our validation.
	if listingRequest.Deleted {
		listingDeleteMessage := &MsgUltranetListing{
			MerchantID:   merchantID,
			PublicKey:    publicKeyBytes,
			TstampSecs:   listingRequest.TstampSecs,
			ListingIndex: uint32(listingRequest.ListingIndex),
			Deleted:      true,
		}

		signAndProcessListing(listingDeleteMessage)
		return
	}

	// Now validate the images that were uploaded during the creation of this listing.
	//
	// Checking that we have at least two images stored is sufficient to
	// guarantee that we also have a thumbnail.
	if len(fes.DraftImages) < 2 {
		_AddBadRequestError(ww, fmt.Sprintf("PublishListing: Must have at least one "+
			"image uploaded (plus a thumbnail)"))
		return
	}

	// Separate the listing images from the thumbnail and gather the byte slices for
	// both so we can set them on the listing message later.
	var thumbnailImage []byte
	var listingImages [][]byte
	for _, draftImage := range fes.DraftImages {
		if draftImage.ID == 0 {
			thumbnailImage = draftImage.Image
		} else {
			listingImages = append(listingImages, draftImage.Image)
		}
	}
	if thumbnailImage == nil {
		_AddBadRequestError(ww, fmt.Sprintf("PublishListing: Missing thumbnail image"))
		return
	}

	// For requried fields we convert them into the appropriate type and check
	// that they're non-empty.
	requiredFields := []*RequiredField{}
	for _, requiredField := range listingRequest.RequiredFields {
		if len(requiredField) == 0 {
			_AddBadRequestError(ww, fmt.Sprintf("PublishListing: Required field label should not be empty"))
			return
		}
		requiredFields = append(requiredFields, &RequiredField{
			Label:      []byte(requiredField),
			IsRequired: true,
		})
	}
	for _, optionalField := range listingRequest.OptionalFields {
		if len(optionalField) == 0 {
			_AddBadRequestError(ww, fmt.Sprintf("PublishListing: Optional field label should not be empty"))
			return
		}
		requiredFields = append(requiredFields, &RequiredField{
			Label:      []byte(optionalField),
			IsRequired: false,
		})
	}

	// Get the ProductType and check that it's valid.
	productType, productTypeExists := FEProductTypes[listingRequest.ProductType]
	if !productTypeExists {
		_AddBadRequestError(ww, fmt.Sprintf("PublishListing: ProductType %s is not in "+
			"the set of valid product types %v", listingRequest.ProductType, FEProductTypes))
		return
	}

	// We now have all the fields to finally create a listing message, which is
	// the actual data structure we need to store listings as.
	listingMessagee := MsgUltranetListing{
		MerchantID: merchantID,
		PublicKey:  publicKeyBytes,

		TstampSecs:   listingRequest.TstampSecs,
		ListingIndex: uint32(listingRequest.ListingIndex),

		Title:    []byte(listingRequest.Title),
		Body:     []byte(listingRequest.Body),
		Category: []byte(listingRequest.Category),

		ThumbnailImage: thumbnailImage,
		ListingImages:  listingImages,

		Deleted: listingRequest.Deleted,

		PricePerUnitNanos: listingRequest.PricePerUnitNanos,
		UnitNameSingular:  []byte(listingRequest.UnitNameSingular),
		UnitNamePlural:    []byte(listingRequest.UnitNamePlural),
		MinQuantity:       listingRequest.MinQuantity,
		MaxQuantity:       listingRequest.MaxQuantity,
		RequiredFields:    requiredFields,

		ProductType: productType,

		TipComment: []byte(listingRequest.TipComment),
		ShipsTo:    []byte(listingRequest.ShipsTo),
		ShipsFrom:  []byte(listingRequest.ShipsFrom),

		// Sign the message after it's constructed.
	}

	signAndProcessListing(&listingMessagee)
}

// Note that defaultPbkdf2Iters is what is suggested but that EncryptSeed may opt to use
// more iterations than that if it finds the CPU its running on is strong. As such, it
// returns whatever number of iterations it uses to encrypt the seed.
func EncryptSeed(unencryptedSeedBytes []byte, password string, defaultPbkdf2Iters uint32) (_encryptedSeedBytes []byte, _pwSaltByts []byte, _pbkdf2Iters uint32, _err error) {
	// Turn the password into an ec key using pbkdf2.
	pwSaltBytes := RandomBytes(btcec.PrivKeyBytesLen)
	// TODO: Instead of using a default value it would be good to calibrate
	// this to e.g. 1s of compute time to make it maximally difficult on the
	// attacker without compromising on the user experience.
	pbkdf2Iters := uint32(defaultPbkdf2Iters)
	pwBytes := pbkdf2.Key(
		[]byte(password),
		pwSaltBytes,
		int(pbkdf2Iters),
		btcec.PrivKeyBytesLen,
		sha256.New)

	// Encrypt the seed with the password pub key.
	//
	// We could just do a simple xor of the pw bytes with the seed but doing it this
	// way gives us some error checking on the decryption side.
	_, pwPubKey := btcec.PrivKeyFromBytes(btcec.S256(), pwBytes)

	encryptedSeedBytes, err := EncryptBytesWithPublicKey(unencryptedSeedBytes, pwPubKey.ToECDSA())
	if err != nil {
		return nil, nil, 0, errors.Wrapf(err, "EncryptSeed: Problem encrypting seed with password")
	}

	return encryptedSeedBytes, pwSaltBytes, pbkdf2Iters, nil
}

func DecryptSeed(encryptedSeedBytes []byte, password string, pwSaltBytes []byte, pbkdf2Iterations uint32) (_unencryptedSeedBytes []byte, _err error) {
	pwBytes := pbkdf2.Key(
		[]byte(password),
		pwSaltBytes,
		int(pbkdf2Iterations),
		btcec.PrivKeyBytesLen,
		sha256.New)

	// Decrypt the seed with the password priv key.
	pwPrivKey, _ := btcec.PrivKeyFromBytes(btcec.S256(), pwBytes)
	unencryptedSeedBytes, err := DecryptBytesWithPrivateKey(encryptedSeedBytes, pwPrivKey.ToECDSA())
	if err != nil {
		return nil, errors.Wrapf(err, "DecryptSeed: Problem decrypting seed with password")
	}

	return unencryptedSeedBytes, nil
}

func ComputeKeysFromSeed(seedBytes []byte, isTestnet bool) (_pubKey *btcec.PublicKey, _privKey *btcec.PrivateKey, _btcAddress string, _err error) {
	// Get the pubkey and privkey from the seed. We use the Bitcoin parameters
	// to generate them.
	// TODO: We should get this from the UltraParams, not reference them directly.
	netParams := &chaincfg.MainNetParams
	if isTestnet {
		netParams = &chaincfg.TestNet3Params
	}
	masterKey, err := hdkeychain.NewMaster(seedBytes, netParams)
	if err != nil {
		return nil, nil, "", fmt.Errorf("ComputeKeyFromSeed: Error encountered generating 'masterKey' from seed (%v)", err)
	}

	// We follow BIP44 to generate the addresses. Recall it follows the following
	// semantic hierarchy:
	// * purpose' / coin_type' / account' / change / address_index
	// For the derivation path we use: m/44'/0'/0'/0/0. Recall that 0' means we're
	// computing a "hardened" key, which means the private key is present, and
	// that 0 (no apostrophe) means we're computing an "unhardened" key which means
	// the private key is not present.
	//
	// m/44'/0'/0'/0/0 also maps to the first
	// address you'd get if you put the user's seed into most standard
	// Bitcoin wallets (Mycelium, Electrum, Ledger, iancoleman, etc...).
	purpose, err := masterKey.Child(hdkeychain.HardenedKeyStart + 44)
	if err != nil {
		return nil, nil, "", fmt.Errorf("ComputeKeyFromSeed: Error encountered generating 'purpose' from seed (%v)", err)
	}
	coinTypeKey, err := purpose.Child(hdkeychain.HardenedKeyStart + 0)
	if err != nil {
		return nil, nil, "", fmt.Errorf("ComputeKeyFromSeed: Error encountered generating 'coinType' from seed (%v)", err)
	}
	accountKey, err := coinTypeKey.Child(hdkeychain.HardenedKeyStart + 0)
	if err != nil {
		return nil, nil, "", fmt.Errorf("ComputeKeyFromSeed: Error encountered generating 'accountKey' from seed (%v)", err)
	}
	changeKey, err := accountKey.Child(0)
	if err != nil {
		return nil, nil, "", fmt.Errorf("ComputeKeyFromSeed: Error encountered generating 'changeKey' from seed (%v)", err)
	}
	addressKey, err := changeKey.Child(0)
	if err != nil {
		return nil, nil, "", fmt.Errorf("ComputeKeyFromSeed: Error encountered generating 'addressKey' from seed (%v)", err)
	}

	pubKey, err := addressKey.ECPubKey()
	if err != nil {
		return nil, nil, "", fmt.Errorf("ComputeKeyFromSeed: Error encountered generating 'pubKey' from seed (%v)", err)
	}
	privKey, err := addressKey.ECPrivKey()
	if err != nil {
		return nil, nil, "", fmt.Errorf("ComputeKeyFromSeed: Error encountered generating 'privKey' from seed (%v)", err)
	}
	addressObj, err := addressKey.Address(netParams)
	if err != nil {
		return nil, nil, "", fmt.Errorf("ComputeKeyFromSeed: Error encountered generating 'addressObj' from seed (%v)", err)
	}
	btcDepositAddress := addressObj.EncodeAddress()

	return pubKey, privKey, btcDepositAddress, nil
}

func ComputeKeysFromEncryptedSeed(
	encryptedSeedBytes []byte, password string, pwSalt []byte, pbkdf2Iters uint32, isTestnet bool) (
	_pubKey *btcec.PublicKey, _privKey *btcec.PrivateKey, _btcAddress string, _err error) {

	decryptedSeed, err := DecryptSeed(encryptedSeedBytes, password, pwSalt, pbkdf2Iters)
	if err != nil {
		return nil, nil, "", fmt.Errorf("ComputeKeysFromEncryptedSeed: Problem decrypting seed: %+v", err)
	}
	return ComputeKeysFromSeed(decryptedSeed, isTestnet)
}

func _checksum(input []byte) (cksum [4]byte) {
	h := sha256.Sum256(input)
	h2 := sha256.Sum256(h[:])
	copy(cksum[:], h2[:4])
	return
}

func Base58CheckEncode(input []byte, isPrivate bool, params *UltranetParams) string {
	prefix := params.Base58PrefixPublicKey
	if isPrivate {
		prefix = params.Base58PrefixPrivateKey
	}
	return Base58CheckEncodeWithPrefix(input, prefix)
}

func Base58CheckEncodeWithPrefix(input []byte, prefix [3]byte) string {
	b := []byte{}
	b = append(b, prefix[:]...)
	b = append(b, input[:]...)
	cksum := _checksum(b)
	b = append(b, cksum[:]...)
	return base58.Encode(b)
}

func mustBase58CheckDecode(input string) []byte {
	if input == "" {
		return nil
	}
	ret, _, err := Base58CheckDecode(input)
	if err != nil {
		glog.Fatal(err)
	}
	return ret
}

func Base58CheckDecode(input string) (_result []byte, _prefix []byte, _err error) {
	return Base58CheckDecodePrefix(input, 3 /*prefixLen*/)
}

func Base58CheckDecodePrefix(input string, prefixLen int) (_result []byte, _prefix []byte, _err error) {
	decoded := base58.Decode(input)
	if len(decoded) < 5 {
		return nil, nil, fmt.Errorf("CheckDecode: Invalid input format")
	}
	var cksum [4]byte
	copy(cksum[:], decoded[len(decoded)-4:])
	if _checksum(decoded[:len(decoded)-4]) != cksum {
		return nil, nil, fmt.Errorf("CheckDecode: Checksum does not match")
	}
	prefix := decoded[:prefixLen]
	payload := decoded[prefixLen : len(decoded)-4]
	return payload, prefix, nil
}

func UtxoEntryToResponse(utxoEntry *UtxoEntry, params *UltranetParams) *UtxoResponse {
	return &UtxoResponse{
		AmountNanos:          utxoEntry.AmountNanos,
		PublicKeyBase58Check: PkToString(utxoEntry.PublicKey, params),
		BlockHeight:          utxoEntry.BlockHeight,
		IsBlockReward:        utxoEntry.IsBlockReward,
		Pos:                  utxoEntry.Pos,
		TxIDBase58Check:      PkToString(utxoEntry.utxoKey.TxID[:], params),
		Index:                utxoEntry.utxoKey.Index,
	}
}

func _computeIsBuyer(user *User, orderEntry *OrderEntry) (bool, error) {
	// Check if the user is the buyer or the merchant.
	isBuyer := true
	if user.MerchantEntry != nil {
		merchantIDBytes, _, err := Base58CheckDecode(user.MerchantEntry.MerchantIDBase58Check)
		if err != nil {
			return false, fmt.Errorf("_computeIsBuyer: Problem decoding "+
				"MerchantID: %s: %v", user.MerchantEntry.MerchantIDBase58Check, err)
		}
		merchantID := &BlockHash{}
		copy(merchantID[:], merchantIDBytes)

		if *merchantID == *orderEntry.MerchantID {
			isBuyer = false
		}
	}
	// If the user is the buyer, the BuyerPk must match the public key of the
	// user or else we return an error.
	if isBuyer {
		pkBytes, _, err := Base58CheckDecode(user.PublicKeyBase58Check)
		if err != nil {
			return false, fmt.Errorf("_computeIsBuyer: Problem decoding "+
				"public key: %s: %v", user.PublicKeyBase58Check, err)
		}
		if !reflect.DeepEqual(pkBytes, orderEntry.BuyerPk) {
			return false, fmt.Errorf("_computeIsBuyer: User was identified as "+
				"buyer (not merchant) yet buyer pk in order %#v does not match user pk %#v",
				orderEntry.BuyerPk, pkBytes)
		}
	}

	return isBuyer, nil
}

func _getEncryptedDataForOrder(user *User, orderIDBase58Check string) (
	_buyerMessage *BuyerMessage, _rejectReason string) {

	buyerMessage, _ := user.LocalState.OrderIDToBuyerMessage[orderIDBase58Check]
	rejectReason, _ := user.LocalState.OrderIDToRejectReason[orderIDBase58Check]

	return buyerMessage, rejectReason
}

// This function decrypts the OrderData and stores it on the various maps associated
// with the user. Namely:
// - OrderIDToBuyerMessage
// - OrderIDToRejectReason
func (fes *FrontendServer) _tryDecryptOrderData(user *User, orderEntry *OrderEntry) (
	_err error) {

	// Compute whether the user is the buyer or the merchant.
	isBuyer, err := _computeIsBuyer(user, orderEntry)
	if err != nil {
		return errors.Wrapf(err, "_tryDecryptOrderData: Problem computing isBuyer: ")
	}

	// It could be the case that the BuyerMessage hasn't been decrypted yet. When
	// that is the case we should try to decrypt it and store it on the user. If
	// decryption fails then the BuyerMessage is left as nil. The FE should be
	// robust to a nil buyer message and gracefully show some kind of decryption
	// error for it when it is nil.
	orderIDBase58Check := PkToString(orderEntry.orderID[:], fes.Params)
	_, buyerMessageExists :=
		user.LocalState.OrderIDToBuyerMessage[orderIDBase58Check]
	if !buyerMessageExists {
		if isBuyer {
			// If the BuyerMessage doesn't exist and the user is the buyer then there
			// is nothing we can do because the BuyerMessage will have been encrypted
			// by the merchant's public key, which means it is no longer decryptable by
			// the user.
			user.LocalState.OrderIDToBuyerMessage[orderIDBase58Check] = nil
		} else {
			// If the BuyerMessage doesn't exist and the user is the merchant, then we
			// try and decrypt the BuyerMessage on the OrderEntry.

			// If either we don't have a password for the user in this case or if the
			// password fails to decrypt our private key then we just leave the buyerMessage
			// as nil. Note that we don't set anything in the map so that decryption can be
			// tried again after the user has entered a valid password.
			password := fes._getPassword(user.PublicKeyBase58Check, "")
			privKey, _, err := fes._getPrivateKeyForPublicKey(user.PublicKeyBase58Check, password)
			if err != nil {
				return errors.Wrapf(err, "_tryDecryptOrderData: Problem decrypting merchant private key with password: ")
			}

			// If we get here, we are confident we have the correct private key for the user
			// so now try and decrypt the BuyerMessage in the order.
			decryptedBuyerMessage := &BuyerMessage{}
			err = decryptedBuyerMessage.DecryptWithPrivKey(orderEntry.BuyerMessage, privKey)
			if err != nil {
				// In this case, as an optimization, we set the OrderIDToBuyerMessage to contain
				// a nil entry for this order. Not doing this would cause us to repeatedly and futile-ly
				// decrypt the BuyerMessage over and over even though it's a bad message.
				user.LocalState.OrderIDToBuyerMessage[orderIDBase58Check] = nil
				return errors.Wrapf(err, "_tryDecryptOrderData: Problem decrypting BuyerMessage with private key: ")
			}

			user.LocalState.OrderIDToBuyerMessage[orderIDBase58Check] = decryptedBuyerMessage
		}
	}

	// Everything related to BuyerMessage above applies to RejectReason, which is
	// typically encrypted with the buyer's public key (as opposed to the merchant's
	// public key).
	//
	// First, try and fetch the RejectReason from the map.
	_, rejectReasonExists := user.LocalState.OrderIDToRejectReason[orderIDBase58Check]
	// A RejectReason only needs to be decrypted if:
	// - The RejectReason has non-zero length in the OrderEntry.
	// - No RejectReason is not present in the map.
	// - The user is the buyer.
	if len(orderEntry.RejectReason) != 0 && !rejectReasonExists && isBuyer {
		// In this case, we have a RejectReason to decrypt. Start by trying to get the
		// user's password. If either we don't have a password for the user in this case or if the
		// password fails to decrypt our private key then we just leave the buyerMessage
		// as nil. Note that we don't set anything in the map so that decryption can be
		// tried again after the user has entered a valid password.
		password := fes._getPassword(user.PublicKeyBase58Check, "")
		privKey, _, err := fes._getPrivateKeyForPublicKey(user.PublicKeyBase58Check, password)
		if err != nil {
			return errors.Wrapf(err, "_tryDecryptOrderData: Problem decrypting buyer private key with password: ")
		}
		rejectReasonBytes, err := DecryptBytesWithPrivateKey(orderEntry.RejectReason, privKey.ToECDSA())
		if err != nil {
			return errors.Wrapf(err, "_tryDecryptOrderData: Problem decrypting RejectReason: ")
		}

		// In this case we have successfully decrypted the RejectReason so set it in the map.
		user.LocalState.OrderIDToRejectReason[orderIDBase58Check] = string(rejectReasonBytes)
	}

	// At this point the maps containing decrypted data should have all been updated.
	return nil
}

// Returns nil if the orderEntry does not satisfy either of the following conditions:
// 1) BuyerPublicKey = publicKey
// 2) MerchantID = merchantID
// Passing a merchantID is optional, and if it's omitted then only a buyer order
// response will be returned.
func (fes *FrontendServer) OrderEntryToResponse(
	orderEntry *OrderEntry, user *User, params *UltranetParams) (
	*OrderEntryResponse, error) {

	isBuyer, err := _computeIsBuyer(user, orderEntry)
	if err != nil {
		return nil, errors.Wrapf(err, "OrderEntryToResponse: Problem computing isBuyer: ")
	}

	// If we encounter a problem decrypting order data for the user, log the error but
	// don't stop the show. This can happen if we're decrypting data for a user who has
	// not yet entered her password.
	if err := fes._tryDecryptOrderData(user, orderEntry); err != nil {
		// Only log an error if this happens to the logged-in user otherwise ignore.
		if fes.UserData != nil && fes.UserData.LoggedInUser != nil &&
			fes.UserData.LoggedInUser.PublicKeyBase58Check == user.PublicKeyBase58Check {

			glog.Errorf(fmt.Sprintf("OrderEntryToResponse: Problem decrypting order "+
				"data for LoggedInUser: %v; this should never happen", err))
		}
	}
	// We separate decryption of the order info from fetching of the order info. At this
	// point, if everything was properly decrypted, then this call should return it.
	orderIDBase58Check := PkToString(orderEntry.orderID[:], params)
	buyerMessage, rejectReason := _getEncryptedDataForOrder(user, orderIDBase58Check)

	// The payment amount on the order does not include the referrer commissions.
	// Those must be computed separately after we've isolated the revenueNanos.
	orderCommissionNanos, revenueNanos, err := _computeCommissionsAndRevenueFromPayment(
		orderEntry.PaymentAmountNanos, params.CommissionBasisPoints)
	if err != nil {
		return nil, errors.Wrapf(err, "OrderEntryToResponse: Problem computing payment "+
			"and commissions")
	}
	commissionsWithReferrerAmount, err := _computeCommissionsFromPriceNanos(
		revenueNanos, params.CommissionBasisPoints+params.ReferrerCommissionBasisPoints)
	if err != nil {
		return nil, errors.Wrapf(err, "OrderEntryToResponse: Problem computing referrer amount")
	}
	referrerAmount := commissionsWithReferrerAmount - orderCommissionNanos

	buyerItemPrice := float64(0)
	merchantItemPrice := float64(0)
	merchantRevenueWithoutTip := float64(0)
	merchantTipRevenue := float64(0)
	if buyerMessage != nil {
		totalPaidWithoutTip := orderEntry.PaymentAmountNanos + referrerAmount - buyerMessage.TipAmountNanos
		if buyerMessage.ItemQuantity != 0 {
			buyerItemPrice = float64(totalPaidWithoutTip) / float64(buyerMessage.ItemQuantity)
		}

		_, merchantTipRevenueUint64, err := _computeCommissionsAndRevenueFromPayment(
			buyerMessage.TipAmountNanos,
			params.CommissionBasisPoints+params.ReferrerCommissionBasisPoints)
		if err != nil {
			return nil, errors.Wrapf(err, "OrderEntryToResponse: Problem computing tip "+
				"after subtracting commissions")
		}
		merchantTipRevenue = float64(merchantTipRevenueUint64)
		merchantRevenueWithoutTip = float64(revenueNanos) - merchantTipRevenue
		if buyerMessage.ItemQuantity != 0 {
			merchantItemPrice = float64(merchantRevenueWithoutTip) / float64(buyerMessage.ItemQuantity)
		}
	}

	// Convert the ConfirmationBlockHeight and the LastModifiedHeight into times.
	confirmedAt := int64(0)
	lastModifiedAt := int64(0)
	if orderEntry.ConfirmationBlockHeight != 0 {
		// Try and find the header at which this order was confirmed. If we can't find it,
		// default to the tip of the header chain. This can happen when we have an order in
		// the mempool that has not yet been mined into a block.
		headerConfirmedAt := fes.blockchain.HeaderAtHeight(orderEntry.ConfirmationBlockHeight)
		if headerConfirmedAt == nil {
			headerConfirmedAt = fes.blockchain.HeaderTip()
		}
		confirmedAt = int64(headerConfirmedAt.Header.TstampSecs)
	}
	if orderEntry.LastModifiedBlock != 0 {
		// Try and find the header at which this order was modified. If we can't find it,
		// default to the tip of the header chain. This can happen when we have an order in
		// the mempool that has not yet been mined into a block.
		headerModifiedAt := fes.blockchain.HeaderAtHeight(orderEntry.LastModifiedBlock)
		if headerModifiedAt == nil {
			headerModifiedAt = fes.blockchain.HeaderTip()
		}
		lastModifiedAt = int64(headerModifiedAt.Header.TstampSecs)
	} else {
		// Orders should always have a last modified time.
		return nil, fmt.Errorf("OrderEntryToResponse: Order's LastModifiedBlock was 0 " +
			"when it should be set to a rational value")
	}

	// Get the MerchantEntry for the order, which must exist. Convert it to a MerchantEntryResponse.
	merchantEntry := DbGetMerchantEntryForMerchantID(fes.blockchain.db, orderEntry.MerchantID)
	if merchantEntry == nil {
		return nil, fmt.Errorf("OrderEntryToResponse: No MerchantEntry found for "+
			"OrderID: %s MerchantID: %v", orderIDBase58Check, orderEntry.MerchantID)
	}
	// We don't care about the merchant rank in order entries.
	merchantEntryResponse := fes.MerchantEntryToResponse(merchantEntry, -1)

	// Get the ListingMessage if we can. If we can't leave it as nil. The FE should
	// be robust to a nil ListingMessage, which can happen if the BuyerMessage is not
	// decryptable or if the merchant has recently deleted the listing.
	orderMerchantIDBase58Check := PkToString(orderEntry.MerchantID[:], params)
	var listingResponse *SingleListingResponse
	if buyerMessage != nil {
		listingResponses, err := fes._getListingResponsesForCriteria(
			orderMerchantIDBase58Check, int(buyerMessage.ListingIndex),
			"" /*searchQuery*/, false, /*categoryQuery*/
			false /*fetchMerchantEntries*/, isBuyer /*adjustPriceForCommissions*/)
		if err != nil {
			return nil, errors.Wrapf(err, "OrderEntryToResponse: Problem fetching listing message "+
				"for MerchantID: %v, ListingIndex: %d",
				orderEntry.MerchantID, buyerMessage.ListingIndex)
		}
		if len(listingResponses) == 1 {
			listingResponse = listingResponses[0]
		} else {
			// If we can't find the listing, just log an error. This can happen if the
			// merchant deleted the listing.
			glog.Errorf("OrderEntryToResponse: Expected to find 1 Listing message "+
				"for MerchantID: %v, ListingIndex: %d but instead found %d",
				orderEntry.MerchantID, buyerMessage.ListingIndex, len(listingResponses))
		}
	}

	// Determine what actions are available and whether action is required.
	isActionRequired := false
	possibleActions := []string{}
	if isBuyer {
		// User is the buyer.
		switch orderEntry.State {
		case OrderStatePlaced:
			isActionRequired = false
			possibleActions = []string{"cancel"}

		case OrderStateCanceled:
			isActionRequired = false
			possibleActions = []string{}

		case OrderStateConfirmed:
			isActionRequired = false
			possibleActions = []string{"review", "request_refund"}

		case OrderStateFulfilled:
			isActionRequired = true
			possibleActions = []string{"review", "request_refund"}

		case OrderStateRejected:
			isActionRequired = false
			possibleActions = []string{}

		case OrderStateReviewed:
			isActionRequired = false
			possibleActions = []string{"edit_review", "request_refund"}

		case OrderStateRefunded:
			isActionRequired = false
			possibleActions = []string{}
		default:
			return nil, fmt.Errorf("OrderEntryToResponse: Unrecognized order state %v. Did you "+
				"forget to update OrderEntryToResponse() when adding a new order state?", orderEntry.State)
		}
	} else {
		// User is the merchant.
		switch orderEntry.State {
		case OrderStatePlaced:
			isActionRequired = true
			possibleActions = []string{"confirm", "reject"}

		case OrderStateCanceled:
			isActionRequired = false
			possibleActions = []string{}

		case OrderStateConfirmed:
			// If enough time has passed and the order is still in the confirmed state then
			// the merchant has the option to mark the order as fulfilled.
			blockHeight := fes.blockchain.HeaderTip().Height
			blocksPassed := int64(blockHeight) - int64(orderEntry.ConfirmationBlockHeight)
			timePassed := time.Duration(int64(fes.Params.TimeBetweenBlocks) * int64(blocksPassed))
			if timePassed >= fes.Params.TimeBeforeOrderFulfilled {
				isActionRequired = true
				possibleActions = []string{"refund_order", "fulfill_order"}
			} else {
				isActionRequired = false
				possibleActions = []string{"refund_order"}
			}
		case OrderStateFulfilled:
			isActionRequired = false
			possibleActions = []string{"refund_order"}

		case OrderStateRejected:
			isActionRequired = false
			possibleActions = []string{}

		case OrderStateReviewed:
			isActionRequired = false
			possibleActions = []string{"refund_order"}

		case OrderStateRefunded:
			isActionRequired = false
			possibleActions = []string{}
		default:
			return nil, fmt.Errorf("OrderEntryToResponse: Unrecognized order state %v. Did you "+
				"forget to update OrderEntryToResponse() when adding a new order state?", orderEntry.State)
		}
	}

	scoreImpact, _ := new(big.Float).SetInt(orderEntry.MerchantScoreImpact).Float64()
	return &OrderEntryResponse{
		OrderIDBase58Check:        PkToString(orderEntry.orderID[:], params),
		BuyerPublicKeyBase58Check: PkToString(orderEntry.BuyerPk[:], params),
		MerchantIDBase58Check:     orderMerchantIDBase58Check,

		PaymentAmountNanos:  orderEntry.PaymentAmountNanos,
		RevenueNanos:        revenueNanos,
		ReferrerAmountNanos: referrerAmount,
		// Include the referrer amount in the commissions to be transparent to
		// the merchant.
		CommissionNanos:   commissionsWithReferrerAmount,
		AmountLockedNanos: orderEntry.AmountLockedNanos,

		MerchantRevenueWithoutTip: merchantRevenueWithoutTip,
		MerchantTipRevenue:        merchantTipRevenue,

		BuyerPricePerItem:    buyerItemPrice,
		MerchantPricePerItem: merchantItemPrice,

		Pos:          orderEntry.Pos,
		BuyerMessage: buyerMessage,
		State:        orderEntry.State.String(),

		ReviewType: orderEntry.ReviewType.String(),
		ReviewText: string(orderEntry.ReviewText),

		RejectReason:             rejectReason,
		ConfirmedAtTstampSecs:    confirmedAt,
		LastModifiedAtTstampSecs: lastModifiedAt,

		MerchantScoreImpact: scoreImpact,

		MerchantEntry:  merchantEntryResponse,
		ListingMessage: listingResponse,

		IsBuyer: isBuyer,

		IsActionRequired: isActionRequired,
		PossibleActions:  possibleActions,
	}, nil
}

// CreateUserRequest ...
type CreateUserRequest struct {
	Username                     string `json:"username"`
	EntropyHex                   string `json:"entropyHex"`
	Mnemonic                     string `json:"mnemonic"`
	ExtraText                    string `json:"extraText"`
	Password                     string `json:"password"`
	SeedHex                      string `json:"seedHex"`
	ReferrerPublicKeyBase58Check string `json:"referrerPublicKeyBase58Check"`
}

// CreateUserResponse ...
type CreateUserResponse struct {
	UserData *LocalUserData `json:"userData"`
}

func (fes *FrontendServer) _tryDecryptMessageText(
	userPublicKeyBytes []byte, messageEntry *MessageEntry,
	messageMap map[string]string) (_decryptedText string, _err error) {

	// First, figure out whether the user is the sender or receiver.
	isSender := false
	if reflect.DeepEqual(userPublicKeyBytes, messageEntry.SenderPublicKey) {
		isSender = true
	}

	// See if we have the message already decrypted in our message map.
	messageKey := MakeMessageKey(userPublicKeyBytes, messageEntry.TstampNanos)
	decryptedText, decryptedTextExists := messageMap[messageKey.StringKey(fes.Params)]
	if decryptedTextExists {
		return decryptedText, nil
	}

	// If we get here, it means we haven't seen this message before and therefore
	// don't have it stored in our map. This has different implications depending
	// on whether we are the sender or the receiver.
	if isSender {
		// Ironically, we cannot decrypt messages we send since they're encrypted with
		// the recipient's public key. So if we don't have them in our map, the best
		// we can do is tell the user this fact.
		decryptedText = "CANNOT DECRYPT MESSAGE: Did you send this message from a " +
			"different machine? Ironically, messages you send are encrypted with the " +
			"recipient's public key and so you can't decrypt them. This means that, " +
			"unless you're on the machine on which you originally sent the message, " +
			"which stores the decrypted text when you send it, you can't see this message."
		messageMap[messageKey.StringKey(fes.Params)] = decryptedText
		return decryptedText, nil
	}

	// If we get here the user is not the sender of the message.

	// There's an edge case where the sender legitimately sent an empty string. In
	// this case the EncryptedText will be empty and we should show an empty string
	// to the user. We can't run normal decryption on this because we'd get an error.
	if len(messageEntry.EncryptedText) == 0 {
		decryptedText = "<EMPTY MESSAGE>"
		messageMap[messageKey.StringKey(fes.Params)] = decryptedText
		return decryptedText, nil
	}

	// If the user is the recipient then we should be able to decrypt the message text
	// with the user's password.
	publicKeyString := PkToString(userPublicKeyBytes, fes.Params)
	password := fes._getPassword(publicKeyString, "")
	privKey, _, err := fes._getPrivateKeyForPublicKey(publicKeyString, password)
	if err != nil {
		return "", errors.Wrapf(err, "_tryDecryptMessageText: Problem decrypting "+
			"merchant private key with password: ")
	}

	decryptedBytes, err := DecryptBytesWithPrivateKey(
		messageEntry.EncryptedText, privKey.ToECDSA())
	if err != nil {
		// In this case decryption failed. Set the decryptedText to an error message to
		// avoid futile-ly trying to decrypt it over and over again.
		decryptedText = "CANNOT DECRYPT MESSAGE: This is likely due to the " +
			"sender encrypting the message improperly before sending"
		messageMap[messageKey.StringKey(fes.Params)] = decryptedText
		return decryptedText, nil
	}

	// In this case the message was decrypted properly so return it.
	decryptedText = string(decryptedBytes)
	messageMap[messageKey.StringKey(fes.Params)] = decryptedText
	return decryptedText, nil
}
