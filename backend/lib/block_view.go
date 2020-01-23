package lib

import (
	"encoding/hex"
	"fmt"
	"math"
	"math/big"
	"reflect"
	"sort"
	"time"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/dgraph-io/badger"
	"github.com/golang/glog"
	merkletree "github.com/laser/go-merkle-tree"
	"github.com/pkg/errors"
)

// block_view.go is the main work-horse for validating transactions in blocks.
// It generally works by creating an "in-memory view" of the current tip and
// then applying a transaction's operations to the view to see if those operations
// are allowed and consistent with the blockchain's current state. Generally,
// every transaction we define has a corresponding connect() and disconnect()
// function defined here that specifies what operations that transaction applies
// to the view and ultimately to the database. If you want to know how any
// particular transaction impacts the database, you've found the right file. A
// good place to start in this file is ConnectTransaction and DisconnectTransaction.
// ConnectBlock is also good.

// OrderState designates what state an order is in. See the whitepaper on
// ultranet.one for a picture of what the order state machine looks like.
type OrderState uint32

const (
	// OrderStatePlaced ...
	OrderStatePlaced OrderState = 0
	// OrderStateCanceled ...
	OrderStateCanceled OrderState = 1
	// OrderStateConfirmed ...
	OrderStateConfirmed OrderState = 2
	// OrderStateFulfilled ...
	OrderStateFulfilled OrderState = 3
	// OrderStateRejected ...
	OrderStateRejected OrderState = 4
	// OrderStateReviewed ...
	OrderStateReviewed OrderState = 5
	// OrderStateRefunded ...
	OrderStateRefunded OrderState = 6
)

func (os OrderState) String() string {
	switch os {
	case OrderStatePlaced:
		return "Placed"
	case OrderStateCanceled:
		return "Cancelled"
	case OrderStateConfirmed:
		return "Confirmed"
	case OrderStateFulfilled:
		return "Fulfilled"
	case OrderStateRejected:
		return "Rejected"
	case OrderStateReviewed:
		return "Reviewed"
	case OrderStateRefunded:
		return "Refunded"
	default:
		return fmt.Sprintf("Unknown(%d)", uint32(os))
	}
}

// ReviewType specifies what type of review the user gave. This impacts how the
// review affects the merchant's score.
type ReviewType uint8

const (
	// ReviewTypeNegative ...
	ReviewTypeNegative ReviewType = 0
	// ReviewTypeNeutral ...
	ReviewTypeNeutral ReviewType = 1
	// ReviewTypePositive ...
	ReviewTypePositive ReviewType = 2
)

func (rt ReviewType) String() string {
	switch rt {
	case ReviewTypeNegative:
		return "Negative"
	case ReviewTypeNeutral:
		return "Neutral"
	case ReviewTypePositive:
		return "Positive"
	default:
		return fmt.Sprintf("Unknown(%d)", uint8(rt))
	}
}

// OrderEntry identifies the data associated with an order.
type OrderEntry struct {
	// BuyerPk is the public key of the buyer in this transaction.
	BuyerPk []byte
	// MerchantID is the id of the merchant in this transaction.
	MerchantID *BlockHash

	// PaymentAmountNanos is the amount of Ultra initially paid by the buyer
	// to place the order. It is saved so that it can be used to compute
	// commissions and revenue to the merchant later on for various
	// operations. It should never change after an order is placed.
	PaymentAmountNanos uint64

	// AmountLockedNanos is the amount of Ultra currently locked in this
	// order. The order data is used to manage a state machine and this
	// field is used to manage the monetary component of this. See the
	// order code for more insight into how the lifecycle of an order is
	// managed.
	AmountLockedNanos uint64

	// Pos is the order entry's position in the order list. We keep entries
	// in an ordered list so that they can be merkle hashed in the future.
	Pos uint64

	// BuyerMessage is some data sent from the buyer to the merchant
	// encrypted with the merchant's public key. It will typically
	// include where to ship the items, possibly contact information, etc.
	BuyerMessage []byte

	// State is the state of this order. See the order code for more
	// information on how this is used to manage the lifecycle of an order.
	State OrderState

	// ConfirmationBlockHeight is the block height at which order was confirmed.
	// When a merchant confirms an order she is able to spend the proceeds
	// (minus commissions), which opens the system up to exit scams whereby
	// merchants confirm a bunch of transactions but don't deliver. To
	// mitigate this, the system applies a penalty to a merchant's reputation
	// score to confirmed orders that are recent such that a merchant who
	// is trying to conduct an exit scam will find it difficult to earn more
	// than what she's burned to bolster her reputation. This also motivates
	// merchants to deliver items to users quickly, as the quicker a user
	// moves the order out of the confirmed state the quicker the merchant's
	// reputation recovers so she can sell more.
	ConfirmationBlockHeight uint32

	// A summary statistic for how the user felt about the order.
	ReviewType ReviewType
	// Some text from the user about what they thought about the purchase. This is
	// not encrypted.
	ReviewText []byte

	// A merchant can include a reason the order is rejected encrypted by
	// the buyer's pk.
	RejectReason []byte

	// LastModifiedBlock indicates the block height at which the order was last
	// modified.
	LastModifiedBlock uint32

	// The impact this order has on the merchant's score. Put another way, this
	// value represents what would need to be removed from the merchant's current
	// score to make it as if the order never happened.
	MerchantScoreImpact *big.Int

	// The fields below are not hashed or serialized to the db and are used
	// mainly for bookkeeping purposes.

	// Whether or not this entry is deleted in the view.
	isDeleted bool

	// A back-reference to the OrderID for this order.
	orderID *BlockHash
}

func (oe *OrderEntry) String() string {
	return fmt.Sprintf("< BuyerPk: %v, MerchantID: %v, PaymentAmountNanos: %d, AmountLockedNanos: %d, "+
		"Pos: %d, BuyerMessageLen: %d, State: %v, ConfHeight: %d, "+
		"ReviewType: %v, ReviewText: %s, RejectReasonLen: %d, "+
		"LastModifiedBlock: %d, MerchantScoreImpact: %v, isDeleted: %v, "+
		"orderID: %v >", PkToStringMainnet(oe.BuyerPk), oe.MerchantID,
		oe.PaymentAmountNanos,
		oe.AmountLockedNanos, oe.Pos, len(oe.BuyerMessage), oe.State, oe.ConfirmationBlockHeight,
		oe.ReviewType, string(oe.ReviewText), len(oe.RejectReason), oe.LastModifiedBlock,
		oe.MerchantScoreImpact, oe.isDeleted, oe.orderID)
}

// NewZeroScore ...
//
// TODO: Delete all of this crap. It was originally used because we were trying to
// represent an int256 as a uint256 that sorts via big-endian, but we pushed all
// the complexity around this to the db side so that none of this is needed anymore
// (although it still works, which is why I don't want to delete it jsut yet).
func NewZeroScore() *BlockHash {
	// We adjust scores by adding 2^255 to them. We do this so that negative scores
	// can be accurately represented by positive 256-bit values.
	return BigintToHash(big.NewInt(0).Exp(big.NewInt(2), big.NewInt(255), nil))
}

// ScorePlusHash ...
//
// TODO: Delete all of this crap. It was originally used because we were trying to
// represent an int256 as a uint256 that sorts via big-endian, but we pushed all
// the complexity around this to the db side so that none of this is needed anymore
// (although it still works, which is why I don't want to delete it jsut yet).
func ScorePlusHash(score *big.Int, amountToAdd *big.Int) *big.Int {
	// Let z be the adjustment we make to a score to prevent it from being a
	// negative value. In this case we have:
	// - score = (s + z)
	// - amountToAdd = (a + z)
	// Adding them together yields:
	// - (s + z) + (a + z) = s + a + 2z
	// Which means we need to subtract z to get the value we want:
	// - newScore = score + amountToAdd - z
	// - = s + a + 1z
	return big.NewInt(0).Add(score, amountToAdd)
	//unadjustedSum := big.NewInt(0).Add(HashToBigint(score), HashToBigint(amountToAdd))
	//return BigintToHash(big.NewInt(0).Sub(unadjustedSum, HashToBigint(NewZeroScore())))
}

// ScoreMinusHash ...
//
// TODO: Delete all of this crap. It was originally used because we were trying to
// represent an int256 as a uint256 that sorts via big-endian, but we pushed all
// the complexity around this to the db side so that none of this is needed anymore
// (although it still works, which is why I don't want to delete it jsut yet).
func ScoreMinusHash(score *big.Int, amountToRemove *big.Int) *big.Int {
	// Let z be the adjustment we make to a score to prevent it from being a
	// negative value. In this case we have:
	// - score = (s + z)
	// - amountToRemove = (a + z)
	// If we were to compute the difference directly we would have:
	// - score - amount = s - a
	// The above is off by z, so we need to instead do the following:
	// - score + z - amount = (s + z) + z - (a + z)
	// - = s - a + z
	// Which is what we want.
	return big.NewInt(0).Sub(score, amountToRemove)
	//adjustedScore := big.NewInt(0).Add(HashToBigint(score), HashToBigint(NewZeroScore()))
	//return BigintToHash(big.NewInt(0).Sub(adjustedScore, HashToBigint(amountToRemove)))
}

// ComputeImpactMultiple ...
//
// TODO: Delete all of this crap. It was originally used because we were trying to
// represent an int256 as a uint256 that sorts via big-endian, but we pushed all
// the complexity around this to the db side so that none of this is needed anymore
// (although it still works, which is why I don't want to delete it jsut yet).
func ComputeImpactMultiple(blockHeight uint32, halfLifeBlocks uint32) *big.Int {
	// All we're trying to do here is multiply score adjustments by a factor of two
	// for each halflife period that passes. For example, if the half-life is 6 months
	// and 12 months have passed, we want to multiply score adjustments by a factor
	// of 2^(2 = # of half-lives that have passed). This has the effect of effectively
	// exponentially decaying the impact of older adjustments, but doing it this way
	// makes it so that updating scores is easier.
	//
	// In between half-lives, we also want to interpolate between the last factor of two
	// and the next factor of two.
	//
	// The end result is the following formula, implemnented using gross Go bigint math
	// below:
	// - halfLifePeriodsPassed := floor(blockHeight / halfLifeBlocks
	// - blocksSinceLastPeriod := blockHeight % halfLifeBlocks
	// - multiple := 2^{halfLifePeriodsPassed} (1 + blocksSinceLastPeriod / halfLifeBlocks)

	// Note we actually want integer division for this.
	halfLifePeriodsPassed := blockHeight / halfLifeBlocks
	blocksSinceLastPeriod := blockHeight % halfLifeBlocks

	// 1 * 2^{halfLifePeriodsPassed}
	multipleLeft := big.NewInt(0).Exp(big.NewInt(2), big.NewInt(int64(halfLifePeriodsPassed)), nil)
	// 2^{halfLifePeriodsPassed} * blocksSinceLastPeriod / halfLifeBlocks
	multipleRight := big.NewInt(0).Mul(multipleLeft, big.NewInt(int64(blocksSinceLastPeriod)))
	multipleRight = big.NewInt(0).Div(multipleRight, big.NewInt(int64(halfLifeBlocks)))

	// 2^{halfLifePeriodsPassed} + 2^{halfLifePeriodsPassed} * blocksSinceLastPeriod / halfLifeBlocks)
	// = 2^{halfLifePeriodsPassed} (1 + blocksSinceLastPeriod / halfLifeBlocks)
	return big.NewInt(0).Add(multipleLeft, multipleRight)
}

// ScoreMinusImpact ...
//
// TODO: Delete all of this crap. It was originally used because we were trying to
// represent an int256 as a uint256 that sorts via big-endian, but we pushed all
// the complexity around this to the db side so that none of this is needed anymore
// (although it still works, which is why I don't want to delete it jsut yet).
func ScoreMinusImpact(score *big.Int, amountToRemove int64, blockHeight uint32, params *UltranetParams) *big.Int {
	halfLifeBlocks := BlocksPerDuration(params.MerchantScoreHalfLife, params.TimeBetweenBlocks)

	// We adjust the amount we are removing by a multiple computed based on the block
	// height. We do this so that we can effectively exponentially decay older score
	// adjustments compared to new score adjustments. This multiplier is also why we
	// use BigInts to do everything rather than just uint64s.
	impactMultipleBigint := ComputeImpactMultiple(blockHeight, halfLifeBlocks)
	adjustedAmount := big.NewInt(0).Mul(impactMultipleBigint, big.NewInt(amountToRemove))

	// Let z be the adjustment we make to a score to prevent it from being a
	// negative value. In this case we have:
	// - score = (s + z)
	// - amountToRemove = a
	// If we were to naively subtract them we would have:
	// - score + amountToRemove = s + z - a
	// Which is actually exactly what we want.
	return big.NewInt(0).Sub(score, adjustedAmount)
	//return BigintToHash(big.NewInt(0).Sub(HashToBigint(score), adjustedAmount))
}

// ScorePlusImpact ...
func ScorePlusImpact(score *big.Int, amountToAdd int64, blockHeight uint32, params *UltranetParams) *big.Int {
	halfLifeBlocks := BlocksPerDuration(params.MerchantScoreHalfLife, params.TimeBetweenBlocks)

	// We adjust the amount we are adding by a multiple computed based on the block
	// height. We do this so that we can effectively exponentially decay older score
	// adjustments compared to new score adjustments. This multiplier is also why we
	// use BigInts to do everything rather than just uint64s.
	impactMultipleBigint := ComputeImpactMultiple(blockHeight, halfLifeBlocks)
	adjustedAmount := big.NewInt(0).Mul(impactMultipleBigint, big.NewInt(amountToAdd))

	// Let z be the adjustment we make to a score to prevent it from being a
	// negative value. In this case we have:
	// - score = (s + z)
	// - amountToAdd = a
	// If we were to naively add them we would have:
	// - score + amountToAdd = s + a + z
	// Which is actually exactly what we want.
	return big.NewInt(0).Add(score, adjustedAmount)
	//return BigintToHash(big.NewInt(0).Add(HashToBigint(score), adjustedAmount))
}

const (
	// MinUsernameLengthBytes ...
	MinUsernameLengthBytes = 1
	// MaxUsernameLengthBytes ...
	MaxUsernameLengthBytes = 120
	// MaxMerchantDescriptionLengthBytes ...
	MaxMerchantDescriptionLengthBytes = 2000
	// MaxBuyerMessageLengthBytes is the maximum number of bytes of encrypted
	// data a buyer is allowed to include in an order transaction.
	MaxBuyerMessageLengthBytes = 10000
	// MaxReviewLengthBytes  is the maximum number of bytes of data a user is
	// allowed to use to post a review.
	MaxReviewLengthBytes = 1000
	// MaxRejectReasonLengthBytes is the maximum number of bytes of encrypted
	// data a merchant is allowed to include in a reject transaction.
	MaxRejectReasonLengthBytes = 1000
	// MaxPrivateMessageLengthBytes is the maximum number of bytes of encrypted
	// data a private message is allowed to include in an PrivateMessage transaction.
	MaxPrivateMessageLengthBytes = 10000
)

// MerchantStats contains values used to compute a merchant's reputation score.
// They are hashed along with the other merchant data and should be verifiable
// by light clients.
type MerchantStats struct {
	// For context, define the following terms:
	// - payment = the full amount the buyer paid
	// - commissions = commission_rate * payment
	// - revenue (for merchant) = payment - commissions
	//
	// We track the quantities below for each merchant and use them to compute
	// a reputation score that can give the user confidence in this merchant's
	// sales history.
	//
	// BurnNanos is the amount of Ultra a merchant has burned directly. Merchants
	// can directly burn Ultra to quickly improve their reputation score.
	AmountBurnedNanos uint64
	// AmountPlacedNanos is the amount of Ultra that is currently locked in
	// "placed" orders by buyers.
	PaymentPlacedNanos uint64
	// AmountRejectedNanos is the amount of Ultra in transactions that the merchant
	// has rejected.
	PaymentRejectedNanos uint64
	// AmountCanceledNanos is the amount of Ultra in transactions that users have
	// placed then canceled with this merchant.
	PaymentCanceledNanos uint64
	// AmountCommissionsNanos is the total amount of commissions that have
	// been burned through transacting with a merchant. For simplicity and
	// to avoid perverse incentives, once commissions are computed and added
	// to this variable(which happens when an order is confirmed), they cannot
	// be reimbursed to anyone. In that sense, this amount represents Ultra
	// that has been "permanently burned" through interacting with the merchant.
	CommissionsNanos uint64
	// RevenueConfirmedNanos is the amount of Ultra the merchant has earned from
	// transactions that are currently in the "confirmed" state. It is the user's
	// payment minus commissions.
	RevenueConfirmedNanos uint64
	// RevenueFulfilledNanos is the amount of Ultra the merchant has earned from
	// transactions currently in the "fulfilled" state. When an order has been
	// in the "confirmed" state for some period of time, the merchant gets the
	// option to mark it as "fulfilled," which changes how the order impacts
	// her reputation.
	RevenueFulfilledNanos uint64

	// Revenue associated with each type of review.
	RevenueNegativeNanos uint64
	RevenueNeutralNanos  uint64
	RevenuePositiveNanos uint64

	// RevenueRefundedNanos is the total amount of revenue the merchant has
	// decided to refund to buyers. It corresponds to orders in the "refunded"
	// state. Note that when a refund is processed, only the revenue (i.e. the
	// buyer's payment minus the commission) is refunded. For simplicity and
	// to avoid perverse incentives, commissions cannot be reimbursed once an
	// order is confirmed.
	RevenueRefundedNanos uint64

	// The score for this merchant expressed as a big-endian big-integer
	// string of bytes.
	MerchantScore *big.Int

	// Keep some very high-level indications of recent activity so that light
	// clients can verify that the merchant is active. For example, if the
	// last striken order happened very recently then the user can have
	// some suspicion that the merchant is currently executing an exit scam.
	LastPlacedOrderHeight         uint32
	LastRejectedOrderHeight       uint32
	LastCanceledOrderHeight       uint32
	LastFulfilledOrderHeight      uint32
	LastConfirmedOrderHeight      uint32
	LastNegativeReviewOrderHeight uint32
	LastNeturalReviewOrderHeight  uint32
	LastPositiveReviewOrderHeight uint32
	LastRefundedOrderHeight       uint32
}

// MerchantEntry identifies the data associated with a merchant.
type MerchantEntry struct {
	// Username is a unique human-readable identifier associated with a merchant.
	Username []byte

	// PublicKey is the key used by the merchant to sign for things and generally
	// verify her identity.
	PublicKey []byte

	// The entry's position in the list of merchant entries stored by
	// all nodes.
	Pos uint64

	// Some text about the merchant.
	Description []byte

	Stats *MerchantStats

	// The fields below aren't serialized or hashed. They are only kept
	// around for in-memory bookkeeping purposes.

	// Whether or not this entry should be deleted when the view is flushed
	// to the db. This is initially set to false, but can become true if for
	// example we update a merchant entry and need to delete the data associated
	// with the old entry.
	isDeleted bool

	// Each merchant has a unique id that is the hash of the txn they used to
	// register themselves.
	merchantID *BlockHash
}

func (mm *MerchantEntry) String() string {
	return fmt.Sprintf(
		" < Username: %s, PublicKey: %s, Pos: %d, isDeleted: %v, merchantID: %v > ",
		string(mm.Username), PkToStringMainnet(mm.PublicKey), mm.Pos, mm.isDeleted, mm.merchantID)
}

// UtxoEntry identifies the data associated with a UTXO.
type UtxoEntry struct {
	AmountNanos   uint64
	PublicKey     []byte
	BlockHeight   uint32
	IsBlockReward bool

	// The UTXO's position in the utxo set. This is important because all
	// nodes compute a merkle root of the utxos and therefore need to be
	// in sync on where a particular utxo is in the set.
	Pos uint64

	// The fields below aren't serialized or hashed. They are only kept
	// around for in-memory bookkeeping purposes.

	// Whether or not the UTXO is spent. This is not used by the database,
	// (in fact it's not even stored in the db) it's used
	// only by the in-memory data structure. The database is simple: A UTXO
	// is unspent if and only if it exists in the db. However, for the view,
	// a UTXO is unspent if it (exists in memory and is unspent) OR (it does not
	// exist in memory at all but does exist in the database).
	//
	// Note that we are relying on the code that serializes the entry to the
	// db to ignore private fields, which is why this variable is lowerCamelCase
	// rather than UpperCamelCase. We are also relying on it defaulting to
	// false when newly-read from the database.
	isSpent bool

	// A back-reference to the utxo key associated with this entry.
	utxoKey *UtxoKey
}

func (utxoEntry *UtxoEntry) String() string {
	return fmt.Sprintf("< PublicKey: %v, BlockHeight: %d, AmountNanos: %d, IsBlockReward: %v, "+
		"Pos: %d, isSpent: %v, utxoKey: %v>", PkToStringMainnet(utxoEntry.PublicKey),
		utxoEntry.BlockHeight, utxoEntry.AmountNanos,
		utxoEntry.IsBlockReward, utxoEntry.Pos, utxoEntry.isSpent, utxoEntry.utxoKey)
}

// UsernameMapKey ...
// Have to define these because Go doesn't let you use raw byte slices as map keys.
type UsernameMapKey [MaxUsernameLengthBytes]byte

// PkMapKey ...
type PkMapKey [btcec.PubKeyBytesLenCompressed]byte

// MakePkMapKey ...
func MakePkMapKey(pk []byte) PkMapKey {
	pkMapKey := PkMapKey{}
	copy(pkMapKey[:], pk)
	return pkMapKey
}

// MakeMessageKey ...
func MakeMessageKey(pk []byte, tstampNanos uint64) MessageKey {
	pkMapKey := MakePkMapKey(pk)
	return MessageKey{
		PublicKey:   pkMapKey,
		TstampNanos: tstampNanos,
	}
}

// MessageKey ...
type MessageKey struct {
	PublicKey   PkMapKey
	BlockHeight uint32
	TstampNanos uint64
}

func (mm *MessageKey) String() string {
	return fmt.Sprintf("<Public Key: %s, TstampNanos: %d>",
		PkToStringMainnet(mm.PublicKey[:]), mm.TstampNanos)
}

// StringKey is useful for creating maps that need to be serialized to JSON.
func (mm *MessageKey) StringKey(params *UltranetParams) string {
	return PkToString(mm.PublicKey[:], params) + string(UintToBuf(mm.TstampNanos))
}

// MessageEntry stores the essential content of a message transaction.
type MessageEntry struct {
	SenderPublicKey    []byte
	RecipientPublicKey []byte
	EncryptedText      []byte
	// TODO: Right now a sender can fake the timestamp and make it appear to
	// the recipient that she sent messages much earlier than she actually did.
	// This isn't a big deal because there is generally not much to gain from
	// faking a timestamp, and it's still impossible for a user to impersonate
	// another user, which is the important thing. Moreover, it is easy to fix
	// the timestamp spoofing issue: You just need to make it so that the nodes
	// index messages based on block height in addition to on the tstamp. The
	// reason I didn't do it yet is because it adds some complexity around
	// detecting duplicates, particularly if a transaction is allowed to have
	// zero inputs/outputs, which is advantageous for various reasons.
	TstampNanos uint64

	isDeleted bool
}

// UtxoView ...
type UtxoView struct {
	// Utxo data
	NumUtxoEntries     uint64
	UtxoKeyToUtxoEntry map[UtxoKey]*UtxoEntry
	PosToUtxoEntry     map[uint64]*UtxoEntry

	// Merchant data
	NumMerchantEntries        uint64
	UsernameToMerchantEntry   map[UsernameMapKey]*MerchantEntry
	PkToMerchantEntry         map[PkMapKey]*MerchantEntry
	PosToMerchantEntry        map[uint64]*MerchantEntry
	MerchantIDToMerchantEntry map[BlockHash]*MerchantEntry

	// Order data
	NumOrderEntries     uint64
	PosToOrderEntry     map[uint64]*OrderEntry
	OrderIDToOrderEntry map[BlockHash]*OrderEntry

	// BitcoinExchange data
	NanosPurchased   uint64
	BitcoinBurnTxIDs map[BlockHash]bool

	// Messages data
	MessageKeyToMessageData map[MessageKey]*MessageEntry

	// The hash of the tip the view is currently referencing. Mainly used
	// for error-checking when doing a bulk operation on the view.
	TipHash *BlockHash

	BitcoinManager *BitcoinManager
	Handle         *badger.DB
	Params         *UltranetParams
}

// OperationType ...
type OperationType uint

const (
	// OperationTypeAddUtxo ...
	OperationTypeAddUtxo OperationType = 0
	// OperationTypeSpendUtxo ...
	OperationTypeSpendUtxo OperationType = 1
	// OperationTypeAddMerchantEntry ...
	OperationTypeAddMerchantEntry OperationType = 2
	// OperationTypeUpdateMerchantEntry ...
	OperationTypeUpdateMerchantEntry OperationType = 3
	// OperationTypeAddOrderEntry ...
	OperationTypeAddOrderEntry OperationType = 4
	// OperationTypeCancelOrder ...
	OperationTypeCancelOrder OperationType = 5
	// OperationTypeRejectOrder ...
	OperationTypeRejectOrder OperationType = 6
	// OperationTypeConfirmOrder ...
	OperationTypeConfirmOrder OperationType = 7
	// OperationTypeFulfillOrder ...
	OperationTypeFulfillOrder OperationType = 8
	// OperationTypeReviewOrder ...
	OperationTypeReviewOrder OperationType = 9
	// OperationTypeRefundOrder ...
	OperationTypeRefundOrder OperationType = 10
	// OperationTypeBitcoinExchange ...
	OperationTypeBitcoinExchange OperationType = 11
	// OperationTypePrivateMessage ...
	OperationTypePrivateMessage OperationType = 12
)

// PrevOrderData contains order fields that could be modified during an order-related
// transaction. We are being a little lazy here by just saving all of these fields
// for every order transaction instead of saving strictly the fields that were
// modified by each order transaction. But doing it this way is much less likely to
// result in bugs, makes code that reverts orders much less redundant, and is
// still much more efficient (and much less lazy) than keeping a full copy of an
// order every time it's modified.
type PrevOrderData struct {
	// Indicates the OrderID of the order that was modified by this operation.
	OrderID                 *BlockHash
	State                   OrderState
	ReviewType              ReviewType
	ReviewText              []byte
	AmountLockedNanos       uint64
	ConfirmationBlockHeight uint32
	RejectReason            []byte
	LastModifiedBlock       uint32
	MerchantScoreImpact     *big.Int
}

func _getPrevOrderData(orderID *BlockHash, orderEntry *OrderEntry) *PrevOrderData {
	return &PrevOrderData{
		// The OrderID doesn't change after initial placement but it is required in order
		// to be able to look up the order entry during a roll-back.
		OrderID:                 orderID,
		State:                   orderEntry.State,
		ReviewType:              orderEntry.ReviewType,
		ReviewText:              orderEntry.ReviewText,
		AmountLockedNanos:       orderEntry.AmountLockedNanos,
		ConfirmationBlockHeight: orderEntry.ConfirmationBlockHeight,
		RejectReason:            orderEntry.RejectReason,
		LastModifiedBlock:       orderEntry.LastModifiedBlock,
		MerchantScoreImpact:     orderEntry.MerchantScoreImpact,

		// Note that PaymentAmountNanos never changes after an order is placed and so
		// there is no need to include it in this list.
	}
}

func _setPrevOrderData(orderEntry *OrderEntry, orderData *PrevOrderData) {
	orderEntry.State = orderData.State
	orderEntry.ReviewType = orderData.ReviewType
	orderEntry.ReviewText = orderData.ReviewText
	orderEntry.AmountLockedNanos = orderData.AmountLockedNanos
	orderEntry.ConfirmationBlockHeight = orderData.ConfirmationBlockHeight
	orderEntry.RejectReason = orderData.RejectReason
	orderEntry.LastModifiedBlock = orderData.LastModifiedBlock
	orderEntry.MerchantScoreImpact = orderData.MerchantScoreImpact
}

// MerchantUpdateData is data that is needed in order to revert a merchant
// update operation.
type MerchantUpdateData struct {
	PrevUsername          []byte
	PrevPublicKey         []byte
	PrevDescription       []byte
	PrevAmountBurnedNanos uint64
	PrevMerchantScore     *big.Int
}

func _getMerchantUpdateData(merchantEntry *MerchantEntry) *MerchantUpdateData {
	return &MerchantUpdateData{
		PrevUsername:          merchantEntry.Username,
		PrevPublicKey:         merchantEntry.PublicKey,
		PrevDescription:       merchantEntry.Description,
		PrevAmountBurnedNanos: merchantEntry.Stats.AmountBurnedNanos,
		PrevMerchantScore:     merchantEntry.Stats.MerchantScore,
	}
}

func _setMerchantUpdateData(merchantEntry *MerchantEntry, updateData *MerchantUpdateData) {
	merchantEntry.Username = updateData.PrevUsername
	merchantEntry.PublicKey = updateData.PrevPublicKey
	merchantEntry.Description = updateData.PrevDescription
	merchantEntry.Stats.AmountBurnedNanos = updateData.PrevAmountBurnedNanos
	merchantEntry.Stats.MerchantScore = updateData.PrevMerchantScore
}

// UtxoOperation ...
type UtxoOperation struct {
	Type OperationType

	// Only set for OperationTypeSpendUtxo
	//
	// When we SPEND a UTXO entry we delete it from the utxo set but we still
	// store its info in case we want to reverse
	// it in the future. This information is not needed for ADD since
	// reversing an ADD just means deleting an entry from the end of our list.
	//
	// SPEND works by swapping the UTXO we want to spend with the UTXO at
	// the end of the list and then deleting from the end of the list. Obviously
	// this is more efficient than deleting the element in-place and then shifting
	// over everything after it. In order to be able to undo this operation,
	// however, we need to store the original index of the item we are
	// spending/deleting. Reversing the operation then amounts to adding a utxo entry
	// at the end of the list and swapping with this index. Given this, the entry
	// we store here has its position set to the position it was at right before the
	// SPEND operation was performed.
	Entry *UtxoEntry

	// Only set for OperationTypeSpendUtxo
	//
	// Store the UtxoKey as well. This isn't necessary but it helps
	// with error-checking during a roll-back so we just keep it.
	//
	// TODO: We can probably delete this at some point and save some space. UTXOs
	// are probably our biggest disk hog so getting rid of this should materially
	// improve disk usage.
	Key *UtxoKey

	// The order fields that could have been modified as a result of this operation
	// and that are therefore saved in case we need to revert the order. Set for all
	// order operations except initial placement, which can be reverted without saving
	// any data (last order in the list can just be deleted).
	PrevOrderData *PrevOrderData

	// The stats the merchant had before this operation. Set for all order-related
	// transactions including after an initial order placement.
	PrevMerchantStats *MerchantStats

	// The data a merchant had set before this operation. Only set for rare mechant
	// update transactions. When unset (or nil) it means nothing changed.
	PrevMerchantUpdateData *MerchantUpdateData

	// Used to revert BitcoinExchange transaction.
	PrevNanosPurchased uint64
}

// Assumes the db Handle is already set on the view, but otherwise the
// initialization is full.
func (bav *UtxoView) _ResetViewMappingsAfterFlush() {
	// Utxo data
	bav.UtxoKeyToUtxoEntry = make(map[UtxoKey]*UtxoEntry)
	bav.PosToUtxoEntry = make(map[uint64]*UtxoEntry)
	bav.NumUtxoEntries = GetUtxoNumEntries(bav.Handle)

	// Merchant data
	bav.UsernameToMerchantEntry = make(map[UsernameMapKey]*MerchantEntry)
	bav.PkToMerchantEntry = make(map[PkMapKey]*MerchantEntry)
	bav.PosToMerchantEntry = make(map[uint64]*MerchantEntry)
	bav.MerchantIDToMerchantEntry = make(map[BlockHash]*MerchantEntry)
	bav.NumMerchantEntries = GetNumMerchantEntries(bav.Handle)

	// Order data
	bav.PosToOrderEntry = make(map[uint64]*OrderEntry)
	bav.OrderIDToOrderEntry = make(map[BlockHash]*OrderEntry)
	bav.NumOrderEntries = GetNumOrderEntries(bav.Handle)

	// BitcoinExchange data
	bav.NanosPurchased = DbGetNanosPurchased(bav.Handle)
	bav.BitcoinBurnTxIDs = make(map[BlockHash]bool)

	// Messages data
	bav.MessageKeyToMessageData = make(map[MessageKey]*MessageEntry)
}

// NewUtxoView ...
func NewUtxoView(
	_handle *badger.DB, _params *UltranetParams, _bitcoinManager *BitcoinManager) (*UtxoView, error) {

	view := UtxoView{
		Handle:         _handle,
		Params:         _params,
		BitcoinManager: _bitcoinManager,
		// Note that the TipHash does not get reset as part of
		// _ResetViewMappingsAfterFlush because it is not something that is affected by a
		// flush operation. Moreover, its value is consistent with the view regardless of
		// whether or not the view is flushed or not. Additionally the utxo view does
		// not concern itself with the header chain (see comment on GetBestHash for more
		// info on that).
		TipHash: DbGetBestHash(_handle, ChainTypeUltranetBlock /* don't get the header chain */),
	}
	// This function is generally used to reset the view after a flush has been performed
	// but we can use it here to initialize the mappings.
	view._ResetViewMappingsAfterFlush()

	return &view, nil
}

func (bav *UtxoView) _deleteUtxoMappings(utxoEntry *UtxoEntry) error {
	if utxoEntry.utxoKey == nil {
		return fmt.Errorf("_deleteUtxoMappings: utxoKey missing for utxoEntry %+v", utxoEntry)
	}

	// Deleting a utxo amounts to setting its mappings to point to an
	// entry that has (isSpent = true). So we create such an entry and set
	// the mappings to point to it.
	tombstoneEntry := *utxoEntry
	tombstoneEntry.isSpent = true

	// _setUtxoMappings will take this and use its fields to update the
	// mappings.
	// TODO: We're doing a double-copy here at the moment. We should make this more
	// efficient.
	return bav._setUtxoMappings(&tombstoneEntry)

	// Note at this point, the utxoEntry passed in is dangling and can
	// be re-used for another purpose if desired.
}

func (bav *UtxoView) _setUtxoMappings(utxoEntry *UtxoEntry) error {
	if utxoEntry.utxoKey == nil {
		return fmt.Errorf("_setUtxoMappings: utxoKey missing for utxoEntry %+v", utxoEntry)
	}

	bav.PosToUtxoEntry[utxoEntry.Pos] = utxoEntry
	bav.UtxoKeyToUtxoEntry[*utxoEntry.utxoKey] = utxoEntry

	return nil
}

func (bav *UtxoView) _getUtxoEntryForPos(pos uint64) *UtxoEntry {
	// Check that this position has a key in our position index
	utxoEntry, ok := bav.PosToUtxoEntry[pos]

	// If the utxo for this pos isn't in our in-memory data structure, fetch it from the
	// db.
	if !ok {
		utxoKey := GetUtxoKeyAtPosition(bav.Handle, pos)
		if utxoKey == nil {
			// This means the position isn't in our map and isn't populated in the
			// db so it must not have anything there. Return nil to signal this.
			return nil
		}
		// If we got the key then also load the entry from the db.
		utxoEntry = DbGetUtxoEntryForUtxoKey(bav.Handle, utxoKey)
		if utxoEntry == nil {
			// This really shouldn't happen. If the key is in the position index
			// then its entry should be in the db. Log an error message in case
			// it does.
			glog.Errorf("_getUtxoEntryForPos: Utxo key (%v) found in position "+
				"index in db but corresponding entry is missing; this should "+
				"never happen", utxoKey)
			return nil
		}
		// Also sanity check that the position of the entry is the same as the
		// position used to fetch it.
		if utxoEntry.Pos != pos {
			glog.Errorf("_getUtxoEntryForPos: Utxo key (%v) found in position "+
				"index in db but corresponding pos (%d) does not match the "+
				"pos used to fetch it (%d)", utxoKey, utxoEntry.Pos, pos)
			return nil
		}

		// Note that it is reasonable to set the utxo entry because the following
		// holds:
		//   (pos is unset on PosToUtxoKey AND this function is called) =>
		//   (the utxo entry corresponding to this key is unmodified)
		// This is easier to prove the contrapositive:
		//   (if the utxo entry corresponding to this key is modified) =>
		//   (then either pos is set on PosToUtxoKey or this function won't be called)
		// This holds because:
		// - Modifying a utxo entry the first time necessarily loads its position
		//   into PosToUtxoKey by the logic explained in GetUtxoEntryForUtxoKey
		// - After a pos is loaded into PosToUtxoKey the only way it can be removed
		//   is if that pos is deleted through a spend operation, which shrinks
		//   the size of the utxo list below the position of this utxo entry.
		// - The only way the position can be repopulated is by an Add operation,
		//   which sets a new item in this position without calling this function.
		// Thus once a utxo entry is modified, its pos will be set on all subsequent
		// calls to this function, making the logic below safe.
		//
		// Nevertheless, check and error in case this condition ever changes.
		if _, exists := bav.UtxoKeyToUtxoEntry[*utxoKey]; exists {
			glog.Errorf("_getUtxoEntryForPos: Utxo key (%v) found in position "+
				"index in db already has its entry set on the UtxoView; this "+
				"should never happen", utxoKey)
			return nil
		}

		// At this point we have the key and the entry corresponding to the
		// requested position loaded from the db. Set them on our data structures.
		// Note that isSpent should be false by default. Also note that a back-reference
		// to the utxoKey should be set on the utxoEntry by this function.
		utxoEntry.utxoKey = utxoKey
		if err := bav._setUtxoMappings(utxoEntry); err != nil {
			glog.Errorf("_getUtxoEntryForPos: Problem encountered setting utxo mapping %v", err)
			return nil
		}
	}

	return utxoEntry
}

// GetUtxoEntryForUtxoKey ...
func (bav *UtxoView) GetUtxoEntryForUtxoKey(utxoKey *UtxoKey) *UtxoEntry {
	utxoEntry, ok := bav.UtxoKeyToUtxoEntry[*utxoKey]
	// If the utxo entry isn't in our in-memory data structure, fetch it from the
	// db.
	if !ok {
		utxoEntry = DbGetUtxoEntryForUtxoKey(bav.Handle, utxoKey)
		if utxoEntry == nil {
			// This means the utxo is neither in our map nor in the db so
			// it doesn't exist. Return nil to signal that in this case.
			return nil
		}

		// Note that it is not immediately obvious that setting
		// the pos index is the correct thing to do. However, it turns out to
		// be OK because it holds that:
		//   (a utxo not in the view) =>
		//   (utxo's position has not yet been modified)
		// Which is the same as saying the contrapositive:
		//   (if a utxo's position has been previously modified) =>
		//   (then it must be in the view) =>
		//   (the code below won't trigger)
		// This holds because the only way a utxo in a particular position can
		// become modified is by the following exhaustive list of operations:
		// - Element added to the end of the utxo list without that position having
		//   previously been modified. Clearly the statement below is harmless in
		//   this case since the map will have nothing stored at that position.
		// - Element is deleted (spent) from the end of the utxo list without that position
		//   having previously been modified. The statement below is harmless because
		//   the map will have nothing stored at that position. Afterward the utxo
		//   for that position will be stored in the view and the code below will not
		//   be called again for that position.
		// - Swap two elements without their positions having been modified. The
		//   statement below is harmless because the view will have nothing stored
		//   in those positions. Afterward the utxos corresponding to both positions
		//   will be stored in the view and the code below will
		//   not be called again for those positions.
		//
		// Just in case this ever changes, though, we print an error message
		// if this happens.
		if _, exists := bav.PosToUtxoEntry[utxoEntry.Pos]; exists {
			glog.Errorf("GetUtxoEntryForUtxoKey: CRITICAL: Element in " +
				"position map in UtxoView is being overwritten")
			return nil
		}

		// At this point we have the utxo entry so load it
		// into our in-memory data structure for future reference. Note that
		// isSpent should be false by default. Also note that a back-reference
		// to the utxoKey should be set on the utxoEntry by this function.
		utxoEntry.utxoKey = utxoKey
		if err := bav._setUtxoMappings(utxoEntry); err != nil {
			glog.Errorf("GetUtxoEntryForUtxoKey: Problem encountered setting utxo mapping %v", err)
			return nil
		}
	}

	return utxoEntry
}

func (bav *UtxoView) _unSpendUtxo(utxoEntryy *UtxoEntry) error {
	// Operate on a copy of the entry in order to avoid bugs. Note that not
	// doing this could result in us maintaining a reference to the entry and
	// modifying it on subsequent calls to this function, which is bad.
	utxoEntryCopy := *utxoEntryy

	// If the utxoKey back-reference on the entry isn't set return an error.
	if utxoEntryCopy.utxoKey == nil {
		return fmt.Errorf("_unSpendUtxo: utxoEntry must have utxoKey set")
	}
	// Make sure isSpent is set to false. It should be false by default if we
	// read this entry from the db but set it in case the caller derived the
	// entry via a different method.
	utxoEntryCopy.isSpent = false

	// When we spent this utxo we swapped it with the utxo at the end and
	// deleted it from our utxo list. Now to reverse the spend we need to
	// effectively add the input utxo to the end and swap it into the position
	// it was in originally. This original position should be recorded in the
	// UtxoEntry passed in.

	// If the utxo is not being added to the end of the list then it's
	// being added in place of an existing utxo. Move that existing utxo
	// to the end before putting this utxo at that position in this case.
	utxoDestinationPos := utxoEntryCopy.Pos
	if utxoDestinationPos > bav.NumUtxoEntries {
		return fmt.Errorf(
			"_unSpendUtxo: Utxo position (%d) is greater than the number of utxos %d "+
				"when trying to unspend utxo (%v); this should never happen",
			utxoDestinationPos, bav.NumUtxoEntries, utxoEntryCopy.utxoKey)
	}
	if utxoDestinationPos != bav.NumUtxoEntries {

		// There should be a utxo at this position if it's not the end of
		// the list.
		utxoEntryAtDestination := bav._getUtxoEntryForPos(utxoDestinationPos)
		if utxoEntryAtDestination == nil || utxoEntryAtDestination.isSpent {
			return fmt.Errorf(
				"_unSpendUtxo: Expected utxo at position (%d) since it is not the end "+
					"of the list %d when trying to unspend utxo (%v)",
				utxoDestinationPos, bav.NumUtxoEntries, utxoEntryCopy.utxoKey)
		}

		// Assuming we found a utxo at this position, clear that position in
		// preparation for unadding the passed-in utxo.
		if err := bav._deleteUtxoMappings(utxoEntryAtDestination); err != nil {
			return errors.Wrapf(err, "_unSpendUtxo: Problem deleting entry: ")
		}

		// Add the entry in the position we just cleared to the end. We don't
		// need to make a copy here because the reference is dangling as of
		// the _deleteMappings call above.
		utxoEntryAtDestination.Pos = bav.NumUtxoEntries
		if err := bav._setUtxoMappings(utxoEntryAtDestination); err != nil {
			return errors.Wrapf(err, "_unSpendUtxo: Problem adding entry %v to the end "+
				"when trying to unspend %v: ",
				utxoEntryAtDestination.utxoKey, utxoEntryCopy.utxoKey)
		}
	}

	// At this point, the position referenced by the passed-in UTXO should be
	// cleared. Double-check this and then add the utxo entry to this position.
	deletedUtxo := bav._getUtxoEntryForPos(utxoEntryCopy.Pos)
	if !(deletedUtxo == nil || deletedUtxo.isSpent) {
		return fmt.Errorf(
			"_unSpendUtxo: Expected position %d to be empty when unspending utxo %v",
			utxoEntryCopy.Pos, utxoEntryCopy.utxoKey)
	}
	// Not setting this to a copy could cause issues down the road where we modify
	// the utxo passed-in on subsequent calls.
	if err := bav._setUtxoMappings(&utxoEntryCopy); err != nil {
		return err
	}

	// Since we re-added the utxo, bump the number of entries.
	bav.NumUtxoEntries++

	return nil
}

func (bav *UtxoView) _spendUtxo(utxoKey *UtxoKey) (*UtxoOperation, error) {
	// Swap this utxo's position with the utxo in the last position and delete it.

	// Get the entry for this utxo from the view if it's cached,
	// otherwise try and get it from the db.
	utxoEntry := bav.GetUtxoEntryForUtxoKey(utxoKey)
	if utxoEntry == nil {
		return nil, fmt.Errorf("_spendUtxo: Attempting to spend non-existent UTXO")
	}
	if utxoEntry.isSpent {
		return nil, fmt.Errorf("_spendUtxo: Attempting to spend an already-spent UTXO")
	}

	// Delete the entry by removing its mappings from our in-memory data
	// structures.
	if err := bav._deleteUtxoMappings(utxoEntry); err != nil {
		return nil, errors.Wrapf(err, "_spendUtxo: ")
	}

	// Get the index of the last entry.
	lastIndex := bav.NumUtxoEntries - 1

	if utxoEntry.Pos >= bav.NumUtxoEntries {
		return nil, fmt.Errorf(
			"_spendUtxo: Utxo at position (%d) is >= the current size "+
				"of the list %d when trying to spend utxo (%v); this should never happen",
			utxoEntry.Pos, bav.NumUtxoEntries, utxoEntry.utxoKey)
	}

	// If this entry was not at the end of the list, move the entry at the
	// end of the list into its place. This keeps our list of UTXOs contiguous
	// by position.
	if lastIndex != utxoEntry.Pos {
		// Fetch the entry at the end and make sure it's unspent.
		lastUtxoEntry := bav._getUtxoEntryForPos(lastIndex)
		if lastUtxoEntry == nil || lastUtxoEntry.isSpent {
			return nil, fmt.Errorf("_spendUtxo: Problem getting last utxo entry (%v)", lastUtxoEntry)
		}

		// Delete it from its current position by removing the mappings for it
		// at its current position.
		if err := bav._deleteUtxoMappings(lastUtxoEntry); err != nil {
			return nil, errors.Wrapf(err, "_spendUtxo: ")
		}

		// Set its position to that of the utxo we just deleted and set its mappings
		// in the db appropriately. We don't need to make a copy of it here because it
		// is dangling as of the deleteMappings call above.
		lastUtxoEntry.Pos = utxoEntry.Pos
		if err := bav._setUtxoMappings(lastUtxoEntry); err != nil {
			return nil, errors.Wrapf(err, "_spendUtxo: ")
		}

		// The last entry has now effectively been moved into the space of the
		// utxo passed-in that we just deleted.
	}

	// Decrement the number of entries by one since we marked one as spent in the
	// view.
	bav.NumUtxoEntries--

	// Record a UtxoOperation in case we want to roll this back in the
	// future. At this point, the UtxoEntry passed in still has all of its
	// fields set to what they were right before SPEND was called. This is
	// exactly what we want (see comment on OperationTypeSpendUtxo for more info).
	// Make a copy of the entry to avoid issues where we accidentally modify
	// the entry in the future.
	utxoEntryCopy := *utxoEntry
	return &UtxoOperation{
		Type:  OperationTypeSpendUtxo,
		Key:   utxoKey,
		Entry: &utxoEntryCopy,
	}, nil
}

func (bav *UtxoView) _unAddUtxo(utxoKey *UtxoKey) error {
	// Get the entry for this utxo from the view if it's cached,
	// otherwise try and get it from the db.
	utxoEntry := bav.GetUtxoEntryForUtxoKey(utxoKey)
	if utxoEntry == nil {
		return fmt.Errorf("_unAddUtxo: Attempting to remove non-existent UTXO")
	}
	if utxoEntry.isSpent {
		return fmt.Errorf("_unAddUtxo: Attempting to remove an already-spent UTXO")
	}
	// Sanity check that the utxo entry is being deleted from the end.
	lastPos := bav.NumUtxoEntries - 1
	if utxoEntry.Pos != lastPos {
		return fmt.Errorf("_unAddUtxo: utxoEntry has position %d != "+
			"(NumUtxoEntries - 1 = %d)", utxoEntry.Pos, lastPos)
	}

	// At this point we should have the entry sanity-checked. To remove
	// it from our data structure, it is sufficient to replace it with an
	// entry that is marked as spent. When the view is eventually flushed
	// to the database the output's status as spent will translate to it
	// getting deleted, which is what we want.
	if err := bav._deleteUtxoMappings(utxoEntry); err != nil {
		return err
	}

	// In addition to marking the output as spent, we update the number of
	// entries to reflect the output is no longer in our utxo list.
	bav.NumUtxoEntries--

	return nil
}

// Note: We assume that the person passing in the utxo key and the utxo entry
// aren't going to modify them after.
func (bav *UtxoView) _addUtxo(utxoEntryy *UtxoEntry) (*UtxoOperation, error) {
	// Use a copy of the utxo passed in so we avoid keeping a reference to it
	// which could be modified in subsequent calls.
	utxoEntryCopy := *utxoEntryy

	// If the utxoKey back-reference on the entry isn't set then error.
	if utxoEntryCopy.utxoKey == nil {
		return nil, fmt.Errorf("_addUtxo: utxoEntry must have utxoKey set")
	}
	// If the UtxoEntry passed in has isSpent set then error. The caller should only
	// pass in entries that are unspent.
	if utxoEntryCopy.isSpent {
		return nil, fmt.Errorf("_addUtxo: UtxoEntry being added has isSpent = true")
	}
	// As a sanity check, make sure the position at the end of the list is empty or
	// contains a deleted entry.
	{
		lastEntry := bav._getUtxoEntryForPos(bav.NumUtxoEntries)
		if lastEntry != nil && !lastEntry.isSpent {
			return nil, fmt.Errorf("_addUtxo: UtxoEntry at pos %d exists and is not marked as spent", bav.NumUtxoEntries)
		}
	}

	// Put the utxo at the end and update our in-memory data structures with
	// this change.
	//
	// Note this may over-write an existing entry but this is OK for a very subtle
	// reason. When we roll back a transaction, e.g. due to a
	// reorg, we mark the outputs of that transaction as "spent" but we don't delete them
	// from our view because doing so would cause us to neglect to actually delete them
	// when we flush the view to the db. What this means is that if we roll back a transaction
	// in a block but then add it later in a different block, that second add could
	// over-write the entry that is currently has isSpent=true with a similar (though
	// not identical because the block height may differ) entry that has isSpent=false.
	// This is OK however because the new entry we're over-writing the old entry with
	// has the same key and so flushing the view to the database will result in the
	// deletion of the old entry as intended when the new entry over-writes it. Put
	// simply, the over-write that could happen here is an over-write we also want to
	// happen when we flush and so it should be OK.
	utxoEntryCopy.Pos = bav.NumUtxoEntries
	if err := bav._setUtxoMappings(&utxoEntryCopy); err != nil {
		return nil, errors.Wrapf(err, "_addUtxo: ")
	}

	// Bump the number of entries since we just added this one at the end.
	bav.NumUtxoEntries++

	// Finally record a UtxoOperation in case we want to roll back this ADD
	// in the future. Note that Entry data isn't required for an ADD operation.
	return &UtxoOperation{
		Type: OperationTypeAddUtxo,
	}, nil
}

func (bav *UtxoView) _disconnectBasicTransfer(currentTxn *MsgUltranetTxn, txnHash *BlockHash, utxoOpsForTxn []*UtxoOperation, blockHeight uint32) error {

	// Loop through the transaction's outputs backwards and remove them
	// from the view. Since the outputs will have been added to the view
	// at the end of the utxo list, removing them from the view amounts to
	// removing the last element from the utxo list.
	//
	// Loop backwards over the utxo operations as we go along.
	operationIndex := len(utxoOpsForTxn) - 1
	for outputIndex := len(currentTxn.TxOutputs) - 1; outputIndex >= 0; outputIndex-- {
		currentOutput := currentTxn.TxOutputs[outputIndex]

		// Compute the utxo key for this output so we can reference it in our
		// data structures.
		outputKey := &UtxoKey{
			TxID:  *txnHash,
			Index: uint32(outputIndex),
		}

		// Verify that the utxo operation we're undoing is an add and advance
		// our index to the next operation.
		currentOperation := utxoOpsForTxn[operationIndex]
		operationIndex--
		if currentOperation.Type != OperationTypeAddUtxo {
			return fmt.Errorf(
				"_disconnectBasicTransfer: Output with key %v does not line up to an "+
					"ADD operation in the passed utxoOps", outputKey)
		}

		// The current output should be at the end of the utxo list so go
		// ahead and fetch it. Do some sanity checks to make sure the view
		// is in sync with the operations we're trying to perform.
		outputEntry := bav.GetUtxoEntryForUtxoKey(outputKey)
		if outputEntry == nil {
			return fmt.Errorf(
				"_disconnectBasicTransfer: Output with key %v is missing from "+
					"utxo view", outputKey)
		}
		if outputEntry.isSpent {
			return fmt.Errorf(
				"_disconnectBasicTransfer: Output with key %v was spent before "+
					"being removed from the utxo view. This should never "+
					"happen", outputKey)
		}
		if outputEntry.Pos != (bav.NumUtxoEntries - 1) {
			return fmt.Errorf(
				"_disconnectBasicTransfer: Output with key %v was being removed "+
					"from the end of the utxo view list but is not actually at "+
					"the end", outputKey)
		}
		if outputEntry.AmountNanos != currentOutput.AmountNanos {
			return fmt.Errorf(
				"_disconnectBasicTransfer: Output with key %v has amount (%d) "+
					"that differs from the amount for the output in the "+
					"view (%d)", outputKey, currentOutput.AmountNanos,
				outputEntry.AmountNanos)
		}
		if !reflect.DeepEqual(outputEntry.PublicKey, currentOutput.PublicKey) {
			return fmt.Errorf(
				"_disconnectBasicTransfer: Output with key %v has public key (%v) "+
					"that differs from the public key for the output in the "+
					"view (%v)", outputKey, currentOutput.PublicKey,
				outputEntry.PublicKey)
		}
		if outputEntry.BlockHeight != blockHeight {
			return fmt.Errorf(
				"_disconnectBasicTransfer: Output with key %v has block height (%d) "+
					"that differs from the block we're disconnecting (%d)",
				outputKey, outputEntry.BlockHeight, blockHeight)
		}
		if outputEntry.IsBlockReward && (currentTxn.TxnMeta.GetTxnType() != TxnTypeBlockReward) {
			return fmt.Errorf(
				"_disconnectBasicTransfer: Output with key %v is a block reward txn according "+
					"to the view, yet is not the first transaction referenced in "+
					"the block", outputKey)
		}

		if err := bav._unAddUtxo(outputKey); err != nil {
			return errors.Wrapf(err, "_disconnectBasicTransfer: Problem unAdding utxo %v: ", outputKey)
		}
	}

	// At this point we should have rolled back all of the transaction's outputs
	// in the view. Now we roll back its inputs, similarly processing them in
	// backwards order.
	for inputIndex := len(currentTxn.TxInputs) - 1; inputIndex >= 0; inputIndex-- {
		currentInput := currentTxn.TxInputs[inputIndex]

		// Convert this input to a utxo key.
		inputKey := UtxoKey(*currentInput)

		// Get the output entry for this input from the utxoOps that were
		// passed in and check its type. For every input that we're restoring
		// we need a SPEND operation that lines up with it.
		currentOperation := utxoOpsForTxn[operationIndex]
		operationIndex--
		if currentOperation.Type != OperationTypeSpendUtxo {
			return fmt.Errorf(
				"_disconnectBasicTransfer: Input with key %v does not line up with a "+
					"SPEND operation in the passed utxoOps", inputKey)
		}

		// Check that the input matches the key of the spend we're rolling
		// back.
		if inputKey != *currentOperation.Key {
			return fmt.Errorf(
				"_disconnectBasicTransfer: Input with key %v does not match the key of the "+
					"corresponding SPEND operation in the passed utxoOps %v",
				inputKey, *currentOperation.Key)
		}

		// Unspend the entry using the information in the UtxoOperation. If the entry
		// was de-serialized from the db it will have its utxoKey unset so we need to
		// set it here in order to make it unspendable.
		currentOperation.Entry.utxoKey = currentOperation.Key
		if err := bav._unSpendUtxo(currentOperation.Entry); err != nil {
			return errors.Wrapf(err, "_disconnectBasicTransfer: Problem unspending utxo %v: ", currentOperation.Key)
		}
	}

	return nil
}

func (bav *UtxoView) _disconnectRegisterMerchant(currentTxn *MsgUltranetTxn, txnHash *BlockHash, utxoOpsForTxn []*UtxoOperation, blockHeight uint32) error {
	// For this we have to go in the reverse order:
	// 	Remove the merchant add operation
	//  Disconnect the transaction

	// We'll be going through the utxo operations backward using this
	// index variable.
	operationIndex := len(utxoOpsForTxn) - 1

	// Start by ensuring that the last operation is a merchant add.
	if len(utxoOpsForTxn) == 0 {
		return fmt.Errorf("_disconnectRegisterMerchant: utxoOperations are missing")
	}
	if utxoOpsForTxn[operationIndex].Type != OperationTypeAddMerchantEntry {

		return fmt.Errorf("_disconnectRegisterMerchant: Trying to revert "+
			"OperationTypeAddMerchantEntry but found %v",
			utxoOpsForTxn[operationIndex].Type)
	}

	// Now we know we are reverting a merchant add so do that part.
	// Merchants are added to the end of the merchant list so reversion requires
	// simply removing the data for the last merchant.

	// Get the index of the last merchant.
	merchantIndex := bav.NumMerchantEntries - 1
	// Use the index to load all the other data into the view if it isn't already
	// loaded.
	merchantEntry := bav._getMerchantEntryForPos(merchantIndex)
	if merchantEntry == nil || merchantEntry.isDeleted {
		// If we don't find the MerchantID for the merchant in this position that's an
		// error.
		return fmt.Errorf("_disconnectRegisterMerchant: Could not find hash "+
			"for position %d even though NumMerchantEntries=%d",
			merchantIndex, bav.NumMerchantEntries)
	}

	// Deleting the mappings associated with a merchant by setting them to point
	// to something that has isDeleted = true is sufficient to result in the
	// deletion of this merchant's data when the view is flushed.
	bav._deleteMerchantMappings(merchantEntry)

	// Decrement the number of merchant entries since we just removed one.
	bav.NumMerchantEntries--

	// Note that although the register merchant txn may have burned some Ultra,
	// this Ultra will be restored when the inputs are restored by the basic transfer
	// disconnect code below. The merchant burn is basically a large implicit
	// txn fee as far as that code is concerned, and treating it as such results
	// in the proper behavior without needing any special casing.

	// Now revert the basic transfer with the remaining operations. Cut off
	// the merchant add operation at the end since we just reverted it.
	return bav._disconnectBasicTransfer(
		currentTxn, txnHash, utxoOpsForTxn[:operationIndex], blockHeight)
}

func (bav *UtxoView) _disconnectUpdateMerchant(currentTxn *MsgUltranetTxn, txnHash *BlockHash, utxoOpsForTxn []*UtxoOperation, blockHeight uint32) error {
	// For this we have to go in the reverse order:
	// 	Remove the merchant update operation
	//  Disconnect the transaction

	// We'll be going through the utxo operations backward using this
	// index variable.
	operationIndex := len(utxoOpsForTxn) - 1

	// Start by ensuring that the last operation is a merchant update.
	if len(utxoOpsForTxn) == 0 {
		return fmt.Errorf("_disconnectUpdateMerchant: utxoOperations are missing")
	}
	if utxoOpsForTxn[operationIndex].Type != OperationTypeUpdateMerchantEntry {

		return fmt.Errorf("_disconnectUpdateMerchant: Trying to revert "+
			"OperationTypeUpdateMerchantEntry but found %v",
			utxoOpsForTxn[operationIndex].Type)
	}
	updateOp := utxoOpsForTxn[operationIndex]
	txMeta := currentTxn.TxnMeta.(*UpdateMerchantMetadata)

	// Now we know we are reverting a merchant update so do that part.

	// Load the current entry for the merchant. It should be sufficient to
	// use the MerchantID from the txn to do this since the merchant must
	// already exist in the db or in our in-memory mappings with this id.
	entryToRevert := bav._getMerchantEntryForMerchantID(txMeta.MerchantID)
	if entryToRevert == nil || entryToRevert.isDeleted {
		// If we don't find the entry to revert return an error.
		return fmt.Errorf("_disconnectUpdateMerchant: Could not find merchant "+
			"entry for MerchantID %+v",
			txMeta.MerchantID)
	}

	// Since we are reverting this entry, go ahead and delete it from all of
	// our in-memory mappings. Doing this will free the entry struct we currently
	// have a pointer to so we can un-update it.
	bav._deleteMerchantMappings(entryToRevert)

	// Revert the fields of this entry using the data in the update operation.
	_setMerchantUpdateData(entryToRevert, updateOp.PrevMerchantUpdateData)

	// entryToRevert should now be in the state the merchant entry was in before
	// the update operation. As such we can now update our mappings to point to
	// it appropriately.
	bav._setMerchantMappings(entryToRevert)

	// Note that although the update merchant txn may have burned some Ultra,
	// this Ultra will be restored when the inputs are restored by the basic transfer
	// disconnect code below. The merchant burn is basically a large implicit
	// txn fee as far as that code is concerned, and treating it as such results
	// in the proper behavior without needing any special casing.
	//
	// Note the important thing is that the burn amount in the merchant entry
	// was reverted by the _setMerchantUpdateData call above.

	// Now revert the basic transfer with the remaining operations. Cut off
	// the merchant update operation at the end since we just reverted it.
	return bav._disconnectBasicTransfer(
		currentTxn, txnHash, utxoOpsForTxn[:operationIndex], blockHeight)
}

// _getOrderIDForPos ...
func (bav *UtxoView) _getOrderEntryForPos(pos uint64) *OrderEntry {
	// Check if this entry exists in our map already.
	orderEntry, exists := bav.PosToOrderEntry[pos]

	// If the orderEntry for this pos doesn't exist in memory then try
	// and look it up in the db.
	if !exists {
		orderID := GetOrderIDForPos(bav.Handle, pos)
		if orderID == nil {
			// If the orderID doesn't exist in the db it means an entry for this
			// orderID hasn't been created yet and we can return nil to signal this.
			return nil
		}

		// If we got here it means an OrderID exists in the db for this position.

		// Fetch the entry for this OrderID.
		orderEntry = DbGetOrderEntryForOrderID(bav.Handle, orderID)
		if orderEntry == nil {
			// This is technically an error but just return nil to keep the API
			// simple.
			glog.Errorf("_getOrderIDForPos: Found OrderID (%+v) for pos "+
				"%d but missing corresponding entry data", orderID, pos)
			return nil
		}

		// Sanity-check that the position in the entry matches the position
		// used to fetch it.
		if orderEntry.Pos != pos {
			glog.Errorf("_getOrderIDForPos: Found OrderID (%+v) for pos "+
				"%d but pos in entry (%d) differs", orderID, pos, orderEntry.Pos)
			return nil
		}

		// At this point we have an OrderID and an OrderEntry for the entry at
		// this position so set the fields on our in-memory data structures.
		orderEntry.orderID = orderID
		if err := bav._setOrderMappings(orderEntry); err != nil {
			glog.Errorf("_getOrderIDForPos: Problem setting mappings for OrderID (%+v) for pos "+
				"%d: %v", orderID, pos, err)
			return nil
		}
	}

	return orderEntry
}

func (bav *UtxoView) _getOrderEntryForOrderID(orderID *BlockHash) *OrderEntry {
	// Check if this entry exists in our map already.
	orderEntry, exists := bav.OrderIDToOrderEntry[*orderID]

	// If the entry for this pos doesn't exist, try and look it up in the db.
	if !exists {
		orderEntry = DbGetOrderEntryForOrderID(bav.Handle, orderID)
		if orderEntry == nil {
			// If the entry doesn't exist in the db it means an entry for this
			// OrderID hasn't been created yet and we can return nil to signal this.
			return nil
		}

		// If we got here it means an entry exists in the db for this OrderID.

		// At this point we have an OrderID and an OrderEntry for the entry at
		// this position so set the fields on our in-memory data structures.
		orderEntry.orderID = orderID
		if err := bav._setOrderMappings(orderEntry); err != nil {
			glog.Errorf("_getOrderIDForPos: Problem setting mappings for OrderID (%+v): %v",
				orderID, err)
			return nil
		}
	}

	return orderEntry
}

func (bav *UtxoView) _disconnectPlaceOrder(currentTxn *MsgUltranetTxn, txnHash *BlockHash, utxoOpsForTxn []*UtxoOperation, blockHeight uint32) error {
	// For this we have to go in the reverse order:
	// 	Remove the order add operation
	//  Disconnect the basic transfer

	// Check that the last operation has OperationTypeAddOrderEntry.
	operationIndex := len(utxoOpsForTxn) - 1
	if len(utxoOpsForTxn) == 0 {
		return fmt.Errorf("_disconnectPlaceOrder: utxoOperations are missing")
	}
	if utxoOpsForTxn[operationIndex].Type != OperationTypeAddOrderEntry {
		return fmt.Errorf("_disconnectPlaceOrder: Trying to revert "+
			"OperationTypeAddOrderEntry but found type %v",
			utxoOpsForTxn[operationIndex].Type)
	}
	addOp := utxoOpsForTxn[operationIndex]

	// Get the order at (NumOrderEntries - 1).
	orderEntryIndex := bav.NumOrderEntries - 1
	orderEntry := bav._getOrderEntryForPos(orderEntryIndex)
	if orderEntry == nil || orderEntry.isDeleted {
		// If we don't find the OrderID for the order in this position that's an
		// error.
		return fmt.Errorf("_disconnectPlaceOrder: Could not find OrderEntry "+
			"for position %d even though NumOrderEntries=%d",
			orderEntryIndex, bav.NumOrderEntries)
	}

	// Sanity-check that the order's position is at the end of the list.
	lastPos := bav.NumOrderEntries - 1
	if orderEntry.Pos != lastPos {
		return fmt.Errorf("_disconnectPlaceOrder: orderEntry has position %d != "+
			"(NumOrderEntries - 1 = %d)", orderEntry.Pos, lastPos)
	}

	// Now that the data is loaded, mark the entry as deleted. This will trigger
	// it to be removed from the db along with its corresponding mappings once it
	// is flushed. After this operation, orderEntry is a dangling pointer that
	// can be used for another purpose if desired. However, we have no use for it.
	if err := bav._deleteOrderMappings(orderEntry); err != nil {
		return err
	}

	// Decrement the number of entries since we deleted one.
	bav.NumOrderEntries--

	// Get the merchant referred to by the order.
	merchantEntry := bav._getMerchantEntryForMerchantID(orderEntry.MerchantID)
	if merchantEntry == nil || merchantEntry.isDeleted {
		return fmt.Errorf("_disconnectPlaceOrder: Could not find MerchantEntry "+
			"for order entry %+v even though order exists",
			orderEntry)
	}

	// Reset the merchant stats. This is the only field in the MerchantEntry that could
	// have changed as a result of this operation.
	merchantEntry.Stats = addOp.PrevMerchantStats

	// Note that although the PlaceOrder txn may have burned some Ultra,
	// this Ultra will be restored when the inputs are restored by the basic transfer
	// disconnect code below. The order burn is basically a large implicit
	// txn fee as far as that code is concerned, and treating it as such results
	// in the proper behavior without needing any special casing.

	// Now revert the basic transfer with the remaining operations. Cut off
	// the order add operation at the end since we just reverted it.
	return bav._disconnectBasicTransfer(
		currentTxn, txnHash, utxoOpsForTxn[:operationIndex], blockHeight)
}

func _computeCommissionsFromPriceNanos(priceNanos uint64, commissionBasisPoints uint64) (
	_commissionsNanos uint64, _err error) {

	if priceNanos > math.MaxInt64 {
		return 0, fmt.Errorf("_computeCommissionsFromPriceNanos: priceNanos " +
			"exceeds maximum size for int64; this should never happen")
	}

	// What we want is a number such that, when the commissions are subtracted from it,
	// we get the price the merchant is asking for. This gives the following:
	// - finalNumber * (1 - commissionsPercentage) = priceNanos
	// - finalNumber = priceNanos / (1 - commissionsPercentage)
	// - commissionsNanos = finalNumber - priceNanos
	// - = priceNanos / (1 - commissionsPercentage) - priceNanos
	// - = priceNanos * (1/(1-commissionsPercentage) - 1)
	// - = priceNanos * (1 - (1 - commissionsPercentage)) / (1 - commissionsPercentage)
	// - = priceNanos * (commissionsPercentage) / (1 - commissionsPercentage)
	// - = priceNanos * (commissionsPercentage) / (1 - commissionsBps / 10000)
	// - = priceNanos * (commissionsPercentage) / ((10000 - commissionsBps) / 10000))
	// - = priceNanos * (commissionBps / 10000) / ((10000 - commissionsBps) / 10000))
	// - = priceNanos * commissionBps / (10000 - commissionsBps)

	priceNanosBigint := big.NewInt(int64(priceNanos))
	commissionsBpsBigint := big.NewInt(int64(commissionBasisPoints))
	tenThousandMinusCommissionsBpsBigint := big.NewInt(int64(10000 - commissionBasisPoints))
	priceTimesCommissionsBpsBigint := big.NewInt(0).Mul(priceNanosBigint, commissionsBpsBigint)
	commissionsNanosBigint := big.NewInt(0).Div(
		priceTimesCommissionsBpsBigint, tenThousandMinusCommissionsBpsBigint)
	if commissionsNanosBigint.Cmp(big.NewInt(math.MaxInt64)) > 0 {
		return 0, fmt.Errorf("_computeCommissionsFromPriceNanos: Overflow "+
			"encountered computing commissions with amount %d and commissionBasisPoints %d",
			priceNanos, commissionBasisPoints)
	}

	return uint64(commissionsNanosBigint.Int64()), nil
}

// Note: This operation is safe as long as the (total supply * 10000) doesn't
// overflow a uint64. We check for overflow regardless.
func _computeCommissionsAndRevenueFromPayment(
	paymentAmountNanos uint64, commissionBasisPoints uint64) (_commissions uint64, _revenue uint64, _err error) {

	if paymentAmountNanos > math.MaxInt64 {
		return 0, 0, fmt.Errorf("_computeCommissionsAndRevenueFromPayment: paymentAmountNanos " +
			"exceeds maximum size for int64; this should never happen")
	}

	// Compute the commissions while checking for overflow.
	paymentAmountBigint := big.NewInt(int64(paymentAmountNanos))
	commissionBpsBigint := big.NewInt(int64(commissionBasisPoints))
	tenThousandBigint := big.NewInt(10000)
	paymentAmountTimesCommissionBps := big.NewInt(0).Mul(
		paymentAmountBigint, commissionBpsBigint)
	commissionNanosBigint := big.NewInt(0).Div(
		paymentAmountTimesCommissionBps, tenThousandBigint)
	if commissionNanosBigint.Cmp(big.NewInt(math.MaxInt64)) > 0 {
		return 0, 0, fmt.Errorf("_computeCommissionsAndRevenueFromPayment: Overflow "+
			"encountered computing commissions with amount %d and commissionBasisPoints %d",
			paymentAmountNanos, commissionBasisPoints)
	}

	// The revenue is just whatever's left after paying commissions.
	commissionNanos := commissionNanosBigint.Uint64()
	revenueNanos := paymentAmountNanos - commissionNanos

	return commissionNanos, revenueNanos, nil
}

func (bav *UtxoView) _disconnectOrderOperation(
	operationType OperationType, currentTxn *MsgUltranetTxn, txnHash *BlockHash,
	utxoOpsForTxn []*UtxoOperation, blockHeight uint32) error {

	// For this we have to go in the reverse order:
	// 	Remove the meta order operation
	//  Disconnect the basic transfer

	// Check that the last operation has the required operation type.
	operationIndex := len(utxoOpsForTxn) - 1
	if len(utxoOpsForTxn) == 0 {
		return fmt.Errorf("_disconnectOrderOperation: utxoOperations are missing")
	}
	if utxoOpsForTxn[operationIndex].Type != operationType {
		return fmt.Errorf("_disconnectOrderOperation: Trying to revert "+
			"%v but found type %v",
			operationType, utxoOpsForTxn[operationIndex].Type)
	}

	// Get the order entry for the OrderID in the last operation.
	operationData := utxoOpsForTxn[operationIndex]
	orderEntry := bav._getOrderEntryForOrderID(operationData.PrevOrderData.OrderID)
	if orderEntry == nil {
		return fmt.Errorf("_disconnectOrderOperation: OrderEntry not found for OrderID %+v for operation type %v",
			operationData.PrevOrderData.OrderID, operationType)
	}
	// Reset the data on the order.
	_setPrevOrderData(orderEntry, operationData.PrevOrderData)

	// Get the merchant referred to by the order.
	merchantEntry := bav._getMerchantEntryForMerchantID(orderEntry.MerchantID)
	if merchantEntry == nil || merchantEntry.isDeleted {
		return fmt.Errorf("_disconnectOrderOperation: Could not find MerchantEntry "+
			"for order entry %+v even though order exists for operation type %v",
			orderEntry, operationType)
	}

	// Reset the merchant stats. This is the field in the MerchantEntry that could
	// have changed as a result of this operation.
	merchantEntry.Stats = operationData.PrevMerchantStats

	// Now revert the basic transfer with the remaining operations. Cut off
	// the operation at the end since we just reverted it.
	return bav._disconnectBasicTransfer(
		currentTxn, txnHash, utxoOpsForTxn[:operationIndex], blockHeight)
}

func (bav *UtxoView) _disconnectBitcoinExchange(
	operationType OperationType, currentTxn *MsgUltranetTxn, txnHash *BlockHash,
	utxoOpsForTxn []*UtxoOperation, blockHeight uint32) error {

	// Check that the last operation has the required OperationType
	operationIndex := len(utxoOpsForTxn) - 1
	if len(utxoOpsForTxn) == 0 {
		return fmt.Errorf("_disconnectBitcoinExchange: Trying to revert "+
			"%v but utxoOperations are missing",
			OperationTypeBitcoinExchange)
	}
	if utxoOpsForTxn[operationIndex].Type != OperationTypeBitcoinExchange {
		return fmt.Errorf("_disconnectBitcoinExchange: Trying to revert "+
			"%v but found type %v",
			OperationTypeBitcoinExchange, utxoOpsForTxn[operationIndex].Type)
	}
	operationData := utxoOpsForTxn[operationIndex]

	// Get the transaction metadata from the transaction now that we know it has
	// OperationTypeBitcoinExchange.
	txMeta := currentTxn.TxnMeta.(*BitcoinExchangeMetadata)

	// Remove the BitcoinTransactionHash from our TxID mappings since we are
	// unspending it. This makes it so that this hash can be processed again in
	// the future in order to re-grant the public key the Ultra they are entitled
	// to (though possibly more or less than the amount of Ultra they had before
	// because they might execute at a different conversion price).
	bav._deleteBitcoinBurnTxIDMappings(txMeta.BitcoinTransactionHash)

	// Un-add the UTXO taht was created as a result of this transaction. It should
	// be the one at the end of our UTXO list at this point.
	//
	// The UtxoKey is simply the transaction hash with index zero.
	utxoKey := UtxoKey{
		TxID: *currentTxn.Hash(),
		// We give all UTXOs that are created as a result of BitcoinExchange transactions
		// an index of zero. There is generally only one UTXO created in a BitcoinExchange
		// transaction so this field doesn't really matter.
		Index: 0,
	}
	if err := bav._unAddUtxo(&utxoKey); err != nil {
		return errors.Wrapf(err, "_disconnectBitcoinExchange: Problem unAdding utxo %v: ", utxoKey)
	}

	// Reset NanosPurchased to the value it was before granting this Ultra to this user.
	// This previous value comes from the UtxoOperation data.
	prevNanosPurchased := operationData.PrevNanosPurchased
	bav.NanosPurchased = prevNanosPurchased

	// At this point the BitcoinExchange transaction should be fully reverted.
	return nil
}

func (bav *UtxoView) _disconnectPrivateMessage(
	operationType OperationType, currentTxn *MsgUltranetTxn, txnHash *BlockHash,
	utxoOpsForTxn []*UtxoOperation, blockHeight uint32) error {

	// Verify that the last operation is a PrivateMessage opration
	if len(utxoOpsForTxn) == 0 {
		return fmt.Errorf("_disconnectPrivateMessage: utxoOperations are missing")
	}
	operationIndex := len(utxoOpsForTxn) - 1
	if utxoOpsForTxn[operationIndex].Type != OperationTypePrivateMessage {
		return fmt.Errorf("_disconnectPrivateMessage: Trying to revert "+
			"OperationTypePrivateMessage but found type %v",
			utxoOpsForTxn[operationIndex].Type)
	}

	// Now we know the txMeta is PrivateMessage
	txMeta := currentTxn.TxnMeta.(*PrivateMessageMetadata)

	// Get the MessageEntry for the sender in the transaction. If we don't find
	// it or if it has isDeleted=true that's an error.
	senderMessageKey := MakeMessageKey(currentTxn.PublicKey, txMeta.TimestampNanos)
	messageEntry := bav._getMessageEntryForMessageKey(&senderMessageKey)
	if messageEntry == nil || messageEntry.isDeleted {
		return fmt.Errorf("_disconnectPrivateMessage: MessageEntry for "+
			"SenderMessageKey %v was found to be nil or deleted: %v",
			&senderMessageKey, messageEntry)
	}

	// Verify that the sender and recipient in the entry match the TxnMeta as
	// a sanity check.
	if !reflect.DeepEqual(messageEntry.SenderPublicKey, currentTxn.PublicKey) {
		return fmt.Errorf("_disconnectPrivateMessage: Sender public key on "+
			"MerchantEntry was %s but the PublicKey on the txn was %s",
			PkToString(messageEntry.SenderPublicKey, bav.Params),
			PkToString(currentTxn.PublicKey, bav.Params))
	}
	if !reflect.DeepEqual(messageEntry.RecipientPublicKey, txMeta.RecipientPublicKey) {
		return fmt.Errorf("_disconnectPrivateMessage: Recipient public key on "+
			"MerchantEntry was %s but the PublicKey on the TxnMeta was %s",
			PkToString(messageEntry.RecipientPublicKey, bav.Params),
			PkToString(txMeta.RecipientPublicKey, bav.Params))
	}
	// Sanity-check that the MessageEntry TstampNanos matches the transaction.
	if messageEntry.TstampNanos != txMeta.TimestampNanos {
		return fmt.Errorf("_disconnectPrivateMessage: TimestampNanos in "+
			"MessageEntry was %d but in transaction it was %d",
			messageEntry.TstampNanos,
			txMeta.TimestampNanos)
	}
	// Sanity-check that the EncryptedText on the MessageEntry matches the transaction
	// just for good measure.
	if !reflect.DeepEqual(messageEntry.EncryptedText, txMeta.EncryptedText) {
		return fmt.Errorf("_disconnectPrivateMessage: EncryptedText in MessageEntry "+
			"did not match EncryptedText in transaction: (%s) != (%s)",
			hex.EncodeToString(messageEntry.EncryptedText),
			hex.EncodeToString(txMeta.EncryptedText))
	}

	// Now that we are confident the MessageEntry lines up with the transaction we're
	// rolling back, use the entry to delete the mappings for this message.
	bav._deleteMessageEntryMappings(messageEntry)

	// Now revert the basic transfer with the remaining operations. Cut off
	// the PrivateMessage operation at the end since we just reverted it.
	return bav._disconnectBasicTransfer(
		currentTxn, txnHash, utxoOpsForTxn[:operationIndex], blockHeight)
}

// DisconnectTransaction ...
func (bav *UtxoView) DisconnectTransaction(currentTxn *MsgUltranetTxn, txnHash *BlockHash,
	utxoOpsForTxn []*UtxoOperation, blockHeight uint32) error {

	if currentTxn.TxnMeta.GetTxnType() == TxnTypeBlockReward || currentTxn.TxnMeta.GetTxnType() == TxnTypeBasicTransfer {
		return bav._disconnectBasicTransfer(
			currentTxn, txnHash, utxoOpsForTxn, blockHeight)
	} else if currentTxn.TxnMeta.GetTxnType() == TxnTypeRegisterMerchant {
		return bav._disconnectRegisterMerchant(
			currentTxn, txnHash, utxoOpsForTxn, blockHeight)
	} else if currentTxn.TxnMeta.GetTxnType() == TxnTypeUpdateMerchant {
		return bav._disconnectUpdateMerchant(
			currentTxn, txnHash, utxoOpsForTxn, blockHeight)
	} else if currentTxn.TxnMeta.GetTxnType() == TxnTypePlaceOrder {
		return bav._disconnectPlaceOrder(
			currentTxn, txnHash, utxoOpsForTxn, blockHeight)
	} else if currentTxn.TxnMeta.GetTxnType() == TxnTypeCancelOrder {
		return bav._disconnectOrderOperation(
			OperationTypeCancelOrder, currentTxn, txnHash, utxoOpsForTxn, blockHeight)
	} else if currentTxn.TxnMeta.GetTxnType() == TxnTypeRejectOrder {
		return bav._disconnectOrderOperation(
			OperationTypeRejectOrder, currentTxn, txnHash, utxoOpsForTxn, blockHeight)
	} else if currentTxn.TxnMeta.GetTxnType() == TxnTypeConfirmOrder {
		return bav._disconnectOrderOperation(
			OperationTypeConfirmOrder, currentTxn, txnHash, utxoOpsForTxn, blockHeight)
	} else if currentTxn.TxnMeta.GetTxnType() == TxnTypeFulfillOrder {
		return bav._disconnectOrderOperation(
			OperationTypeFulfillOrder, currentTxn, txnHash, utxoOpsForTxn, blockHeight)
	} else if currentTxn.TxnMeta.GetTxnType() == TxnTypeReviewOrder {
		return bav._disconnectOrderOperation(
			OperationTypeReviewOrder, currentTxn, txnHash, utxoOpsForTxn, blockHeight)
	} else if currentTxn.TxnMeta.GetTxnType() == TxnTypeRefundOrder {
		return bav._disconnectOrderOperation(
			OperationTypeRefundOrder, currentTxn, txnHash, utxoOpsForTxn, blockHeight)
	} else if currentTxn.TxnMeta.GetTxnType() == TxnTypeBitcoinExchange {
		return bav._disconnectBitcoinExchange(
			OperationTypeBitcoinExchange, currentTxn, txnHash, utxoOpsForTxn, blockHeight)
	} else if currentTxn.TxnMeta.GetTxnType() == TxnTypePrivateMessage {
		return bav._disconnectPrivateMessage(
			OperationTypePrivateMessage, currentTxn, txnHash, utxoOpsForTxn, blockHeight)
	}

	return fmt.Errorf("DisconnectBlock: Unimplemented txn type %v", currentTxn.TxnMeta.GetTxnType().String())
}

// DisconnectBlock ...
func (bav *UtxoView) DisconnectBlock(
	ultranetBlock *MsgUltranetBlock, txHashes []*BlockHash, utxoOps [][]*UtxoOperation) error {

	// Verify that the block being disconnected is the current tip. DisconnectBlock
	// can only be called on a block at the tip. We do this to keep the API simple.
	blockHash, err := ultranetBlock.Header.Hash()
	if err != nil {
		return fmt.Errorf("DisconnectBlock: Problem computing block hash")
	}
	if *bav.TipHash != *blockHash {
		return fmt.Errorf("DisconnectBlock: Block being disconnected does not match tip")
	}

	// Verify the number of ADD and SPEND operations in the utxOps list is equal
	// to the number of outputs and inputs in the block respectively.
	numInputs := 0
	numOutputs := 0
	for _, txn := range ultranetBlock.Txns {
		numInputs += len(txn.TxInputs)
		numOutputs += len(txn.TxOutputs)
	}
	numSpendOps := 0
	numAddOps := 0
	for _, utxoOpsForTxn := range utxoOps {
		for _, op := range utxoOpsForTxn {
			if op.Type == OperationTypeSpendUtxo {
				numSpendOps++
			} else if op.Type == OperationTypeAddUtxo {
				numAddOps++
			}
		}
	}
	if numInputs != numSpendOps {
		return fmt.Errorf(
			"DisconnectBlock: Number of inputs in passed block (%d) "+
				"not equal to number of SPEND operations in passed "+
				"utxoOps (%d)", numInputs, numSpendOps)
	}
	if numOutputs != numAddOps {
		return fmt.Errorf(
			"DisconnectBlock: Number of outputs in passed block (%d) "+
				"not equal to number of ADD operations in passed "+
				"utxoOps (%d)", numOutputs, numAddOps)
	}

	// Loop through the txns backwards to process them.
	// Track the operation we're performing as we go.
	for txnIndex := len(ultranetBlock.Txns) - 1; txnIndex >= 0; txnIndex-- {
		currentTxn := ultranetBlock.Txns[txnIndex]
		txnHash := txHashes[txnIndex]
		utxoOpsForTxn := utxoOps[txnIndex]
		blockHeight := ultranetBlock.Header.Height

		err := bav.DisconnectTransaction(currentTxn, txnHash, utxoOpsForTxn, blockHeight)
		if err != nil {
			return errors.Wrapf(err, "DisconnectBlock: Problem disconnecting transaction: %v", currentTxn)
		}
	}

	// At this point, all of the transactions in the block should be fully
	// reversed and the view should therefore be in the state it was in before
	// this block was applied.

	// Update the tip to point to the parent of this block since we've managed
	// to successfully disconnect it.
	bav.TipHash = ultranetBlock.Header.PrevBlockHash

	return nil
}

func _isEntryImmatureBlockReward(utxoEntry *UtxoEntry, blockHeight uint32, params *UltranetParams) bool {
	if utxoEntry.IsBlockReward {
		blocksPassed := blockHeight - utxoEntry.BlockHeight
		// Note multiplication is OK here and has no chance of overflowing because
		// block heights are computed by our code and are guaranteed to be sane values.
		timePassed := time.Duration(int64(params.TimeBetweenBlocks) * int64(blocksPassed))
		if timePassed < params.BlockRewardMaturity {
			// Mark the block as invalid and return error if an immature block reward
			// is being spent.
			return true
		}
	}
	return false
}

func _verifySignature(txn *MsgUltranetTxn) error {
	// Compute a hash of the transaction
	txBytes, err := txn.ToBytes(true /*preSignature*/)
	if err != nil {
		return errors.Wrapf(err, "_verifySignature: Problem serializing txn without signature: ")
	}
	txHash := Sha256DoubleHash(txBytes)
	// Convert the txn public key into a *btcec.PublicKey
	txnPk, err := btcec.ParsePubKey(txn.PublicKey, btcec.S256())
	if err != nil {
		return errors.Wrapf(err, "_verifySignature: Problem parsing public key: ")
	}
	// Verify that the transaction is signed by the specified key.
	if txn.Signature == nil || !txn.Signature.Verify(txHash[:], txnPk) {
		return RuleErrorInvalidTransactionSignature
	}

	return nil
}

func (bav *UtxoView) _connectBasicTransfer(
	txn *MsgUltranetTxn, txHash *BlockHash, blockHeight uint32, verifySignatures bool,
	verifyMerchantMerkleRoot bool) (
	_totalInput uint64, _totalOutput uint64, _utxoOps []*UtxoOperation, _err error) {

	var utxoOpsForTxn []*UtxoOperation

	// Loop through all the inputs and validate them.
	var totalInput uint64
	// Each input should have a UtxoEntry corresponding to it if the transaction
	// is legitimate. These should all have back-pointers to their UtxoKeys as well.
	utxoEntriesForInputs := []*UtxoEntry{}
	for _, ultranetInput := range txn.TxInputs {
		// Fetch the utxoEntry for this input from the view. Make a copy to
		// avoid having the iterator change under our feet.
		utxoKey := UtxoKey(*ultranetInput)
		utxoEntry := bav.GetUtxoEntryForUtxoKey(&utxoKey)
		// If the utxo doesn't exist mark the block as invalid and return an error.
		if utxoEntry == nil {
			return 0, 0, nil, RuleErrorInputSpendsNonexistentUtxo
		}
		// If the utxo exists but is already spent mark the block as invalid and
		// return an error.
		if utxoEntry.isSpent {
			return 0, 0, nil, RuleErrorInputSpendsPreviouslySpentOutput
		}
		// If the utxo is from a block reward txn, make sure enough time has passed to
		// make it spendable.
		if _isEntryImmatureBlockReward(utxoEntry, blockHeight, bav.Params) {
			glog.Debugf("utxoKey: %v, utxoEntry: %v, height: %d", &utxoKey, utxoEntry, blockHeight)
			return 0, 0, nil, RuleErrorInputSpendsImmatureBlockReward
		}

		// Verify that the input's public key is the same as the public key specified
		// in the transaction.
		//
		// TODO: Enforcing this rule isn't a clear-cut decision. On the one hand,
		// we save space and minimize complexity by enforcing this constraint. On
		// the other hand, we make certain things harder to implement in the
		// future. For example, implementing constant key rotation like Bitcoin
		// has is difficult to do with a scheme like this. As are things like
		// multi-sig (although that could probably be handled using transaction
		// metadata). Key rotation combined with the use of addresses also helps
		// a lot with quantum resistance. Nevertheless, if we assume the platform
		// is committed to "one identity = roughly one public key" for usability
		// reasons (e.g. reputation is way easier to manage without key rotation),
		// then I don't think this constraint should pose much of an issue.
		if !reflect.DeepEqual(utxoEntry.PublicKey, txn.PublicKey) {
			return 0, 0, nil, RuleErrorInputWithPublicKeyDifferentFromTxnPublicKey
		}

		// Sanity check the amount of the input.
		if utxoEntry.AmountNanos > MaxNanos ||
			totalInput >= (math.MaxUint64-utxoEntry.AmountNanos) ||
			totalInput+utxoEntry.AmountNanos > MaxNanos {

			return 0, 0, nil, RuleErrorInputSpendsOutputWithInvalidAmount
		}
		// Add the amount of the utxo to the total input and add the UtxoEntry to
		// our list.
		totalInput += utxoEntry.AmountNanos
		utxoEntriesForInputs = append(utxoEntriesForInputs, utxoEntry)

		// At this point we know the utxo exists in the view and is unspent so actually
		// tell the view to spend the input. If the spend fails for any reason we return
		// an error. Don't mark the block as invalid though since this is not necessarily
		// a rule error and the block could benefit from reprocessing.
		newUtxoOp, err := bav._spendUtxo(&utxoKey)

		if err != nil {
			return 0, 0, nil, errors.Wrapf(err, "_connectBasicTransfer: Problem spending input utxo")
		}

		utxoOpsForTxn = append(utxoOpsForTxn, newUtxoOp)
	}

	if len(txn.TxInputs) != len(utxoEntriesForInputs) {
		// Something went wrong if these lists differ in length.
		return 0, 0, nil, fmt.Errorf("_connectBasicTransfer: Length of list of " +
			"UtxoEntries does not match length of input list; this should never happen")
	}

	// Block rewards are a bit special in that we don't allow them to have any
	// inputs. Part of the reason for this stems from the fact that we explicitly
	// require that block reward transactions not be signed. If a block reward is
	// not allowed to have a signature then it should not be trying to spend any
	// inputs.
	if txn.TxnMeta.GetTxnType() == TxnTypeBlockReward && len(txn.TxInputs) != 0 {
		return 0, 0, nil, RuleErrorBlockRewardTxnNotAllowedToHaveInputs
	}

	// The block rewards are special in that we may want to verify that their merchant
	// merkle root lines up with what we currently think the state of the merchant db
	// is. This is helpful for light clients.
	if txn.TxnMeta.GetTxnType() == TxnTypeBlockReward && verifyMerchantMerkleRoot {
		// If we get this far we know the first transaction in the block is a valid
		// block reward.
		blockRewardMeta := txn.TxnMeta.(*BlockRewardMetadataa)
		merchantMerkle, err := bav._computeMerchantMerkleRoot()
		if err != nil {
			return 0, 0, nil, errors.Wrapf(
				err, "ConnectBlock: Problem computing merchant merkle root: ")
		}
		if !reflect.DeepEqual(blockRewardMeta.MerchantMerkleRoot, merchantMerkle) {
			glog.Errorf("ConnectBlock: Merchant merkle root in block %v does not match "+
				"computed merchant merkle root %v", blockRewardMeta.MerchantMerkleRoot, merchantMerkle)
			return 0, 0, nil, RuleErrorInvalidMerchantMerkleRoot
		}
	}

	// At this point, all of the utxos corresponding to inputs of this txn
	// should be marked as spent in the view. Now we go through and process
	// the outputs.
	var totalOutput uint64
	for outputIndex, ultranetOutput := range txn.TxOutputs {
		// Sanity check the amount of the output. Mark the block as invalid and
		// return an error if it isn't sane.
		if ultranetOutput.AmountNanos > MaxNanos ||
			totalOutput >= (math.MaxUint64-ultranetOutput.AmountNanos) ||
			totalOutput+ultranetOutput.AmountNanos > MaxNanos {

			return 0, 0, nil, RuleErrorTxnOutputWithInvalidAmount
		}

		// Since the amount is sane, add it to the total.
		totalOutput += ultranetOutput.AmountNanos

		// Create a new entry for this output and add it to the view. It should be
		// added at the end of the utxo list.
		outputKey := UtxoKey{
			TxID:  *txHash,
			Index: uint32(outputIndex),
		}
		utxoEntry := UtxoEntry{
			AmountNanos:   ultranetOutput.AmountNanos,
			PublicKey:     ultranetOutput.PublicKey,
			BlockHeight:   blockHeight,
			IsBlockReward: (txn.TxnMeta.GetTxnType() == TxnTypeBlockReward),
			utxoKey:       &outputKey,
			// We leave the position unset and isSpent to false by default.
			// The position will be set in the call to _addUtxo.
		}
		// If we have a problem adding this utxo return an error but don't
		// mark this block as invalid since it's not a rule error and the block
		// could therefore benefit from being processed in the future.
		newUtxoOp, err := bav._addUtxo(&utxoEntry)
		if err != nil {
			return 0, 0, nil, errors.Wrapf(err, "_connectBasicTransfer: Problem adding output utxo")
		}
		utxoOpsForTxn = append(utxoOpsForTxn, newUtxoOp)
	}

	// If signature verification is requested then do that as well.
	if verifySignatures {
		// When we looped through the inputs we verified that all of them belong
		// to the public key specified in the transaction. So, as long as the transaction
		// public key has signed the transaction as a whole, we can assume that
		// all of the inputs are authorized to be spent. One signature to rule them
		// all.
		//
		// We treat block rewards as a special case in that we actually require that they
		// not have a transaction-level public key and that they not be signed. Doing this
		// simplifies things operationally for miners because it means they can run their
		// mining operation without having any private key material on any of the mining
		// nodes. Block rewards are the only transactions that get a pass on this. They are
		// also not allowed to have any inputs because they by construction cannot authorize
		// the spending of any inputs.
		if txn.TxnMeta.GetTxnType() == TxnTypeBlockReward {
			if len(txn.PublicKey) != 0 || txn.Signature != nil {
				return 0, 0, nil, RuleErrorBlockRewardTxnNotAllowedToHaveSignature
			}
		} else {
			if err := _verifySignature(txn); err != nil {
				return 0, 0, nil, errors.Wrapf(err, "_connectBasicTransfer: Problem verifying txn signature: ")
			}
		}
	}

	// Now that we've processed the transaction, return all of the computed
	// data.
	return totalInput, totalOutput, utxoOpsForTxn, nil
}

func (bav *UtxoView) _deleteMerchantMappings(merchantEntry *MerchantEntry) {
	// Deleting a merchant amounts to setting its mappings to point to an
	// entry that has isDeleted = true. So we create such an entry and set
	// the mappings to point to it.
	tombstoneEntry := *merchantEntry
	tombstoneEntry.isDeleted = true

	// _setMerchantMappings will take this and use its fields to update the
	// mappings.
	bav._setMerchantMappings(&tombstoneEntry)

	// Note at this point, the merchantEntry can be re-used if desired.
}

func (bav *UtxoView) _setMerchantMappings(merchantEntry *MerchantEntry) error {
	if merchantEntry.merchantID == nil {
		return fmt.Errorf("_setMerchantMappings: merchantID missing for merchantEntry %+v", merchantEntry)
	}
	if len(merchantEntry.Username) == 0 {
		return fmt.Errorf("_setMerchantMappings: Username missing for merchantEntry %+v", merchantEntry)
	}
	if len(merchantEntry.PublicKey) == 0 {
		return fmt.Errorf("_setMerchantMappings: PublicKey missing for merchantEntry %+v", merchantEntry)
	}

	usernameKey := UsernameMapKey{}
	copy(usernameKey[:], merchantEntry.Username)

	// The merchant entry provides us with everything we need to set all
	// the maps. Note that we load, modify, and write all these maps together such
	// that a request for one field means that all the others are necessarily stored
	// in the view.
	bav.UsernameToMerchantEntry[usernameKey] = merchantEntry
	// Set the public key to merchantID mapping by computing the key first.
	pkKey := PkMapKey{}
	copy(pkKey[:], merchantEntry.PublicKey)
	bav.PkToMerchantEntry[pkKey] = merchantEntry
	bav.PosToMerchantEntry[merchantEntry.Pos] = merchantEntry
	bav.MerchantIDToMerchantEntry[*merchantEntry.merchantID] = merchantEntry

	return nil
}

func (bav *UtxoView) _getAllMerchantsInViewWithScores() ([]*BlockHash, []*MerchantEntry) {
	merchantIDs := []*BlockHash{}
	merchantEntries := []*MerchantEntry{}
	for merchantID, merchantEntry := range bav.MerchantIDToMerchantEntry {
		if merchantEntry.isDeleted {
			continue
		}
		merchantIDCopy := merchantID
		merchantIDs = append(merchantIDs, &merchantIDCopy)
		merchantEntries = append(merchantEntries, merchantEntry)
	}
	return merchantIDs, merchantEntries
}

func (bav *UtxoView) _getMerchantEntryForPos(pos uint64) *MerchantEntry {
	// Check if this entry exists in our map already.
	merchantEntry, exists := bav.PosToMerchantEntry[pos]

	// If the merchant merchantID for this pos doesn't exist in memory then try
	// and look it up in the db.
	if !exists {
		merchantID := GetMerchantIDForPos(bav.Handle, pos)
		if merchantID == nil {
			// If the block merchantID doesn't exist in the database it means this
			// entry hasn't been created and we can return nil.
			return nil
		}

		// If we're here it means we do have an entry for this in the database.
		// Load all the other data for this merchant into memory to process it.

		// Start by fetching the merchant entry for this merchantID.
		merchantEntry = DbGetMerchantEntryForMerchantID(bav.Handle, merchantID)
		if merchantEntry == nil {
			// This is technically an error but just return nil to keep the API
			// simple.
			glog.Errorf("_getMerchantEntryForPos: Found merchantID for pos "+
				"%d but missing entry for merchantID %+v", pos, merchantID)
			return nil
		}

		// Note the merchantID is not set by default so we set it here.
		merchantEntry.merchantID = merchantID

		// Ensure that the pos of the entry lines up with the pos provided.
		if merchantEntry.Pos != pos {
			glog.Errorf("_getMerchantEntryForPos: Found merchantID for pos "+
				"%d but pos in entry %d differs", pos, merchantEntry.Pos)
			return nil
		}

		bav._setMerchantMappings(merchantEntry)
	}

	return merchantEntry
}

func (bav *UtxoView) _getMerchantEntryForUsername(username []byte) *MerchantEntry {
	// Create a key object from the username to do a map lookup. This copy
	// works because maps are initialized to zero in go.
	usernameKey := UsernameMapKey{}
	copy(usernameKey[:], username)

	// Check if this entry exists in our map already.
	merchantEntry, exists := bav.UsernameToMerchantEntry[usernameKey]

	// If the merchant merchantID for this username doesn't exist in memory then try
	// and look it up in the db.
	if !exists {
		merchantID := GetMerchantIDForUsername(bav.Handle, username)
		if merchantID == nil {
			// If the merchantID doesn't exist in the database it means this
			// entry hasn't been created and we can return nil.
			return nil
		}

		// If we're here it means we do have an entry for this in the database.
		// Load all the other data for this merchant into memory to process it.

		// Start by fetching the merchant entry for this merchantID.
		merchantEntry = DbGetMerchantEntryForMerchantID(bav.Handle, merchantID)
		if merchantEntry == nil {
			// This is technically an error but just return nil to keep the API
			// simple.
			glog.Errorf("_getMerchantEntryForUsername: Found merchantID for username "+
				"%s but missing entry for merchantID %+v", string(username), merchantID)
			return nil
		}

		// Note the merchantID is not set by default so we set it here.
		merchantEntry.merchantID = merchantID

		// Ensure that the username of the entry lines up with the username provided.
		if !reflect.DeepEqual(merchantEntry.Username, username) {
			glog.Errorf("_getMerchantEntryForUsername: Found merchantEntry for username %s "+
				"%v but username in entry %s differs", string(username), merchantEntry,
				string(merchantEntry.Username))
			return nil
		}

		bav._setMerchantMappings(merchantEntry)
	}

	return merchantEntry
}

func _dumpMerchantsByUsernamesAndPublicKeys(db *badger.DB) {
	{
		publicKeys, merchantIDs, merchantEntries, err := DbGetAllPubKeyMerchantIDMappings(db)
		if err != nil {
			glog.Errorf("_dumpMerchantsByUsernamesAndPublicKeys: Problem getting public keys: %v", err)
			return
		}
		for ii := range publicKeys {
			fmt.Printf("%d: public key: %v, merchantID: %v, merchantEntry: %v\n", ii, PkToStringMainnet(publicKeys[ii]), merchantIDs[ii], merchantEntries[ii])
		}
	}

	{
		usernames, merchantIDs, merchantEntries, err := DbGetAllUsernameMerchantIDMappings(db)
		if err != nil {
			glog.Errorf("_dumpMerchantsByUsernamesAndPublicKeys: Problem getting usernames: %v", err)
		}
		for ii := range usernames {
			fmt.Printf("%d: username: %v, merchantID: %v, merchantEntry: %v\n", ii, string(usernames[ii]), merchantIDs[ii], merchantEntries[ii])
		}
	}
}

func (bav *UtxoView) _getMerchantEntryForPublicKey(pk []byte) *MerchantEntry {
	// Create a key object from the pk to do a map lookup. This copy
	// works because maps are initialized to zero in go.
	pkKey := PkMapKey{}
	copy(pkKey[:], pk)

	// Check if this entry exists in our map already.
	merchantEntry, exists := bav.PkToMerchantEntry[pkKey]

	// If the merchantID for this pk doesn't exist in memory then try
	// and look it up in the db.
	if !exists {
		merchantID := DbGetMerchantIDForPubKey(bav.Handle, pk)
		if merchantID == nil {
			// If the merchantID doesn't exist in the database it means this
			// entry hasn't been created and we can return nil.
			return nil
		}

		// If we're here it means we do have an entry for this in the database.
		// Load all the other data for this merchant into memory to process it.

		// Start by fetching the merchant entry for this merchantID.
		merchantEntry = DbGetMerchantEntryForMerchantID(bav.Handle, merchantID)
		if merchantEntry == nil {
			// This is technically an error but just return nil to keep the API
			// simple.
			glog.Errorf("_getMerchantEntryForPublicKey: Found merchantID for pk "+
				"%+v but missing entry for merchantID %+v", PkToString(pk, bav.Params), merchantID)
			return nil
		}

		// Note the merchantID is not set by default so we set it here.
		merchantEntry.merchantID = merchantID

		// Ensure that the pk of the entry lines up with the pk provided.
		if !reflect.DeepEqual(merchantEntry.PublicKey, pk) {
			glog.Errorf("_getMerchantIDForPubKey: Found merchantID for pk "+
				"%+v but pk in entry %+v differs (entry: %v)", PkToString(pk, bav.Params),
				PkToString(merchantEntry.PublicKey, bav.Params), merchantEntry)
			return nil
		}

		bav._setMerchantMappings(merchantEntry)
	}

	return merchantEntry
}

func (bav *UtxoView) _getMerchantEntryForMerchantID(merchantID *BlockHash) *MerchantEntry {
	// Check if this entry exists in our map already.
	merchantEntry, exists := bav.MerchantIDToMerchantEntry[*merchantID]

	// If the entry for this merchantID doesn't exist in memory then try
	// and look it up in the db.
	if !exists {
		merchantEntry = DbGetMerchantEntryForMerchantID(bav.Handle, merchantID)
		if merchantEntry == nil {
			// If the MerchantEntry doesn't exist in the database it means this
			// entry hasn't been created and we can return nil.
			return nil
		}

		// If we're here it means we do have an entry for this in the database.
		// Load all the other data for this merchant into memory to process it.

		// Note the merchantID is not set when we fetch this from the db by
		// default so we set it here.
		merchantEntry.merchantID = merchantID

		bav._setMerchantMappings(merchantEntry)
	}

	return merchantEntry
}

func (bav *UtxoView) _connectRegisterMerchant(
	txn *MsgUltranetTxn, txHash *BlockHash, blockHeight uint32, verifySignatures bool) (
	_totalInput uint64, _totalOutput uint64, _utxoOps []*UtxoOperation, _err error) {

	// Double-check that the transaction is a RegisterMerchant transaction.
	if txn.TxnMeta.GetTxnType() != TxnTypeRegisterMerchant {
		return 0, 0, nil, fmt.Errorf("_connectRegisterMerchant called with bad TxnType %s", txn.TxnMeta.GetTxnType().String())
	}
	txMeta := txn.TxnMeta.(*RegisterMerchantMetadata)

	// Do basic validation on the input fields.
	if len(txn.PublicKey) != btcec.PubKeyBytesLenCompressed {
		return 0, 0, nil, RuleErrorPubKeyLen
	}
	if len(txMeta.Username) < MinUsernameLengthBytes || len(txMeta.Username) > MaxUsernameLengthBytes {
		return 0, 0, nil, RuleErrorUsernameLen
	}
	if len(txMeta.Description) > MaxMerchantDescriptionLengthBytes {
		return 0, 0, nil, RuleErrorMerchantDescriptionLen
	}

	// Connect basic txn to get the total input and the total output without
	// considering the transaction metadata.
	totalInput, totalOutput, utxoOpsForTxn, err := bav._connectBasicTransfer(
		txn, txHash, blockHeight, verifySignatures, false /*verifyMerchantMerkleRoot*/)
	if err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectRegisterMerchant: ")
	}

	// At this point the inputs and outputs have been processed. Now we
	// need to handle the metadata.

	// The burn amount specified in the merchant metadata contributes to the
	// output since the merchant is vaporizing it to bolster their reputation.
	burnAmount := txMeta.BurnAmountNanos
	// Check for overflow of the outputs before adding.
	if totalOutput > math.MaxUint64-burnAmount {
		return 0, 0, nil, RuleErrorTxnOutputWithInvalidAmount
	}
	totalOutput += burnAmount
	// It's assumed the caller code will check that things like output <= input.

	// Check that the merchant's info doesn't already exist in the db.
	//
	// Note that the merchantID for a pk or username could exist but be associated
	// with a deleted entry. This can happen for example when a transaction
	// is rolled back and then re-applied. In this case we still want to
	// process this new entry and potentially over-write the old
	// <pk/username -> entry>
	// mappings while leaving the old <merchantID -> deleted entry> mapping so that
	// it can be deleted from the db when we flush (though the <merchantID -> entry>
	// mapping will also be over-written if the new entry is identical to the
	// old one, and that's OK).
	{
		merchantEntry := bav._getMerchantEntryForUsername(txMeta.Username)
		if merchantEntry != nil && !merchantEntry.isDeleted {
			return 0, 0, nil, RuleErrorMerchantUsernameExists
		}
		merchantEntry = bav._getMerchantEntryForPublicKey(txn.PublicKey)
		if merchantEntry != nil && !merchantEntry.isDeleted {
			return 0, 0, nil, RuleErrorMerchantPkExists
		}
	}

	if verifySignatures {
		// No need to check signatures here because _connectBasicTransfer will
		// have verified that the entire transaction has been signed by the transaction's
		// public key, which is what we're using to register the merchant.
	}

	// Once we're sure that a unique merchant is being created, we can construct
	// the entry for the new merchant.
	merchantEntry := MerchantEntry{
		Username:    txMeta.Username,
		PublicKey:   txn.PublicKey,
		Description: txMeta.Description,
		// This merchant entry is being added to the end of our merchant list and
		// so its position will be the size of the array.
		Pos: bav.NumMerchantEntries,
		// Initially the amount the merchant has burned is whatever was burned
		// in this transaction. All the other stats are zero.
		Stats: &MerchantStats{
			AmountBurnedNanos: txMeta.BurnAmountNanos,
			// The burn amount shouldn't have any risk of overflowing an int64.
			MerchantScore: ScorePlusImpact(
				big.NewInt(0), int64(txMeta.BurnAmountNanos), blockHeight, bav.Params),
		},
		merchantID: txHash,
		// All the other data for the merchant is basically zero at this point.
	}

	// Merchants are referenced in the db by the txid where they were registered.
	// Since we're using UTXOs, the txid should be unique for each merchant if
	// the transaction is valid.
	bav._setMerchantMappings(&merchantEntry)

	// Increment the number of entries since we're adding one.
	bav.NumMerchantEntries++

	// Add an operation to the operation list of type OperationTypeAddMerchantEntry.
	utxoOpsForTxn = append(utxoOpsForTxn, &UtxoOperation{
		Type: OperationTypeAddMerchantEntry,
	})

	return totalInput, totalOutput, utxoOpsForTxn, nil
}

func (bav *UtxoView) _connectUpdateMerchant(
	txn *MsgUltranetTxn, txHash *BlockHash, blockHeight uint32, verifySignatures bool) (
	_totalInput uint64, _totalOutput uint64, _utxoOps []*UtxoOperation, _err error) {

	// Double-check that the transaction is an UpdateMerchant transaction.
	if txn.TxnMeta.GetTxnType() != TxnTypeUpdateMerchant {
		return 0, 0, nil, fmt.Errorf("_connectUpdateMerchant called with bad TxnType %s", txn.TxnMeta.GetTxnType().String())
	}
	txMeta := txn.TxnMeta.(*UpdateMerchantMetadata)

	// Do basic validation on the input fields.
	if txMeta.MerchantID == nil {
		return 0, 0, nil, RuleErrorBadMerchantID
	}

	// Connect basic txn to get the total input and the total output without
	// considering the transaction metadata.
	totalInput, totalOutput, utxoOpsForTxn, err := bav._connectBasicTransfer(
		txn, txHash, blockHeight, verifySignatures, false /*verifyMerchantMerkleRoot*/)
	if err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectUpdateMerchant: ")
	}

	// At this point the inputs and outputs have been processed. Now we
	// need to handle the metadata.

	// Because UpdateMerchant can be re-applied, we have to do something to
	// prevent the replay of a prior UpdateMerchant transaction. The way we
	// choose to do this here is to require the totalInput to be non-zero. This
	// makes it impossible to replay a duplicate UpdateMerchant transaction
	// because doing so would imply you're double-spending inputs. If we didn't
	// do this, then UpdateMerchant transactions without any inputs or outputs
	// would be possible and replayable.
	if totalInput == 0 {
		return 0, 0, nil, RuleErrorUpdateMerchantRequiresNonZeroInput
	}

	// Fetch the merchant entry for this merchantID if it exists.
	merchantEntry := bav._getMerchantEntryForMerchantID(txMeta.MerchantID)
	if merchantEntry == nil {
		return 0, 0, nil, RuleErrorNonexistentMerchant
	}
	// Save the relevant update data before we modify it for this merchant.
	prevMerchantUpdateData := _getMerchantUpdateData(merchantEntry)

	// Deleting the mappings associated with this merchant by setting them to point
	// to something that has (isDeleted = true) is sufficient to result in the
	// deletion of this merchant's data when the view is flushed.
	//
	// Note however that this leaves the resulting merchantEntry as a dangling
	// pointer that we can use to make the update.
	bav._deleteMerchantMappings(merchantEntry)

	// _connectBasicTransfer has already checked that the transaction is
	// signed by the top-level public key so all that we need to do is
	// verify that the top-level public key is equal to the merchant
	// public key to be confident that the person who created this transaction
	// has the authority to modify this merchantEntry.
	if !reflect.DeepEqual(merchantEntry.PublicKey, txn.PublicKey) {
		return 0, 0, nil, errors.Wrapf(
			RuleErrorTxnPublicKeyDiffersFromMerchantPublicKey, "_connectUpdateMerchant: "+
				"txn.PublicKey: %v, merchantEntry.PublicKey: %v", PkToString(txn.PublicKey, bav.Params),
			PkToString(merchantEntry.PublicKey, bav.Params))
	}

	// This has to come after the merchantEntry was deleted since it modifies the
	// fields on the entry.
	if len(txMeta.NewPublicKey) != 0 {
		// If the public key has improper length, return an error.
		if len(txMeta.NewPublicKey) != btcec.PubKeyBytesLenCompressed {
			return 0, 0, nil, RuleErrorPubKeyLen
		}

		// If we already have a merchant with this public key, return an error.
		existingEntry := bav._getMerchantEntryForPublicKey(txMeta.NewPublicKey)
		if existingEntry != nil && !existingEntry.isDeleted {
			return 0, 0, nil, RuleErrorMerchantPkExists
		}

		merchantEntry.PublicKey = txMeta.NewPublicKey
	}
	if len(txMeta.NewUsername) != 0 {
		if len(txMeta.NewUsername) < MinUsernameLengthBytes || len(txMeta.NewUsername) > MaxUsernameLengthBytes {
			return 0, 0, nil, RuleErrorUsernameLen
		}

		// If the username is set but a merchant already exists with this username
		// then return an error.
		existingEntry := bav._getMerchantEntryForUsername(txMeta.NewUsername)
		if existingEntry != nil && !existingEntry.isDeleted {
			return 0, 0, nil, RuleErrorMerchantUsernameExists
		}

		merchantEntry.Username = txMeta.NewUsername
	}
	if len(txMeta.NewDescription) != 0 {
		if len(txMeta.NewDescription) > MaxMerchantDescriptionLengthBytes {
			return 0, 0, nil, RuleErrorMerchantDescriptionLen
		}

		merchantEntry.Description = txMeta.NewDescription
	}

	// The burn amount specified in the metadata contributes to the
	// output since the merchant is vaporizing it to bolster their reputation.
	burnAmount := txMeta.BurnAmountNanos
	// Check for overflow of the outputs before adding.
	if totalOutput > math.MaxUint64-burnAmount {
		return 0, 0, nil, RuleErrorTxnOutputWithInvalidAmount
	}
	totalOutput += burnAmount
	// It's assumed the caller code will check that things like output <= input.

	// Add the burn amount to the entry.
	merchantEntry.Stats.AmountBurnedNanos += txMeta.BurnAmountNanos
	// This operation is OK because ScorePlusImpact does not modify the original
	// pointer to the merchant score. If it did then our prevMerchantUpdateData
	// that we saved above would be compromised.
	merchantEntry.Stats.MerchantScore = ScorePlusImpact(
		merchantEntry.Stats.MerchantScore, int64(txMeta.BurnAmountNanos), blockHeight, bav.Params)

	// Now that we have updated the entry, update the mappings to point to it
	// appropriately. Note if some fields haven't changed this will result in
	// the undoing of our _deleteMerchantMappings above but that is OK.
	bav._setMerchantMappings(merchantEntry)

	// Add an operation to the operation list of type OperationTypeUpdateMerchantEntry.
	utxoOpsForTxn = append(utxoOpsForTxn, &UtxoOperation{
		Type:                   OperationTypeUpdateMerchantEntry,
		PrevMerchantUpdateData: prevMerchantUpdateData,
	})

	return totalInput, totalOutput, utxoOpsForTxn, nil
}

func (bav *UtxoView) _deleteOrderMappings(orderEntry *OrderEntry) error {
	if orderEntry.orderID == nil {
		return fmt.Errorf("_deleteOrderMappings: orderID missing for orderEntry %+v", orderEntry)
	}

	// Deleting an order amounts to setting its mappings to point to an
	// entry that has (isDeleted = true). So we create such an entry and set
	// the mappings to point to it.
	tombstoneEntry := &OrderEntry{
		Pos:       orderEntry.Pos,
		isDeleted: true,
		orderID:   orderEntry.orderID,
	}

	// _setOrderMappings will take this and use its fields to update the
	// mappings.
	return bav._setOrderMappings(tombstoneEntry)

	// Note at this point, the orderEntry passed in is dangling and can
	// be re-used for another purpose if desired.
}

func (bav *UtxoView) _setOrderMappings(orderEntry *OrderEntry) error {
	if orderEntry.orderID == nil {
		return fmt.Errorf("_setOrderMappings: orderID missing for orderEntry %+v", orderEntry)
	}

	bav.PosToOrderEntry[orderEntry.Pos] = orderEntry
	bav.OrderIDToOrderEntry[*orderEntry.orderID] = orderEntry

	return nil
}

func (bav *UtxoView) _connectPlaceOrder(
	txn *MsgUltranetTxn, txHash *BlockHash, blockHeight uint32, verifySignatures bool) (
	_totalInput uint64, _totalOutput uint64, _utxoOps []*UtxoOperation, _err error) {

	// Check that it's a place order txn.
	if txn.TxnMeta.GetTxnType() != TxnTypePlaceOrder {
		return 0, 0, nil, fmt.Errorf("_connectPlaceOrder called with bad TxnType %s", txn.TxnMeta.GetTxnType().String())
	}
	txMeta := txn.TxnMeta.(*PlaceOrderMetadata)

	// Check the length of the encrypted data.
	if len(txMeta.BuyerMessage) > MaxBuyerMessageLengthBytes {
		return 0, 0, nil, RuleErrorEncryptedDataLen
	}

	// Connect basic txn to get the total input and the total output without
	// considering the transaction metadata.
	totalInput, totalOutput, utxoOpsForTxn, err := bav._connectBasicTransfer(
		txn, txHash, blockHeight, verifySignatures, false /*verifyMerchantMerkleRoot*/)
	if err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectPlaceOrder: ")
	}

	// At this point the inputs and outputs have been processed. Now we
	// need to handle the metadata.

	// The burn amount specified in the PlaceOrderMetadata contributes to the
	// output since the user is committing it to the order.
	//
	// Check for overflow of the outputs before adding.
	if totalOutput > math.MaxUint64-txMeta.AmountLockedNanos {
		return 0, 0, nil, RuleErrorTxnOutputWithInvalidAmount
	}
	totalOutput += txMeta.AmountLockedNanos
	// It's assumed the caller code will check that things like output <= input.

	// Get the merchant referred to by the pk.
	merchantEntry := bav._getMerchantEntryForMerchantID(txMeta.MerchantID)
	if merchantEntry == nil || merchantEntry.isDeleted {
		return 0, 0, nil, RuleErrorMissingMerchantForOrder
	}

	/*
		// I'm commenting this out for now because including a referrer in the PlaceOrder
		// transaction seems like a legitimate use-case, and removing this check doesn't
		// decrease security (aside from increasing the possibility of implementation error).

		// All of the outpts in this transaction need to be destined either for the
		// merchant's public key or the buyer's public key (recall the buyer public key
		// is the public key embedded in the transaction). This prevents situations where
		// a buyer somehow sends money to the wrong person.
		for _, txOut := range txn.TxOutputs {
			if !(reflect.DeepEqual(txOut.PublicKey, txn.PublicKey) ||
				reflect.DeepEqual(txOut.PublicKey, merchantEntry.PublicKey)) {

				return 0, 0, nil, RuleErrorOutputPublicKeyNotRecognized
			}
		}
	*/

	if verifySignatures {
		// _connectBasicTransfer has already checked that the transaction is
		// signed by the top-level public key, which we take to be the buyer's
		// public key so there is no need to verify anything futher.
	}

	// Create the OrderEntry that we're going to put into the db. Note there is no need
	// to check for duplicate orders because if an order has passed the initial
	// call to _connectBasicTransfer then the txid we use to identify it is necessarily
	// unique. At the end of the day, an order is really just a transfer with reputational
	// metadata attached and the ability to process a refund.
	orderEntry := OrderEntry{
		BuyerPk:    txn.PublicKey,
		MerchantID: txMeta.MerchantID,
		// Every entry saves the initial amount that was locked in placing the order.
		// This value never changes after initial order creation and is used to reliably
		// compute commissions in later functions that manipulate the order.
		PaymentAmountNanos: txMeta.AmountLockedNanos,
		// The order starts with some amount of nanos locked. This should
		// be equal to (purchase price + commissions). Later on, the purchase
		// price will be paid to the merchant but the (commissions) will remain
		// locked in the order, and stay there unless a refund is issued.
		AmountLockedNanos: txMeta.AmountLockedNanos,
		// The order goes at the end of the list.
		Pos:          bav.NumOrderEntries,
		BuyerMessage: txMeta.BuyerMessage,
		// The order starts in the "placed" state.
		State: OrderStatePlaced,

		LastModifiedBlock: blockHeight,

		// Initially an order has no impact on a merchant's score.
		MerchantScoreImpact: big.NewInt(0),

		// Set the orderID to match the tx hash.
		orderID: txHash,

		// The other fields are initialized to default values.
	}

	// Set the fields on the im-memory data structures for this new order entry.
	if err := bav._setOrderMappings(&orderEntry); err != nil {
		return 0, 0, nil, err
	}

	// Since we added this order to our list, bump the number of order entries.
	bav.NumOrderEntries++

	// Save the previous merchant stats before we modify them.
	prevStats := &MerchantStats{}
	*prevStats = *merchantEntry.Stats

	// Since an order has been placed for this merchant, increment the merchant
	// entry's value.
	merchantEntry.Stats.PaymentPlacedNanos += orderEntry.AmountLockedNanos
	merchantEntry.Stats.LastPlacedOrderHeight = blockHeight

	// Add an operation to the list at the end indicating we've added an order
	// to our data structure.
	utxoOpsForTxn = append(utxoOpsForTxn, &UtxoOperation{
		Type:              OperationTypeAddOrderEntry,
		PrevMerchantStats: prevStats,
	})

	return totalInput, totalOutput, utxoOpsForTxn, nil
}

// AdjustScoreOnMerchantAndOrder assumes we are removing the impact of the
// order from the merchant score and adding the new impact passed as an arg. Since
// this order's impact has now been updated, it is also reflected on the order entry.
func AdjustScoreOnMerchantAndOrder(merchantEntry *MerchantEntry, orderEntry *OrderEntry, newImpact *big.Int) {
	// The value stored in the order reflects the order's current impact on
	// the merchant's score.
	oldImpact := orderEntry.MerchantScoreImpact

	// Remove the old order impact and add the new order impact.
	merchantEntry.Stats.MerchantScore = ScoreMinusHash(
		merchantEntry.Stats.MerchantScore, oldImpact)
	merchantEntry.Stats.MerchantScore = ScorePlusHash(
		merchantEntry.Stats.MerchantScore, newImpact)

	// Adjust the impact on the order entry to reflect the update.
	orderEntry.MerchantScoreImpact = newImpact
}

func (bav *UtxoView) _connectConfirmOrder(
	txn *MsgUltranetTxn, txHash *BlockHash, blockHeight uint32, verifySignatures bool) (
	_totalInput uint64, _totalOutput uint64, _utxoOps []*UtxoOperation, _err error) {

	// Check that the order has the right TxnType.
	if txn.TxnMeta.GetTxnType() != TxnTypeConfirmOrder {
		return 0, 0, nil, fmt.Errorf("_connectConfirmOrder called with bad TxnType %s", txn.TxnMeta.GetTxnType().String())
	}
	txMeta := txn.TxnMeta.(*ConfirmOrderMetadata)

	// Validate that the OrderID in the txn isn't nil.
	if txMeta.OrderID == nil || len(txMeta.OrderID[:]) != HashSizeBytes {
		return 0, 0, nil, RuleErrorBadOrderID
	}

	// Connect basic transfer to get the total input and the total output without
	// considering the transaction metadata.
	totalInput, totalOutput, utxoOpsForTxn, err := bav._connectBasicTransfer(
		txn, txHash, blockHeight, verifySignatures, false /*verifyMerchantMerkleRoot*/)
	if err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectConfirmOrder: ")
	}

	// Dig up the order using the OrderID in the txn and make sure it's not nil.
	orderEntry := bav._getOrderEntryForOrderID(txMeta.OrderID)
	if orderEntry == nil {
		return 0, 0, nil, fmt.Errorf("_connectConfirmOrder: OrderID %v does not have corresponding OrderEntry in the db", txMeta.OrderID)
	}
	// Save the order data immediately before we start modifying it.
	prevOrderData := _getPrevOrderData(txMeta.OrderID, orderEntry)

	// Can't modify a deleted order.
	if orderEntry.isDeleted {
		return 0, 0, nil, fmt.Errorf("_connectConfirmOrder: OrderID %v has deleted OrderEntry in the view", txMeta.OrderID)
	}

	// A confirmation can only occur if the order is currently in the "placed"
	// state.
	if orderEntry.State != OrderStatePlaced {
		return 0, 0, nil, RuleErrorOrderBeingConfirmedNotInPlacedState
	}

	// As a sanity-check, verify that the payment amount in the order is equal to the
	// amount locked at this point.
	if orderEntry.PaymentAmountNanos != orderEntry.AmountLockedNanos {
		return 0, 0, nil, fmt.Errorf("_connectConfirmOrder: OrderID %v has payment "+
			"amount %d that differed from amount locked %d; this should never happen",
			txMeta.OrderID, orderEntry.PaymentAmountNanos, orderEntry.AmountLockedNanos)
	}

	// Change the state of the order. This is sufficient to result in the order's
	// state change being propagated to the db on the next flush.
	orderEntry.State = OrderStateConfirmed

	// Set the last modified height on the order.
	orderEntry.LastModifiedBlock = blockHeight

	// Upon confirmation of an order, the merchant is entitled to the amount locked
	// in the order minus the commissions on the transaction, which stay attached to
	// the order. We refer to the amount the merchant is entitled to as the "revenue."
	//
	// Note that this works because _connectBasicTransfer
	// only validates that inputs are spendable, and we don't validate
	// inputs >= outputs until after a transaction's metadata is processed.
	//
	// Note there is no need to verify that the outputs are spending to addresses owned
	// by the merchant since the person signing this transaction is the merchant herself,
	// in contrast to a refund where we must check that the merchant is reimbursing the
	// user.
	commissionNanos, revenueNanos, err := _computeCommissionsAndRevenueFromPayment(
		orderEntry.PaymentAmountNanos, bav.Params.CommissionBasisPoints)

	if err != nil {
		return 0, 0, nil, RuleErrorCommissionRevenueOverflow
	}

	// Add the revenue to the inputs since confirmation allows the merchant
	// to spend this amount. Check for overflow first as always.
	if totalInput > (math.MaxUint64 - revenueNanos) {
		return 0, 0, nil, fmt.Errorf("_connectConfirmOrder: Overflow "+
			"encountered computing input with amounts %d and %d", totalInput, revenueNanos)
	}
	totalInput += revenueNanos

	// Get the merchant referred to by the order.
	merchantEntry := bav._getMerchantEntryForMerchantID(orderEntry.MerchantID)
	if merchantEntry == nil || merchantEntry.isDeleted {
		return 0, 0, nil, RuleErrorMissingMerchantForOrder
	}

	// Save the previous merchant stats before we modify them.
	prevStats := &MerchantStats{}
	*prevStats = *merchantEntry.Stats

	// Verify that the merchant public key is equivalent to the public key referred
	// to by the transaction.
	if !reflect.DeepEqual(merchantEntry.PublicKey, txn.PublicKey) {
		return 0, 0, nil, RuleErrorConfirmTransactionMustBeSignedByMerchant
	}

	// Verify the signatures.
	if verifySignatures {
		// No need to verify anything here because the following is sufficient for the
		// action to be legal:
		// 1) The public key in the transaction is equivalent to the merchant public
		//    key for the order.
		// 2) The transaction is signed by the transaction public key, which is verified
		//    in _connectBasicTransfer.
	}

	// Since we're moving an order from the "placed" state to the "confirmed"
	// state, we need to break the buyer's payment into the commission and the
	// merchant's revenue and adjust the corresponding counters. Note that we
	// need to do this before modifying the order below.
	merchantEntry.Stats.PaymentPlacedNanos -= orderEntry.PaymentAmountNanos
	merchantEntry.Stats.CommissionsNanos += commissionNanos
	merchantEntry.Stats.RevenueConfirmedNanos += revenueNanos

	merchantEntry.Stats.LastConfirmedOrderHeight = blockHeight

	// Since we added the revenue to the input, we need to deduct it from the amount
	// locked in the order. We do this by setting the amount equal to the commissions,
	// which corresponds to (payment_amount - revenue).
	orderEntry.AmountLockedNanos = commissionNanos

	// Set the confirmation height for future reference.
	orderEntry.ConfirmationBlockHeight = blockHeight

	// When a confirmation occurs, the impact on the merchant's score is that
	// we add the commissions and subtract the revenue. We do this because
	// revenue she earns from an order should count against her until the order
	// is fulfilled in order to prevent her from being able to exit scam a
	// lot of people by pumping her score and then taking a lot of orders without
	// a large negative impact on her score until it's too late.
	newOrderImpact := big.NewInt(0)
	newOrderImpact = ScorePlusImpact(newOrderImpact, int64(commissionNanos), blockHeight, bav.Params)
	newOrderImpact = ScoreMinusImpact(newOrderImpact, int64(revenueNanos), blockHeight, bav.Params)

	AdjustScoreOnMerchantAndOrder(merchantEntry, orderEntry, newOrderImpact)

	// Add an operation with type OperationTypeConfirmOrder to the
	// operation list. Set the OrderIDModified
	// so that the transaction can be reverted if the block is disconnected.
	utxoOpsForTxn = append(utxoOpsForTxn, &UtxoOperation{
		Type:              OperationTypeConfirmOrder,
		PrevOrderData:     prevOrderData,
		PrevMerchantStats: prevStats,
	})

	return totalInput, totalOutput, utxoOpsForTxn, nil
}

func (bav *UtxoView) _connectRejectOrder(
	txn *MsgUltranetTxn, txHash *BlockHash, blockHeight uint32, verifySignatures bool) (
	_totalInput uint64, _totalOutput uint64, _utxoOps []*UtxoOperation, _err error) {

	// Check that the order has the right TxnType.
	if txn.TxnMeta.GetTxnType() != TxnTypeRejectOrder {
		return 0, 0, nil, fmt.Errorf("_connectRejectOrder called with bad TxnType %s", txn.TxnMeta.GetTxnType().String())
	}
	txMeta := txn.TxnMeta.(*RejectOrderMetadata)

	// Validate that the OrderID in the txn isn't nil.
	if txMeta.OrderID == nil || len(txMeta.OrderID[:]) != HashSizeBytes {
		return 0, 0, nil, RuleErrorBadOrderID
	}
	// Validate that the RejectReason field is valid.
	if len(txMeta.RejectReason) > MaxRejectReasonLengthBytes {
		return 0, 0, nil, RuleErrorRejectReasonLen
	}

	// Connect basic transfer to get the total input and the total output without
	// considering the transaction metadata.
	totalInput, totalOutput, utxoOpsForTxn, err := bav._connectBasicTransfer(
		txn, txHash, blockHeight, verifySignatures, false /*verifyMerchantMerkleRoot*/)
	if err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectRejectOrder: ")
	}

	// Dig up the order using the OrderID in the txn and make sure it's not nil.
	orderEntry := bav._getOrderEntryForOrderID(txMeta.OrderID)
	if orderEntry == nil {
		return 0, 0, nil, fmt.Errorf("_connectRejectOrder: OrderID %v does not have corresponding OrderEntry in the db", txMeta.OrderID)
	}
	// Save the order data immediately before we start modifying it.
	prevOrderData := _getPrevOrderData(txMeta.OrderID, orderEntry)

	// Can't modify a deleted order.
	if orderEntry.isDeleted {
		return 0, 0, nil, fmt.Errorf("_connectRejectOrder: OrderID %v has deleted OrderEntry in the view", txMeta.OrderID)
	}

	// A rejection can only be made if the order is in the "placed" state
	if orderEntry.State != OrderStatePlaced {
		return 0, 0, nil, fmt.Errorf("_connectRejectOrder: Cannot reject OrderEntry %+v because State != OrderStatePlaced", orderEntry)
	}

	// As a sanity-check, verify that the payment amount in the order is equal to the
	// amount locked at this point.
	if orderEntry.PaymentAmountNanos != orderEntry.AmountLockedNanos {
		return 0, 0, nil, fmt.Errorf("_connectRejectOrder: OrderID %v has payment "+
			"amount %d that differed from amount locked %d; this should never happen",
			txMeta.OrderID, orderEntry.PaymentAmountNanos, orderEntry.AmountLockedNanos)
	}

	// Get the merchant referred to by the order.
	merchantEntry := bav._getMerchantEntryForMerchantID(orderEntry.MerchantID)
	if merchantEntry == nil || merchantEntry.isDeleted {
		return 0, 0, nil, RuleErrorMissingMerchantForOrder
	}

	// Verify that the public key in the transaction is the merchant's public
	// key. Only the merchant is allowed to reject an order that belongs to
	// them.
	if !reflect.DeepEqual(txn.PublicKey, merchantEntry.PublicKey) {
		return 0, 0, nil, RuleErrorRejectTransactionMustBeSignedByMerchant
	}

	if verifySignatures {
		// No need to verify anything since the following is already sufficient to
		// ensure the transaction is valid:
		// - The public key of the transaction belongs to the merchant.
		// - _connectBasicTransfer has validated that the public key has signed
		//   the transaction.
	}

	// Save the previous merchant stats before we modify them.
	prevStats := &MerchantStats{}
	*prevStats = *merchantEntry.Stats

	// Since this order is being rejected, decrement the merchant's placed counter
	// and add to the merchant's rejected counter. Note we need the amount in the
	// order before modifying it with the code below.
	merchantEntry.Stats.PaymentPlacedNanos -= orderEntry.AmountLockedNanos
	merchantEntry.Stats.PaymentRejectedNanos += orderEntry.AmountLockedNanos
	merchantEntry.Stats.LastRejectedOrderHeight = blockHeight
	// Rejecting an order has no impact on a merchant's score.

	// When an order is rejected by a merchant, the outputs in the transaction
	// must reimburse the buyer the full amount of the order or else the order
	// is invalid.
	//
	// Sum all the outputs that are being paid to the buyer. No need to check for
	// overflow since the _connectBasicTransfer code already does this.
	var buyerOutputNanos uint64
	for _, ultranetOutput := range txn.TxOutputs {
		if reflect.DeepEqual(orderEntry.BuyerPk, ultranetOutput.PublicKey) {
			buyerOutputNanos += ultranetOutput.AmountNanos
		}
	}
	// Check that the total being refunded is greater than or equal to the expected
	// refund.
	if buyerOutputNanos < orderEntry.AmountLockedNanos {
		return 0, 0, nil, RuleErrorInsufficientRefund
	}

	// To reverse the order placement, add the amount that was locked in the order
	// back to the input. This gives the merchant the amount she needs to pay the
	// outputs destined for the buyer.
	if totalInput > (math.MaxUint64 - orderEntry.AmountLockedNanos) {
		return 0, 0, nil, RuleErrorInputOverflows
	}
	totalInput += orderEntry.AmountLockedNanos

	// Set the amount locked in the order to zero since it's being reimbursed to
	// the buyer's outputs in this txn.
	//
	// Note this ensures no Ultra is created or destroyed throughout the lifecycle
	// of the order (although some moves between the utxo and order db).
	orderEntry.AmountLockedNanos = 0

	// Change the state of the order. This is sufficient to result in the order's
	// state change being propagated to the db on the next flush.
	orderEntry.State = OrderStateRejected

	// Set the last modified height on the order.
	orderEntry.LastModifiedBlock = blockHeight

	// Set the reject reason and hash on the order.
	orderEntry.RejectReason = txMeta.RejectReason

	// Add an operation with type OperationTypeRejectOrder to the
	// operation list. Set the OrderIDModified
	// so that the transaction can be reverted if the block is disconnected.
	utxoOpsForTxn = append(utxoOpsForTxn, &UtxoOperation{
		Type:              OperationTypeRejectOrder,
		PrevOrderData:     prevOrderData,
		PrevMerchantStats: prevStats,
	})

	return totalInput, totalOutput, utxoOpsForTxn, nil
}

func (bav *UtxoView) _connectCancelOrder(
	txn *MsgUltranetTxn, txHash *BlockHash, blockHeight uint32, verifySignatures bool) (
	_totalInput uint64, _totalOutput uint64, _utxoOps []*UtxoOperation, _err error) {

	// Check that the order has the right TxnType.
	if txn.TxnMeta.GetTxnType() != TxnTypeCancelOrder {
		return 0, 0, nil, fmt.Errorf("_connectCancelOrder called with bad TxnType %s", txn.TxnMeta.GetTxnType().String())
	}
	txMeta := txn.TxnMeta.(*CancelOrderMetadata)

	// Validate that the OrderID in the txn isn't nil.
	if txMeta.OrderID == nil || len(txMeta.OrderID[:]) != HashSizeBytes {
		return 0, 0, nil, RuleErrorBadOrderID
	}

	// Connect basic transfer to get the total input and the total output without
	// considering the transaction metadata.
	totalInput, totalOutput, utxoOpsForTxn, err := bav._connectBasicTransfer(
		txn, txHash, blockHeight, verifySignatures, false /*verifyMerchantMerkleRoot*/)
	if err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectCancelOrder: ")
	}

	// Dig up the order using the OrderID in the txn and make sure it's not nil.
	orderEntry := bav._getOrderEntryForOrderID(txMeta.OrderID)
	if orderEntry == nil {
		return 0, 0, nil, fmt.Errorf("_connectCancelOrder: OrderID %v does not have corresponding OrderEntry in the db", txMeta.OrderID)
	}
	// Save the order data immediately before we start modifying it.
	prevOrderData := _getPrevOrderData(txMeta.OrderID, orderEntry)

	// Can't modify a deleted order.
	if orderEntry.isDeleted {
		return 0, 0, nil, fmt.Errorf("_connectCancelOrder: OrderID %v has deleted OrderEntry in the view", txMeta.OrderID)
	}

	// A cancellation can only be made if the order is in the "placed" state. After a merchant
	// confirms the order isn't cancelable.
	if orderEntry.State != OrderStatePlaced {
		return 0, 0, nil, RuleErrorOrderBeingCanceledNotInPlacedState
	}

	// As a sanity-check, verify that the payment amount in the order is equal to the
	// amount locked at this point.
	if orderEntry.PaymentAmountNanos != orderEntry.AmountLockedNanos {
		return 0, 0, nil, fmt.Errorf("_connectCancelOrder: OrderID %v has payment "+
			"amount %d that differed from amount locked %d; this should never happen",
			txMeta.OrderID, orderEntry.PaymentAmountNanos, orderEntry.AmountLockedNanos)
	}

	// An order can only be canceled by the user who created the order
	// in the first place. Thus return an error if this transaction's
	// public key does not match the buyer public key in the order.
	if !reflect.DeepEqual(orderEntry.BuyerPk, txn.PublicKey) {
		return 0, 0, nil, RuleErrorOnlyBuyerCanCancelOrder
	}

	// Get the merchant referred to by the order.
	merchantEntry := bav._getMerchantEntryForMerchantID(orderEntry.MerchantID)
	if merchantEntry == nil || merchantEntry.isDeleted {
		return 0, 0, nil, RuleErrorMissingMerchantForOrder
	}

	// Verify the signatures.
	if verifySignatures {
		// Since we verify that the buyer public key for the order is the same
		// as the public key for this transaction, and since _connectBasicTransfer
		// checks the signature on this transaction, there is nothing to do here.
	}

	// Save the previous merchant stats before we modify them.
	prevStats := &MerchantStats{}
	*prevStats = *merchantEntry.Stats

	// Since this order is being canceled, decrement the merchant's placed counter
	// and add to the merchant's canceled counter. Note we need the amount in the
	// order before modifying it with the code below.
	merchantEntry.Stats.PaymentPlacedNanos -= orderEntry.AmountLockedNanos
	merchantEntry.Stats.PaymentCanceledNanos += orderEntry.AmountLockedNanos
	merchantEntry.Stats.LastCanceledOrderHeight = blockHeight

	// In the case of an order cancelation, the person canceling the order is also
	// the person who should be getting the money back. So there isn't a need to
	// check that the outputs are paying a particular public key, since it can be
	// assumed that whatever outputs are being paid were authorized by the buyer
	// if the signature validation passed.

	// To reverse the order placement, add the amount that was locked in the order
	// back to the input. This gives the buyer the ability to send this amount to
	// any outputs she pleases. Check for overflow first.
	if totalInput > (math.MaxUint64 - orderEntry.AmountLockedNanos) {
		return 0, 0, nil, RuleErrorInputOverflows
	}
	totalInput += orderEntry.AmountLockedNanos

	// Set the amount locked in the order to zero since it's being reimbursed to
	// the buyer's outputs in this txn.
	//
	// Note this ensures no Ultra is created or destroyed throughout the lifecycle
	// of the order (although some moves between the utxo and order db).
	orderEntry.AmountLockedNanos = 0

	// Change the state of the order. This is sufficient to result in the order's
	// state change being propagated to the db on the next flush.
	orderEntry.State = OrderStateCanceled

	// Set the last modified height on the order.
	orderEntry.LastModifiedBlock = blockHeight

	// Add an operation with type OperationTypeCancelOrder to the
	// operation list. Set the OrderIDModified
	// so that the transaction can be reverted if the block is disconnected.
	utxoOpsForTxn = append(utxoOpsForTxn, &UtxoOperation{
		Type:              OperationTypeCancelOrder,
		PrevOrderData:     prevOrderData,
		PrevMerchantStats: prevStats,
	})

	return totalInput, totalOutput, utxoOpsForTxn, nil
}

func (bav *UtxoView) _connectFulfillOrder(
	txn *MsgUltranetTxn, txHash *BlockHash, blockHeight uint32, verifySignatures bool) (
	_totalInput uint64, _totalOutput uint64, _utxoOps []*UtxoOperation, _err error) {

	// Check that the order has the right TxnType.
	if txn.TxnMeta.GetTxnType() != TxnTypeFulfillOrder {
		return 0, 0, nil, fmt.Errorf("_connectFulfillOrder called with bad TxnType %s", txn.TxnMeta.GetTxnType().String())
	}
	txMeta := txn.TxnMeta.(*FulfillOrderMetadata)

	// Validate that the OrderID in the txn isn't nil.
	if txMeta.OrderID == nil || len(txMeta.OrderID[:]) != HashSizeBytes {
		return 0, 0, nil, RuleErrorBadOrderID
	}

	// Connect basic transfer to get the total input and the total output without
	// considering the transaction metadata.
	totalInput, totalOutput, utxoOpsForTxn, err := bav._connectBasicTransfer(
		txn, txHash, blockHeight, verifySignatures, false /*verifyMerchantMerkleRoot*/)
	if err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectFulfillOrder: ")
	}

	// Dig up the order using the OrderID in the txn and make sure it's not nil.
	orderEntry := bav._getOrderEntryForOrderID(txMeta.OrderID)
	if orderEntry == nil {
		return 0, 0, nil, fmt.Errorf("_connectFulfillOrder: OrderID %v does not have corresponding OrderEntry in the db", txMeta.OrderID)
	}
	// Save the order data immediately before we start modifying it.
	prevOrderData := _getPrevOrderData(txMeta.OrderID, orderEntry)

	// Can't modify a deleted order.
	if orderEntry.isDeleted {
		return 0, 0, nil, fmt.Errorf("_connectFulfillOrder: OrderID %v has deleted OrderEntry in the view", txMeta.OrderID)
	}

	// An order can only move into the "fulfilled" state from the "confirmed" state,
	// and only after enough time has passed.
	if orderEntry.State != OrderStateConfirmed {
		return 0, 0, nil, fmt.Errorf("_connectFulfillOrder: Cannot fulfill OrderEntry %+v because State != OrderStateConfirmed: %v", orderEntry, RuleErrorFulfillingOrderNotInConfirmedState)
	}
	// The confirmation block height must be set.
	if orderEntry.ConfirmationBlockHeight == 0 {
		return 0, 0, nil, fmt.Errorf("_connectFulfillOrder: Confirmation time not set even though order %+v is confirmed", orderEntry)
	}
	// The confirmation time must be sufficiently far in the past.
	blocksPassed := blockHeight - orderEntry.ConfirmationBlockHeight
	timePassed := time.Duration(int64(bav.Params.TimeBetweenBlocks) * int64(blocksPassed))
	if timePassed < bav.Params.TimeBeforeOrderFulfilled {
		return 0, 0, nil, RuleErrorFulfillingOrderTooSoon
	}

	// Get the merchant referred to by the order.
	merchantEntry := bav._getMerchantEntryForMerchantID(orderEntry.MerchantID)
	if merchantEntry == nil || merchantEntry.isDeleted {
		return 0, 0, nil, RuleErrorMissingMerchantForOrder
	}

	// Verify that the merchant's public key is the same as the public key referred
	// to by the transaction. Only the merchant is allowed to fulfill an order.
	if !reflect.DeepEqual(merchantEntry.PublicKey, txn.PublicKey) {
		return 0, 0, nil, RuleErrorOnlyMerchantCanFulfillOrder
	}

	// Verify the signatures.
	if verifySignatures {
		// No need to check any signatures because we have verified that the
		// merchant's public key is equal to the transaction public key and that
		// the transaction's public key has signed the transaction (according to
		// _connectBasicTransfer).
	}

	// Save the previous merchant stats before we modify them.
	prevStats := &MerchantStats{}
	*prevStats = *merchantEntry.Stats

	// Compute the original revenue from the order. The amount left in the order
	// when we reach this state is the commissions.
	commissionNanos, revenueNanos, err := _computeCommissionsAndRevenueFromPayment(
		orderEntry.PaymentAmountNanos, bav.Params.CommissionBasisPoints)

	if err != nil {
		return 0, 0, nil, RuleErrorCommissionRevenueOverflow
	}

	// Verify that the amount locked is equal to the commissions at this point.
	if orderEntry.AmountLockedNanos != commissionNanos {
		return 0, 0, nil, fmt.Errorf("_connectFulfillOrder: AmountLockedNanos %d not "+
			"equal to commissionNanos %d; this should never happen",
			orderEntry.AmountLockedNanos, commissionNanos)
	}

	// When an order moves from confirmed to fulfilled, we just move the revenue
	// over.
	merchantEntry.Stats.RevenueConfirmedNanos -= revenueNanos
	merchantEntry.Stats.RevenueFulfilledNanos += revenueNanos

	merchantEntry.Stats.LastFulfilledOrderHeight = blockHeight

	// Update the state of the order
	orderEntry.State = OrderStateFulfilled

	// Set the last modified height on the order.
	orderEntry.LastModifiedBlock = blockHeight

	// When a fulfillment occurs, the impact on the merchant's score is that
	// we add the commissions only. If the order was previously confirmed,
	// this has the effect of removing a penalty on the merchant equal to the
	// revenue of the order.
	newOrderImpact := big.NewInt(0)
	newOrderImpact = ScorePlusImpact(newOrderImpact, int64(commissionNanos), blockHeight, bav.Params)

	AdjustScoreOnMerchantAndOrder(merchantEntry, orderEntry, newOrderImpact)

	// This type of transaction doesn't modify inputs and outputs.

	// Add an operation with type OperationTypeFulfillOrder to the
	// operation list. Set the OrderIDModified
	// so that the transaction can be reverted if the block is disconnected.
	utxoOpsForTxn = append(utxoOpsForTxn, &UtxoOperation{
		Type:              OperationTypeFulfillOrder,
		PrevOrderData:     prevOrderData,
		PrevMerchantStats: prevStats,
	})

	return totalInput, totalOutput, utxoOpsForTxn, nil
}

func (bav *UtxoView) _connectReviewOrder(
	txn *MsgUltranetTxn, txHash *BlockHash, blockHeight uint32, verifySignatures bool) (
	_totalInput uint64, _totalOutput uint64, _utxoOps []*UtxoOperation, _err error) {

	// Check that the order has the right TxnType.
	if txn.TxnMeta.GetTxnType() != TxnTypeReviewOrder {
		return 0, 0, nil, fmt.Errorf("_connectReviewOrder called with bad TxnType %s", txn.TxnMeta.GetTxnType().String())
	}
	txMeta := txn.TxnMeta.(*ReviewOrderMetadata)

	// Validate that the OrderID in the txn isn't nil.
	if txMeta.OrderID == nil || len(txMeta.OrderID[:]) != HashSizeBytes {
		return 0, 0, nil, RuleErrorBadOrderID
	}

	// Validate that the review text isn't too long.
	if len(txMeta.ReviewText) > MaxReviewLengthBytes {
		return 0, 0, nil, RuleErrorReviewLen
	}

	// Connect basic transfer to get the total input and the total output without
	// considering the transaction metadata.
	totalInput, totalOutput, utxoOpsForTxn, err := bav._connectBasicTransfer(
		txn, txHash, blockHeight, verifySignatures, false /*verifyMerchantMerkleRoot*/)
	if err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectReviewOrder: ")
	}

	// Because ReviewOrder can be re-applied, we have to do something to
	// prevent the replay of a prior ReviewOrder transaction. The way we
	// choose to do this here is to require the totalInput to be non-zero. This
	// makes it impossible to replay a duplicate ReviewOrder transaction
	// because doing so would imply you're double-spending inputs. If we didn't
	// do this, then ReviewOrder transactions without any inputs or outputs
	// would be possible and replayable.
	if totalInput == 0 {
		return 0, 0, nil, RuleErrorReviewOrderRequiresNonZeroInput
	}

	// Dig up the order using the OrderID in the txn and make sure it's not nil.
	orderEntry := bav._getOrderEntryForOrderID(txMeta.OrderID)
	if orderEntry == nil {
		return 0, 0, nil, fmt.Errorf("_connectReviewOrder: OrderID %v does not have corresponding OrderEntry in the db", txMeta.OrderID)
	}
	// Save the order data immediately before we start modifying it.
	prevOrderData := _getPrevOrderData(txMeta.OrderID, orderEntry)

	// Can't modify a deleted order.
	if orderEntry.isDeleted {
		return 0, 0, nil, fmt.Errorf("_connectReviewOrder: OrderID %v has deleted OrderEntry in the view", txMeta.OrderID)
	}

	// A review can only be made if the order is in the "confirmed" state or
	// "fulfilled" state or "reviewed" state. In the latter case the user is
	// revising a review.
	if orderEntry.State != OrderStateConfirmed && orderEntry.State != OrderStateReviewed && orderEntry.State != OrderStateFulfilled {
		return 0, 0, nil, fmt.Errorf("_connectReviewOrder: Cannot review OrderEntry %v "+
			"because State != OrderState(Confirmed|Reviewed|Fulfilled): %v",
			orderEntry, RuleErrorReviewingOrderNotInPlacedOrFulfilledOrReviewedState)
	}

	// Verify that the transaction public key is the same as the buyer's public
	// key according to the order. The buyer is the only one who has the authority
	// to review an order.
	if !reflect.DeepEqual(orderEntry.BuyerPk, txn.PublicKey) {
		return 0, 0, nil, RuleErrorOnlyBuyerCanReviewOrder
	}

	// Verify the signatures.
	if verifySignatures {
		// No need to do anything since the buyer's public key has signed this order
		// and this signature has already been verified by _connectBasicTransfer.
	}

	// Get the merchant referred to by the order.
	merchantEntry := bav._getMerchantEntryForMerchantID(orderEntry.MerchantID)
	if merchantEntry == nil || merchantEntry.isDeleted {
		return 0, 0, nil, RuleErrorMissingMerchantForOrder
	}

	// Save the previous merchant stats before we modify them.
	prevStats := &MerchantStats{}
	*prevStats = *merchantEntry.Stats

	// Compute the original revenue from the order. The amount left in the order
	// when we reach this state is the commissions.
	commissionNanos, revenueNanos, err := _computeCommissionsAndRevenueFromPayment(
		orderEntry.PaymentAmountNanos, bav.Params.CommissionBasisPoints)

	if err != nil {
		return 0, 0, nil, RuleErrorCommissionRevenueOverflow
	}

	// Verify that the amount locked is equal to the commissions at this point.
	if orderEntry.AmountLockedNanos != commissionNanos {
		return 0, 0, nil, fmt.Errorf("_connectReviewOrder: AmountLockedNanos %d not "+
			"equal to commissionNanos %d; this should never happen",
			orderEntry.AmountLockedNanos, commissionNanos)
	}

	// Depending on what the order's previous state was, deduct the commissions
	// from the proper counter. Note we need to do this before modifying the order's
	// State and HasStrike below.
	if orderEntry.State == OrderStateConfirmed {
		merchantEntry.Stats.RevenueConfirmedNanos -= revenueNanos
	} else if orderEntry.State == OrderStateFulfilled {
		merchantEntry.Stats.RevenueFulfilledNanos -= revenueNanos
	} else if orderEntry.State == OrderStateReviewed {
		// If the order was already in the reviewed state then subtract the
		// revenue off of the proper counter depending on whether or not it
		// had a strike or not.
		if orderEntry.ReviewType == ReviewTypeNegative {
			merchantEntry.Stats.RevenueNegativeNanos -= revenueNanos
		} else if orderEntry.ReviewType == ReviewTypeNeutral {
			merchantEntry.Stats.RevenueNeutralNanos -= revenueNanos
		} else if orderEntry.ReviewType == ReviewTypePositive {
			merchantEntry.Stats.RevenuePositiveNanos -= revenueNanos
		} else {
			return 0, 0, nil, fmt.Errorf("_connectReviewOrder: Unrecognized ReviewType %d", orderEntry.ReviewType)
		}
	} else {
		return 0, 0, nil, fmt.Errorf("_connectReviewOrder: Unrecognized previous state: %v", orderEntry.State)
	}

	// Now add the revenue to the proper counter depending on whether or not
	// the user has decided to strike the merchant. Note that this is OK because
	// we made sure to subtract the revenue off the corresponding counter in the
	// block above. So no Ultra is being created here.
	if txMeta.ReviewType == ReviewTypeNegative {
		merchantEntry.Stats.RevenueNegativeNanos += revenueNanos
		merchantEntry.Stats.LastNegativeReviewOrderHeight = blockHeight
	} else if txMeta.ReviewType == ReviewTypeNeutral {
		merchantEntry.Stats.RevenueNeutralNanos += revenueNanos
		merchantEntry.Stats.LastNeturalReviewOrderHeight = blockHeight
	} else if txMeta.ReviewType == ReviewTypePositive {
		merchantEntry.Stats.RevenuePositiveNanos += revenueNanos
		merchantEntry.Stats.LastPositiveReviewOrderHeight = blockHeight
	} else {
		return 0, 0, nil, fmt.Errorf("_connectReviewOrder: Unrecognized ReviewType %d", orderEntry.ReviewType)
	}

	// Change the state of the order. This is sufficient to result in the order's
	// state change being propagated to the db on the next flush. If this txn is
	// modifying a pre-existing review, this will be a no-op and that's OK.
	orderEntry.State = OrderStateReviewed

	// Set the last modified height on the order.
	orderEntry.LastModifiedBlock = blockHeight

	// When an order is reviewed, we modify the entry to include the review. This
	// will get flushed to the db later as well.
	orderEntry.ReviewType = txMeta.ReviewType
	orderEntry.ReviewText = txMeta.ReviewText

	// When a review occurs, the impact on the merchant's score is that
	// we add the commissions and subtract the revenue from the order *only if*
	// the review is negative.
	newOrderImpact := big.NewInt(0)
	// TODO: Perhaps a neutral review should result in the loss of commissions as well.
	newOrderImpact = ScorePlusImpact(newOrderImpact, int64(commissionNanos), blockHeight, bav.Params)
	if txMeta.ReviewType == ReviewTypeNegative {
		newOrderImpact = ScoreMinusImpact(newOrderImpact, int64(revenueNanos), blockHeight, bav.Params)
	}

	AdjustScoreOnMerchantAndOrder(merchantEntry, orderEntry, newOrderImpact)

	// This type of transaction doesn't modify inputs and outputs.

	// Add an operation with type OperationTypeReviewOrder to the
	// operation list. Set the OrderIDModified
	// so that the transaction can be reverted if the block is disconnected.
	utxoOpsForTxn = append(utxoOpsForTxn, &UtxoOperation{
		Type:              OperationTypeReviewOrder,
		PrevOrderData:     prevOrderData,
		PrevMerchantStats: prevStats,
	})

	return totalInput, totalOutput, utxoOpsForTxn, nil
}

func (bav *UtxoView) _connectRefundOrder(
	txn *MsgUltranetTxn, txHash *BlockHash, blockHeight uint32, verifySignatures bool) (
	_totalInput uint64, _totalOutput uint64, _utxoOps []*UtxoOperation, _err error) {

	// Check that the order has the right TxnType.
	if txn.TxnMeta.GetTxnType() != TxnTypeRefundOrder {
		return 0, 0, nil, fmt.Errorf("_connectRefundOrder called with bad TxnType %s", txn.TxnMeta.GetTxnType().String())
	}
	txMeta := txn.TxnMeta.(*RefundOrderMetadata)

	// Validate that the OrderID in the txn isn't nil.
	if txMeta.OrderID == nil || len(txMeta.OrderID[:]) != HashSizeBytes {
		return 0, 0, nil, RuleErrorBadOrderID
	}

	// Connect basic transfer to get the total input and the total output without
	// considering the transaction metadata.
	totalInput, totalOutput, utxoOpsForTxn, err := bav._connectBasicTransfer(
		txn, txHash, blockHeight, verifySignatures, false /*verifyMerchantMerkleRoot*/)
	if err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectRefundOrder: ")
	}

	// Dig up the order using the OrderID in the txn and make sure it's not nil.
	orderEntry := bav._getOrderEntryForOrderID(txMeta.OrderID)
	if orderEntry == nil {
		return 0, 0, nil, fmt.Errorf("_connectRefundOrder: OrderID %v does not have corresponding OrderEntry in the db", txMeta.OrderID)
	}
	// Save the order data immediately before we start modifying it.
	prevOrderData := _getPrevOrderData(txMeta.OrderID, orderEntry)

	// Can't modify a deleted order.
	if orderEntry.isDeleted {
		return 0, 0, nil, fmt.Errorf("_connectRefundOrder: OrderID %v has deleted OrderEntry in the view", txMeta.OrderID)
	}

	// A refund can only be made if the order is in the "confirmed" state, the
	// "fulfilled" state or the "reviewed" state.
	if orderEntry.State != OrderStateConfirmed && orderEntry.State != OrderStateReviewed && orderEntry.State != OrderStateFulfilled {
		return 0, 0, nil, fmt.Errorf("_connectRefundOrder: Cannot refund OrderEntry "+
			"%v because State != OrderState(Confirmed|Reviewed|Fulfilled): %v",
			orderEntry, RuleErrorRefundingOrderNotInStateConfirmedOrReviewdOrFulfilled)
	}

	// Get the merchant referred to by the order.
	merchantEntry := bav._getMerchantEntryForMerchantID(orderEntry.MerchantID)
	if merchantEntry == nil || merchantEntry.isDeleted {
		return 0, 0, nil, RuleErrorMissingMerchantForOrder
	}

	// Save the previous merchant stats before we modify them.
	prevStats := &MerchantStats{}
	*prevStats = *merchantEntry.Stats

	// Only the merchant has the authority to refund an order.
	if !reflect.DeepEqual(merchantEntry.PublicKey, txn.PublicKey) {
		return 0, 0, nil, RuleErrorOnlyMerchantCanRefundOrder
	}

	// Verify the signatures.
	if verifySignatures {
		// Verifying that the merchant's public key is equivalent to the transaction's
		// public key is sufficient because _connectBasicTransfer has verified that the
		// transaction's public key has signed the transaction.
	}

	// Compute the original revenue from the order. The amount left in the order
	// when we reach this state is the commissions.
	//
	// When an order is refunded, we do the following:
	// - Get the amount locked in the order, which is equal to the commissions
	//   retained for the order.
	// - Compute the "revenue" of the order, which is the
	//   (original payment amount - commissions). This is the amount that will be
	//   refunded to the user. Note that we don't refund commissions to users to
	//   avoid giving merchants a perverse incentive to create a lot of fake
	//   transactions.
	// - Sum all the outputs that are being paid to the buyer's pk.
	// - Ensure (sum of buyer pk outputs) > (revenue = refund amount).
	//
	// Note that all of the above ensures that no new Ultra is created throughout
	// the lifecycle of the order (although it does move around between the utxo
	// db and the order db).
	//
	// Note that because the order's state is confirmed or reviewed, the order
	// currently stores:
	// - commissions = (original_ultra_amount * commission_rate)
	commissionNanos, revenueNanos, err := _computeCommissionsAndRevenueFromPayment(
		orderEntry.PaymentAmountNanos, bav.Params.CommissionBasisPoints)
	refundNanos := revenueNanos

	if err != nil {
		return 0, 0, nil, RuleErrorCommissionRevenueOverflow
	}

	// Verify that the amount locked is equal to the commissions at this point.
	if orderEntry.AmountLockedNanos != commissionNanos {
		return 0, 0, nil, fmt.Errorf("_connectRefundOrder: AmountLockedNanos %d not "+
			"equal to commissionNanos %d; this should never happen",
			orderEntry.AmountLockedNanos, commissionNanos)
	}

	// Sum all the outputs that are being paid to the buyer. No need to check for
	// overflow since the _connectBasicTransfer code already does this.
	var buyerOutputNanos uint64
	for _, ultranetOutput := range txn.TxOutputs {
		if reflect.DeepEqual(orderEntry.BuyerPk, ultranetOutput.PublicKey) {
			buyerOutputNanos += ultranetOutput.AmountNanos
		}
	}
	// Check that the total being refunded is greater than or equal to the expected
	// refund.
	if buyerOutputNanos < refundNanos {
		return 0, 0, nil, RuleErrorInsufficientRefund
	}

	// Depending on what the order's previous state was, deduct the commissions
	// from the proper counter. Note we need to do this before we modify the order's
	// State below.
	if orderEntry.State == OrderStateConfirmed {
		merchantEntry.Stats.RevenueConfirmedNanos -= refundNanos
	} else if orderEntry.State == OrderStateFulfilled {
		merchantEntry.Stats.RevenueFulfilledNanos -= refundNanos
	} else if orderEntry.State == OrderStateReviewed {
		// If the order was reviewed, we need to subract the refund amount from the
		// proper counting depenting on the nature of the review.
		if orderEntry.ReviewType == ReviewTypeNegative {
			merchantEntry.Stats.RevenueNegativeNanos -= refundNanos
		} else if orderEntry.ReviewType == ReviewTypeNeutral {
			merchantEntry.Stats.RevenueNeutralNanos -= refundNanos
		} else if orderEntry.ReviewType == ReviewTypePositive {
			merchantEntry.Stats.RevenuePositiveNanos -= refundNanos
		} else {
			return 0, 0, nil, fmt.Errorf("_connectRefundOrder: Unrecognized ReviewType %d", orderEntry.ReviewType)
		}
	} else {
		return 0, 0, nil, fmt.Errorf("_connectRefundOrder: Unrecognized previous state: %v", orderEntry.State)
	}

	// Now add the revenue to the refund counter.
	merchantEntry.Stats.RevenueRefundedNanos += refundNanos

	merchantEntry.Stats.LastRefundedOrderHeight = blockHeight

	// Note that while commissions are not refunded as part of an order being
	// refunded, we still deduct the commissions from the merchant's counter because
	// the commissions no longer count toward a merchant's reputation. We have
	// to do this in order to avoid giving merchants a perverse incentive to
	// confirm a bunch of orders and refund them.
	merchantEntry.Stats.CommissionsNanos -= commissionNanos

	// Change the state of the order. This is sufficient to result in the order's
	// state change being propagated to the db on the next flush.
	orderEntry.State = OrderStateRefunded

	// Set the last modified height on the order.
	orderEntry.LastModifiedBlock = blockHeight

	// When a refund occurs, the impact on the merchant's score is zero.
	//
	// Note that while commissions are not refunded as part of an order being
	// refunded, we still don't include commissions in the merchant's score in
	// this case. We have to do this in order to avoid giving merchants a
	// perverse incentive to confirm a bunch of orders and refund them.
	newOrderImpact := big.NewInt(0)

	AdjustScoreOnMerchantAndOrder(merchantEntry, orderEntry, newOrderImpact)

	// Add an operation with type OperationTypeRefundOrder to the
	// operation list. Set the OrderIDModified
	// so that the transaction can be reverted if the block is disconnected.
	utxoOpsForTxn = append(utxoOpsForTxn, &UtxoOperation{
		Type:              OperationTypeRefundOrder,
		PrevOrderData:     prevOrderData,
		PrevMerchantStats: prevStats,
	})

	return totalInput, totalOutput, utxoOpsForTxn, nil
}

func (bav *UtxoView) _getMessageEntryForMessageKey(messageKey *MessageKey) *MessageEntry {
	// If an entry exists in the in-memory map, return the value of that mapping.
	mapValue, existsMapValue := bav.MessageKeyToMessageData[*messageKey]
	if existsMapValue {
		return mapValue
	}

	// If we get here it means no value exists in our in-memory map. In this case,
	// defer to the db. If a mapping exists in the db, return it. If not, return
	// nil. Either way, save the value to the in-memory view mapping got later.
	dbMessageEntry := DbGetMessageEntry(bav.Handle, messageKey.PublicKey[:], messageKey.TstampNanos)
	if dbMessageEntry != nil {
		bav._setMessageEntryMappings(dbMessageEntry)
	}
	return dbMessageEntry
}

func (bav *UtxoView) _setMessageEntryMappings(messageEntry *MessageEntry) {
	// This function shouldn't be called with nil.
	if messageEntry == nil {
		glog.Errorf("_setMessageEntryMappings: Called with nil MessageEntry; " +
			"this should never happen.")
		return
	}

	// Add a mapping for the sender and the recipient.
	senderKey := MakeMessageKey(messageEntry.SenderPublicKey, messageEntry.TstampNanos)
	bav.MessageKeyToMessageData[senderKey] = messageEntry

	recipientKey := MakeMessageKey(messageEntry.RecipientPublicKey, messageEntry.TstampNanos)
	bav.MessageKeyToMessageData[recipientKey] = messageEntry
}

func (bav *UtxoView) _deleteMessageEntryMappings(messageEntry *MessageEntry) {

	// Create a tombstone entry.
	tombstoneMessageEntry := *messageEntry
	tombstoneMessageEntry.isDeleted = true

	// Set the mappings to point to the tombstone entry.
	bav._setMessageEntryMappings(&tombstoneMessageEntry)
}

func (bav *UtxoView) _existsBitcoinTxIDMapping(bitcoinBurnTxID *BlockHash) bool {
	// If an entry exists in the in-memory map, return the value of that mapping.
	mapValue, existsMapValue := bav.BitcoinBurnTxIDs[*bitcoinBurnTxID]
	if existsMapValue {
		return mapValue
	}

	// If we get here it means no value exists in our in-memory map. In this case,
	// defer to the db. If a mapping exists in the db, return true. If not, return
	// false. Either way, save the value to the in-memory view mapping got later.
	dbHasMapping := DbExistsBitcoinBurnTxID(bav.Handle, bitcoinBurnTxID)
	bav.BitcoinBurnTxIDs[*bitcoinBurnTxID] = dbHasMapping
	return dbHasMapping
}

func (bav *UtxoView) _setBitcoinBurnTxIDMappings(bitcoinBurnTxID *BlockHash) {
	bav.BitcoinBurnTxIDs[*bitcoinBurnTxID] = true
}

func (bav *UtxoView) _deleteBitcoinBurnTxIDMappings(bitcoinBurnTxID *BlockHash) {
	bav.BitcoinBurnTxIDs[*bitcoinBurnTxID] = false
}

func _extractBitcoinPublicKeyFromBitcoinTransactionInputs(
	bitcoinTransaction *wire.MsgTx, btcdParams *chaincfg.Params) (
	_publicKey *btcec.PublicKey, _err error) {

	for _, input := range bitcoinTransaction.TxIn {
		// Parse the script operations.
		sigPops, err := txscript.ParseScript(input.SignatureScript)
		if err != nil {
			// If we encounter an error parsing the input script just continue. We only
			// need on public key in order for the transaction to be valid and it's OK
			// if some of the inputs have issues.
			continue
		}
		for _, pop := range sigPops {
			maybePkBytes := pop.Data
			addr, err := btcutil.NewAddressPubKey(maybePkBytes, btcdParams)
			if err == nil {
				// If we were able to successfully decode the bytes into a public key,
				// return it.
				if addr.PubKey() == nil {
					// If the public key is nil, don't use this input. Instead keep iterating
					// to find one with a non-nil public key.
					continue
				}
				return addr.PubKey(), nil
			}

			// If we encounter an error parsing the operation just continue. We
			// parse operations until one of them can be decoded into a public key
			// that we can actually use on a best-effort basis.
			continue
		}

		// If we get here it means we could not extract a public key from this
		// particular input. This is OK as long as we can find a public key in
		// one of the other inputs.
	}

	// If we get here it means we went through all the inputs and were not able to
	// successfully decode a public key from the inputs. Error in this case.
	return nil, fmt.Errorf("_extractBitcoinPublicKeyFromBitcoinTransactionInputs: " +
		"No valid public key found after scanning all input signature scripts")
}

func _computeBitcoinBurnOutput(bitcoinTransaction *wire.MsgTx, bitcoinBurnAddress string,
	btcdParams *chaincfg.Params) (_burnedOutputSatoshis int64, _err error) {

	totalBurnedOutput := int64(0)
	for _, output := range bitcoinTransaction.TxOut {
		class, addresses, _, err := txscript.ExtractPkScriptAddrs(
			output.PkScript, btcdParams)
		if err != nil {
			// If we hit an error processing an output just let it slide. We only honor
			// P2PKH transactions and even this we do on a best-effort basis.
			//
			// TODO: Run this over a few Bitcoin blocks to see what its errors look like
			// so we can catch them here.
			continue
		}
		// We only allow P2PK and P2PKH transactions to be counted as burns. Allowing
		// anything else would require making this logic more sophisticated. Additionally,
		// limiting the gamut of possible transactions protects us from weird attacks
		// whereby someone could make us think that some Bitcoin was burned when really
		// it's just some fancy script that fools us into thinking that.
		if !(class == txscript.PubKeyTy || class == txscript.PubKeyHashTy) {
			continue
		}
		// We only process outputs if they have a single address in them, which should
		// be the case anyway given the classes we're limiting ourselves to above.
		if len(addresses) != 1 {
			continue
		}

		// At this point we're confident that we're dealing with a nice vanilla
		// P2PK or P2PKH output that contains just one address that its making a
		// simple payment to.

		// Extract the address and add its output to the total if it happens to be
		// equal to the burn address.
		outputAddress := addresses[0]
		if outputAddress.EncodeAddress() == bitcoinBurnAddress {
			// Check for overflow just in case.
			if output.Value < 0 || totalBurnedOutput > math.MaxInt64-output.Value {
				return 0, fmt.Errorf("_computeBitcoinBurnOutput: output value %d would "+
					"overflow totalBurnedOutput %d; this should never happen",
					output.Value, totalBurnedOutput)
			}
			totalBurnedOutput += output.Value
		}
	}

	return totalBurnedOutput, nil
}

func (bav *UtxoView) _connectBitcoinExchange(
	txn *MsgUltranetTxn, txHash *BlockHash, blockHeight uint32, verifySignatures bool,
	enforceMinBitcoinBurnWork bool) (
	_totalInput uint64, _totalOutput uint64, _utxoOps []*UtxoOperation, _err error) {

	if bav.BitcoinManager == nil ||
		!bav.BitcoinManager.IsCurrent(false /*considerCumWork*/) {

		return 0, 0, nil, fmt.Errorf("_connectBitcoinExchange: BitcoinManager "+
			"must be non-nil and time-current in order to connect "+
			"BitcoinExchange transactions: %v", bav.BitcoinManager)
	}
	// At this point we are confident that we have a non-nil time-current
	// BitcoinManager we can refer to for validation purposes.

	// Check that the transaction has the right TxnType.
	if txn.TxnMeta.GetTxnType() != TxnTypeBitcoinExchange {
		return 0, 0, nil, fmt.Errorf("_connectBitcoinExchange: called with bad TxnType %s",
			txn.TxnMeta.GetTxnType().String())
	}
	txMeta := txn.TxnMeta.(*BitcoinExchangeMetadata)

	// Verify that the the transaction has:
	// - no inputs
	// - no outputs
	// - no public key
	// - no signature
	//
	// For BtcExchange transactions the only thing that should be set is the
	// BitcoinExchange metadata. This is because we derive all of the other
	// fields for this transaction from the underlying BitcoinTransaction in
	// the metadata. Not doing this would potentially open up avenues for people
	// to repackage Bitcoin burn transactions paying themselves rather than the person
	// who originally burned the Bitcoin.
	if len(txn.TxInputs) != 0 {
		return 0, 0, nil, RuleErrorBitcoinExchangeShouldNotHaveInputs
	}
	if len(txn.TxOutputs) != 0 {
		return 0, 0, nil, RuleErrorBitcoinExchangeShouldNotHaveOutputs
	}
	if len(txn.PublicKey) != 0 {
		return 0, 0, nil, RuleErrorBitcoinExchangeShouldNotHavePublicKey
	}
	if txn.Signature != nil {
		return 0, 0, nil, RuleErrorBitcoinExchangeShouldNotHaveSignature
	}

	// Check that the BitcoinTransaction has a hash that lines up with the
	// BitcoinTransactionHash included in the transaction.
	bitcoinTxHash := (BlockHash)(txMeta.BitcoinTransaction.TxHash())
	if bitcoinTxHash != *txMeta.BitcoinTransactionHash {
		return 0, 0, nil, RuleErrorBitcoinExchangeHasBadBitcoinTxHash
	}

	// Check that the BitcoinTransactionHash has not been used in a BitcoinExchange
	// transaction in the past. This ensures that all the Bitcoin that is burned can
	// be converted to Ultra precisely one time. No need to worry about malleability
	// because we also verify that the transaction was mined into a valid Bitcoin block
	// with a lot of work on top of it, which means we can't be tricked by someone
	// twiddling the transaction to give it a different hash (unless the Bitcoin chain
	// is also tricked, in which case we have bigger problems).
	if bav._existsBitcoinTxIDMapping(&bitcoinTxHash) {
		return 0, 0, nil, RuleErrorBitcoinExchangeDoubleSpendingBitcoinTransaction
	}

	// Check that the BitcoinBlockHash exists in our main Bitcoin header chain.
	blockNodeForBlockHash := bav.BitcoinManager.GetBitcoinBlockNode(txMeta.BitcoinBlockHash)
	if blockNodeForBlockHash == nil {
		return 0, 0, nil, RuleErrorBitcoinExchangeBlockHashNotFoundInMainBitcoinChain
	}

	// Check that the Bitcoin block has a sufficient amount of work built on top of it
	// for us to consider its contents. Note that the amount of work must be determined
	// based on the oldest time-current block that we have rather than the tip. Note also
	// that because we verified that the BitcoinManager is time-current that we must have
	// at least one time-current block in our main chain.
	bitcoinBurnWorkBlocks :=
		bav.BitcoinManager.GetBitcoinBurnWorkBlocks(blockNodeForBlockHash.Height)
	if enforceMinBitcoinBurnWork &&
		bitcoinBurnWorkBlocks < int64(bav.Params.BitcoinMinBurnWorkBlocks) {

		// Note we opt against returning a RuleError here. This should prevent the block
		// from being marked as invalid so we can reconsider it if a fork favors it in the
		// long run which, although unlikely, could theoretically happen
		return 0, 0, nil, fmt.Errorf("_connectBitcoinExchange: Number of Bitcoin "+
			"burn work blocks mined on top of transaction %d is below MinBitcoinBurnWork %d",
			bitcoinBurnWorkBlocks, bav.Params.BitcoinMinBurnWorkBlocks)
	}

	// At this point we found a node on the main Bitcoin chain corresponding to the block hash
	// in the txMeta and have verified that this block has a sufficient amount of work built on
	// top of it to make us want to consider it. Its values should be set according to the
	// corresponding Bitcoin header.

	// Verify that the BitcoinMerkleRoot lines up with what is present in the Bitcoin
	// header.
	if *blockNodeForBlockHash.Header.TransactionMerkleRoot != *txMeta.BitcoinMerkleRoot {
		return 0, 0, nil, RuleErrorBitcoinExchangeHasBadMerkleRoot
	}

	// Check that the BitcoinMerkleProof successfully proves that the
	// BitcoinTransaction was legitimately included in the mined Bitcoin block. Note
	// that we verified taht the BitcoinMerkleRoot is the same one that corresponds
	// to the provided BitcoinBlockHash.
	if !merkletree.VerifyProof(
		txMeta.BitcoinTransactionHash[:], txMeta.BitcoinMerkleProof, txMeta.BitcoinMerkleRoot[:]) {

		return 0, 0, nil, RuleErrorBitcoinExchangeInvalidMerkleProof
	}
	// At this point we are sure that the BitcoinTransaction provided was mined into
	// a Bitcoin block with a sufficient amount of work on top of it and that the
	// BitcoinTransaction has not been used in a BitcoinExchange transaction in the
	// past.

	if verifySignatures {
		// We don't check for signatures and we don't do any checks to verify that
		// the inputs of the BitcoinTransaction are actually entitled to spend their
		// outputs. We get away with this because we check that the transaction
		// was mined into a Bitcoin block with a lot of work on top of it, which
		// would presumably be near-impossible if the Bitcoin transaction were invalid.
	}

	// Extract a public key from the BitcoinTransaction's inputs. Note that we only
	// consider P2PKH inputs to be valid. If no P2PKH inputs are found then we consider
	// the transaction as a whole to be invalid since we don't know who to credit the
	// new Ultra to. If we find more than one P2PKH input, we consider the public key
	// corresponding to the first of these inputs to be the one that will receive the
	// Ultra that will be created.
	publicKey, err := _extractBitcoinPublicKeyFromBitcoinTransactionInputs(
		txMeta.BitcoinTransaction, bav.Params.BitcoinBtcdParams)
	if err != nil {
		return 0, 0, nil, RuleErrorBitcoinExchangeValidPublicKeyNotFoundInInputs
	}
	// At this point, we should have extracted a public key from the Bitcoin transaction
	// that we expect to credit the newly-created Ultra to.

	// Go through the transaction's outputs and count up the satoshis that are being
	// allocated to the burn address. If no Bitcoin is being sent to the burn address
	// then we consider the transaction to be invalid. Watch out for overflow as we do
	// this.
	totalBurnOutput, err := _computeBitcoinBurnOutput(
		txMeta.BitcoinTransaction, bav.Params.BitcoinBurnAddress,
		bav.Params.BitcoinBtcdParams)
	if err != nil {
		return 0, 0, nil, RuleErrorBitcoinExchangeProblemComputingBurnOutput
	}
	if totalBurnOutput <= 0 {
		return 0, 0, nil, RuleErrorBitcoinExchangeTotalOutputLessThanOrEqualZero
	}

	// At this point we know how many satoshis were burned and we know the public key
	// that should receive the Ultra we are going to create.

	// Compute the amount of Ultra that we should create as a result of this transaction.
	nanosToCreate, err := CalcNanosToCreate(bav.NanosPurchased, uint64(totalBurnOutput))
	if err != nil {
		return 0, 0, nil, fmt.Errorf("_connectBitcoinExchange: Problem calculating "+
			"nanos to create with startNanos %d and satoshisToBurn %d",
			bav.NanosPurchased, totalBurnOutput)
	}

	// Compute the amount of Ultra that the user will receive. Note
	// that we allocate a small fee to the miner to incentivize her to include the
	// transaction in a block. The fee for BitcoinExchange transactions is fixed because
	// if it weren't then a miner could theoretically repackage the BitcoinTransaction
	// into a new BitcoinExchange transaction that spends all of the newly-created Ultra as
	// a fee. This way of doing it is a bit annoying because it means that for small
	// BitcoinExchange transactions they might have to wait a long time and for large
	// BitcoinExchange transactions they are highly likely to be overpaying. But it has
	// the major benefit that all miners can autonomously scan the Bitcoin chain for
	// burn transactions that they can turn into BitcoinExchange transactions, effectively
	// making it so that the user doesn't have to manage the process of wrapping the
	// Bitcoin burn into a BitcoinExchange transaction herself.
	//
	// We use bigints because we're paranoid about overflow. Realistically, though,
	// it will never happen.
	nanosToCreateBigint := big.NewInt(int64(nanosToCreate))
	bitcoinExchangeFeeBigint := big.NewInt(
		int64(bav.Params.BitcoinExchangeFeeBasisPoints))
	// = nanosToCreate * bitcoinExchangeFeeBps
	nanosTimesFeeBps := big.NewInt(0).Mul(nanosToCreateBigint, bitcoinExchangeFeeBigint)
	// feeNanos = nanosToCreate * bitcoinExchangeFeeBps / 10000
	feeNanosBigint := big.NewInt(0).Div(nanosTimesFeeBps, big.NewInt(10000))
	if feeNanosBigint.Cmp(big.NewInt(math.MaxInt64)) > 0 ||
		nanosToCreate < uint64(feeNanosBigint.Int64()) {

		return 0, 0, nil, RuleErrorBitcoinExchangeFeeOverflow
	}
	feeNanos := feeNanosBigint.Uint64()
	userNanos := nanosToCreate - feeNanos

	// Now that we have all the information we need, save a UTXO allowing the user to
	// spend the Ultra she's purchased in the future.
	outputKey := UtxoKey{
		TxID: *txn.Hash(),
		// We give all UTXOs that are created as a result of BitcoinExchange transactions
		// an index of zero. There is generally only one UTXO created in a BitcoinExchange
		// transaction so this field doesn't really matter.
		Index: 0,
	}
	utxoEntry := UtxoEntry{
		AmountNanos:   userNanos,
		PublicKey:     publicKey.SerializeCompressed(),
		BlockHeight:   blockHeight,
		IsBlockReward: false,
		utxoKey:       &outputKey,
		// We leave the position unset and isSpent to false by default.
		// The position will be set in the call to _addUtxo.
	}
	// If we have a problem adding this utxo return an error but don't
	// mark this block as invalid since it's not a rule error and the block
	// could therefore benefit from being processed in the future.
	newUtxoOp, err := bav._addUtxo(&utxoEntry)
	if err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectBitcoinExchange: Problem adding output utxo")
	}
	// Save a UtxoOperation adding the UTXO so we can roll it back later if needed.
	var utxoOpsForTxn []*UtxoOperation
	utxoOpsForTxn = append(utxoOpsForTxn, newUtxoOp)

	// Increment NanosPurchased to reflect the total nanos we created with this
	// transaction, which includes the fee paid to the miner. Save the previous
	// value so it can be easily reverted.
	prevNanosPurchased := bav.NanosPurchased
	bav.NanosPurchased += nanosToCreate

	// Save a UtxoOperation of type OperationTypeBitcoinExchange that will allow
	// us to easily revert NanosPurchased when we disconnect the transaction.
	utxoOpsForTxn = append(utxoOpsForTxn, &UtxoOperation{
		Type:               OperationTypeBitcoinExchange,
		PrevNanosPurchased: prevNanosPurchased,
	})

	// Note that the fee is implicitly equal to (nanosToCreate - userNanos)
	return nanosToCreate, userNanos, utxoOpsForTxn, nil
}

func (bav *UtxoView) _connectPrivateMessage(
	txn *MsgUltranetTxn, txHash *BlockHash, blockHeight uint32, verifySignatures bool) (
	_totalInput uint64, _totalOutput uint64, _utxoOps []*UtxoOperation, _err error) {

	// Check that the transaction has the right TxnType.
	if txn.TxnMeta.GetTxnType() != TxnTypePrivateMessage {
		return 0, 0, nil, fmt.Errorf("_connectPrivateMessage: called with bad TxnType %s",
			txn.TxnMeta.GetTxnType().String())
	}
	txMeta := txn.TxnMeta.(*PrivateMessageMetadata)

	// Check the length of the EncryptedText
	if len(txMeta.EncryptedText) > MaxPrivateMessageLengthBytes {
		return 0, 0, nil, errors.Wrapf(
			RuleErrorPrivateMessageEncryptedTextLengthExceedsMax, "_connectPrivateMessage: "+
				"EncryptedTextLen = %d; Max length = %d",
			len(txMeta.EncryptedText), MaxPrivateMessageLengthBytes)
	}

	// Check that a proper public key is provided in the message metadata
	if len(txMeta.RecipientPublicKey) != btcec.PubKeyBytesLenCompressed {
		return 0, 0, nil, errors.Wrapf(
			RuleErrorPrivateMessageRecipientPubKeyLen, "_connectPrivateMessage: "+
				"RecipientPubKeyLen = %d; Expected length = %d",
			len(txMeta.RecipientPublicKey), btcec.PubKeyBytesLenCompressed)
	}
	_, err := btcec.ParsePubKey(txMeta.RecipientPublicKey, btcec.S256())
	if err != nil {
		return 0, 0, nil, errors.Wrapf(
			RuleErrorPrivateMessageParsePubKeyError, "_connectPrivateMessage: Parse error: %v", err)
	}

	// You can't send a message to yourself.
	if reflect.DeepEqual(txn.PublicKey, txMeta.RecipientPublicKey) {
		return 0, 0, nil, errors.Wrapf(
			RuleErrorPrivateMessageSenderPublicKeyEqualsRecipientPublicKey,
			"_connectPrivateMessage: Parse error: %v", err)
	}

	// Check that the timestamp is greater than zero. Not doing this could make
	// the message not get returned when we call Seek() in our db. It's also just
	// a reasonable sanity check.
	if txMeta.TimestampNanos == 0 {
		return 0, 0, nil, RuleErrorPrivateMessageTstampIsZero
	}

	// Connect basic txn to get the total input and the total output without
	// considering the transaction metadata.
	totalInput, totalOutput, utxoOpsForTxn, err := bav._connectBasicTransfer(
		txn, txHash, blockHeight, verifySignatures, false /*verifyMerchantMerkleRoot*/)
	if err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectPrivateMessage: ")
	}

	// At this point the inputs and outputs have been processed. Now we
	// need to handle the metadata.

	// If a message already exists and does not have isDeleted=true then return
	// an error. In general, messages must have unique (pubkey, tstamp) tuples.
	senderMessageKey := MakeMessageKey(txn.PublicKey, txMeta.TimestampNanos)
	senderMessage := bav._getMessageEntryForMessageKey(&senderMessageKey)
	if senderMessage != nil && !senderMessage.isDeleted {
		return 0, 0, nil, errors.Wrapf(
			RuleErrorPrivateMessageExistsWithSenderPublicKeyTstampTuple,
			"_connectPrivateMessage: Message key: %v", &senderMessageKey)
	}
	recipientMessageKey := MakeMessageKey(txMeta.RecipientPublicKey, txMeta.TimestampNanos)
	recipientMessage := bav._getMessageEntryForMessageKey(&recipientMessageKey)
	if recipientMessage != nil && !recipientMessage.isDeleted {
		return 0, 0, nil, errors.Wrapf(
			RuleErrorPrivateMessageExistsWithRecipientPublicKeyTstampTuple,
			"_connectPrivateMessage: Message key: %v", &recipientMessageKey)
	}

	if verifySignatures {
		// _connectBasicTransfer has already checked that the transaction is
		// signed by the top-level public key, which we take to be the sender's
		// public key so there is no need to verify anything further.
	}

	// At this point we are confident that we are parsing a message with a unique
	// <PublicKey, TstampNanos> tuple. We also know that the sender and recipient
	// have different public keys.

	// Create a MessageEntry
	messageEntry := &MessageEntry{
		SenderPublicKey:    txn.PublicKey,
		RecipientPublicKey: txMeta.RecipientPublicKey,
		EncryptedText:      txMeta.EncryptedText,
		TstampNanos:        txMeta.TimestampNanos,
	}

	// Set the mappings in our in-memory map for the MessageEntry.
	bav._setMessageEntryMappings(messageEntry)

	// Add an operation to the list at the end indicating we've added an order
	// to our data structure.
	utxoOpsForTxn = append(utxoOpsForTxn, &UtxoOperation{
		Type: OperationTypePrivateMessage,
	})

	return totalInput, totalOutput, utxoOpsForTxn, nil
}

// ConnectTransaction ...
func (bav *UtxoView) ConnectTransaction(txn *MsgUltranetTxn, txHash *BlockHash,
	blockHeight uint32, verifySignatures bool, verifyMerchantMerkleRoot bool) (
	_utxoOps []*UtxoOperation, _totalInput uint64, _totalOutput uint64,
	_fees uint64, _err error) {

	return bav._connectTransaction(txn, txHash, blockHeight, verifySignatures,
		verifyMerchantMerkleRoot,
		true /*enforceMinBitcoinBurnWork*/)

}

func (bav *UtxoView) _connectTransaction(txn *MsgUltranetTxn, txHash *BlockHash,
	blockHeight uint32, verifySignatures bool, verifyMerchantMerkleRoot bool,
	enforceMinBitcoinBurnWork bool) (
	_utxoOps []*UtxoOperation, _totalInput uint64, _totalOutput uint64,
	_fees uint64, _err error) {

	// Do a quick sanity check before trying to connect.
	if err := CheckTransactionSanity(txn); err != nil {
		return nil, 0, 0, 0, errors.Wrapf(err, "_connectTransaction: ")
	}

	// Don't allow transactions that take up more than half of the block.
	txnBytes, err := txn.ToBytes(false)
	if err != nil {
		return nil, 0, 0, 0, errors.Wrapf(
			err, "CheckTransactionSanity: Problem serializing transaction: ")
	}
	if len(txnBytes) > int(bav.Params.MaxBlockSizeBytes/2) {
		return nil, 0, 0, 0, RuleErrorTxnTooBig
	}

	var totalInput, totalOutput uint64
	var utxoOpsForTxn []*UtxoOperation
	if txn.TxnMeta.GetTxnType() == TxnTypeBlockReward || txn.TxnMeta.GetTxnType() == TxnTypeBasicTransfer {
		totalInput, totalOutput, utxoOpsForTxn, err =
			bav._connectBasicTransfer(
				txn, txHash, blockHeight, verifySignatures, verifyMerchantMerkleRoot)

	} else if txn.TxnMeta.GetTxnType() == TxnTypeRegisterMerchant {
		totalInput, totalOutput, utxoOpsForTxn, err =
			bav._connectRegisterMerchant(txn, txHash, blockHeight, verifySignatures)

	} else if txn.TxnMeta.GetTxnType() == TxnTypeUpdateMerchant {
		totalInput, totalOutput, utxoOpsForTxn, err =
			bav._connectUpdateMerchant(txn, txHash, blockHeight, verifySignatures)

	} else if txn.TxnMeta.GetTxnType() == TxnTypePlaceOrder {
		totalInput, totalOutput, utxoOpsForTxn, err =
			bav._connectPlaceOrder(txn, txHash, blockHeight, verifySignatures)

	} else if txn.TxnMeta.GetTxnType() == TxnTypeCancelOrder {
		totalInput, totalOutput, utxoOpsForTxn, err =
			bav._connectCancelOrder(txn, txHash, blockHeight, verifySignatures)

	} else if txn.TxnMeta.GetTxnType() == TxnTypeRejectOrder {
		totalInput, totalOutput, utxoOpsForTxn, err =
			bav._connectRejectOrder(txn, txHash, blockHeight, verifySignatures)

	} else if txn.TxnMeta.GetTxnType() == TxnTypeConfirmOrder {
		totalInput, totalOutput, utxoOpsForTxn, err =
			bav._connectConfirmOrder(txn, txHash, blockHeight, verifySignatures)

	} else if txn.TxnMeta.GetTxnType() == TxnTypeFulfillOrder {
		totalInput, totalOutput, utxoOpsForTxn, err =
			bav._connectFulfillOrder(txn, txHash, blockHeight, verifySignatures)

	} else if txn.TxnMeta.GetTxnType() == TxnTypeReviewOrder {
		totalInput, totalOutput, utxoOpsForTxn, err =
			bav._connectReviewOrder(txn, txHash, blockHeight, verifySignatures)

	} else if txn.TxnMeta.GetTxnType() == TxnTypeRefundOrder {
		totalInput, totalOutput, utxoOpsForTxn, err =
			bav._connectRefundOrder(txn, txHash, blockHeight, verifySignatures)

	} else if txn.TxnMeta.GetTxnType() == TxnTypeBitcoinExchange {
		totalInput, totalOutput, utxoOpsForTxn, err =
			bav._connectBitcoinExchange(
				txn, txHash, blockHeight, verifySignatures, enforceMinBitcoinBurnWork)

	} else if txn.TxnMeta.GetTxnType() == TxnTypePrivateMessage {
		totalInput, totalOutput, utxoOpsForTxn, err =
			bav._connectPrivateMessage(
				txn, txHash, blockHeight, verifySignatures)

	} else {
		err = fmt.Errorf("ConnectTransaction: Unimplemented txn type %v", txn.TxnMeta.GetTxnType().String())
	}
	if err != nil {
		return nil, 0, 0, 0, errors.Wrapf(err, "ConnectTransaction: ")
	}

	// Do some extra processing for non-block-reward transactions. Block reward transactions
	// will return zero for their fees.
	fees := uint64(0)
	if txn.TxnMeta.GetTxnType() != TxnTypeBlockReward {
		// If this isn't a block reward transaction, make sure the total input does
		// not exceed the total output. If it does, mark the block as invalid and
		// return an error.
		if totalInput < totalOutput {
			return nil, 0, 0, 0, RuleErrorTxnOutputExceedsInput
		}
		fees = totalInput - totalOutput
	}

	return utxoOpsForTxn, totalInput, totalOutput, fees, nil
}

// ConnectBlock ...
func (bav *UtxoView) ConnectBlock(
	ultranetBlock *MsgUltranetBlock, txHashes []*BlockHash, verifySignatures bool, verifyMerchantMerkleRoot bool) (
	[][]*UtxoOperation, error) {

	// Check that the block being connected references the current tip. ConnectBlock
	// can only add a block to the current tip. We do this to keep the API simple.
	if *ultranetBlock.Header.PrevBlockHash != *bav.TipHash {
		return nil, fmt.Errorf(
			"ConnectBlock: Parent hash of block being connected does not match tip")
	}

	blockHeader := ultranetBlock.Header
	// Loop through all the transactions and validate them using the view. Also
	// keep track of the total fees throughout.
	var totalFees uint64
	utxoOps := [][]*UtxoOperation{}
	for txIndex, txn := range ultranetBlock.Txns {
		txHash := txHashes[txIndex]

		// ConnectTransaction validates all of the transactions in the block and
		// is responsible for verifying signatures.
		utxoOpsForTxn, totalInput, totalOutput, currentFees, err := bav.ConnectTransaction(
			txn, txHash, blockHeader.Height, verifySignatures, verifyMerchantMerkleRoot)
		_, _ = totalInput, totalOutput // A bit surprising we don't use these
		if err != nil {
			return nil, errors.Wrapf(err, "ConnectBlock: ")
		}

		// Add the fees from this txn to the total fees. If any overflow occurs
		// mark the block as invalid and return a rule error. Note that block reward
		// txns should count as having zero fees.
		if totalFees > (math.MaxUint64 - currentFees) {
			return nil, RuleErrorTxnOutputWithInvalidAmount
		}
		totalFees += currentFees

		// Add the utxo operations to our list for all the txns.
		utxoOps = append(utxoOps, utxoOpsForTxn)
	}

	// We should now have computed totalFees. Use this to check that
	// the block reward's outputs are correct.
	//
	// Compute the sum of the outputs in the block reward. If an overflow
	// occurs mark the block as invalid and return a rule error.
	var blockRewardOutput uint64
	for _, bro := range ultranetBlock.Txns[0].TxOutputs {
		if bro.AmountNanos > MaxNanos ||
			blockRewardOutput > (math.MaxUint64-bro.AmountNanos) {

			return nil, RuleErrorBlockRewardOutputWithInvalidAmount
		}
		blockRewardOutput += bro.AmountNanos
	}
	// Verify that the block reward does not overflow when added to
	// the block's fees.
	blockReward := CalcBlockRewardNanos(blockHeader.Height)
	if totalFees > MaxNanos ||
		blockReward > (math.MaxUint64-totalFees) {

		return nil, RuleErrorBlockRewardOverflow
	}
	maxBlockReward := blockReward + totalFees
	// If the outputs of the block reward txn exceed the max block reward
	// allowed then mark the block as invalid and return an error.
	if blockRewardOutput > maxBlockReward {
		glog.Errorf("ConnectBlock(RuleErrorBlockRewardExceedsMaxAllowed): "+
			"blockRewardOutput %d exceeds maxBlockReward %d", blockRewardOutput, maxBlockReward)
		return nil, RuleErrorBlockRewardExceedsMaxAllowed
	}

	// If we made it to the end and this block is valid, advance the tip
	// of the view to reflect that.
	blockHash, err := ultranetBlock.Header.Hash()
	if err != nil {
		return nil, fmt.Errorf("ConnectBlock: Problem computing block hash after validation")
	}
	bav.TipHash = blockHash

	return utxoOps, nil
}

// GetOrdersForUser ...
// Can specify publicKey or merchantID or both.
func (bav *UtxoView) GetOrdersForUser(publicKey []byte, merchantID *BlockHash) (
	_orderEntries []*OrderEntry, _err error) {

	// If a public key is provided, fetch the orders assuming the user is the buyer.
	orderIDsForBuyer := []*BlockHash{}
	var err error
	if len(publicKey) == btcec.PubKeyBytesLenCompressed {
		_, orderIDsForBuyer, _, err =
			DbGetOrdersForBuyerPublicKey(bav.Handle, publicKey, false /*fetchEntries*/)
	}
	if err != nil {
		return nil, errors.Wrapf(err,
			"GetOrdersForPublicKey: Problem fetching OrderIDs from DB as buyer: ")
	}
	orderIDsForMerchant := []*BlockHash{}
	// If a merchantID is provided, fetch the orders assuming the user is the merchant.
	if merchantID != nil {
		_, orderIDsForMerchant, _, err =
			DbGetOrdersForMerchantID(bav.Handle, merchantID, false /*fetchEntries*/)
	}
	if err != nil {
		return nil, errors.Wrapf(err,
			"GetOrdersForPublicKey: Problem fetching OrderIDs from DB as Merchant: ")
	}

	// Load all the orders associated with the OrderIDs we fetched above into the
	// view.
	orderIDsToFetch := append(orderIDsForBuyer, orderIDsForMerchant...)
	for _, orderID := range orderIDsToFetch {
		bav._getOrderEntryForOrderID(orderID)
	}
	// At this point the view should have loaded the latest data for all of the orderIDs
	// we could fetch.

	// Now that the view has loaded all of the OrderIDs above, filter out the ones that
	// are deleted and return the ones that aren't.
	orderEntriesToReturn := []*OrderEntry{}
	for orderIDIter, orderEntry := range bav.OrderIDToOrderEntry {
		if orderEntry.isDeleted {
			continue
		}
		orderID := orderIDIter
		orderEntry.orderID = &orderID
		orderEntriesToReturn = append(orderEntriesToReturn, orderEntry)
	}

	return orderEntriesToReturn, nil
}

// GetMessagesForUser ...
// Can specify publicKey or merchantID or both.
func (bav *UtxoView) GetMessagesForUser(publicKey []byte) (
	_messageEntries []*MessageEntry, _err error) {

	// Start by fetching all the messages we have in the db.
	dbMessageEntries, err := DbGetMessageEntriesForPublicKey(bav.Handle, publicKey)
	if err != nil {
		return nil, errors.Wrapf(err, "GetMessagesForUser: Problem fetching MessageEntrys from db: ")
	}

	// Iterate through the entries found in the db and force the view to load them.
	// This fills in any gaps in the view so that, after this, the view should contain
	// the union of what it had before plus what was in the db.
	for _, dbMessageEntry := range dbMessageEntries {
		messageKey := MakeMessageKey(publicKey, dbMessageEntry.TstampNanos)
		bav._getMessageEntryForMessageKey(&messageKey)
	}

	// Now that the view mappings are a complete picture, iterate through them
	// and set them on the map we're returning. Skip entries that don't match
	// our public key or that are deleted. Note that only considering mappings
	// where our public key is part of the key should ensure there are no
	// duplicates in the resulting list.
	messageEntriesToReturn := []*MessageEntry{}
	for viewMessageKey, viewMessageEntry := range bav.MessageKeyToMessageData {
		if viewMessageEntry.isDeleted {
			continue
		}
		messageKey := MakeMessageKey(publicKey, viewMessageEntry.TstampNanos)
		if viewMessageKey != messageKey {
			continue
		}

		// At this point we are confident the map key is equal to the message
		// key containing the passed-in public key so add it to the mapping.
		messageEntriesToReturn = append(messageEntriesToReturn, viewMessageEntry)
	}

	return messageEntriesToReturn, nil
}

// GetUnspentUtxoEntrysForPublicKey returns the UtxoEntrys corresponding to the
// passed-in public key that are currently unspent. It does this while factoring
// in any transactions that have already been connected to it. This is useful,
// as an example, when one whats to see what UtxoEntrys are available for spending
// after factoring in (i.e. connecting) all of the transactions currently in the
// mempool that are related to this public key.
//
// At a high level, this function allows one to get the utxos that are the union of:
// - utxos in the db
// - utxos in the view from previously-connected transactions
func (bav *UtxoView) GetUnspentUtxoEntrysForPublicKey(pkBytes []byte) ([]*UtxoEntry, error) {
	// Fetch the relevant utxos for this public key from the db. We do this because
	// the db could contain utxos that are not currently loaded into the view.
	utxoEntriesForPublicKey, err := DbGetUtxosForPubKey(pkBytes, bav.Handle)
	if err != nil {
		return nil, errors.Wrapf(err, "UtxoView.GetUnspentUtxoEntrysForPublicKey: Problem fetching "+
			"utxos for public key %s", PkToString(pkBytes, bav.Params))
	}

	// Load all the utxos associated with this public key into
	// the view. This makes it so that the view can enumerate all of the utxoEntries
	// known for this public key. To put it another way, it allows the view to
	// contain the union of:
	// - utxos in the db
	// - utxos in the view from previously-connected transactions
	for _, utxoEntry := range utxoEntriesForPublicKey {
		bav.GetUtxoEntryForUtxoKey(utxoEntry.utxoKey)
	}

	// Now that all of the utxos for this key have been loaded, filter the
	// ones for this public key and return them.
	utxoEntriesToReturn := []*UtxoEntry{}
	for utxoKeyTmp, utxoEntry := range bav.UtxoKeyToUtxoEntry {
		// Make a copy of the iterator since it might change from underneath us
		// if we take its pointer.
		utxoKey := utxoKeyTmp
		utxoEntry.utxoKey = &utxoKey
		if !utxoEntry.isSpent && reflect.DeepEqual(utxoEntry.PublicKey, pkBytes) {
			utxoEntriesToReturn = append(utxoEntriesToReturn, utxoEntry)
		}
	}

	return utxoEntriesToReturn, nil
}

// The ChainLock must be acquired by the caller of this funciton.
func (bav *UtxoView) _computeMerchantMerkleRoot() (*BlockHash, error) {
	// Fetch the top merchants from the database.
	dbMerchantIDs, _, dbMerchantEntries, err :=
		DbGetBlockchainTopMerchants(
			bav.Handle, bav.Params.MaxMerchantsToIndex, false /*noMerchantEntries*/)
	if err != nil {
		return nil, errors.Wrapf(err, "_computeMerchantMerkleRoot: Problem fetching top merchants from db")
	}

	viewMerchantIDs, viewMerchantEntries := bav._getAllMerchantsInViewWithScores()

	// Deduplicate all of the merchants. Allow the view to over-write the db entries.
	merchantIDToMerchantEntry := make(map[BlockHash]*MerchantEntry)
	for ii, merchantID := range dbMerchantIDs {
		merchantIDToMerchantEntry[*merchantID] = dbMerchantEntries[ii]
	}
	for ii, merchantID := range viewMerchantIDs {
		merchantIDToMerchantEntry[*merchantID] = viewMerchantEntries[ii]
	}

	// Sort the new set of merchants by their score. Break ties using the MerchantID.
	merchantList := []*MerchantEntry{}
	for _, merchantEntry := range merchantIDToMerchantEntry {
		merchantList = append(merchantList, merchantEntry)
	}
	sort.Slice(merchantList, func(ii, jj int) bool {
		cmpValue := merchantList[ii].Stats.MerchantScore.Cmp(merchantList[jj].Stats.MerchantScore)
		if cmpValue == 0 {
			return PkToString(merchantList[ii].merchantID[:], bav.Params) > PkToString(merchantList[jj].merchantID[:], bav.Params)
		}
		return cmpValue > 0
	})

	// Truncate the merchant list to the maximum number allowed.
	maxMerchants := int(bav.Params.MaxMerchantsToIndex)
	if maxMerchants > len(merchantList) {
		maxMerchants = len(merchantList)
	}
	merchantList = merchantList[:maxMerchants]

	// In the edge case where there are no merchants yet, the merchant merkle
	// root is simply a BlockHash that is all zeros.
	if len(merchantList) == 0 {
		return &BlockHash{}, nil
	}

	merchantEntryHashes := [][]byte{}
	for _, merchantEntry := range merchantList {
		merchantEntryHashes = append(
			merchantEntryHashes, HashMerchantEntry(merchantEntry)[:])
	}
	merkleTree := merkletree.NewTreeFromHashes(
		merkletree.Sha256DoubleHash, merchantEntryHashes)

	rootHash := &BlockHash{}
	copy(rootHash[:], merkleTree.Root.GetHash()[:])

	return rootHash, nil
}

func (bav *UtxoView) _flushUtxosToDbWithTxn(txn *badger.Txn) error {
	for utxoKeyIter, utxoEntry := range bav.UtxoKeyToUtxoEntry {
		// Make a copy of the iterator since it might change from under us.
		utxoKey := utxoKeyIter

		// As a sanity-check, make sure the back-reference for each entry
		// points to its key.
		if utxoEntry.utxoKey == nil || *utxoEntry.utxoKey != utxoKey {
			return fmt.Errorf("_flushUtxosToDbWithTxn: Found utxoEntry %+v for "+
				"utxoKey %v has invalid back-refernce utxoKey %v",
				utxoEntry, utxoKey, utxoEntry.utxoKey)
		}

		// Start by deleting the pre-existing mappings in the db for this key if they
		// have not yet been modified.
		if err := DeleteUnmodifiedMappingsForUtxoWithTxn(txn, &utxoKey); err != nil {
			return err
		}

		if utxoEntry.isSpent {
			// If an entry is spent then there's nothing to do, since the mappings in
			// the db have already been deleted.
		} else {
			// If the entry is unspent, then we need to re-set its mappings in the db
			// appropriately.
			if err := PutMappingsForUtxoWithTxn(txn, &utxoKey, utxoEntry); err != nil {
				return err
			}

			// As a sanity-check, make sure the in-memory position mapping is in-sync
			// with the <key -> entry> mapping.
			posEntryForKey, posEntryExists := bav.PosToUtxoEntry[utxoEntry.Pos]
			if !posEntryExists {
				return fmt.Errorf("_flushUtxosToDbWithTxn: Utxo entry %+v "+
					"found in UtxoView with utxoKey %+v but mapping is missing for "+
					"its pos %d", utxoEntry, utxoKey, utxoEntry.Pos)

			}
			if posEntryForKey.utxoKey == nil || *posEntryForKey.utxoKey != utxoKey {
				return fmt.Errorf("_flushUtxosToDbWithTxn: Utxo entry %+v "+
					"found undeleted in UtxoView with utxoKey %+v but pos "+
					"%d has unexpected utxoKey %+v",
					utxoEntry, utxoKey, utxoEntry.Pos, *posEntryForKey.utxoKey)
			}

			// As a sanity-check, make sure this entry's position doesn't exceed
			// the view's length.
			if utxoEntry.Pos >= bav.NumUtxoEntries {
				return fmt.Errorf("_flushUtxosToDbWithTxn: Pos %d being set "+
					"is >= NumUtxoEntries %d",
					utxoEntry.Pos, bav.NumUtxoEntries)
			}
		}
	}

	// As a final sanity check, for each pos entry between the view's
	// NumUtxoEntries and the db's NumUtxoEntries, ensure that the db has
	// no mapping.
	numUtxoEntriesDb := GetUtxoNumEntriesWithTxn(txn)
	for deletedPos := bav.NumUtxoEntries; deletedPos < numUtxoEntriesDb; deletedPos++ {
		utxoKeyForPos := GetUtxoKeyAtPositionWithTxn(txn, deletedPos)
		if utxoKeyForPos != nil {
			return fmt.Errorf("_flushUtxosToDbWithTxn: Mapping for pos "+
				"%d found in db is >= the view's NumUtxoEntries %d",
				deletedPos, bav.NumUtxoEntries)
		}
	}

	// Now update the number of entries in the db with confidence.
	if err := PutUtxoNumEntriesWithTxn(txn, bav.NumUtxoEntries); err != nil {
		return err
	}

	// At this point, the db's position index should be updated and the (key -> entry)
	// index should be updated to remove all spent utxos. The number of entries field
	// in the db should also be accurate.

	return nil
}

func (bav *UtxoView) _flushMerchantEntriesToDbWithTxn(txn *badger.Txn) error {
	// Go through all the entries in the <merchantID -> entry> map.
	for merchantIDIter, merchantEntry := range bav.MerchantIDToMerchantEntry {
		// Use a copy of the merchantID iterator to avoid having the value change from
		// under our feet.
		merchantID := BlockHash{}
		copy(merchantID[:], merchantIDIter[:])

		// As a sanity-check, make sure the back-reference for each entry
		// points to its key.
		if merchantEntry.merchantID == nil || *merchantEntry.merchantID != merchantID {
			return fmt.Errorf("_flushMerchantEntriesToDbWithTxn: Found merchantEntry %+v for "+
				"merchantID %v has invalid back-refernce merchantID %v",
				merchantEntry, merchantID, merchantEntry.merchantID)
		}

		// Set up the username and public key map keys.
		pkMapKey := PkMapKey{}
		copy(pkMapKey[:], merchantEntry.PublicKey)
		usernameMapKey := UsernameMapKey{}
		copy(usernameMapKey[:], merchantEntry.Username)

		// The way we do the update for a merchant is we first delete all of its original
		// mappings regardless of whether or not the view says they should be deleted. Then
		// we add new mappings (which might be the same as the original mappings) for the
		// merchant if the merchant isn't deleted according to the view.
		//
		// Note that care must be taken in this process to only delete the entries for a
		// MerchantID if they are unchanged. For example, if the <username -> merchantID>
		// mapping in the db no longer corresponds to *this* merchantID then we should not
		// delete it since doing so would step on another entry's update. For this reason
		// this function only deletes *unmodified* mappings for a given MerchantID.
		//
		// TODO: This could probably be made to be a lot more efficient but for now we
		// do this because fully clearing and re-setting all the mappings every time is
		// less error-prone than maodifying only the mappings that have changed.
		if err := DbDeleteUnmodifiedMappingsForMerchantIDWithTxn(txn, &merchantID); err != nil {
			return err
		}

		if merchantEntry.isDeleted {
			// All of the merchant's original data has been deleted by default so there's
			// nothing more to do here.
		} else {
			// Since the merchant isn't deleted according to the view add all her mappings
			// to the db to replace what we cleared earlier.
			if err := DbPutMappingsForMerchantWithTxn(txn, &merchantID, merchantEntry); err != nil {
				return err
			}

			// As a sanity check, make sure the in-memory mappings point to this merchantID.
			pkMerchantEntry, pkMerchantEntryExists := bav.PkToMerchantEntry[pkMapKey]
			usernameMerchantEntry, usernameMerchantEntryExists := bav.UsernameToMerchantEntry[usernameMapKey]
			posMerchantEntry, posMerchantEntryExists := bav.PosToMerchantEntry[merchantEntry.Pos]
			if !pkMerchantEntryExists {
				return fmt.Errorf("_flushMerchantEntriesToDbWithTxn: Merchant entry %+v "+
					"found in UtxoView with merchantID %+v but mapping is missing for "+
					"its public key %+v", merchantEntry, &merchantID, PkToString(merchantEntry.PublicKey, bav.Params))
			}
			if pkMerchantEntry.merchantID == nil || *pkMerchantEntry.merchantID != merchantID {
				return fmt.Errorf("_flushMerchantEntriesToDbWithTxn: Merchant entry %+v "+
					"found undeleted in UtxoView with merchantID %+v but public key "+
					"%v has unexpected merchantID %v",
					merchantEntry, &merchantID, PkToString(merchantEntry.PublicKey, bav.Params), pkMerchantEntry.merchantID)
			}
			if !usernameMerchantEntryExists {
				// We have to have some entry for this username since we never delete anything
				// from our maps once we load data into them.
				return fmt.Errorf("_flushMerchantEntriesToDbWithTxn: Merchant entry %+v "+
					"found in UtxoView with merchantID %+v but mapping is missing for "+
					"its username %s", merchantEntry, &merchantID, string(merchantEntry.Username))
			}
			if usernameMerchantEntry.merchantID == nil || *usernameMerchantEntry.merchantID != merchantID {
				return fmt.Errorf("_flushMerchantEntriesToDbWithTxn: Merchant entry %+v "+
					"found undeleted in UtxoView with merchantID %+v but username "+
					"%s has unexpected merchantID %+v",
					merchantEntry, &merchantID, string(merchantEntry.Username), usernameMerchantEntry.merchantID)
			}
			if !posMerchantEntryExists {
				// We have to have some entry for this pos since we never delete anything
				// from our maps once we load data into them.
				return fmt.Errorf("_flushMerchantEntriesToDbWithTxn: Merchant entry %+v "+
					"found in UtxoView with merchantID %+v but mapping is missing for "+
					"its pos %d", merchantEntry, &merchantID, merchantEntry.Pos)
			}
			if posMerchantEntry.merchantID == nil || *posMerchantEntry.merchantID != merchantID {
				return fmt.Errorf("_flushMerchantEntriesToDbWithTxn: Merchant entry %+v "+
					"found undeleted in UtxoView with merchantID %+v but pos  "+
					"%d has unexpected merchantID %+v",
					merchantEntry, &merchantID, merchantEntry.Pos, *posMerchantEntry.merchantID)
			}

			// Sanity check that the pos does not exceed the number of entries in the db
			// according to the view.
			if merchantEntry.Pos >= bav.NumMerchantEntries {
				return fmt.Errorf("_flushMerchantEntriesToDbWithTxn: Pos %d being set "+
					"is >= NumMerchantEntries %d",
					merchantEntry.Pos, bav.NumMerchantEntries)
			}
		}
	}

	// As a final sanity check, for each pos entry between the view's
	// NumMerchantEntries and the db's NumMerchantEntries, ensure that the db has
	// no mapping.
	numMerchantEntriesDb := GetNumMerchantEntriesWithTxn(txn)
	for deletedPos := bav.NumMerchantEntries; deletedPos < numMerchantEntriesDb; deletedPos++ {
		merchantIDForPos := GetMerchantIDForPosWithTxn(txn, deletedPos)
		if merchantIDForPos != nil {
			return fmt.Errorf("_flushMerchantEntriesToDbWithTxn: Mapping for pos "+
				"%d found in db is >= the view's NumMerchantEntries %d",
				deletedPos, bav.NumMerchantEntries)
		}
	}

	// Now update the number of entries in the db with confidence.
	if err := PutNumMerchantEntriesWithTxn(txn, bav.NumMerchantEntries); err != nil {
		return err
	}

	// At this point all of the merchant mappings in the db should be up-to-date.

	return nil
}

func (bav *UtxoView) _flushOrderEntriesToDbWithTxn(txn *badger.Txn) error {
	// Go through all the entries in the <OrderID -> entry> map.
	for orderIDIter, orderEntry := range bav.OrderIDToOrderEntry {
		// Make a copy of the iterator since we take references to it below.
		orderID := orderIDIter

		// Sanity-check that the orderID in the entry is equal to the orderID that
		// maps to that entry.
		if orderEntry.orderID == nil || *orderEntry.orderID != orderID {
			return fmt.Errorf("_flushOrderEntriesToDbWithTxn: orderEntry %v for "+
				"orderID %v has invalid back-refernce orderID %v",
				orderEntry, &orderID, orderEntry.orderID)
		}

		// Delete all unmodified mappings in the db for this orderID. If the order
		// has (isDeleted = false) they will be re-set appropriately below.
		if err := DeleteUnmodifiedMappingsForOrderWithTxn(txn, &orderID); err != nil {
			return err
		}

		if orderEntry.isDeleted {
			// If an order entry is deleted, we have nothing to do since the above code
			// wiped out the relevant mappings for this orderID.
		} else {
			// If the order entry has (isDeleted = false) then we put the corresponding
			// mappings for it into the db.
			if err := PutMappingsForOrderWithTxn(txn, &orderID, orderEntry); err != nil {
				return err
			}

			// Sanity-check that the position mapping lines up with the orderID mapping.
			posOrderEntry, posOrderExists := bav.PosToOrderEntry[orderEntry.Pos]
			if !posOrderExists {
				return fmt.Errorf("_flushOrderEntriesToDbWithTxn: Order entry %+v "+
					"found in UtxoView with orderID %v but mapping is missing for "+
					"its pos %d", orderEntry, &orderID, orderEntry.Pos)
			}
			if posOrderEntry == nil || *posOrderEntry.orderID != orderID {
				return fmt.Errorf("_flushOrderEntriesToDbWithTxn: Order entry %+v "+
					"found undeleted in UtxoView with orderID %v but pos  "+
					"%d has unexpected orderID %v",
					orderEntry, &orderID, orderEntry.Pos, *posOrderEntry.orderID)
			}

			// Sanity-check that none of the positions in the undeleted entries
			// exceed the NumOrderEntries in the view.
			if orderEntry.Pos >= bav.NumOrderEntries {
				return fmt.Errorf("_flushOrderEntriesToDbWithTxn: Pos %d being set "+
					"is >= NumOrderEntries %d",
					orderEntry.Pos, bav.NumOrderEntries)
			}
		}
	}

	// As a final sanity check, for each pos entry between the view's
	// NumOrderEntries and the db's NumOrderEntries, ensure that the db has
	// no mapping.
	numOrderEntriesDb := GetNumOrderEntriesWithTxn(txn)
	for deletedPos := bav.NumOrderEntries; deletedPos < numOrderEntriesDb; deletedPos++ {
		orderIDForPos := GetOrderIDForPosWithTxn(txn, deletedPos)
		if orderIDForPos != nil {
			return fmt.Errorf("_flushOrderEntriesToDbWithTxn: Mapping for pos "+
				"%d found in db is >= the view's NumOrderEntries %d",
				deletedPos, bav.NumOrderEntries)
		}
	}

	// Now update the number of entries in the db with confidence.
	if err := PutNumOrderEntriesWithTxn(txn, bav.NumOrderEntries); err != nil {
		return err
	}

	// At this point all of the order mappings in the db should be up-to-date.

	return nil
}

func (bav *UtxoView) _flushBitcoinExchangeDataWithTxn(txn *badger.Txn) error {
	// Iterate through our in-memory map. If anything has a value of false it means
	// that particular mapping should be expunged from the db. If anything has a value
	// of true it means that mapping should be added to the db.
	for bitcoinBurnTxIDIter, mappingExists := range bav.BitcoinBurnTxIDs {
		// Be paranoid and copy the iterator in case anything takes a reference below.
		bitcoinBurnTxID := bitcoinBurnTxIDIter

		if mappingExists {
			// In this case we should add the mapping to the db.
			if err := DbPutBitcoinBurnTxIDWithTxn(txn, &bitcoinBurnTxID); err != nil {
				return errors.Wrapf(err, "UtxoView._flushBitcoinExchangeDataWithTxn: "+
					"Problem putting BitcoinBurnTxID %v to db", &bitcoinBurnTxID)
			}
		} else {
			// In this case we should delete the mapping from the db.
			if err := DbDeleteBitcoinBurnTxIDWithTxn(txn, &bitcoinBurnTxID); err != nil {
				return errors.Wrapf(err, "UtxoView._flushBitcoinExchangeDataWithTxn: "+
					"Problem deleting BitcoinBurnTxID %v to db", &bitcoinBurnTxID)
			}
		}
	}

	// Update NanosPurchased
	if err := DbPutNanosPurchasedWithTxn(txn, bav.NanosPurchased); err != nil {
		errors.Wrapf(err, "UtxoView._flushBitcoinExchangeDataWithTxn: "+
			"Problem putting NanosPurchased %d to db", bav.NanosPurchased)
	}

	// DB should be fully up to date as far as BitcoinBurnTxIDs and NanosPurchased go.
	return nil
}

func (bav *UtxoView) _flushMessageEntriesToDbWithTxn(txn *badger.Txn) error {
	// Go through all the entries in the MessageKeyToMessageData map.
	for messageKeyIter, messageEntry := range bav.MessageKeyToMessageData {
		// Make a copy of the iterator since we take references to it below.
		messageKey := messageKeyIter

		// Sanity-check that one of the MessageKey computed from the MEssageEntry is
		// equal to the MessageKey that maps to that entry.
		senderMessageKeyInEntry := MakeMessageKey(
			messageEntry.SenderPublicKey, messageEntry.TstampNanos)
		recipientMessageKeyInEntry := MakeMessageKey(
			messageEntry.RecipientPublicKey, messageEntry.TstampNanos)
		if senderMessageKeyInEntry != messageKey && recipientMessageKeyInEntry != messageKey {
			return fmt.Errorf("_flushMessageEntriesToDbWithTxn: MessageEntry has "+
				"SenderMessageKey: %v and RecipientMessageKey %v, neither of which match "+
				"the MessageKeyToMessageData map key %v",
				&senderMessageKeyInEntry, &recipientMessageKeyInEntry, &messageKey)
		}

		// Delete the existing mappings in the db for this MessageKey. They will be re-added
		// if the corresponding entry in memory has isDeleted=false.
		if err := DbDeleteMessageEntryMappingsWithTxn(
			txn, messageKey.PublicKey[:], messageKey.TstampNanos); err != nil {

			return errors.Wrapf(
				err, "_flushMessageEntriesToDbWithTxn: Problem deleting mappings "+
					"for MessageKey: %v: ", &messageKey)
		}

		if messageEntry.isDeleted {
			// If the MessageEntry has isDeleted=true then there's nothing to do because
			// we already deleted the entry above.
		} else {
			// If the MessageEntry has (isDeleted = false) then we put the corresponding
			// mappings for it into the db.
			if err := DbPutMessageEntryWithTxn(txn, messageEntry); err != nil {

				return err
			}
		}
	}

	// At this point all of the MessageEntry mappings in the db should be up-to-date.

	return nil
}

// FlushToDbWithTxn ...
func (bav *UtxoView) FlushToDbWithTxn(txn *badger.Txn) error {
	// Flush the utxos to the db.
	if err := bav._flushUtxosToDbWithTxn(txn); err != nil {
		return err
	}

	if err := bav._flushMerchantEntriesToDbWithTxn(txn); err != nil {
		return err
	}

	if err := bav._flushOrderEntriesToDbWithTxn(txn); err != nil {
		return err
	}

	if err := bav._flushBitcoinExchangeDataWithTxn(txn); err != nil {
		return err
	}

	if err := bav._flushMessageEntriesToDbWithTxn(txn); err != nil {
		return err
	}

	return nil
}

// FlushToDb ...
func (bav *UtxoView) FlushToDb() error {
	// Make sure everything happens inside a single transaction.
	err := bav.Handle.Update(func(txn *badger.Txn) error {
		return bav.FlushToDbWithTxn(txn)
	})
	if err != nil {
		return err
	}

	// After a successful flush, reset the in-memory mappings for the view
	// so that it can be re-used if desired.
	//
	// Note that the TipHash does not get reset as part of _ResetViewMappingsAfterFlush because
	// it is not something that is affected by a flush operation. Moreover, its value
	// is consistent with the view regardless of whether or not the view is flushed or
	// not.
	bav._ResetViewMappingsAfterFlush()

	return nil
}
