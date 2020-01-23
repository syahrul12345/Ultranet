package lib

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/big"
	"net"
	"time"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/wire"
	"github.com/ethereum/go-ethereum/crypto/ecies"
	"github.com/golang/glog"
	merkletree "github.com/laser/go-merkle-tree"

	"github.com/pkg/errors"
)

// network.go defines all the basic data structures that get sent over the
// network and defines precisely how they are serialized and de-serialized.

// MaxMessagePayload is the maximum size alowed for a message payload.
const MaxMessagePayload = (1024 * 1024 * 10) // 10MB

// MaxBlockRewardDataSizeBytes is the maximum size allowed for a BLOCK_REWARD's ExtraData field.
var MaxBlockRewardDataSizeBytes = 200

// MaxHeadersPerMsg is the maximum numbers allowed in a GetHeaders response.
var MaxHeadersPerMsg = uint32(2000)

// MaxBitcoinHeadersPerMsg is the maximum number of headers Bitcoin allows in
// a getheaders response. It is used to determine whether a node has more headers
// to give us.
var MaxBitcoinHeadersPerMsg = uint32(2000)

// HashSizeBytes ...
const HashSizeBytes = 32

// OutputSizeBytes is the size of an UltranetOutput in bytes. 33 bytes for
// the public key and 8 bytes for the uint64.
const OutputSizeBytes = 33 + 8

// BlockHash is a convenient alias for a block hash.
type BlockHash [HashSizeBytes]byte

func (bh *BlockHash) String() string {
	return fmt.Sprintf("%064x", HashToBigint(bh))
}

// The MsgType is usually sent on the wire to indicate what type of
// struct is being sent in the payload part of the message.
type MsgType uint64

const (
	// ControlMessagesStart is used to indicate the ID value at which control
	// messages start. Anything with an ID value greater than or equal to this
	// is a control message.
	ControlMessagesStart = 1000000

	// MsgTypeUnset ...
	MsgTypeUnset MsgType = 0
	// MsgTypeVersion ...
	//
	// The first message a peer sends. Used to negotiate a version
	// between the two peers.
	MsgTypeVersion MsgType = 1
	// MsgTypeVerack ...
	//
	// Sent after a peer has both sent its version message
	// and received its peer's version message and completed
	// the version negotiation.
	MsgTypeVerack MsgType = 2
	// MsgTypeHeader ...
	MsgTypeHeader MsgType = 3
	// MsgTypeBlock ...
	MsgTypeBlock MsgType = 4
	// MsgTypeTxn ...
	MsgTypeTxn MsgType = 5
	// MsgTypeListing ...
	MsgTypeListing MsgType = 6
	// MsgTypeGetHeaders is used to fetch headers from a peer.
	MsgTypeGetHeaders MsgType = 7
	// MsgTypeHeaderBundle contains headers from a peer.
	MsgTypeHeaderBundle MsgType = 8

	// MsgTypePing ...
	MsgTypePing MsgType = 9
	// MsgTypePong ...
	MsgTypePong MsgType = 10
	// MsgTypeInv ...
	MsgTypeInv MsgType = 11
	// MsgTypeGetBlocks ...
	MsgTypeGetBlocks MsgType = 12
	// MsgTypeGetTransactions ...
	MsgTypeGetTransactions MsgType = 13
	// MsgTypeTransactionBundle contains transactions from a peer.
	MsgTypeTransactionBundle MsgType = 14
	// MsgTypeMempool ...
	MsgTypeMempool MsgType = 15
	// MsgTypeGetListings ...
	// TODO: GetBlocks, GetTransactions, and GetListings can all be consolidated
	// into a single GetData message that has a type associated with it since
	// they all just send a hash list.
	MsgTypeGetListings MsgType = 16
	// MsgTypeListingBundle contains transactions from a peer.
	MsgTypeListingBundle MsgType = 17
	// MsgTypeListingSync ...
	MsgTypeListingSync MsgType = 18
	// MsgTypeAddr is used by peers to share addresses of nodes they're aware about
	// with other peers.
	MsgTypeAddr MsgType = 19
	// MsgTypeGetAddr is used to solicit Addr messages from peers.
	MsgTypeGetAddr MsgType = 20

	// Below are control messages used to signal to the Server from other parts of
	// the code but not actually sent among peers.
	//
	// TODO: Should probably split these out into a separate channel in the server to
	// make things more parallelized.

	// MsgTypeQuit ...
	MsgTypeQuit MsgType = ControlMessagesStart
	// MsgTypeNewPeer ...
	MsgTypeNewPeer MsgType = ControlMessagesStart + 1
	// MsgTypeDonePeer ...
	MsgTypeDonePeer MsgType = ControlMessagesStart + 2
	// MsgTypeBlockMainChainConnected ...
	MsgTypeBlockMainChainConnected MsgType = ControlMessagesStart + 3
	// MsgTypeBlockMainChainDisconnected ...
	MsgTypeBlockMainChainDisconnected MsgType = ControlMessagesStart + 4
	// MsgTypeBlockAccepted ...
	MsgTypeBlockAccepted MsgType = ControlMessagesStart + 5
	// MsgTypeBitcoinManagerUpdate ...
	MsgTypeBitcoinManagerUpdate MsgType = ControlMessagesStart + 6
)

// IsControlMessage is used by functions to determine whether a particular message
// is a control message. This is useful, for example, in disallowing external Peers
// from manipulating our node by sending control messages of their own.
func IsControlMessage(msgType MsgType) bool {
	return uint64(msgType) >= ControlMessagesStart
}

func (msgType MsgType) String() string {
	switch msgType {
	case MsgTypeUnset:
		return "UNSET"
	case MsgTypeVersion:
		return "VERSION"
	case MsgTypeVerack:
		return "VERACK"
	// Note that we don't usually write single block headers to the wire,
	// preferring instead to bundle headers into a single HEADER_BUNDLE message.
	case MsgTypeHeader:
		return "HEADER"
	case MsgTypeBlock:
		return "BLOCK"
	case MsgTypeTxn:
		return "TXN"
	case MsgTypeListing:
		return "LISTING"
	case MsgTypeGetHeaders:
		return "GET_HEADERS"
	case MsgTypeHeaderBundle:
		return "HEADER_BUNDLE"
	case MsgTypePing:
		return "PING"
	case MsgTypePong:
		return "PONG"
	case MsgTypeInv:
		return "INV"
	case MsgTypeGetBlocks:
		return "GET_BLOCKS"
	case MsgTypeGetTransactions:
		return "GET_TRANSACTIONS"
	case MsgTypeTransactionBundle:
		return "TRANSACTION_BUNDLE"
	case MsgTypeGetListings:
		return "GET_LISTINGS"
	case MsgTypeListingBundle:
		return "LISTING_BUNDLE"
	case MsgTypeMempool:
		return "MEMPOOL"
	case MsgTypeListingSync:
		return "LISTING_SYNC"
	case MsgTypeAddr:
		return "ADDR"
	case MsgTypeGetAddr:
		return "GET_ADDR"
	case MsgTypeQuit:
		return "QUIT"
	case MsgTypeNewPeer:
		return "NEW_PEER"
	case MsgTypeDonePeer:
		return "DONE_PEER"
	case MsgTypeBlockMainChainConnected:
		return "BLOCK_CONNECTED"
	case MsgTypeBlockMainChainDisconnected:
		return "BLOCK_DISCONNECTED"
	case MsgTypeBlockAccepted:
		return "BLOCK_ACCEPTED"
	case MsgTypeBitcoinManagerUpdate:
		return "BITCOIN_MANAGER_UPDATE"
	default:
		return fmt.Sprintf("UNRECOGNIZED(%d) - make sure String() is up to date", msgType)
	}
}

// UltranetMessage is the interface that a message we send on the wire must implement.
type UltranetMessage interface {
	// The following methods allow one to convert a message struct into
	// a byte slice and back. Example usage:
	//
	//   params := &UltranetTestnetParams
	//   msgType := MsgTypeVersion
	//   byteSlice := []byte{0x00, ...}
	//
	// 	 msg := NewMessage(msgType)
	//   err := msg.FromBytes(byteSlice)
	//   newByteSlice, err := msg.ToBytes(false)
	//
	// The data format is intended to be compact while allowing for efficient
	// transmission over the wire and storage in a database.
	//
	// The preSignature field specifies whether the message should be fully
	// serialized or whether it should be serialized in such a way that it
	// can be signed (which involves, for example, not serializing signature
	// fields).
	ToBytes(preSignature bool) ([]byte, error)
	FromBytes(data []byte) error

	// Each Message has a particular type.
	GetMsgType() MsgType
}

// TxnType specifies the type for a transaction message.
type TxnType uint64

const (
	// TxnTypeUnset ...
	TxnTypeUnset TxnType = 0
	// TxnTypeBlockReward ...
	TxnTypeBlockReward TxnType = 1
	// TxnTypeBasicTransfer ...
	TxnTypeBasicTransfer TxnType = 2
	// TxnTypeRegisterMerchant ...
	TxnTypeRegisterMerchant TxnType = 3
	// TxnTypeUpdateMerchant ...
	TxnTypeUpdateMerchant TxnType = 4
	// TxnTypePlaceOrder ...
	TxnTypePlaceOrder TxnType = 5
	// TxnTypeCancelOrder ...
	TxnTypeCancelOrder TxnType = 6
	// TxnTypeRejectOrder ...
	TxnTypeRejectOrder TxnType = 7
	// TxnTypeConfirmOrder ...
	TxnTypeConfirmOrder TxnType = 8
	// TxnTypeFulfillOrder ...
	TxnTypeFulfillOrder TxnType = 9
	// TxnTypeReviewOrder ...
	TxnTypeReviewOrder TxnType = 10
	// TxnTypeRefundOrder ...
	TxnTypeRefundOrder TxnType = 11
	// TxnTypeBitcoinExchange ...
	TxnTypeBitcoinExchange TxnType = 12
	// TxnTypePrivateMessage ...
	TxnTypePrivateMessage TxnType = 13
)

func (txnType TxnType) String() string {
	switch txnType {
	case TxnTypeUnset:
		return "UNSET"
	case TxnTypeBlockReward:
		return "BLOCK_REWARD"
	case TxnTypeBasicTransfer:
		return "BASIC_TRANSFER"
	case TxnTypeRegisterMerchant:
		return "REGISTER_MERCHANT"
	case TxnTypeUpdateMerchant:
		return "UPDATE_MERCHANT"
	case TxnTypePlaceOrder:
		return "PLACE_ORDER"
	case TxnTypeCancelOrder:
		return "CANCEL_ORDER"
	case TxnTypeRejectOrder:
		return "REJECT_ORDER"
	case TxnTypeConfirmOrder:
		return "CONFIRM_ORDER"
	case TxnTypeFulfillOrder:
		return "FULFILL_ORDER"
	case TxnTypeReviewOrder:
		return "REVIEW_ORDER"
	case TxnTypeRefundOrder:
		return "REFUND_ORDER"
	case TxnTypeBitcoinExchange:
		return "BITCOIN_EXCHANGE"
	case TxnTypePrivateMessage:
		return "PRIVATE_MESSAGE"
	default:
		return fmt.Sprintf("UNRECOGNIZED(%d) - make sure String() is up to date", txnType)
	}
}

// UltranetTxnMetadata ...
type UltranetTxnMetadata interface {
	ToBytes(preSignature bool) ([]byte, error)
	FromBytes(data []byte) error
	New() UltranetTxnMetadata
	GetTxnType() TxnType
}

// NewTxnMetadata ...
func NewTxnMetadata(txType TxnType) (UltranetTxnMetadata, error) {
	switch txType {
	case TxnTypeUnset:
		return nil, fmt.Errorf("NewTxnMetadata: UNSET TxnType: %v", TxnTypeUnset)
	case TxnTypeBlockReward:
		return (&BlockRewardMetadataa{}).New(), nil
	case TxnTypeBasicTransfer:
		return (&BasicTransferMetadata{}).New(), nil
	case TxnTypeRegisterMerchant:
		return (&RegisterMerchantMetadata{}).New(), nil
	case TxnTypeUpdateMerchant:
		return (&UpdateMerchantMetadata{}).New(), nil
	case TxnTypePlaceOrder:
		return (&PlaceOrderMetadata{}).New(), nil
	case TxnTypeCancelOrder:
		return (&CancelOrderMetadata{}).New(), nil
	case TxnTypeRejectOrder:
		return (&RejectOrderMetadata{}).New(), nil
	case TxnTypeConfirmOrder:
		return (&ConfirmOrderMetadata{}).New(), nil
	case TxnTypeFulfillOrder:
		return (&FulfillOrderMetadata{}).New(), nil
	case TxnTypeReviewOrder:
		return (&ReviewOrderMetadata{}).New(), nil
	case TxnTypeRefundOrder:
		return (&RefundOrderMetadata{}).New(), nil
	case TxnTypeBitcoinExchange:
		return (&BitcoinExchangeMetadata{}).New(), nil
	case TxnTypePrivateMessage:
		return (&PrivateMessageMetadata{}).New(), nil
	default:
		return nil, fmt.Errorf("NewTxnMetadata: Unrecognized TxnType: %v; make sure you add the new type of transaction to NewTxnMetadata", txType)
	}
}

// NewBlockHash ...
func NewBlockHash(hexBytes string) *BlockHash {
	bb, err := hex.DecodeString(hexBytes)
	if err != nil {
		glog.Errorf("NewBlockHash: Problem decoding hex string (%s) to bytes: %v", hexBytes, err)
	}
	var newHash BlockHash
	copy(newHash[:], bb)
	return &newHash
}

// IsEqual returns true if target is the same as hash.
func (bh *BlockHash) IsEqual(target *BlockHash) bool {
	if bh == nil && target == nil {
		return true
	}
	if bh == nil || target == nil {
		return false
	}
	return *bh == *target
}

// WriteMessage takes an io.Writer and serializes and writes the specified message
// to it. Returns an error if the message is malformed or invalid for any reason.
// Otherwise returns the payload that was written sans the header.
func WriteMessage(ww io.Writer, msg UltranetMessage, networkType NetworkType) ([]byte, error) {
	hdr := []byte{}

	// Add the network as a uvarint.
	hdr = append(hdr, UintToBuf(uint64(networkType))...)

	// Add the MsgType as a uvarint.
	hdr = append(hdr, UintToBuf(uint64(msg.GetMsgType()))...)

	// Compute the payload we're going to write but don't add it
	// yet.
	payload, err := msg.ToBytes(false)
	if err != nil {
		return nil, errors.Wrap(err, "WriteMessage: Failed to convert message to bytes")
	}

	// Check that the length of the payload does not exceed the maximum
	// allowed limit.
	if len(payload) > MaxMessagePayload {
		return nil, fmt.Errorf("WriteMessage: Payload size (%d) bytes is too "+
			"large. Should be no larger than (%d) bytes", len(payload), MaxMessagePayload)
	}

	// Add an eight-byte checksum of the payload. Note that although
	// we generally communicate over TCP, it's not a great idea to rely on the
	// checksum it uses since its guarantees are relatively weak.
	// https://www.evanjones.ca/tcp-checksums.html
	hash := Sha256DoubleHash(payload)
	hdr = append(hdr, hash[:8]...)

	// Add the payload length as a uvarint.
	hdr = append(hdr, UintToBuf(uint64(len(payload)))...)

	// Write the message header.
	_, err = ww.Write(hdr)
	if err != nil {
		return nil, errors.Wrap(err, "WriteMessage: Failed to write header")
	}

	// Write the payload.
	_, err = ww.Write(payload)
	if err != nil {
		return nil, errors.Wrap(err, "WriteMessage: Failed to write payload")
	}
	return payload, nil
}

// ReadMessage takes an io.Reader and de-serializes a single message from it.
// Returns an error if the message is malformed or invalid for any reason. Otherwise
// returns a formed message object and the raw byte payload from which it was
// derived.
func ReadMessage(rr io.Reader, networkType NetworkType) (UltranetMessage, []byte, error) {
	// Read the network as a uvarint.
	inNetworkType, err := ReadUvarint(rr)
	if err != nil {
		return nil, nil, errors.Wrapf(err, "ReadMessage: Problem decoding NetworkType")
	}
	if NetworkType(inNetworkType) != networkType {
		return nil, nil, fmt.Errorf("ReadMessage: Incorrect network type (%s) expected (%s)", NetworkType(inNetworkType), networkType)
	}

	// Read the MsgType as a uvarint.
	inMsgType, err := ReadUvarint(rr)
	if err != nil {
		return nil, nil, errors.Wrap(err, "ReadMessage: Could not read MsgType")
	}

	// Create a new message object based on the type.
	retMsg := NewMessage(MsgType(inMsgType))
	if retMsg == nil {
		return nil, nil, fmt.Errorf("ReadMessage: Unknown message type (%s)", MsgType(inMsgType))
	}

	// Read the payload checksum.
	checksum := make([]byte, 8)
	_, err = io.ReadFull(rr, checksum)
	if err != nil {
		return nil, nil, fmt.Errorf("ReadMessage: Error reading checksum for messate type (%s)", MsgType(inMsgType))
	}

	// Read the length of the payload.
	payloadLength, err := ReadUvarint(rr)
	if err != nil {
		return nil, nil, errors.Wrapf(err, "ReadMessage: Could not read payload length for message type (%s)", MsgType(inMsgType))
	}

	// Check that the payload length does not exceed the maximum value allowed.
	// This prevents adversarial machines from overflowing our
	if payloadLength > MaxMessagePayload {
		return nil, nil, fmt.Errorf("ReadMessage: Payload size (%d) bytes is too "+
			"large. Should be no larger than (%d) bytes", payloadLength, MaxMessagePayload)
	}

	// Read the payload.
	payload := make([]byte, payloadLength)
	_, err = io.ReadFull(rr, payload)
	if err != nil {
		return nil, nil, errors.Wrapf(err, "ReadMessage: Could not read payload for message type (%s)", MsgType(inMsgType))
	}

	// Check the payload checksum.
	hash := Sha256DoubleHash(payload)
	if !bytes.Equal(hash[:8], checksum) {
		return nil, nil, fmt.Errorf("ReadMessage: Payload checksum computed "+
			"(%#v) does not match payload checksum in header: (%#v)", hash[:8], checksum)
	}

	// Now we have the payload, initialize the message.
	err = retMsg.FromBytes(payload)
	if err != nil {
		return nil, nil, errors.Wrapf(err, "ReadMessage: Problem parsing "+
			"message payload into message object for message type (%s)", MsgType(inMsgType))
	}

	return retMsg, payload, nil
}

// NewMessage ...
func NewMessage(msgType MsgType) UltranetMessage {
	switch msgType {
	case MsgTypeVersion:
		{
			return &MsgUltranetVersion{}
		}
	case MsgTypeVerack:
		{
			return &MsgUltranetVerack{}
		}
	case MsgTypeHeader:
		{
			return &MsgUltranetHeader{
				PrevBlockHash:         &BlockHash{},
				TransactionMerkleRoot: &BlockHash{},
			}
		}
	case MsgTypeBlock:
		{
			return &MsgUltranetBlock{
				Header: NewMessage(MsgTypeHeader).(*MsgUltranetHeader),
			}
		}
	case MsgTypeTxn:
		{
			return &MsgUltranetTxn{}
		}
	case MsgTypeListing:
		{
			return &MsgUltranetListing{}
		}
	case MsgTypePing:
		{
			return &MsgUltranetPing{}
		}
	case MsgTypePong:
		{
			return &MsgUltranetPong{}
		}
	case MsgTypeInv:
		{
			return &MsgUltranetInv{}
		}
	case MsgTypeGetBlocks:
		{
			return &MsgUltranetGetBlocks{}
		}
	case MsgTypeGetTransactions:
		{
			return &MsgUltranetGetTransactions{}
		}
	case MsgTypeTransactionBundle:
		{
			return &MsgUltranetTransactionBundle{}
		}
	case MsgTypeMempool:
		{
			return &MsgUltranetMempool{}
		}
	case MsgTypeGetListings:
		{
			return &MsgUltranetGetListings{}
		}
	case MsgTypeListingBundle:
		{
			return &MsgUltranetListingBundle{}
		}
	case MsgTypeListingSync:
		{
			return &MsgUltranetListingSync{}
		}
	case MsgTypeGetHeaders:
		{
			return &MsgUltranetGetHeaders{}
		}
	case MsgTypeHeaderBundle:
		{
			return &MsgUltranetHeaderBundle{}
		}
	case MsgTypeAddr:
		{
			return &MsgUltranetAddr{}
		}
	case MsgTypeGetAddr:
		{
			return &MsgUltranetGetAddr{}
		}
	default:
		{
			return nil
		}
	}
}

// ==================================================================
// Control Messages
// ==================================================================

// MsgUltranetQuit ...
type MsgUltranetQuit struct {
}

// GetMsgType ...
func (msg *MsgUltranetQuit) GetMsgType() MsgType {
	return MsgTypeQuit
}

// ToBytes ...
func (msg *MsgUltranetQuit) ToBytes(preSignature bool) ([]byte, error) {
	return nil, fmt.Errorf("MsgUltranetQuit.ToBytes not implemented")
}

// FromBytes ...
func (msg *MsgUltranetQuit) FromBytes(data []byte) error {
	return fmt.Errorf("MsgUltranetQuit.FromBytes not implemented")
}

// MsgUltranetNewPeer ...
type MsgUltranetNewPeer struct {
}

// GetMsgType ...
func (msg *MsgUltranetNewPeer) GetMsgType() MsgType {
	return MsgTypeNewPeer
}

// ToBytes ...
func (msg *MsgUltranetNewPeer) ToBytes(preSignature bool) ([]byte, error) {
	return nil, fmt.Errorf("MsgUltranetNewPeer.ToBytes: Not implemented")
}

// FromBytes ...
func (msg *MsgUltranetNewPeer) FromBytes(data []byte) error {
	return fmt.Errorf("MsgUltranetNewPeer.FromBytes not implemented")
}

// MsgUltranetDonePeer ...
type MsgUltranetDonePeer struct {
}

// GetMsgType ...
func (msg *MsgUltranetDonePeer) GetMsgType() MsgType {
	return MsgTypeDonePeer
}

// ToBytes ...
func (msg *MsgUltranetDonePeer) ToBytes(preSignature bool) ([]byte, error) {
	return nil, fmt.Errorf("MsgUltranetDonePeer.ToBytes: Not implemented")
}

// FromBytes ...
func (msg *MsgUltranetDonePeer) FromBytes(data []byte) error {
	return fmt.Errorf("MsgUltranetDonePeer.FromBytes not implemented")
}

// MsgUltranetBlockMainChainConnected ...
type MsgUltranetBlockMainChainConnected struct {
	block *MsgUltranetBlock
}

// GetMsgType ...
func (msg *MsgUltranetBlockMainChainConnected) GetMsgType() MsgType {
	return MsgTypeBlockMainChainConnected
}

// ToBytes ...
func (msg *MsgUltranetBlockMainChainConnected) ToBytes(preSignature bool) ([]byte, error) {
	return nil, fmt.Errorf("MsgUltranetBlockMainChainConnected.ToBytes: Not implemented")
}

// FromBytes ...
func (msg *MsgUltranetBlockMainChainConnected) FromBytes(data []byte) error {
	return fmt.Errorf("MsgUltranetBlockMainChainConnected.FromBytes not implemented")
}

// MsgUltranetBlockMainChainDisconnected ...
type MsgUltranetBlockMainChainDisconnected struct {
	block *MsgUltranetBlock
}

// GetMsgType ...
func (msg *MsgUltranetBlockMainChainDisconnected) GetMsgType() MsgType {
	return MsgTypeBlockMainChainDisconnected
}

// ToBytes ...
func (msg *MsgUltranetBlockMainChainDisconnected) ToBytes(preSignature bool) ([]byte, error) {
	return nil, fmt.Errorf("MsgUltranetBlockMainChainDisconnected.ToBytes: Not implemented")
}

// FromBytes ...
func (msg *MsgUltranetBlockMainChainDisconnected) FromBytes(data []byte) error {
	return fmt.Errorf("MsgUltranetBlockMainChainDisconnected.FromBytes not implemented")
}

// MsgUltranetBlockAccepted ...
type MsgUltranetBlockAccepted struct {
	block *MsgUltranetBlock
}

// GetMsgType ...
func (msg *MsgUltranetBlockAccepted) GetMsgType() MsgType {
	return MsgTypeBlockAccepted
}

// ToBytes ...
func (msg *MsgUltranetBlockAccepted) ToBytes(preSignature bool) ([]byte, error) {
	return nil, fmt.Errorf("MsgUltranetBlockAccepted.ToBytes: Not implemented")
}

// FromBytes ...
func (msg *MsgUltranetBlockAccepted) FromBytes(data []byte) error {
	return fmt.Errorf("MsgUltranetBlockAccepted.FromBytes not implemented")
}

func mustParseSignature(sigBytes []byte) *btcec.Signature {
	if len(sigBytes) == 0 {
		return nil
	}
	sig, err := btcec.ParseDERSignature(sigBytes, btcec.S256())
	if err != nil {
		glog.Fatal(err)
	}
	return sig
}

// MsgUltranetBitcoinManagerUpdate ...
type MsgUltranetBitcoinManagerUpdate struct {
	// Keep it simple for now. A BitcoinManagerUpdate just signals that
	// the BitcoinManager has added at least one block or done a reorg.
	// No serialization because we don't want this sent on the wire ever.
	TransactionsFound []*MsgUltranetTxn
}

// GetMsgType ...
func (msg *MsgUltranetBitcoinManagerUpdate) GetMsgType() MsgType {
	return MsgTypeBitcoinManagerUpdate
}

// ToBytes ...
func (msg *MsgUltranetBitcoinManagerUpdate) ToBytes(preSignature bool) ([]byte, error) {
	return nil, fmt.Errorf("MsgUltranetBitcoinManagerUpdate.ToBytes: Not implemented")
}

// FromBytes ...
func (msg *MsgUltranetBitcoinManagerUpdate) FromBytes(data []byte) error {
	return fmt.Errorf("MsgUltranetBitcoinManagerUpdate.FromBytes not implemented")
}

// ==================================================================
// GET_HEADERS message
// ==================================================================

// MsgUltranetGetHeaders ...
type MsgUltranetGetHeaders struct {
	StopHash     *BlockHash
	BlockLocator []*BlockHash
}

// GetMsgType ...
func (msg *MsgUltranetGetHeaders) GetMsgType() MsgType {
	return MsgTypeGetHeaders
}

// ToBytes ...
func (msg *MsgUltranetGetHeaders) ToBytes(preSignature bool) ([]byte, error) {
	data := []byte{}

	// Encode the StopHash first.
	data = append(data, msg.StopHash[:]...)

	// Encode the number of hashes in the BlockLocator.
	data = append(data, UintToBuf(uint64(len(msg.BlockLocator)))...)

	// Encode all of the hashes in the BlockLocator.
	for _, hash := range msg.BlockLocator {
		data = append(data, hash[:]...)
	}

	return data, nil
}

// FromBytes ...
func (msg *MsgUltranetGetHeaders) FromBytes(data []byte) error {
	rr := bytes.NewReader(data)
	retGetHeaders := NewMessage(MsgTypeGetHeaders).(*MsgUltranetGetHeaders)

	// StopHash
	stopHash := BlockHash{}
	_, err := io.ReadFull(rr, stopHash[:])
	if err != nil {
		return errors.Wrapf(err, "MsgUltranetGetHeaders.FromBytes: Problem decoding StopHash")
	}
	retGetHeaders.StopHash = &stopHash

	// Number of hashes in block locator.
	numHeaders, err := ReadUvarint(rr)
	if err != nil {
		return fmt.Errorf("MsgUltranetGetHeaders.FromBytes: %v", err)
	}

	for ii := uint64(0); ii < numHeaders; ii++ {
		currentHeader := BlockHash{}
		_, err := io.ReadFull(rr, currentHeader[:])
		if err != nil {
			return errors.Wrapf(err, "MsgUltranetGetHeaders.FromBytes: Problem decoding header hash")
		}

		retGetHeaders.BlockLocator = append(retGetHeaders.BlockLocator, &currentHeader)
	}

	*msg = *retGetHeaders
	return nil
}

// ==================================================================
// HEADER_BUNDLE message
// ==================================================================

// MsgUltranetHeaderBundle ...
type MsgUltranetHeaderBundle struct {
	Headers   []*MsgUltranetHeader
	TipHash   *BlockHash
	TipHeight uint32
}

// GetMsgType ...
func (msg *MsgUltranetHeaderBundle) GetMsgType() MsgType {
	return MsgTypeHeaderBundle
}

// ToBytes ...
func (msg *MsgUltranetHeaderBundle) ToBytes(preSignature bool) ([]byte, error) {
	data := []byte{}

	// Encode the number of headers in the bundle.
	data = append(data, UintToBuf(uint64(len(msg.Headers)))...)

	// Encode all the headers.
	for _, header := range msg.Headers {
		headerBytes, err := header.ToBytes(preSignature)
		if err != nil {
			return nil, errors.Wrapf(err, "MsgUltranetHeaderBundle.ToBytes: Problem encoding header")
		}
		data = append(data, headerBytes...)
	}

	// Encode the tip hash.
	data = append(data, msg.TipHash[:]...)

	// Encode the tip height.
	data = append(data, UintToBuf(uint64(msg.TipHeight))...)

	return data, nil
}

// FromBytes ...
func (msg *MsgUltranetHeaderBundle) FromBytes(data []byte) error {
	rr := bytes.NewReader(data)
	retBundle := NewMessage(MsgTypeHeaderBundle).(*MsgUltranetHeaderBundle)

	// Read in the number of headers in the bundle.
	numHeaders, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "MsgUltranetHeaderBundle.FromBytes: Problem decoding number of header")
	}

	// Read in all of the headers.
	for ii := uint64(0); ii < numHeaders; ii++ {
		retHeader, err := _readHeader(rr)
		if err != nil {
			return errors.Wrapf(err, "MsgUltranetHeader.FromBytes: ")
		}

		retBundle.Headers = append(retBundle.Headers, retHeader)
	}

	// Read in the tip hash.
	retBundle.TipHash = &BlockHash{}
	_, err = io.ReadFull(rr, retBundle.TipHash[:])
	if err != nil {
		return errors.Wrapf(err, "MsgUltranetHeaderBundle.FromBytes:: Error reading TipHash: ")
	}

	// Read in the tip height.
	tipHeight, err := ReadUvarint(rr)
	if err != nil || tipHeight > math.MaxUint32 {
		return fmt.Errorf("MsgUltranetHeaderBundle.FromBytes: %v", err)
	}
	retBundle.TipHeight = uint32(tipHeight)

	*msg = *retBundle
	return nil
}

// ==================================================================
// GetBlocks Messages
// ==================================================================

// MsgUltranetGetBlocks ...
type MsgUltranetGetBlocks struct {
	HashList []*BlockHash
}

// GetMsgType ...
func (msg *MsgUltranetGetBlocks) GetMsgType() MsgType {
	return MsgTypeGetBlocks
}

// ToBytes ...
func (msg *MsgUltranetGetBlocks) ToBytes(preSignature bool) ([]byte, error) {
	data := []byte{}

	if len(msg.HashList) > MaxBlocksInFlight {
		return nil, fmt.Errorf("MsgUltranetGetBlocks.ToBytes: Blocks requested %d "+
			"exceeds MaxBlocksInFlight %d", len(msg.HashList), MaxBlocksInFlight)
	}

	// Encode the number of hashes.
	data = append(data, UintToBuf(uint64(len(msg.HashList)))...)
	// Encode each hash.
	for _, hash := range msg.HashList {
		data = append(data, hash[:]...)
	}

	return data, nil
}

// FromBytes ...
func (msg *MsgUltranetGetBlocks) FromBytes(data []byte) error {
	rr := bytes.NewReader(data)

	// Parse the nmber of block hashes.
	numHashes, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "MsgUltranetGetBlocks.FromBytes: Problem "+
			"reading number of block hashes requested")
	}
	if numHashes > MaxBlocksInFlight {
		return fmt.Errorf("MsgUltranetGetBlocks.FromBytes: HashList length (%d) "+
			"exceeds maximum allowed (%d)", numHashes, MaxBlocksInFlight)
	}

	// Read in all the hashes.
	hashList := []*BlockHash{}
	for ii := uint64(0); ii < numHashes; ii++ {
		newHash := BlockHash{}

		_, err = io.ReadFull(rr, newHash[:])
		if err != nil {
			return errors.Wrapf(err, "MsgUltranetGetBlocks.FromBytes:: Error reading Hash: ")
		}
		hashList = append(hashList, &newHash)
	}

	*msg = MsgUltranetGetBlocks{
		HashList: hashList,
	}
	return nil
}

func (msg *MsgUltranetGetBlocks) String() string {
	return fmt.Sprintf("%v", msg.HashList)
}

// ==================================================================
// GetListings Messages
// ==================================================================

// MsgUltranetGetListings ...
type MsgUltranetGetListings struct {
	HashList []*BlockHash
}

// GetMsgType ...
func (msg *MsgUltranetGetListings) GetMsgType() MsgType {
	return MsgTypeGetListings
}

// ToBytes ...
func (msg *MsgUltranetGetListings) ToBytes(preSignature bool) ([]byte, error) {
	data := []byte{}

	if len(msg.HashList) > MaxInvPerMsg {
		return nil, fmt.Errorf("MsgUltranetGetListings.ToBytes: Listings requested %d "+
			"exceeds MaxInvPerMsg %d",
			len(msg.HashList), MaxInvPerMsg)
	}

	// Encode the number of hashes.
	data = append(data, UintToBuf(uint64(len(msg.HashList)))...)
	// Encode each hash.
	for _, hash := range msg.HashList {
		data = append(data, hash[:]...)
	}

	return data, nil
}

// FromBytes ...
func (msg *MsgUltranetGetListings) FromBytes(data []byte) error {
	rr := bytes.NewReader(data)

	// Parse the nmber of block hashes.
	numHashes, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "MsgUltranetGetListings.FromBytes: Problem "+
			"reading number of listing hashes requested")
	}
	if numHashes > MaxInvPerMsg {
		return fmt.Errorf("MsgUltranetGetListings.FromBytes: HashList length (%d) "+
			"exceeds maximum allowed (%d)", numHashes, MaxInvPerMsg)
	}

	// Read in all the hashes.
	hashList := []*BlockHash{}
	for ii := uint64(0); ii < numHashes; ii++ {
		newHash := BlockHash{}

		_, err = io.ReadFull(rr, newHash[:])
		if err != nil {
			return errors.Wrapf(err, "MsgUltranetGetListings.FromBytes: Error reading Hash: ")
		}
		hashList = append(hashList, &newHash)
	}

	*msg = MsgUltranetGetListings{
		HashList: hashList,
	}
	return nil
}

func (msg *MsgUltranetGetListings) String() string {
	return fmt.Sprintf("%v", msg.HashList)
}

// ==================================================================
// ListingBundle message
// ==================================================================

// MsgUltranetListingBundle ...
type MsgUltranetListingBundle struct {
	Listings []*MsgUltranetListing
}

// GetMsgType ...
func (msg *MsgUltranetListingBundle) GetMsgType() MsgType {
	return MsgTypeListingBundle
}

// ToBytes ...
func (msg *MsgUltranetListingBundle) ToBytes(preSignature bool) ([]byte, error) {
	data := []byte{}

	// Encode the number of listings in the bundle.
	data = append(data, UintToBuf(uint64(len(msg.Listings)))...)

	// Encode all the listings.
	for ii, listing := range msg.Listings {
		listingBytes, err := listing.ToBytes(preSignature)
		if err != nil {
			return nil, errors.Wrapf(err, "MsgUltranetListingBundle.ToBytes: Problem encoding listing number %d: %v", ii, listing)
		}
		data = append(data, listingBytes...)
	}

	return data, nil
}

// FromBytes ...
func (msg *MsgUltranetListingBundle) FromBytes(data []byte) error {
	rr := bytes.NewReader(data)
	retBundle := NewMessage(MsgTypeListingBundle).(*MsgUltranetListingBundle)

	// Read in the number of listings in the bundle.
	numListings, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "MsgUltranetListingBundle.FromBytes: Problem decoding number of listing")
	}

	// Read in all of the listings.
	for ii := uint64(0); ii < numListings; ii++ {
		retListing, err := _readListing(rr)
		if err != nil {
			return errors.Wrapf(err, "MsgUltranetListingBundle.FromBytes: Problem reading listing number %d: ", ii)
		}

		retBundle.Listings = append(retBundle.Listings, retListing)
	}

	*msg = *retBundle
	return nil
}

// ==================================================================
// ListingSync Message
// ==================================================================

// MsgUltranetListingSync ...
type MsgUltranetListingSync struct {
}

// GetMsgType ...
func (msg *MsgUltranetListingSync) GetMsgType() MsgType {
	return MsgTypeListingSync
}

// ToBytes ...
func (msg *MsgUltranetListingSync) ToBytes(preSignature bool) ([]byte, error) {
	// A ListingSync message is just empty.
	return []byte{}, nil
}

// FromBytes ...
func (msg *MsgUltranetListingSync) FromBytes(data []byte) error {
	// A ListingSync message is just empty.
	return nil
}

func (msg *MsgUltranetListingSync) String() string {
	return fmt.Sprintf("%v", msg.GetMsgType())
}

// ==================================================================
// GetTransactions Messages
// ==================================================================

// MsgUltranetGetTransactions ...
type MsgUltranetGetTransactions struct {
	HashList []*BlockHash
}

// GetMsgType ...
func (msg *MsgUltranetGetTransactions) GetMsgType() MsgType {
	return MsgTypeGetTransactions
}

// ToBytes ...
func (msg *MsgUltranetGetTransactions) ToBytes(preSignature bool) ([]byte, error) {
	data := []byte{}

	if len(msg.HashList) > MaxInvPerMsg {
		return nil, fmt.Errorf("MsgUltranetGetTransactions.ToBytes: Transactions requested %d "+
			"exceeds MaxInvPerMsg %d",
			len(msg.HashList), MaxInvPerMsg)
	}

	// Encode the number of hashes.
	data = append(data, UintToBuf(uint64(len(msg.HashList)))...)
	// Encode each hash.
	for _, hash := range msg.HashList {
		data = append(data, hash[:]...)
	}

	return data, nil
}

// FromBytes ...
func (msg *MsgUltranetGetTransactions) FromBytes(data []byte) error {
	rr := bytes.NewReader(data)

	// Parse the nmber of block hashes.
	numHashes, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "MsgUltranetGetTransactions.FromBytes: Problem "+
			"reading number of transaction hashes requested")
	}
	if numHashes > MaxInvPerMsg {
		return fmt.Errorf("MsgUltranetGetTransactions.FromBytes: HashList length (%d) "+
			"exceeds maximum allowed (%d)", numHashes, MaxInvPerMsg)
	}

	// Read in all the hashes.
	hashList := []*BlockHash{}
	for ii := uint64(0); ii < numHashes; ii++ {
		newHash := BlockHash{}

		_, err = io.ReadFull(rr, newHash[:])
		if err != nil {
			return errors.Wrapf(err, "MsgUltranetGetTransactions.FromBytes: Error reading Hash: ")
		}
		hashList = append(hashList, &newHash)
	}

	*msg = MsgUltranetGetTransactions{
		HashList: hashList,
	}
	return nil
}

func (msg *MsgUltranetGetTransactions) String() string {
	return fmt.Sprintf("%v", msg.HashList)
}

// ==================================================================
// TransactionBundle message
// ==================================================================

// MsgUltranetTransactionBundle ...
type MsgUltranetTransactionBundle struct {
	Transactions []*MsgUltranetTxn
}

// GetMsgType ...
func (msg *MsgUltranetTransactionBundle) GetMsgType() MsgType {
	return MsgTypeTransactionBundle
}

// ToBytes ...
func (msg *MsgUltranetTransactionBundle) ToBytes(preSignature bool) ([]byte, error) {
	data := []byte{}

	// Encode the number of transactions in the bundle.
	data = append(data, UintToBuf(uint64(len(msg.Transactions)))...)

	// Encode all the transactions.
	for _, transaction := range msg.Transactions {
		transactionBytes, err := transaction.ToBytes(preSignature)
		if err != nil {
			return nil, errors.Wrapf(err, "MsgUltranetTransactionBundle.ToBytes: Problem encoding transaction")
		}
		data = append(data, transactionBytes...)
	}

	return data, nil
}

// FromBytes ...
func (msg *MsgUltranetTransactionBundle) FromBytes(data []byte) error {
	rr := bytes.NewReader(data)
	retBundle := NewMessage(MsgTypeTransactionBundle).(*MsgUltranetTransactionBundle)

	// Read in the number of transactions in the bundle.
	numTransactions, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "MsgUltranetTransactionBundle.FromBytes: Problem decoding number of transaction")
	}

	// Read in all of the transactions.
	for ii := uint64(0); ii < numTransactions; ii++ {
		retTransaction, err := _readTransaction(rr)
		if err != nil {
			return errors.Wrapf(err, "MsgUltranetTransaction.FromBytes: ")
		}

		retBundle.Transactions = append(retBundle.Transactions, retTransaction)
	}

	*msg = *retBundle
	return nil
}

// ==================================================================
// Mempool Messages
// ==================================================================

// MsgUltranetMempool ...
type MsgUltranetMempool struct {
}

// GetMsgType ...
func (msg *MsgUltranetMempool) GetMsgType() MsgType {
	return MsgTypeMempool
}

// ToBytes ...
func (msg *MsgUltranetMempool) ToBytes(preSignature bool) ([]byte, error) {
	// A mempool message is just empty.
	return []byte{}, nil
}

// FromBytes ...
func (msg *MsgUltranetMempool) FromBytes(data []byte) error {
	// A mempool message is just empty.
	return nil
}

func (msg *MsgUltranetMempool) String() string {
	return fmt.Sprintf("%v", msg.GetMsgType())
}

// ==================================================================
// INV Messages
// ==================================================================

const (
	// MaxInvPerMsg is the maximum number of inventory vectors that can be in a
	// single inv message.
	MaxInvPerMsg = 50000
	// MaxBlocksInFlight is the maximum number of blocks that can be requested
	// from a peer.
	MaxBlocksInFlight = 250

	// MaxTxnsPerGetTransactionsMsg is the maximum number of transactions we will
	// request from a Peer in a single message.
	MaxTxnsPerGetTransactionsMsg = 10000

	// MaxListingsInFlight ...
	// 500kb per listing * 500 = 250MB in flight at a time, whih seems like a good
	// limit on how much is being fetched at once (similar to MaxBlocksInFlight).
	MaxListingsInFlight = 500

	// MaxListingsPerGetListingsMsg ...
	// 500kb per listing * 4 = 2MB, which seems like a good cutoff per message.
	// Remember these things contain images.
	MaxListingsPerGetListingsMsg = 4
)

// InvType represents the allowed types of inventory vectors. See InvVect.
type InvType uint32

// These constants define the various supported inventory vector types.
const (
	InvTypeTx      InvType = 0
	InvTypeBlock   InvType = 1
	InvTypeListing InvType = 2
)

// Map of service flags back to their constant names for pretty printing.
var ivStrings = map[InvType]string{
	InvTypeTx:      "TX_INV",
	InvTypeBlock:   "BLOCK_INV",
	InvTypeListing: "LISTING",
}

// String returns the InvType in human-readable form.
func (invtype InvType) String() string {
	if s, ok := ivStrings[invtype]; ok {
		return s
	}

	return fmt.Sprintf("Unknown InvType (%d)", uint32(invtype))
}

// InvVect defines an inventory vector which is used to describe data,
// as specified by the Type field, that a peer wants, has, or does not have to
// another peer.
type InvVect struct {
	Type InvType   // Type of data
	Hash BlockHash // Hash of the data
}

// MsgUltranetInv ...
type MsgUltranetInv struct {
	InvList []*InvVect
	// IsSyncResponse indicates that the inv was sent in response to a sync message.
	// This indicates that the node shouldn't relay it to peers because they likely
	// already have it.
	IsSyncResponse bool
}

// GetMsgType ...
func (msg *MsgUltranetInv) GetMsgType() MsgType {
	return MsgTypeInv
}

func _invListToBytes(invList []*InvVect) ([]byte, error) {
	data := []byte{}

	// If there are too many items return an error.
	if len(invList) > MaxInvPerMsg {
		return nil, fmt.Errorf("_invListToBytes: InvList length (%d) exceeds maximum allowed (%d)", len(invList), MaxInvPerMsg)
	}

	// Encode the number of inventory vectors.
	data = append(data, UintToBuf(uint64(len(invList)))...)

	// Encode each inventory vector subsequent.
	for _, invVect := range invList {
		data = append(data, UintToBuf(uint64(invVect.Type))...)
		data = append(data, invVect.Hash[:]...)
	}

	return data, nil
}

func _readInvList(rr io.Reader) ([]*InvVect, error) {
	invList := []*InvVect{}

	// Parse the number of inventory vectors in the message and make sure it doesn't
	// exceed the limit.
	numInvVects, err := ReadUvarint(rr)
	if err != nil {
		return nil, errors.Wrapf(err, "_readInvList: Problem reading number of InvVects")
	}
	if numInvVects > MaxInvPerMsg {
		return nil, fmt.Errorf("_readInvList: InvList length (%d) exceeds maximum allowed (%d)", numInvVects, MaxInvPerMsg)
	}

	// Now parse each individual InvVect.
	for ii := uint64(0); ii < numInvVects; ii++ {
		// Parse the type field, which was encoded as a varint.
		typeUint, err := ReadUvarint(rr)
		if err != nil {
			return nil, errors.Wrapf(err, "_readInvList: Problem parsing Type for InvVect")
		}
		if typeUint > math.MaxUint32 {
			return nil, fmt.Errorf("_readInvList: Type field exceeds maximum value sanity check (%f) vs (%f)", float64(typeUint), float64(math.MaxUint32))
		}

		// Read the Hash of the InvVect.
		invHash := BlockHash{}
		_, err = io.ReadFull(rr, invHash[:])
		if err != nil {
			return nil, errors.Wrapf(err, "_readInvList:: Error reading Hash for InvVect: ")
		}

		invVect := &InvVect{
			Type: InvType(typeUint),
			Hash: invHash,
		}

		invList = append(invList, invVect)
	}

	return invList, nil
}

// ToBytes ...
func (msg *MsgUltranetInv) ToBytes(preSignature bool) ([]byte, error) {
	data, err := _invListToBytes(msg.InvList)
	if err != nil {
		return nil, errors.Wrapf(err, "MsgUltranetGetInv: ")
	}
	data = append(data, _boolToByte(msg.IsSyncResponse))

	return data, nil
}

// FromBytes ...
func (msg *MsgUltranetInv) FromBytes(data []byte) error {
	rr := bytes.NewReader(data)
	invList, err := _readInvList(rr)
	if err != nil {
		return errors.Wrapf(err, "MsgUltranetInv: ")
	}
	isSyncResponse := _readBoolByte(rr)

	*msg = MsgUltranetInv{
		InvList:        invList,
		IsSyncResponse: isSyncResponse,
	}
	return nil
}

// ==================================================================
// PING and PONG Messages
// ==================================================================

// MsgUltranetPing ...
type MsgUltranetPing struct {
	Nonce uint64
}

// GetMsgType ...
func (msg *MsgUltranetPing) GetMsgType() MsgType {
	return MsgTypePing
}

// ToBytes ...
func (msg *MsgUltranetPing) ToBytes(preSignature bool) ([]byte, error) {
	return UintToBuf(msg.Nonce), nil
}

// FromBytes ...
func (msg *MsgUltranetPing) FromBytes(data []byte) error {
	nonce, err := ReadUvarint(bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("MsgUltranetPing.FromBytes: %v", err)
	}
	*msg = MsgUltranetPing{Nonce: nonce}
	return nil
}

// MsgUltranetPong ...
type MsgUltranetPong struct {
	Nonce uint64
}

// GetMsgType ...
func (msg *MsgUltranetPong) GetMsgType() MsgType {
	return MsgTypePong
}

// ToBytes ...
func (msg *MsgUltranetPong) ToBytes(preSignature bool) ([]byte, error) {
	return UintToBuf(msg.Nonce), nil
}

// FromBytes ...
func (msg *MsgUltranetPong) FromBytes(data []byte) error {
	nonce, err := ReadUvarint(bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("MsgUltranetPong.FromBytes: %v", err)
	}
	*msg = MsgUltranetPong{Nonce: nonce}
	return nil
}

// ==================================================================
// VERSION Message
// ==================================================================

// ServiceFlag ...
type ServiceFlag uint64

const (
	// SFFullNode is a flag used to indicate a peer is a full node.
	SFFullNode ServiceFlag = 1 << iota
)

// MsgUltranetVersion ...
type MsgUltranetVersion struct {
	// What is the current version we're on?
	Version uint64

	// What are the services offered by this node?
	Services ServiceFlag

	// The node's unix timestamp that we use to compute a
	// robust "network time" using NTP.
	TstampSecs int64

	// Used to detect when a node connects to itself, which
	// we generally want to prevent.
	Nonce uint64

	// Used as a "vanity plate" to identify different Ultranet
	// clients. Mainly useful in analyzing the network at
	// a meta level, not in the protocol itself.
	UserAgent string

	// The height of the last block on the main chain for
	// this node.
	StartBlockHeight uint32

	// MinFeeRateNanosPerKB is the minimum feerate that a peer will
	// accept from other peers when validating transactions.
	MinFeeRateNanosPerKB uint64

	// The port on which the node listens to JSON API requests.
	JSONAPIPort uint16
}

// ToBytes ...
func (msg *MsgUltranetVersion) ToBytes(preSignature bool) ([]byte, error) {
	retBytes := []byte{}

	// Version
	//
	// We give each one of these its own scope to avoid issues where
	// nn accidentally gets recycled.
	retBytes = append(retBytes, UintToBuf(msg.Version)...)

	// Services
	retBytes = append(retBytes, UintToBuf(uint64(msg.Services))...)

	// TstampSecs
	retBytes = append(retBytes, IntToBuf(msg.TstampSecs)...)

	// Nonce
	retBytes = append(retBytes, UintToBuf(msg.Nonce)...)

	// UserAgent
	//
	// Strings are encoded by putting their length first as uvarints
	// then their values afterward as bytes.
	retBytes = append(retBytes, UintToBuf(uint64(len(msg.UserAgent)))...)
	retBytes = append(retBytes, msg.UserAgent...)

	// StartBlockHeight
	retBytes = append(retBytes, UintToBuf(uint64(msg.StartBlockHeight))...)

	// MinFeeRateNanosPerKB
	retBytes = append(retBytes, UintToBuf(uint64(msg.MinFeeRateNanosPerKB))...)

	// JSONAPIPort
	retBytes = append(retBytes, UintToBuf(uint64(msg.JSONAPIPort))...)

	return retBytes, nil
}

// FromBytes ...
func (msg *MsgUltranetVersion) FromBytes(data []byte) error {
	rr := bytes.NewReader(data)
	retVer := MsgUltranetVersion{}

	// Version
	//
	// We give each one of these its own scope to avoid issues where
	// a value accidentally gets recycled.
	{
		ver, err := ReadUvarint(rr)
		if err != nil {
			return errors.Wrapf(err, "MsgUltranetVersion.FromBytes: Problem converting msg.Version")
		}
		retVer.Version = ver
	}

	// Services
	{
		services, err := ReadUvarint(rr)
		if err != nil {
			return errors.Wrapf(err, "MsgUltranetVersion.FromBytes: Problem converting msg.Services")
		}
		retVer.Services = ServiceFlag(services)
	}

	// TstampSecs
	{
		tstampSecs, err := ReadVarint(rr)
		if err != nil {
			return errors.Wrapf(err, "MsgUltranetVersion.FromBytes: Problem converting msg.TstampSecs")
		}
		retVer.TstampSecs = tstampSecs
	}

	// Nonce
	{
		nonce, err := ReadUvarint(rr)
		if err != nil {
			return errors.Wrapf(err, "MsgUltranetVersion.FromBytes: Problem converting msg.Nonce")
		}
		retVer.Nonce = nonce
	}

	// UserAgent
	//
	// Strings are encoded by putting their length first as uvarints
	// then their values afterward as bytes.
	{
		strLen, err := ReadUvarint(rr)
		if err != nil {
			return errors.Wrapf(err, "MsgUltranetVersion.FromBytes: Problem reading length of msg.UserAgent")
		}
		if strLen > MaxMessagePayload {
			return fmt.Errorf("MsgUltranetVersion.FromBytes: Length msg.UserAgent %d larger than max allowed %d", strLen, MaxMessagePayload)
		}
		userAgent := make([]byte, strLen)
		_, err = io.ReadFull(rr, userAgent)
		if err != nil {
			return errors.Wrapf(err, "MsgUltranetVersion.FromBytes: Error reading msg.UserAgent")
		}
		retVer.UserAgent = string(userAgent)
	}

	// StartBlockHeight
	{
		lastBlockHeight, err := ReadUvarint(rr)
		if err != nil || lastBlockHeight > math.MaxUint32 {
			return errors.Wrapf(err, "MsgUltranetVersion.FromBytes: Problem converting msg.LatestBlockHeight")
		}
		retVer.StartBlockHeight = uint32(lastBlockHeight)
	}

	// MinFeeRateNanosPerKB
	{
		minFeeRateNanosPerKB, err := ReadUvarint(rr)
		if err != nil {
			return errors.Wrapf(err, "MsgUltranetVersion.FromBytes: Problem converting msg.MinFeeRateNanosPerKB")
		}
		retVer.MinFeeRateNanosPerKB = minFeeRateNanosPerKB
	}

	// JSONAPIPort
	{
		jsonAPIPort, err := ReadUvarint(rr)
		if err != nil {
			return errors.Wrapf(err, "MsgUltranetVersion.FromBytes: Problem converting msg.JSONAPIPort")
		}
		if jsonAPIPort > math.MaxUint16 {
			return errors.Wrapf(err, "MsgUltranetVersion.FromBytes: Invalid value for "+
				"JSONAPIPort %d exceeds maximum port value %d", jsonAPIPort, math.MaxUint16)
		}
		retVer.JSONAPIPort = uint16(jsonAPIPort)
	}

	*msg = retVer
	return nil
}

// GetMsgType ...
func (msg *MsgUltranetVersion) GetMsgType() MsgType {
	return MsgTypeVersion
}

// ==================================================================
// ADDR Message
// ==================================================================

const (
	// MaxAddrsPerAddrMsg is the maximum number of addresses we allow in a single
	// addr message from a peer.
	MaxAddrsPerAddrMsg = 1000
	// AddrRelayIntervalSeconds is the amount of time we wait before relaying each
	// batch of addresses we've received recently.
	AddrRelayIntervalSeconds = 60

	// RebroadcastNodeAddrIntervalMinutes is how often we broadcast our own address
	// to our peers.
	RebroadcastNodeAddrIntervalMinutes = 24 * 60
)

// SingleAddr is similar to the wire.NetAddress definition from the btcd guys.
type SingleAddr struct {
	// Last time the address was seen. Encoded as number UNIX seconds on the wire.
	Timestamp time.Time

	// Bitfield which identifies the services supported by the address.
	Services ServiceFlag

	// IP address of the peer. Must be 4 or 16 bytes for IPV4 or IPV6 respectively.
	IP net.IP

	// Port the peer is using.
	Port uint16
}

func (addr *SingleAddr) String(includePort bool) string {
	// Always include the port for localhost as it's useful for testing.
	if includePort || net.IP([]byte{127, 0, 0, 1}).Equal(addr.IP) {
		return fmt.Sprintf("%s:%d", addr.IP.String(), addr.Port)
	}

	return addr.IP.String()
}

// MsgUltranetAddr ...
type MsgUltranetAddr struct {
	// The definition of NetAddress as defined by the btcd guys works fine for
	// our purposes. The only difference is that for Ultra nodes, the Service
	// flag in the NetAddress is as we define it above in ServiceFlag.
	// Note that we also rewrite the serialization logic as well to avoid
	// relying on potentially crusty Bitcoin-related work-arounds going forward.
	AddrList []*SingleAddr
}

// ToBytes ...
func (msg *MsgUltranetAddr) ToBytes(preSignature bool) ([]byte, error) {
	retBytes := []byte{}

	// Encode the number of addresses as a uvarint.
	retBytes = append(retBytes, UintToBuf(uint64(len(msg.AddrList)))...)

	// Encode each address.
	for _, addr := range msg.AddrList {
		// Timestamp
		// Assume it's always positive.
		retBytes = append(retBytes, UintToBuf(uint64(addr.Timestamp.Unix()))...)

		// Services
		retBytes = append(retBytes, UintToBuf(uint64(addr.Services))...)

		// IP
		// Encode the length of the IP and then the actual bytes.
		retBytes = append(retBytes, UintToBuf(uint64(len(addr.IP[:])))...)
		retBytes = append(retBytes, addr.IP[:]...)

		// Port
		retBytes = append(retBytes, UintToBuf(uint64(addr.Port))...)
	}

	return retBytes, nil
}

// FromBytes ...
func (msg *MsgUltranetAddr) FromBytes(data []byte) error {
	rr := bytes.NewReader(data)
	retVer := MsgUltranetAddr{}

	// Read the number of addresses encoded.
	numAddrs, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "MsgUltranetAddr.FromBytes: Problem reading numAddrs: ")
	}
	for ii := uint64(0); ii < numAddrs; ii++ {
		// Read each addr and add it to the AddrList.
		currentAddr := &SingleAddr{}

		// Timestamp
		tstampSecs, err := ReadUvarint(rr)
		if err != nil {
			return errors.Wrapf(err, "MsgUltranetAddr.FromBytes: Problem reading tstamp: ")
		}
		currentAddr.Timestamp = time.Unix(int64(tstampSecs), 0)

		// Services
		serviceUint, err := ReadUvarint(rr)
		if err != nil {
			return errors.Wrapf(err, "MsgUltranetAddr.FromBytes: Problem reading services: ")
		}
		currentAddr.Services = ServiceFlag(serviceUint)

		// IP
		ipLen, err := ReadUvarint(rr)
		if err != nil {
			return errors.Wrapf(err, "MsgUltranetAddr.FromBytes: Problem reading IP: ")
		}
		if ipLen != 4 && ipLen != 16 {
			return fmt.Errorf("MsgUltranetAddr.FromBytes: IP length must be 4 or 16 bytes but was %d", ipLen)
		}
		currentAddr.IP = net.IP(make([]byte, ipLen))
		_, err = io.ReadFull(rr, currentAddr.IP)
		if err != nil {
			return errors.Wrapf(err, "MsgUltranetAddr.FromBytes: Error reading IP")
		}

		// Port
		port, err := ReadUvarint(rr)
		if err != nil {
			return errors.Wrapf(err, "MsgUltranetAddr.FromBytes: Problem reading port: ")
		}
		if port > math.MaxUint16 {
			return fmt.Errorf("MsgUltranetAddr.FromBytes: Port value %d exceeds max "+
				"allowed %d", port, math.MaxUint16)
		}
		currentAddr.Port = uint16(port)

		retVer.AddrList = append(retVer.AddrList, currentAddr)
	}

	*msg = retVer
	return nil
}

// GetMsgType ...
func (msg *MsgUltranetAddr) GetMsgType() MsgType {
	return MsgTypeAddr
}

// ==================================================================
// GET_ADDR Message
// ==================================================================

// MsgUltranetGetAddr ...
type MsgUltranetGetAddr struct {
}

// ToBytes ...
func (msg *MsgUltranetGetAddr) ToBytes(preSignature bool) ([]byte, error) {
	return []byte{}, nil
}

// FromBytes ...
func (msg *MsgUltranetGetAddr) FromBytes(data []byte) error {
	return nil
}

// GetMsgType ...
func (msg *MsgUltranetGetAddr) GetMsgType() MsgType {
	return MsgTypeGetAddr
}

// ==================================================================
// VERACK Message
// ==================================================================

// MsgUltranetVerack ...
// VERACK messages have no payload.
type MsgUltranetVerack struct {
	// A verack message must contain the nonce the peer received in the
	// initial version message. This ensures the peer that is communicating
	// with us actually controls the address she says she does similar to
	// "SYN Cookie" DDOS protection.
	Nonce uint64
}

// ToBytes ...
func (msg *MsgUltranetVerack) ToBytes(preSignature bool) ([]byte, error) {
	retBytes := []byte{}

	// Nonce
	retBytes = append(retBytes, UintToBuf(msg.Nonce)...)
	return retBytes, nil
}

// FromBytes ...
func (msg *MsgUltranetVerack) FromBytes(data []byte) error {
	rr := bytes.NewReader(data)
	retMsg := NewMessage(MsgTypeVerack).(*MsgUltranetVerack)
	{
		nonce, err := ReadUvarint(rr)
		if err != nil {
			return errors.Wrapf(err, "MsgUltranetVerack.FromBytes: Problem reading Nonce")
		}
		retMsg.Nonce = nonce
	}
	*msg = *retMsg
	return nil
}

// GetMsgType ...
func (msg *MsgUltranetVerack) GetMsgType() MsgType {
	return MsgTypeVerack
}

// ==================================================================
// HEADER Message
// ==================================================================

// MsgUltranetHeader definition.
//
// Note that all of these fields must be encoded as *full* little-endian
// ints/uints rather than varints. This is because these fields are hashed to
// produce a block and allowing them to be varints will heavily
// incentivize miners to keep them short, which corrupts their
// actual utility.
//
// Additionally note that it's particularly important that headers be
// space-efficient, since light clients will need to download an entire
// history of them in order to be able to validate anything.
type MsgUltranetHeader struct {
	// The Version field doesn't seem strictly necessary but to the extent
	// it is cheap to include and can be used for things like soft fork
	// signaling then it seems handy to include. For now, nodes will
	// generally expect it to be set to zero until we find a use for it.
	//
	// Note this is encoded as a fixed-width uint32 rather than a
	// uvarint.
	Version uint32

	// Hash of the previous block in the chain.
	PrevBlockHash *BlockHash

	// The merkle root of all the transactions contained within the block.
	TransactionMerkleRoot *BlockHash

	// The unix timestamp (in seconds) specifying when this block was
	// mined.
	//
	// Note that we use a an unsigned 32-bit integer here, which means
	// we'll overflow it on (06:28:15 UTC on Sunday, 7 February 2106).
	// Hopefully we'll be able to stomach four extra bytes in the header
	// by then.
	TstampSecs uint32

	// The height of the block this header corresponds to.
	Height uint32

	// The nonce is encoded as a little-endian 32-bit integer. If more than 2^32
	// hashes are required in order to mine a block, the block reward's ExtraData
	// field can be twiddled to change the merkle root to give a miner a fresh set
	// of 2^32 header nonces to try. Note that we don't use 64 bits (or more) because
	// keeping the header small is important for the efficiency of light clients and
	// because it doesn't add much value over over just twiddling the ExtraData
	// every 2^32 values.
	Nonce uint32
}

// HeaderSizeBytes ...
func HeaderSizeBytes() int {
	header := NewMessage(MsgTypeHeader)
	headerBytes, _ := header.ToBytes(false)
	return len(headerBytes)
}

// ToBytes ...
func (msg *MsgUltranetHeader) ToBytes(preSignature bool) ([]byte, error) {
	retBytes := []byte{}

	// Version
	{
		scratchBytes := [4]byte{}
		binary.LittleEndian.PutUint32(scratchBytes[:], msg.Version)
		retBytes = append(retBytes, scratchBytes[:]...)
	}

	// PrevBlockHash
	prevBlockHash := msg.PrevBlockHash
	if prevBlockHash == nil {
		prevBlockHash = &BlockHash{}
	}
	retBytes = append(retBytes, prevBlockHash[:]...)

	// TransactionMerkleRoot
	transactionMerkleRoot := msg.TransactionMerkleRoot
	if transactionMerkleRoot == nil {
		transactionMerkleRoot = &BlockHash{}
	}
	retBytes = append(retBytes, transactionMerkleRoot[:]...)

	// TstampSecs
	{
		scratchBytes := [4]byte{}
		binary.LittleEndian.PutUint32(scratchBytes[:], msg.TstampSecs)
		retBytes = append(retBytes, scratchBytes[:]...)
	}

	// Height
	{
		scratchBytes := [4]byte{}
		binary.LittleEndian.PutUint32(scratchBytes[:], msg.Height)
		retBytes = append(retBytes, scratchBytes[:]...)
	}

	// Nonce
	{
		scratchBytes := [4]byte{}
		binary.LittleEndian.PutUint32(scratchBytes[:], msg.Nonce)
		retBytes = append(retBytes, scratchBytes[:]...)
	}

	return retBytes, nil
}

func _readHeader(rr io.Reader) (*MsgUltranetHeader, error) {
	retHeader := NewMessage(MsgTypeHeader).(*MsgUltranetHeader)

	// Version
	{
		scratchBytes := [4]byte{}
		_, err := io.ReadFull(rr, scratchBytes[:])
		if err != nil {
			return nil, errors.Wrapf(err, "MsgUltranetHeader.FromBytes: Problem decoding Version")
		}
		retHeader.Version = binary.LittleEndian.Uint32(scratchBytes[:])
	}

	// PrevBlockHash
	_, err := io.ReadFull(rr, retHeader.PrevBlockHash[:])
	if err != nil {
		return nil, errors.Wrapf(err, "MsgUltranetHeader.FromBytes: Problem decoding PrevBlockHash")
	}

	// TransactionMerkleRoot
	_, err = io.ReadFull(rr, retHeader.TransactionMerkleRoot[:])
	if err != nil {
		return nil, errors.Wrapf(err, "MsgUltranetHeader.FromBytes: Problem decoding TransactionMerkleRoot")
	}

	// TstampSecs
	{
		scratchBytes := [4]byte{}
		_, err := io.ReadFull(rr, scratchBytes[:])
		if err != nil {
			return nil, errors.Wrapf(err, "MsgUltranetHeader.FromBytes: Problem decoding TstampSecs")
		}
		retHeader.TstampSecs = binary.LittleEndian.Uint32(scratchBytes[:])
	}

	// Height
	{
		scratchBytes := [4]byte{}
		_, err := io.ReadFull(rr, scratchBytes[:])
		if err != nil {
			return nil, errors.Wrapf(err, "MsgUltranetHeader.FromBytes: Problem decoding Height")
		}
		retHeader.Height = binary.LittleEndian.Uint32(scratchBytes[:])
	}

	// Nonce
	{
		scratchBytes := [4]byte{}
		_, err := io.ReadFull(rr, scratchBytes[:])
		if err != nil {
			return nil, errors.Wrapf(err, "MsgUltranetHeader.FromBytes: Problem decoding Nonce")
		}
		retHeader.Nonce = binary.LittleEndian.Uint32(scratchBytes[:])
	}

	return retHeader, nil
}

// FromBytes ...
func (msg *MsgUltranetHeader) FromBytes(data []byte) error {
	rr := bytes.NewReader(data)
	retHeader, err := _readHeader(rr)
	if err != nil {
		return errors.Wrapf(err, "MsgUltranetHeader.FromBytes: ")
	}

	*msg = *retHeader
	return nil
}

// GetMsgType ...
func (msg *MsgUltranetHeader) GetMsgType() MsgType {
	return MsgTypeHeader
}

// Hash is a helper function to compute a hash of the header. Note that the header
// hash is special in that we always hash it using the ProofOfWorkHash rather than
// Sha256DoubleHash.
func (msg *MsgUltranetHeader) Hash() (*BlockHash, error) {
	preSignature := false
	headerBytes, err := msg.ToBytes(preSignature)
	if err != nil {
		return nil, errors.Wrap(err, "MsgUltranetHeader.Hash: ")
	}

	return ProofOfWorkHash(headerBytes), nil
}

func (msg *MsgUltranetHeader) String() string {
	hash, _ := msg.Hash()
	return fmt.Sprintf("< %d, %s >", msg.Height, hash)
}

// ==================================================================
// BLOCK Message
// ==================================================================

// MsgUltranetBlock ...
type MsgUltranetBlock struct {
	Header *MsgUltranetHeader
	Txns   []*MsgUltranetTxn
}

// ToBytes ...
func (msg *MsgUltranetBlock) ToBytes(preSignature bool) ([]byte, error) {
	data := []byte{}

	// Serialize the header.
	if msg.Header == nil {
		return nil, fmt.Errorf("MsgUltranetBlock.ToBytes: Header should not be nil")
	}
	hdrBytes, err := msg.Header.ToBytes(preSignature)
	if err != nil {
		return nil, errors.Wrapf(err, "MsgUltranetBlock.ToBytes: Problem encoding header")
	}
	data = append(data, UintToBuf(uint64(len(hdrBytes)))...)
	data = append(data, hdrBytes...)

	// Serialize all the transactions.
	numTxns := uint64(len(msg.Txns))
	data = append(data, UintToBuf(numTxns)...)
	for ii := uint64(0); ii < numTxns; ii++ {
		currentTxnBytes, err := msg.Txns[ii].ToBytes(preSignature)
		if err != nil {
			return nil, errors.Wrapf(err, "MsgUltranetBlock.ToBytes: Problem encoding txn")
		}
		data = append(data, UintToBuf(uint64(len(currentTxnBytes)))...)
		data = append(data, currentTxnBytes...)
	}

	return data, nil
}

// FromBytes ...
func (msg *MsgUltranetBlock) FromBytes(data []byte) error {
	ret := NewMessage(MsgTypeBlock).(*MsgUltranetBlock)
	rr := bytes.NewReader(data)

	// De-serialize the header.
	hdrLen, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "MsgUltranetBlock.FromBytes: Problem decoding header length")
	}
	if hdrLen > MaxMessagePayload {
		return fmt.Errorf("MsgUltranetBlock.FromBytes: Header length %d longer than max %d", hdrLen, MaxMessagePayload)
	}
	hdrBytes := make([]byte, hdrLen)
	_, err = io.ReadFull(rr, hdrBytes)
	if err != nil {
		return errors.Wrapf(err, "MsgUltranetBlock.FromBytes: Problem reading header")
	}

	err = ret.Header.FromBytes(hdrBytes)
	if err != nil {
		return errors.Wrapf(err, "MsgUltranetBlock.FromBytes: Problem converting header")
	}

	// De-serialize the transactions.
	numTxns, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "MsgUltranetBlock.FromBytes: Problem decoding num txns")
	}
	ret.Txns = make([]*MsgUltranetTxn, 0)
	for ii := uint64(0); ii < numTxns; ii++ {
		txBytesLen, err := ReadUvarint(rr)
		if err != nil {
			return errors.Wrapf(err, "MsgUltranetBlock.FromBytes: Problem decoding txn length")
		}
		if txBytesLen > MaxMessagePayload {
			return fmt.Errorf("MsgUltranetBlock.FromBytes: Txn %d length %d longer than max %d", ii, hdrLen, MaxMessagePayload)
		}
		txBytes := make([]byte, txBytesLen)
		_, err = io.ReadFull(rr, txBytes)
		if err != nil {
			return errors.Wrapf(err, "MsgUltranetBlock.FromBytes: Problem reading tx bytes")
		}
		currentTxn := NewMessage(MsgTypeTxn).(*MsgUltranetTxn)
		err = currentTxn.FromBytes(txBytes)
		if err != nil {
			return errors.Wrapf(err, "MsgUltranetBlock.FromBytes: Problem decoding txn")
		}
		ret.Txns = append(ret.Txns, currentTxn)
	}

	*msg = *ret
	return nil
}

// GetMsgType ...
func (msg *MsgUltranetBlock) GetMsgType() MsgType {
	return MsgTypeBlock
}

// Hash ...
func (msg *MsgUltranetBlock) Hash() (*BlockHash, error) {
	if msg == nil || msg.Header == nil {
		return nil, fmt.Errorf("MsgUltranetBLock.Hash: nil block or nil header")
	}
	return msg.Header.Hash()
}

func (msg *MsgUltranetBlock) String() string {
	if msg == nil || msg.Header == nil {
		return "<nil block or header>"
	}
	return msg.Header.String()
}

// ==================================================================
// MerchantEntry serialization
//
// To compute a merchant merkle root we define a canonical way to serialize
// a MerchantEntry that captures the salient features we want to capture
// in a merchant and then hash it.
// ==================================================================

func MerchantScoreFromHash(scoreHash *BlockHash) *big.Int {
	return big.NewInt(0).Sub(HashToBigint(scoreHash), HashToBigint(NewZeroScore()))
}

func MerchantScoreToHash(score *big.Int) *BlockHash {
	return BigintToHash(big.NewInt(0).Add(score, HashToBigint(NewZeroScore())))
}

func HashMerchantEntry(merchantEntry *MerchantEntry) *BlockHash {
	data := []byte{}

	// MerchantID
	data = append(data, merchantEntry.merchantID[:]...)

	// Username
	data = append(data, merchantEntry.Username...)

	// PublicKey
	data = append(data, merchantEntry.PublicKey...)

	// Description
	data = append(data, merchantEntry.Description...)

	// All of the merchant stats.
	data = append(data, UintToBuf(merchantEntry.Stats.AmountBurnedNanos)...)
	data = append(data, UintToBuf(merchantEntry.Stats.PaymentPlacedNanos)...)
	data = append(data, UintToBuf(merchantEntry.Stats.PaymentRejectedNanos)...)
	data = append(data, UintToBuf(merchantEntry.Stats.PaymentCanceledNanos)...)
	data = append(data, UintToBuf(merchantEntry.Stats.CommissionsNanos)...)
	data = append(data, UintToBuf(merchantEntry.Stats.RevenueConfirmedNanos)...)
	data = append(data, UintToBuf(merchantEntry.Stats.RevenueFulfilledNanos)...)

	data = append(data, UintToBuf(merchantEntry.Stats.RevenueNegativeNanos)...)
	data = append(data, UintToBuf(merchantEntry.Stats.RevenueNeutralNanos)...)
	data = append(data, UintToBuf(merchantEntry.Stats.RevenuePositiveNanos)...)

	data = append(data, UintToBuf(merchantEntry.Stats.RevenueRefundedNanos)...)

	data = append(data, MerchantScoreToHash(merchantEntry.Stats.MerchantScore)[:]...)

	data = append(data, UintToBuf(uint64(merchantEntry.Stats.LastPlacedOrderHeight))...)
	data = append(data, UintToBuf(uint64(merchantEntry.Stats.LastRejectedOrderHeight))...)
	data = append(data, UintToBuf(uint64(merchantEntry.Stats.LastCanceledOrderHeight))...)
	data = append(data, UintToBuf(uint64(merchantEntry.Stats.LastFulfilledOrderHeight))...)
	data = append(data, UintToBuf(uint64(merchantEntry.Stats.LastConfirmedOrderHeight))...)
	data = append(data, UintToBuf(uint64(merchantEntry.Stats.LastNegativeReviewOrderHeight))...)
	data = append(data, UintToBuf(uint64(merchantEntry.Stats.LastNeturalReviewOrderHeight))...)
	data = append(data, UintToBuf(uint64(merchantEntry.Stats.LastPositiveReviewOrderHeight))...)
	data = append(data, UintToBuf(uint64(merchantEntry.Stats.LastRefundedOrderHeight))...)

	return Sha256DoubleHash(data)
}

// ==================================================================
// TXN Message
// ==================================================================

// UtxoKey is a 32-byte txid with a 4-byte uint32 index
// identifying the particular output in the transaction where
// this utxo occurs.
// When fetching from the db the txid and index are concatenated to
// form the key, with the index serialized as big-endian.
type UtxoKey struct {
	// TxID ...
	// The 32-byte transaction id where the unspent output occurs.
	TxID BlockHash
	// Index ...
	// The index within the txn where the unspent output occurs.
	Index uint32
}

func (utxoKey *UtxoKey) String() string {
	return fmt.Sprintf("< TxID: %v, Index: %d >", &utxoKey.TxID, utxoKey.Index)
}

const (
	// MaxUltranetInputSizeBytes is the size required to encode an UltranetInput.
	// 32 bytes for the TxID and 4 bytes for the Index = 36 bytes. Note
	// that because the index is encoded as a uvarint, this size represents
	// a maximum.
	MaxUltranetInputSizeBytes = 32 + 4
	// MaxUltranetOutputSizeBytes is the size required to encode an UltranetOutput.
	// It is 33 bytes for the public key and 8 bytes for the amount
	// = 41 bytes. Note that because the amount is encoded as a uvarint,
	// this size represents a maximum.
	MaxUltranetOutputSizeBytes = btcec.PubKeyBytesLenCompressed + 8
)

// UltranetInput represents a single unspent output from a previous txn.
// For that reason it specifies the previous txn and the index in that txn where
// the output appears by simply aliasing UtxoKey.
type UltranetInput UtxoKey

func (ultranetInput *UltranetInput) String() string {
	return (*UtxoKey)(ultranetInput).String()
}

// NewUltranetInput ...
func NewUltranetInput() *UltranetInput {
	return &UltranetInput{
		TxID: BlockHash{},
	}
}

// UltranetOutput ...
type UltranetOutput struct {
	// Outputs always compensate a specific public key.
	PublicKey []byte
	// The amount of Ultra to send to this public key.
	AmountNanos uint64
}

func (ultranetOutput *UltranetOutput) String() string {
	return fmt.Sprintf("< PublicKey: %#v, AmountNanos: %d >",
		PkToStringMainnet(ultranetOutput.PublicKey), ultranetOutput.AmountNanos)
}

// MsgUltranetTxn ...
type MsgUltranetTxn struct {
	TxInputs  []*UltranetInput
	TxOutputs []*UltranetOutput

	// UltranetTxnMetadata is an interface type that will give us information on how
	// we should handle the transaction, including what type of transaction this
	// is.
	TxnMeta UltranetTxnMetadata

	// Transactions must generally explicitly include the key that is
	// spending the inputs to the transaction. The exception to this rule is that
	// BlockReward and BitcoinExchange transactions do not require the inclusion
	// of a public key since they have no inputs to spend.
	//
	// The public key should be a serialized compressed ECDSA public key on the
	// secp256k1 curve.
	PublicKey []byte

	// Transactions must generally be signed by the key that is spending the
	// inputs to the transaction. The exception to this rule is that
	// BLOCK_REWARD and CREATE_ULTRA transactions do not require a signature
	// since they have no inputs.
	Signature *btcec.Signature

	// (!!) **DO_NOT_USE** (!!)
	//
	// Use txn.TxnMeta.GetTxnType() instead.
	//
	// We need this for JSON encoding/decoding. It isn't used for anything
	// else and it isn't actually serialized or de-serialized when sent
	// across the network using ToBytes/FromBytes because we prefer that
	// any use of the MsgUltranetTxn in Go code rely on TxnMeta.GetTxnType() rather
	// than checking this value, which, in Go context, is redundant and
	// therefore error-prone (e.g. someone might change TxnMeta while
	// forgetting to set it). We make it a uint64 explicitly to prevent
	// people from using it in Go code.
	TxnTypeJSON uint64
}

func (msg *MsgUltranetTxn) String() string {
	return fmt.Sprintf("< PublicKey: %v, TxnType: %v, Inputs: %v, Outputs: %v, Meta: %v >",
		PkToStringMainnet(msg.PublicKey), msg.TxnMeta.GetTxnType(), msg.TxInputs,
		msg.TxOutputs, msg.TxnMeta)
}

// ToBytes ...
func (msg *MsgUltranetTxn) ToBytes(preSignature bool) ([]byte, error) {
	data := []byte{}

	// Serialize the inputs
	data = append(data, UintToBuf(uint64(len(msg.TxInputs)))...)
	for _, ultranetInput := range msg.TxInputs {
		data = append(data, ultranetInput.TxID[:]...)
		data = append(data, UintToBuf(uint64(ultranetInput.Index))...)
	}

	// Serialize the outputs
	data = append(data, UintToBuf(uint64(len(msg.TxOutputs)))...)
	for _, ultranetOutput := range msg.TxOutputs {
		// The public key is always 33 bytes.
		data = append(data, ultranetOutput.PublicKey[:]...)
		data = append(data, UintToBuf(ultranetOutput.AmountNanos)...)
	}

	// Serialize the metadata
	//
	// Encode the type as a uvarint.
	data = append(data, UintToBuf(uint64(msg.TxnMeta.GetTxnType()))...)
	// Encode the length and payload for the metadata.
	//
	// Note that we do *NOT* serialize the metadata using the preSignature
	// flag. This is the correct thing to do since by the time we're ready
	// to serialize the full transaction, all of the metadata should have
	// its signatures fully computed. As a result, the proper way to use
	// the preSignature flag when metadata is involved is as follows:
	// - Compute the bytes for the meta using preSignature=true
	// - Sign the bytes for the meta however that particular metadata
	//   requires.
	// - Compute the bytes for the full transaction using preSignature=true.
	//   This will fully-serialize the meta with its computed signature,
	//   which is correct.
	// - Sign the bytes for the full transaction from above.
	preSignatureForMeta := false
	metadataBuf, err := msg.TxnMeta.ToBytes(preSignatureForMeta)
	if err != nil {
		return nil, errors.Wrapf(err, "MsgUltranetTxn.ToBytes: Problem encoding meta of type %v: ",
			msg.TxnMeta.GetTxnType())
	}
	data = append(data, UintToBuf(uint64(len(metadataBuf)))...)
	data = append(data, metadataBuf...)

	// Serialize the public key if there is one. Encode the length in
	// case this field was left empty.
	data = append(data, UintToBuf(uint64(len(msg.PublicKey)))...)
	data = append(data, msg.PublicKey...)

	// Serialize the signature. Since this can be variable length, encode
	// the length first and then the signature. If there is no signature, then
	// a zero will be encoded for the length and no signature bytes will be added
	// beyond it.
	sigBytes := []byte{}
	if !preSignature && msg.Signature != nil {
		sigBytes = msg.Signature.Serialize()
	}
	// Note that even though we encode the length as a varint as opposed to a
	// fixed-width int, it should always take up just one byte since the length
	// of the signature will never exceed 127 bytes in length. This is important
	// to note for e.g. operations that try to compute a transaction's size
	// before a signature is present such as during transaction fee computations.
	data = append(data, UintToBuf(uint64(len(sigBytes)))...)
	data = append(data, sigBytes...)

	return data, nil
}

func _readTransaction(rr io.Reader) (*MsgUltranetTxn, error) {
	ret := NewMessage(MsgTypeTxn).(*MsgUltranetTxn)

	// De-serialize the inputs
	numInputs, err := ReadUvarint(rr)
	if err != nil {
		return nil, errors.Wrapf(err, "_readTransaction: Problem converting len(msg.TxInputs)")
	}
	for ii := uint64(0); ii < numInputs; ii++ {
		currentInput := NewUltranetInput()
		_, err = io.ReadFull(rr, currentInput.TxID[:])
		if err != nil {
			return nil, errors.Wrapf(err, "_readTransaction: Problem converting input txid")
		}
		inputIndex, err := ReadUvarint(rr)
		if err != nil {
			return nil, errors.Wrapf(err, "_readTransaction: Problem converting input index")
		}
		if inputIndex > uint64(^uint32(0)) {
			return nil, fmt.Errorf("_readTransaction: Input index (%d) must not exceed (%d)", inputIndex, ^uint32(0))
		}
		currentInput.Index = uint32(inputIndex)

		ret.TxInputs = append(ret.TxInputs, currentInput)
	}

	// De-serialize the outputs
	numOutputs, err := ReadUvarint(rr)
	if err != nil {
		return nil, errors.Wrapf(err, "_readTransaction: Problem converting len(msg.TxOutputs)")
	}
	for ii := uint64(0); ii < numOutputs; ii++ {
		currentOutput := &UltranetOutput{}
		currentOutput.PublicKey = make([]byte, btcec.PubKeyBytesLenCompressed)
		_, err = io.ReadFull(rr, currentOutput.PublicKey)
		if err != nil {
			return nil, errors.Wrapf(err, "_readTransaction: Problem reading UltranetOutput.PublicKey")
		}

		amountNanos, err := ReadUvarint(rr)
		if err != nil {
			return nil, errors.Wrapf(err, "_readTransaction: Problem reading UltranetOutput.AmountNanos")
		}
		currentOutput.AmountNanos = amountNanos

		ret.TxOutputs = append(ret.TxOutputs, currentOutput)
	}

	// De-serialize the metadata
	//
	// Encode the type as a uvarint.
	txnMetaType, err := ReadUvarint(rr)
	if err != nil {
		return nil, errors.Wrapf(err, "_readTransaction: Problem reading MsgUltranetTxn.TxnType")
	}
	ret.TxnMeta, err = NewTxnMetadata(TxnType(txnMetaType))
	if err != nil {
		return nil, fmt.Errorf("_readTransaction: Problem initializing metadata: %v", err)
	}
	if ret.TxnMeta == nil {
		return nil, fmt.Errorf("_readTransaction: Metadata was nil: %v", ret.TxnMeta)
	}
	metaLen, err := ReadUvarint(rr)
	if err != nil {
		return nil, errors.Wrapf(err, "_readTransaction: Problem reading len(TxnMeta)")
	}
	if metaLen > MaxMessagePayload {
		return nil, fmt.Errorf("_readTransaction.FromBytes: metaLen length %d longer than max %d", metaLen, MaxMessagePayload)
	}
	metaBuf := make([]byte, metaLen)
	_, err = io.ReadFull(rr, metaBuf)
	if err != nil {
		return nil, errors.Wrapf(err, "_readTransaction: Problem reading TxnMeta")
	}
	err = ret.TxnMeta.FromBytes(metaBuf)
	if err != nil {
		return nil, errors.Wrapf(err, "_readTransaction: Problem decoding TxnMeta: ")
	}

	// De-serialize the public key if there is one
	pkLen, err := ReadUvarint(rr)
	if err != nil {
		return nil, errors.Wrapf(err, "_readTransaction: Problem reading len(UltranetTxn.PublicKey)")
	}
	if pkLen > MaxMessagePayload {
		return nil, fmt.Errorf("_readTransaction.FromBytes: pkLen length %d longer than max %d", pkLen, MaxMessagePayload)
	}
	ret.PublicKey = nil
	if pkLen != 0 {
		ret.PublicKey = make([]byte, pkLen)
		_, err = io.ReadFull(rr, ret.PublicKey)
		if err != nil {
			return nil, errors.Wrapf(err, "_readTransaction: Problem reading UltranetTxn.PublicKey")
		}
	}

	// De-serialize the signature if there is one.
	sigLen, err := ReadUvarint(rr)
	if err != nil {
		return nil, errors.Wrapf(err, "_readTransaction: Problem reading len(UltranetTxn.Signature)")
	}
	if sigLen > MaxMessagePayload {
		return nil, fmt.Errorf("_readTransaction.FromBytes: sigLen length %d longer than max %d", sigLen, MaxMessagePayload)
	}
	ret.Signature = nil
	if sigLen != 0 {
		sigBytes := make([]byte, sigLen)
		_, err = io.ReadFull(rr, sigBytes)
		if err != nil {
			return nil, errors.Wrapf(err, "_readTransaction: Problem reading UltranetTxn.Signature")
		}
		sig, err := btcec.ParseDERSignature(sigBytes, btcec.S256())
		if err != nil {
			return nil, errors.Wrapf(err, "_readTransaction: Problem parsing UltranetTxn.Signature bytes")
		}
		ret.Signature = sig
	}

	return ret, nil
}

// FromBytes ...
func (msg *MsgUltranetTxn) FromBytes(data []byte) error {
	rr := bytes.NewReader(data)

	ret, err := _readTransaction(rr)
	if err != nil {
		return errors.Wrapf(err, "MsgUltranetTxn.FromBytes: Problem reading txn: ")
	}
	*msg = *ret
	return nil
}

// GetMsgType ...
func (msg *MsgUltranetTxn) GetMsgType() MsgType {
	return MsgTypeTxn
}

// Hash is a helper function to compute a hash of the transaction aka a
// transaction ID.
func (msg *MsgUltranetTxn) Hash() *BlockHash {
	preSignature := false
	txBytes, err := msg.ToBytes(preSignature)
	if err != nil {
		return nil
	}

	return Sha256DoubleHash(txBytes)
}

func (msg *MsgUltranetTxn) Copy() (*MsgUltranetTxn, error) {
	txnBytes, err := msg.ToBytes(false /*preSignature*/)
	if err != nil {
		return nil, errors.Wrapf(err, "MsgUltranetTxn.Copy: ")
	}
	newTxn := &MsgUltranetTxn{}
	err = newTxn.FromBytes(txnBytes)
	if err != nil {
		return nil, errors.Wrapf(err, "MsgUltranetTxn.Copy: ")
	}
	return newTxn, nil
}

func (msg *MsgUltranetTxn) Sign(privKey *btcec.PrivateKey) (*btcec.Signature, error) {
	// Serialize the transaction without the signature portion.
	txnBytes, err := msg.ToBytes(true /*preSignature*/)
	if err != nil {
		return nil, err
	}
	// Compute a hash of the transaction bytes without the signature
	// portion and sign it with the passed private key.
	txnSignatureHash := Sha256DoubleHash(txnBytes)
	txnSignature, err := privKey.Sign(txnSignatureHash[:])
	if err != nil {
		return nil, err
	}
	return txnSignature, nil
}

// MarshalJSON and UnmarshalJSON implement custom JSON marshaling/unmarshaling
// to support transaction metadata. The reason this needs to exist is because
// TxnMeta is an abstract interface and therefore
// when its decoded to JSON, the type information (i.e. which TxnType it is)
// cannot be inferred from the JSON unless we augment it a little bit.
// Note this format is not used to relay messages between nodes, only
// for replying to frontend/user-facing queries.
func (msg *MsgUltranetTxn) MarshalJSON() ([]byte, error) {
	// Copy the txn so none of the fields get set on the passed-in txn.
	txnCopy := *msg
	// If there's no metadata then we have an error. Transactions should
	// always have a metadata field that indicates what type the transaction
	// is.
	if txnCopy.TxnMeta == nil {
		return nil, fmt.Errorf("MsgUltranetTxn.MarshalJSON: Transaction is missing TxnMeta: %v", txnCopy)
	}
	// Set the txnType based on the metadata that is set.
	txnCopy.TxnTypeJSON = uint64(txnCopy.TxnMeta.GetTxnType())
	return json.Marshal(txnCopy)
}

// UnmarshalJSON is covered by the comment on MarshalJSON.
func (msg *MsgUltranetTxn) UnmarshalJSON(data []byte) error {
	// Use the map-based JSON conversion to determine the type of the
	// TxnMeta and initialize it appropriately.
	var responseMap map[string]interface{}
	err := json.Unmarshal(data, &responseMap)
	if err != nil {
		return err
	}

	// Set the TxnMeta based on the TxnType that's set in the top level
	// of the transaction.
	txnType, txnTypeExists := responseMap["TxnTypeJSON"]
	if !txnTypeExists {
		// If there is not metadata that's an error.
		return fmt.Errorf("MsgUltranetTxn.UnmarshalJSON: Field txnType is missing "+
			"from JSON decoded map: %v", responseMap)
	}
	txnMeta, err := NewTxnMetadata(TxnType(uint64(txnType.(float64))))
	if err != nil {
		return fmt.Errorf("MsgUltranetTxn.UnmarshalJSON: Problem parsing TxnType: %v, %v", err, responseMap)
	}
	msg.TxnMeta = txnMeta

	// TODO: The code below is a gruesome hack, but it achieves the goal of making
	// TxnMeta (and MsgUltranetTxn by proxy) serializable to JSON without any extra overhead
	// needed on the caller side. This is particularly important when one considers
	// that transactions can be serialized to JSON as part of listings or blocks,
	// and this makes it so that even in those cases no special handling is
	// needed by the code serializing/deserializing, which is good. Still, would
	// be nice if, for example, the code below didn't break whenever we modify
	// MsgUltranetTxn (which is admittedly very rare and a test can easily catch this
	// by erroring when the number of fields changes with a helpful message).
	anonymousTxn := struct {
		TxInputs  []*UltranetInput
		TxOutputs []*UltranetOutput
		TxnMeta   UltranetTxnMetadata
		PublicKey []byte
		Signature *btcec.Signature
		TxnType   uint64
	}{
		TxInputs:  msg.TxInputs,
		TxOutputs: msg.TxOutputs,
		TxnMeta:   msg.TxnMeta,
		PublicKey: msg.PublicKey,
		Signature: msg.Signature,
		TxnType:   msg.TxnTypeJSON,
	}
	json.Unmarshal(data, &anonymousTxn)

	msg.TxInputs = anonymousTxn.TxInputs
	msg.TxOutputs = anonymousTxn.TxOutputs
	msg.TxnMeta = anonymousTxn.TxnMeta
	msg.PublicKey = anonymousTxn.PublicKey
	msg.Signature = anonymousTxn.Signature
	// Don't set the TxnTypeJSON when unmarshaling. It should never be used in
	// Go code, only at the interface between Go and non-Go.
	msg.TxnTypeJSON = 0

	return nil
}

// ProductType specifies the type of listing represented by a MsgUltranetListing
type ProductType uint8

const (
	// ProductTypeInstant is a product that can be delivered instantly, e.g.
	// something downloadable.
	ProductTypeInstant ProductType = 0
	// ProductTypeDelivered is a product that requires shipping information
	// and delivery.
	ProductTypeDelivered ProductType = 1

	// TODO: Would be good to have ListingTypeService to describe something
	// that is provided locally. The parameters for this would be a list of
	// locations and radii describing where the service is provided.
)

func (pp ProductType) String() string {
	if pp == ProductTypeInstant {
		return "instant"
	} else if pp == ProductTypeDelivered {
		return "delivered"
	} else {
		return "unknown"
	}
}

// RequiredField ...
type RequiredField struct {
	Label      []byte
	IsRequired bool
}

func (rf *RequiredField) String() string {
	return fmt.Sprintf("<Label: %s, IsRequired: %v>", string(rf.Label), rf.IsRequired)
}

// MsgUltranetListing ...
type MsgUltranetListing struct {
	// The MerchantID of the merchant to whom this listing message belongs.
	MerchantID *BlockHash

	// PublicKey is the key of the merchant who's supposedly authorized to
	// make this update. Note this must be equal to the MerchantPk in the
	// MerchantEntry corresponding to this MerchantID or else it will be
	// rejected.
	PublicKey []byte

	// TstampSecs is a timestamp indicating when this update was made. Every
	// update has a timestamp giving it priority over updates that came before
	// it.
	TstampSecs uint32

	// The index of this listing. Generally between 0 and MaxListingsPerMerchant.
	ListingIndex uint32

	// When a listing has Deleted=true it doesn't count toward a merchant's size
	// quota and nodes treat it as basically not existing except that an entry is
	// generally kept in the db with the latest timestamp to avoid a replay attack.
	Deleted bool

	// Basic fields for a listing.
	Title             []byte
	Body              []byte
	Category          []byte
	ThumbnailImage    []byte
	ListingImages     [][]byte
	PricePerUnitNanos uint64
	UnitNameSingular  []byte
	UnitNamePlural    []byte
	MinQuantity       uint64
	MaxQuantity       uint64
	RequiredFields    []*RequiredField
	ProductType       ProductType
	// Encourages people to leave a tip to accommodate for special circumstances.
	// For example, merchant can instruct buyers to leave a tip if they live in an
	// area that's expensive to ship to.
	TipComment []byte

	// Set for ProductTypeDelivered only.
	ShipsTo   []byte
	ShipsFrom []byte

	// Signature is a signature of the above by the public key specified.
	Signature *btcec.Signature
}

func (msg *MsgUltranetListing) String() string {
	hasThumbnail := len(msg.ThumbnailImage) != 0
	return fmt.Sprintf("Listing <\n\tMerchantID: %v\n\tListingIndex: %d\n\t"+
		"TstampSecs: %d\n\tTitle: %s\n\tBody: %s\n\tCategory: %s\n\tNum Images: %d\n\t"+
		"Thumbnail?: %v\n\tPricePerUnitNanos: %d\n\tUnit Name (singular): %s\n\t"+
		"Unit Name (plural): %s\n\tMinQuantity: %d\n\tMaxQuantity: %d\n\t"+
		"RequiredFields: %v\n\tProductType: %s\n\tTipComment: %s\n\tShipsTo: %s\n\t"+
		"ShipsFrom: %s\n\tPublicKey: %v\n>", msg.MerchantID, msg.ListingIndex, msg.TstampSecs,
		string(msg.Title), string(msg.Body), string(msg.Category), len(msg.ListingImages),
		hasThumbnail, msg.PricePerUnitNanos, msg.UnitNameSingular, msg.UnitNamePlural,
		msg.MinQuantity, msg.MaxQuantity, msg.RequiredFields, msg.ProductType,
		msg.TipComment, msg.ShipsTo, msg.ShipsFrom, PkToStringMainnet(msg.PublicKey))
}

func (msg *MsgUltranetListing) Sign(privKey *btcec.PrivateKey) (*btcec.Signature, error) {
	// Compute the signature of the message above using the private key retrieved.
	listingSignatureBytes, err := msg.ToBytes(true)
	if err != nil {
		return nil, errors.Wrapf(err, "MsgUltranetListing.Sign: Problem computing signature hash for listing")
	}
	listingSignatureHash := Sha256DoubleHash(listingSignatureBytes)
	listingSignature, err := privKey.Sign(listingSignatureHash[:])
	if err != nil {
		return nil, errors.Wrapf(err, "MsgUltranetListing.Sign: Problem computing signature hash for listing")
	}
	return listingSignature, err
}

func (msg *MsgUltranetListing) Hash() *BlockHash {
	listingBytes, err := msg.ToBytes(false /*preSignature*/)
	if err != nil {
		return nil
	}
	return Sha256DoubleHash(listingBytes)
}

func _readBoolByte(rr *bytes.Reader) bool {
	boolByte, err := rr.ReadByte()
	if err != nil {
		return false
	}
	if boolByte != 0 {
		return true
	}
	return false
}

func _boolToByte(val bool) byte {
	if val {
		return 1
	}
	return 0
}

// ToBytes ...
func (msg *MsgUltranetListing) ToBytes(preSignature bool) ([]byte, error) {
	data := []byte{}

	_encodeBytes := func(bb []byte) {
		data = append(data, UintToBuf(uint64(len(bb)))...)
		data = append(data, bb...)
	}

	// MerchantID *BlockHash (assumed 32 bytes)
	data = append(data, msg.MerchantID[:]...)

	// PublicKey []byte (assumed 33 bytes)
	data = append(data, msg.PublicKey...)

	// TstampSecs uint64
	data = append(data, UintToBuf(uint64(msg.TstampSecs))...)

	// ListingIndex uint32
	data = append(data, UintToBuf(uint64(msg.ListingIndex))...)

	// Title             []byte
	_encodeBytes(msg.Title)
	// Body              []byte
	_encodeBytes(msg.Body)
	// Category          []byte
	_encodeBytes(msg.Category)
	// ThumbnailImage    []byte
	_encodeBytes(msg.ThumbnailImage)
	// ListingImages     [][]byte
	data = append(data, UintToBuf(uint64(len(msg.ListingImages)))...)
	for _, listingImage := range msg.ListingImages {
		_encodeBytes(listingImage)
	}
	// Deleted          bool (assumed 1 byte)
	data = append(data, _boolToByte(msg.Deleted))
	// PricePerUnitNanos uint64
	data = append(data, UintToBuf(msg.PricePerUnitNanos)...)
	// UnitNameSingular  []byte
	_encodeBytes(msg.UnitNameSingular)
	// UnitNamePlural    []byte
	_encodeBytes(msg.UnitNamePlural)
	// MinQuantity       uint64
	data = append(data, UintToBuf(msg.MinQuantity)...)
	// MaxQuantity       uint64
	data = append(data, UintToBuf(msg.MaxQuantity)...)
	// RequiredFields    []RequiredField
	data = append(data, UintToBuf(uint64(len(msg.RequiredFields)))...)
	for _, requiredField := range msg.RequiredFields {
		data = append(data, _boolToByte(requiredField.IsRequired))
		_encodeBytes(requiredField.Label)
	}
	// ProductType       ProductType (assumed 1 byte)
	data = append(data, byte(msg.ProductType))

	// TipComment []byte
	_encodeBytes(msg.TipComment)

	// ShipsTo   []byte
	_encodeBytes(msg.ShipsTo)
	// ShipsFrom []byte
	_encodeBytes(msg.ShipsFrom)

	// Signature *btcec.Signature
	sig := []byte{}
	if !preSignature && msg.Signature != nil {
		sig = msg.Signature.Serialize()
	}
	_encodeBytes(sig)

	return data, nil
}

func _readListing(rr *bytes.Reader) (*MsgUltranetListing, error) {
	ret := NewMessage(MsgTypeListing).(*MsgUltranetListing)

	_readBytes := func(_rr *bytes.Reader) ([]byte, error) {
		bytesLen, err := ReadUvarint(_rr)
		if err != nil {
			return nil, err
		}
		if bytesLen > MaxMessagePayload {
			return nil, fmt.Errorf("_readTransaction.FromBytes: bytes length %d longer than max %d", bytesLen, MaxMessagePayload)
		}
		ret := make([]byte, bytesLen)
		_, err = io.ReadFull(_rr, ret[:])
		if err != nil {
			return nil, err
		}

		return ret, nil
	}

	// MerchantID *BlockHash (assumed 32 bytes)
	ret.MerchantID = &BlockHash{}
	_, err := io.ReadFull(rr, ret.MerchantID[:])
	if err != nil {
		return nil, errors.Wrapf(err, "_readListing: Problem reading MerchantID")
	}

	// PublicKey []byte (assumed 33 bytes)
	ret.PublicKey = make([]byte, btcec.PubKeyBytesLenCompressed)
	_, err = io.ReadFull(rr, ret.PublicKey[:])
	if err != nil {
		return nil, errors.Wrapf(err, "_readListing: Problem reading PublicKey")
	}

	// TstampSecs uint32
	{
		TstampSecs, err := ReadUvarint(rr)
		if err != nil {
			return nil, errors.Wrapf(err, "_readListing: Problem reading TstampSecs")
		}
		if TstampSecs > uint64(math.MaxUint32) {
			return nil, fmt.Errorf("_readListing: TstampSecs too large %d", TstampSecs)
		}
		ret.TstampSecs = uint32(TstampSecs)
	}

	// ListingIndex uint32
	{
		listingIndex, err := ReadUvarint(rr)
		if err != nil {
			return nil, errors.Wrapf(err, "_readListing: Problem reading ListingIndex")
		}
		if listingIndex > uint64(math.MaxUint32) {
			return nil, fmt.Errorf("_readListing: ListingIndex too large %d", listingIndex)
		}
		ret.ListingIndex = uint32(listingIndex)
	}

	// Title             []byte
	{
		title, err := _readBytes(rr)
		if err != nil {
			return nil, errors.Wrapf(err, "_readListing: Problem reading Title")
		}
		ret.Title = title
	}
	// Body              []byte
	{
		Body, err := _readBytes(rr)
		if err != nil {
			return nil, errors.Wrapf(err, "_readListing: Problem reading Body")
		}
		ret.Body = Body
	}
	// Category          []byte
	{
		Category, err := _readBytes(rr)
		if err != nil {
			return nil, errors.Wrapf(err, "_readListing: Problem reading Category")
		}
		ret.Category = Category
	}
	// ThumbnailImage    []byte
	{
		ThumbnailImage, err := _readBytes(rr)
		if err != nil {
			return nil, errors.Wrapf(err, "_readListing: Problem reading ThumbnailImage")
		}
		ret.ThumbnailImage = ThumbnailImage
	}
	// ListingImages     [][]byte
	{
		ret.ListingImages = [][]byte{}
		numImages, err := ReadUvarint(rr)
		if err != nil {
			return nil, errors.Wrapf(err, "_readListing: Problem reading num images")
		}
		for ii := uint64(0); ii < numImages; ii++ {
			currentImage, err := _readBytes(rr)
			if err != nil {
				return nil, errors.Wrapf(err, "_readListing: Problem reading image number %d", ii)
			}
			ret.ListingImages = append(ret.ListingImages, currentImage)
		}
	}
	// Deleted          bool (assumed 1 byte)
	bb, err := rr.ReadByte()
	if err != nil {
		return nil, errors.Wrapf(err, "_readListing: Problem reading Deleted")
	}
	if bb == 0 {
		ret.Deleted = false
	} else {
		ret.Deleted = true
	}
	// PricePerUnitNanos uint64
	{
		PricePerUnitNanos, err := ReadUvarint(rr)
		if err != nil {
			return nil, errors.Wrapf(err, "_readListing: Problem reading PricePerUnitNanos")
		}
		ret.PricePerUnitNanos = PricePerUnitNanos
	}
	// UnitNameSingular  []byte
	{
		UnitNameSingular, err := _readBytes(rr)
		if err != nil {
			return nil, errors.Wrapf(err, "_readListing: Problem reading UnitNameSingular")
		}
		ret.UnitNameSingular = UnitNameSingular
	}
	// UnitNamePlural    []byte
	{
		UnitNamePlural, err := _readBytes(rr)
		if err != nil {
			return nil, errors.Wrapf(err, "_readListing: Problem reading UnitNamePlural")
		}
		ret.UnitNamePlural = UnitNamePlural
	}
	// MinQuantity       uint64
	{
		MinQuantity, err := ReadUvarint(rr)
		if err != nil {
			return nil, errors.Wrapf(err, "_readListing: Problem reading MinQuantity")
		}
		ret.MinQuantity = MinQuantity
	}
	// MaxQuantity       uint64
	{
		MaxQuantity, err := ReadUvarint(rr)
		if err != nil {
			return nil, errors.Wrapf(err, "_readListing: Problem reading MaxQuantity")
		}
		ret.MaxQuantity = MaxQuantity
	}
	// RequiredFields    []RequiredField
	numRequiredFields, err := ReadUvarint(rr)
	if err != nil {
		return nil, errors.Wrapf(err, "_readListing: Problem reading num required fields")
	}
	for ii := uint64(0); ii < numRequiredFields; ii++ {
		rf := &RequiredField{}
		bb, err := rr.ReadByte()
		if err != nil {
			return nil, errors.Wrapf(err, "_readListing: Problem reading IsRequired for RequiredField %d", ii)
		}
		if bb == 0 {
			rf.IsRequired = false
		} else {
			rf.IsRequired = true
		}
		{
			Label, err := _readBytes(rr)
			if err != nil {
				return nil, errors.Wrapf(err, "_readListing: Problem reading Label for RequiredField %d", ii)
			}
			rf.Label = Label
		}
		ret.RequiredFields = append(ret.RequiredFields, rf)
	}
	// ProductType       ProductType (assumed 1 byte)
	productType, err := rr.ReadByte()
	if err != nil {
		return nil, errors.Wrapf(err, "_readListing: Problem reading ProductType")
	}
	// TipComment  []byte
	{
		TipComment, err := _readBytes(rr)
		if err != nil {
			return nil, errors.Wrapf(err, "_readListing: Problem reading TipComment")
		}
		ret.TipComment = TipComment
	}
	ret.ProductType = ProductType(productType)
	// ShipsTo   []byte
	{
		ShipsTo, err := _readBytes(rr)
		if err != nil {
			return nil, errors.Wrapf(err, "_readListing: Problem reading ShipsTo")
		}
		ret.ShipsTo = ShipsTo
	}
	// ShipsFrom []byte
	{
		ShipsFrom, err := _readBytes(rr)
		if err != nil {
			return nil, errors.Wrapf(err, "_readListing: Problem reading ShipsFrom")
		}
		ret.ShipsFrom = ShipsFrom
	}

	// Signature *btcec.Signature
	{
		sigBytes, err := _readBytes(rr)
		if err != nil {
			return nil, errors.Wrapf(err, "_readListing: Problem reading Signature length")
		}
		if len(sigBytes) > 0 {
			ret.Signature, err = btcec.ParseDERSignature(sigBytes, btcec.S256())
			if err != nil {
				return nil, errors.Wrapf(err, "_readListing: Problem reading Signature")
			}
		}
	}

	return ret, nil
}

// FromBytes ...
func (msg *MsgUltranetListing) FromBytes(data []byte) error {
	rr := bytes.NewReader(data)

	ret, err := _readListing(rr)
	if err != nil {
		return errors.Wrapf(err, "MsgUltranetListing.FromBytes: ")
	}
	*msg = *ret

	return nil
}

// GetMsgType ...
func (msg *MsgUltranetListing) GetMsgType() MsgType {
	return MsgTypeListing
}

// ==================================================================
// BasicTransferMetadata
// ==================================================================

// BasicTransferMetadata ...
type BasicTransferMetadata struct {
	// Requires no extra information
}

// GetTxnType ...
func (txnData *BasicTransferMetadata) GetTxnType() TxnType {
	return TxnTypeBasicTransfer
}

// ToBytes ...
func (txnData *BasicTransferMetadata) ToBytes(preSignature bool) ([]byte, error) {
	return []byte{}, nil
}

// FromBytes ...
func (txnData *BasicTransferMetadata) FromBytes(data []byte) error {
	// Nothing to set
	return nil
}

func (txnData *BasicTransferMetadata) New() UltranetTxnMetadata {
	return &BasicTransferMetadata{}
}

// ==================================================================
// BlockRewardMetadataa
// ==================================================================

// BlockRewardMetadataa ...
type BlockRewardMetadataa struct {
	// The root of a merkle tree whose leaves are hashes of each merchant's
	// identifying information. Block reward transactions are only valid if
	// this merkle root lines up with the state of the merchant db before applying
	// the current block (i.e. before applying the block containing this transaction).
	//
	// This field is useful for light clients who don't want to download and
	// verify blocks or store a listing index. Without this field, light clients
	// would not be able to check the validity of listings that they query from
	// untrusted nodes. With this field, however, an untrusted node is no longer
	// able to lie about the score and rank of the merchants associated with the
	// listings it returns. It can still omit listings, but this is a much less
	// severe attack vector than impersonating a merchant and stealing their order
	// flow, which is what would be possible without this field.
	//
	// A light client would demand this field from whatever node it queries listings
	// from, and it would verify the following:
	// - This BlockReward transaction is its header chain using the
	//   TransactionMerkleRoot of the block.
	// - The block this transaction is in has some minimal amount of work on it. Say
	//   one block worth of work.
	// - The merchant list it downloaded from the untrusted node is consistent with
	//   this merkle root.
	// Once it is confident of the above, it can trust that the merchants it is
	// transacting with are authentic.
	//
	// Also note that I'm putting this in the block reward because it seems a bit
	// wasteful to include at the top level header. From a technical standpoint it
	// is sufficient for a light client to download just one of these from whatever untrusted node is
	// being used and so putting it in the header, which would require that this field
	// be downloaded for every single block even by light clients, seems unnecessary.
	MerchantMerkleRoot *BlockHash

	// ExtraData ...
	// A block reward txn has an ExtraData field that can be between
	// zero and 100 bytes long. It can theoretically contain anything
	// but in practice it's likely that miners will use this field to
	// update the merkle root of the block, which may make the block
	// easier to mine (namely by allowing the Nonce in the header to
	// be shorter).
	ExtraData []byte
}

// GetTxnType ...
func (txnData *BlockRewardMetadataa) GetTxnType() TxnType {
	return TxnTypeBlockReward
}

// ToBytes ...
func (txnData *BlockRewardMetadataa) ToBytes(preSignature bool) ([]byte, error) {
	retBytes := []byte{}

	// MerchantMerkleRoot
	merchantMerkleRoot := txnData.MerchantMerkleRoot
	if merchantMerkleRoot == nil {
		merchantMerkleRoot = &BlockHash{}
	}
	retBytes = append(retBytes, merchantMerkleRoot[:]...)

	// ExtraData.
	numExtraDataBytes := len(txnData.ExtraData)
	if numExtraDataBytes > MaxBlockRewardDataSizeBytes {
		return nil, fmt.Errorf(
			"BLOCK_REWARD txn ExtraData length (%d) cannot be longer than "+
				"(%d) bytes", numExtraDataBytes, MaxBlockRewardDataSizeBytes)
	}
	retBytes = append(retBytes, UintToBuf(uint64(numExtraDataBytes))...)
	retBytes = append(retBytes, txnData.ExtraData...)

	return retBytes, nil
}

// FromBytes ...
func (txnData *BlockRewardMetadataa) FromBytes(dataa []byte) error {
	ret := BlockRewardMetadataa{}
	rr := bytes.NewReader(dataa)

	// MerchantMerkleRoot
	ret.MerchantMerkleRoot = &BlockHash{}
	_, err := io.ReadFull(rr, ret.MerchantMerkleRoot[:])
	if err != nil {
		return errors.Wrapf(err, "BlockRewardMetadataa.FromBytes: Problem decoding MerchantMerkleRoot")
	}

	// ExtraData
	numExtraDataBytes, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "BlockRewardMetadataa.FromBytes: Problem reading NumExtraDataBytes")
	}

	if numExtraDataBytes > uint64(MaxBlockRewardDataSizeBytes) {
		return fmt.Errorf(
			"BLOCK_REWARD txn ExtraData length (%d) cannot be longer than "+
				"(%d) bytes", numExtraDataBytes, MaxBlockRewardDataSizeBytes)
	}
	ret.ExtraData = make([]byte, numExtraDataBytes)
	_, err = io.ReadFull(rr, ret.ExtraData[:])
	if err != nil {
		return errors.Wrapf(err, "BlockRewardMetadataa.FromBytes: Problem reading ExtraData")
	}

	*txnData = ret
	return nil
}

func (txnData *BlockRewardMetadataa) New() UltranetTxnMetadata {
	return &BlockRewardMetadataa{}
}

// ==================================================================
// RegisterMerchantMetadata
// ==================================================================

// RegisterMerchantMetadata ...
type RegisterMerchantMetadata struct {
	// Username is the identifiable string that users will associate with the
	// merchant and the merchant's reputation.
	Username []byte
	// Description is some text about the merchant.
	Description []byte
	// BurnAmountNanos is the amount that is being burned to back this merchant.
	// All merchants must burn a non-zero amount to become a merchant and most
	// full nodes will rank a merchant more favorably the more that she has burned.
	BurnAmountNanos uint64
}

// GetTxnType ...
func (txnData *RegisterMerchantMetadata) GetTxnType() TxnType {
	return TxnTypeRegisterMerchant
}

// ToBytes ...
func (txnData *RegisterMerchantMetadata) ToBytes(preSignature bool) ([]byte, error) {
	data := []byte{}

	// Username
	data = append(data, UintToBuf(uint64(len(txnData.Username)))...)
	data = append(data, txnData.Username...)

	// Description
	data = append(data, UintToBuf(uint64(len(txnData.Description)))...)
	data = append(data, txnData.Description...)

	// BurnAmountNanos
	data = append(data, UintToBuf(uint64(txnData.BurnAmountNanos))...)

	return data, nil
}

// FromBytes ...
func (txnData *RegisterMerchantMetadata) FromBytes(data []byte) error {
	ret := RegisterMerchantMetadata{}
	rr := bytes.NewReader(data)

	// Username
	usernameLen, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "RegisterMerchantMetadata.FromBytes: Problem reading len(txnData.Username)")
	}
	if usernameLen > MaxMessagePayload {
		return fmt.Errorf("RegisterMerchantMetadata.FromBytes: usernameLen length %d longer than max %d", usernameLen, MaxMessagePayload)
	}
	ret.Username = make([]byte, usernameLen)
	_, err = io.ReadFull(rr, ret.Username[:])
	if err != nil {
		return errors.Wrapf(err, "RegisterMerchantMetadata.FromBytes: Problem converting input txnData.Username")
	}

	// Description
	descriptionLen, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "RegisterMerchantMetadata.FromBytes: Problem reading len(txnData.Description)")
	}
	if descriptionLen > MaxMessagePayload {
		return fmt.Errorf("RegisterMerchantMetadata.FromBytes: descriptionLen length %d longer than max %d", descriptionLen, MaxMessagePayload)
	}
	ret.Description = make([]byte, descriptionLen)
	_, err = io.ReadFull(rr, ret.Description[:])
	if err != nil {
		return errors.Wrapf(err, "RegisterMerchantMetadata.FromBytes: Problem converting input txnData.Description")
	}

	// BurnAmountNanos
	burnAmountNanos, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "RegisterMerchantMetadata.FromBytes: Problem reading txnData.BurnAmountNanos")
	}
	ret.BurnAmountNanos = burnAmountNanos

	*txnData = ret

	return nil
}

func (txnData *RegisterMerchantMetadata) New() UltranetTxnMetadata {
	return &RegisterMerchantMetadata{}
}

// ==================================================================
// PlaceOrderMetadata
// ==================================================================

// BuyerMessage is a serializable package of data corresponding to information
// that a buyer might send to a seller. It is generally serialized and encrypted
// with the mercahnt's public key prior to being included in a PlaceOrderMetadata.
type BuyerMessage struct {
	RequiredFields []string
	OptionalFields []string
	ItemQuantity   float64
	TipAmountNanos uint64
	ListingIndex   uint64
}

func (bm *BuyerMessage) ToBytes() []byte {
	data := []byte{}

	// RequiredFields
	data = append(data, UintToBuf(uint64(len(bm.RequiredFields)))...)
	for _, requiredFieldStr := range bm.RequiredFields {
		requiredFieldBytes := []byte(requiredFieldStr)
		data = append(data, UintToBuf(uint64(len(requiredFieldBytes)))...)
		data = append(data, requiredFieldBytes...)
	}

	// OptionalFields
	data = append(data, UintToBuf(uint64(len(bm.OptionalFields)))...)
	for _, optionalFieldStr := range bm.OptionalFields {
		optionalFieldBytes := []byte(optionalFieldStr)
		data = append(data, UintToBuf(uint64(len(optionalFieldBytes)))...)
		data = append(data, optionalFieldBytes...)
	}

	// ItemQuantity
	itemQuantityAsUint := math.Float64bits(bm.ItemQuantity)
	data = append(data, UintToBuf(itemQuantityAsUint)...)

	// TipAmountNanos
	data = append(data, UintToBuf(bm.TipAmountNanos)...)

	// ListingIndex
	data = append(data, UintToBuf(bm.ListingIndex)...)

	return data
}

func (bm *BuyerMessage) FromBytes(data []byte) error {
	rr := bytes.NewReader(data)
	ret := BuyerMessage{}

	// RequiredFields
	{
		numRequiredFields, err := ReadUvarint(rr)
		if err != nil {
			return errors.Wrapf(err, "BuyerMessage.FromBytes: Problem reading number "+
				"of required fields")
		}
		for ii := uint64(0); ii < numRequiredFields; ii++ {
			requiredFieldLen, err := ReadUvarint(rr)
			if err != nil {
				return errors.Wrapf(err, "BuyerMessage.FromBytes: Problem reading field "+
					"size for required field %d", ii)
			}

			requiredFieldBytes := make([]byte, requiredFieldLen)
			_, err = io.ReadFull(rr, requiredFieldBytes[:])
			if err != nil {
				return errors.Wrapf(err, "BuyerMessage.FromBytes: Problem reading "+
					"required field %d", ii)
			}
			ret.RequiredFields = append(ret.RequiredFields, string(requiredFieldBytes))
		}
	}

	// OptionalFields
	{
		numOptionalFields, err := ReadUvarint(rr)
		if err != nil {
			return errors.Wrapf(err, "BuyerMessage.FromBytes: Problem reading number "+
				"of optional fields")
		}
		for ii := uint64(0); ii < numOptionalFields; ii++ {
			optionalFieldLen, err := ReadUvarint(rr)
			if err != nil {
				return errors.Wrapf(err, "BuyerMessage.FromBytes: Problem reading field "+
					"size for optional field %d", ii)
			}

			optionalFieldBytes := make([]byte, optionalFieldLen)
			_, err = io.ReadFull(rr, optionalFieldBytes[:])
			if err != nil {
				return errors.Wrapf(err, "BuyerMessage.FromBytes: Problem reading "+
					"optional field %d", ii)
			}
			ret.OptionalFields = append(ret.OptionalFields, string(optionalFieldBytes))
		}
	}

	// ItemQuantity
	itemQuantityAsUint, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "BuyerMessage.FromBytes: Problem reading item quantity")
	}
	ret.ItemQuantity = math.Float64frombits(itemQuantityAsUint)

	// TipAmountNanos
	tipAmountNanos, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "BuyerMessage.FromBytes: Problem reading TipAmountNanos")
	}
	ret.TipAmountNanos = tipAmountNanos

	// ListingIndex
	listingIndex, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "BuyerMessage.FromBytes: Problem reading ListingIndex")
	}
	ret.ListingIndex = listingIndex

	*bm = ret
	return nil
}

func EncryptBytesWithPublicKey(bytesToEncrypt []byte, pubkey *ecdsa.PublicKey) ([]byte, error) {
	eciesPubkey := ecies.ImportECDSAPublic(pubkey)
	// Note we need to manually set the Params. Params is normally
	// set automatically in ImportECDSA based on what curve you're using.
	// However, because we use btcec.S256() rather than Ethereum's
	// implementation ethcrypto.S256(), which is just a wrapper around
	// secp256k1, the ecies library fails to fetch the proper parameters
	// for our curve even though it is functionally identical. So we just
	// set the params here and everything works.
	eciesPubkey.Params = ecies.ECIES_AES128_SHA256
	return ecies.Encrypt(rand.Reader, eciesPubkey, bytesToEncrypt, nil, nil)
}

func DecryptBytesWithPrivateKey(bytesToDecrypt []byte, privKey *ecdsa.PrivateKey) ([]byte, error) {
	eciesKeypair := ecies.ImportECDSA(privKey)
	// Note we need to manually set the Params. Params is normally
	// set automatically in ImportECDSA based on what curve you're using.
	// However, because we use btcec.S256() rather than Ethereum's
	// implementation ethcrypto.S256(), which is just a wrapper around
	// secp256k1, the ecies library fails to fetch the proper parameters
	// for our curve even though it is functionally identical. So we just
	// set the params here and everything works.
	eciesKeypair.Params = ecies.ECIES_AES128_SHA256
	return eciesKeypair.Decrypt(bytesToDecrypt, nil, nil)
}

func (bm *BuyerMessage) EncryptWithPubKey(pubKey *btcec.PublicKey) ([]byte, error) {
	bmBytes := bm.ToBytes()
	encryptedBytes, err := EncryptBytesWithPublicKey(bmBytes, pubKey.ToECDSA())
	if err != nil {
		return nil, errors.Wrapf(err, "BuyerMessage.EncryptWithPubKey: ")
	}
	return encryptedBytes, nil
}

func (bm *BuyerMessage) DecryptWithPrivKey(encryptedBytes []byte, privKey *btcec.PrivateKey) error {
	decryptedBytes, err := DecryptBytesWithPrivateKey(encryptedBytes, privKey.ToECDSA())
	if err != nil {
		return errors.Wrapf(err, "BuyerMessage.DecryptWithPrivKey: ")
	}

	return bm.FromBytes(decryptedBytes)
}

// PlaceOrderMetadata ...
type PlaceOrderMetadata struct {
	// MerchantID is the ID of the merchant in this transaction.
	MerchantID *BlockHash
	// AmountLockedNanos is the amount of Ultra that is going to be locked
	// into this order once it is placed.
	AmountLockedNanos uint64

	// BuyerMessage is some actual data sent from this user to the merchant
	// encrypted with the merchant's public key. It will typically
	// include where to ship the items, possibly contact information, etc.
	BuyerMessage []byte
}

// GetTxnType ...
func (txnData *PlaceOrderMetadata) GetTxnType() TxnType {
	return TxnTypePlaceOrder
}

// ToBytes ...
func (txnData *PlaceOrderMetadata) ToBytes(preSignature bool) ([]byte, error) {
	data := []byte{}

	// MerchantID
	data = append(data, txnData.MerchantID[:]...)

	// AmountLockedNanos
	data = append(data, UintToBuf(txnData.AmountLockedNanos)...)

	// BuyerMessage
	data = append(data, UintToBuf(uint64(len(txnData.BuyerMessage)))...)
	data = append(data, txnData.BuyerMessage...)

	return data, nil
}

// FromBytes ...
func (txnData *PlaceOrderMetadata) FromBytes(data []byte) error {
	ret := PlaceOrderMetadata{}
	rr := bytes.NewReader(data)

	// MerchantID
	ret.MerchantID = &BlockHash{}
	_, err := io.ReadFull(rr, ret.MerchantID[:])
	if err != nil {
		return errors.Wrapf(err, "PlaceOrderMetadata.FromBytes: Problem converting input txnData.MerchantID")
	}

	// AmountLockedNanos
	amountLockedNanos, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "PlaceOrderMetadata.FromBytes: Problem reading amountLockedNanos")
	}
	ret.AmountLockedNanos = amountLockedNanos

	// BuyerMessage
	buyerMessageLen, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "PlaceOrderMetadata.FromBytes: Problem reading buyerMessageLen")
	}
	if buyerMessageLen > MaxMessagePayload {
		return fmt.Errorf("PlaceOrderMetadata.FromBytes: buyerMessageLen length %d longer than max %d", buyerMessageLen, MaxMessagePayload)
	}
	ret.BuyerMessage = make([]byte, buyerMessageLen)
	_, err = io.ReadFull(rr, ret.BuyerMessage[:])
	if err != nil {
		return errors.Wrapf(err, "PlaceOrderMetadata.FromBytes: Problem reading BuyerMessage")
	}
	*txnData = ret

	return nil
}

func (txnData *PlaceOrderMetadata) New() UltranetTxnMetadata {
	return &PlaceOrderMetadata{}
}

// ==================================================================
// CancelOrderMetadata
// ==================================================================

// CancelOrderMetadata ...
type CancelOrderMetadata struct {
	OrderID *BlockHash
}

// GetTxnType ...
func (txnData *CancelOrderMetadata) GetTxnType() TxnType {
	return TxnTypeCancelOrder
}

// ToBytes ...
func (txnData *CancelOrderMetadata) ToBytes(preSignature bool) ([]byte, error) {
	return txnData.OrderID[:], nil
}

// FromBytes ...
func (txnData *CancelOrderMetadata) FromBytes(data []byte) error {
	if len(data) != HashSizeBytes {
		return fmt.Errorf("CancelOrderMetadata.FromBytes: Data length "+
			"%d improper length %d", len(data), HashSizeBytes)
	}
	txnData.OrderID = &BlockHash{}
	copy(txnData.OrderID[:], data[:])
	return nil
}

func (txnData *CancelOrderMetadata) New() UltranetTxnMetadata {
	return &CancelOrderMetadata{}
}

// ==================================================================
// ConfirmOrderMetadata
// ==================================================================

// ConfirmOrderMetadata ...
type ConfirmOrderMetadata struct {
	OrderID *BlockHash
}

// GetTxnType ...
func (txnData *ConfirmOrderMetadata) GetTxnType() TxnType {
	return TxnTypeConfirmOrder
}

// ToBytes ...
func (txnData *ConfirmOrderMetadata) ToBytes(preSignature bool) ([]byte, error) {
	return txnData.OrderID[:], nil
}

// FromBytes ...
func (txnData *ConfirmOrderMetadata) FromBytes(data []byte) error {
	if len(data) != HashSizeBytes {
		return fmt.Errorf("ConfirmOrderMetadata.FromBytes: Data length "+
			"%d improper length %d", len(data), HashSizeBytes)
	}
	txnData.OrderID = &BlockHash{}
	copy(txnData.OrderID[:], data[:])
	return nil
}

func (txnData *ConfirmOrderMetadata) New() UltranetTxnMetadata {
	return &ConfirmOrderMetadata{}
}

// ==================================================================
// ReviewOrderMetadata
// ==================================================================

// ReviewOrderMetadata ...
type ReviewOrderMetadata struct {
	OrderID    *BlockHash
	ReviewType ReviewType
	ReviewText []byte

	// TODO: Merchants really like being able to reply to feedback. But this
	// could be an artifact of the fact that feedback can't be changed on other
	// sites. Think about whether we want to add this feature.
}

// GetTxnType ...
func (txnData *ReviewOrderMetadata) GetTxnType() TxnType {
	return TxnTypeReviewOrder
}

// ToBytes ...
func (txnData *ReviewOrderMetadata) ToBytes(preSignature bool) ([]byte, error) {
	data := []byte{}

	data = append(data, txnData.OrderID[:]...)
	data = append(data, uint8(txnData.ReviewType))

	data = append(data, UintToBuf(uint64(len(txnData.ReviewText)))...)
	data = append(data, txnData.ReviewText...)

	return data, nil
}

// FromBytes ...
func (txnData *ReviewOrderMetadata) FromBytes(data []byte) error {
	rr := bytes.NewReader(data)
	ret := ReviewOrderMetadata{}

	// OrderID
	ret.OrderID = &BlockHash{}
	_, err := io.ReadFull(rr, ret.OrderID[:])
	if err != nil {
		return errors.Wrapf(err, "ReviewOrderMetadata.FromBytes: Problem reading OrderID: ")
	}

	// ReviewType
	reviewType, err := rr.ReadByte()
	if err != nil {
		return errors.Wrapf(err, "ReviewOrderMetadata.FromBytes: Problem reading ReviewType: ")
	}
	ret.ReviewType = ReviewType(reviewType)

	// ReviewText
	reviewLen, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "ReviewOrderMetadata.FromBytes: Problem reading ReviewText length: ")
	}
	if reviewLen > MaxMessagePayload {
		return errors.Wrapf(err, "ReviewOrderMetadata.FromBytes: reviewLen length %d longer than max %d", reviewLen, MaxMessagePayload)
	}
	ret.ReviewText = make([]byte, reviewLen)
	_, err = io.ReadFull(rr, ret.ReviewText[:])
	if err != nil {
		return errors.Wrapf(err, "ReviewOrderMetadata.FromBytes: Problem reading ReviewText: ")
	}

	*txnData = ret
	return nil
}

func (txnData *ReviewOrderMetadata) New() UltranetTxnMetadata {
	return &ReviewOrderMetadata{}
}

// ==================================================================
// RefundOrderMetadata
// ==================================================================

// RefundOrderMetadata ...
type RefundOrderMetadata struct {
	OrderID *BlockHash
}

// GetTxnType ...
func (txnData *RefundOrderMetadata) GetTxnType() TxnType {
	return TxnTypeRefundOrder
}

// ToBytes ...
func (txnData *RefundOrderMetadata) ToBytes(preSignature bool) ([]byte, error) {
	data := []byte{}

	data = append(data, txnData.OrderID[:]...)

	return data, nil
}

// FromBytes ...
func (txnData *RefundOrderMetadata) FromBytes(data []byte) error {
	if len(data) != HashSizeBytes {
		return fmt.Errorf("RefundOrderMetadata.FromBytes: Data length "+
			"%d improper length %d", len(data), HashSizeBytes)
	}
	txnData.OrderID = &BlockHash{}
	copy(txnData.OrderID[:], data[:])
	return nil
}

func (txnData *RefundOrderMetadata) New() UltranetTxnMetadata {
	return &RefundOrderMetadata{}
}

// ==================================================================
// RejectOrderMetadata
// ==================================================================

// RejectOrderMetadata ...
type RejectOrderMetadata struct {
	OrderID      *BlockHash
	RejectReason []byte
}

// GetTxnType ...
func (txnData *RejectOrderMetadata) GetTxnType() TxnType {
	return TxnTypeRejectOrder
}

// ToBytes ...
func (txnData *RejectOrderMetadata) ToBytes(preSignature bool) ([]byte, error) {
	data := []byte{}

	// OrderID
	data = append(data, txnData.OrderID[:]...)

	// RejectReason
	data = append(data, UintToBuf(uint64(len(txnData.RejectReason)))...)
	data = append(data, txnData.RejectReason...)

	return data, nil
}

// FromBytes ...
func (txnData *RejectOrderMetadata) FromBytes(data []byte) error {
	ret := RejectOrderMetadata{}
	rr := bytes.NewReader(data)

	// OrderID
	ret.OrderID = &BlockHash{}
	_, err := io.ReadFull(rr, ret.OrderID[:])
	if err != nil {
		return errors.Wrapf(err, "RejectOrderMetadata.FromBytes: Problem reading OrderID: ")
	}

	// RejectReason
	reasonLen, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "RejectOrderMetadata.FromBytes: Problem reading RejectReason length: ")
	}
	if reasonLen > MaxMessagePayload {
		return fmt.Errorf("RejectOrderMetadata.FromBytes: reasonLen length %d longer than max %d", reasonLen, MaxMessagePayload)
	}
	if reasonLen > 0 {
		ret.RejectReason = make([]byte, reasonLen)
		_, err = io.ReadFull(rr, ret.RejectReason[:])
		if err != nil {
			return errors.Wrapf(err, "RejectOrderMetadata.FromBytes: Problem reasing RejectReason: ")
		}
	}

	*txnData = ret
	return nil
}

// RejectOrderMetadata ...
func (txnData *RejectOrderMetadata) New() UltranetTxnMetadata {
	return &RejectOrderMetadata{}
}

// ==================================================================
// FulfillOrderMetadata
// ==================================================================

// FulfillOrderMetadata ...
type FulfillOrderMetadata struct {
	OrderID *BlockHash
}

// GetTxnType ...
func (txnData *FulfillOrderMetadata) GetTxnType() TxnType {
	return TxnTypeFulfillOrder
}

// ToBytes ...
func (txnData *FulfillOrderMetadata) ToBytes(preSignature bool) ([]byte, error) {
	data := []byte{}

	data = append(data, txnData.OrderID[:]...)

	return data, nil
}

// FromBytes ...
func (txnData *FulfillOrderMetadata) FromBytes(data []byte) error {
	if len(data) != HashSizeBytes {
		return fmt.Errorf("FulfillOrderMetadata.FromBytes: Data length "+
			"%d improper length %d", len(data), HashSizeBytes)
	}
	txnData.OrderID = &BlockHash{}
	copy(txnData.OrderID[:], data[:])
	return nil
}

func (txnData *FulfillOrderMetadata) New() UltranetTxnMetadata {
	return &FulfillOrderMetadata{}
}

// ==================================================================
// UpdateOrderMetadata
// ==================================================================

// UpdateMerchantMetadata ...
type UpdateMerchantMetadata struct {
	MerchantID *BlockHash

	NewPublicKey   []byte
	NewUsername    []byte
	NewDescription []byte
	// A merchant can use this txn type to burn more Ultra to improve her reputation.
	BurnAmountNanos uint64
}

// GetTxnType ...
func (txnData *UpdateMerchantMetadata) GetTxnType() TxnType {
	return TxnTypeUpdateMerchant
}

// ToBytes ...
func (txnData *UpdateMerchantMetadata) ToBytes(preSignature bool) ([]byte, error) {
	data := []byte{}
	if txnData.MerchantID == nil {
		return nil, fmt.Errorf("UpdateMerchantMetadata.ToBytes: Nil merchantID found: %v", txnData)
	}
	// MerchantID
	data = append(data, txnData.MerchantID[:]...)

	// NewPublicKey
	data = append(data, UintToBuf(uint64(len(txnData.NewPublicKey)))...)
	data = append(data, txnData.NewPublicKey...)

	// NewUsername
	data = append(data, UintToBuf(uint64(len(txnData.NewUsername)))...)
	data = append(data, txnData.NewUsername...)

	// NewDescription
	data = append(data, UintToBuf(uint64(len(txnData.NewDescription)))...)
	data = append(data, txnData.NewDescription...)

	// BurnAmountNanos
	data = append(data, UintToBuf(txnData.BurnAmountNanos)...)

	return data, nil
}

// FromBytes ...
func (txnData *UpdateMerchantMetadata) FromBytes(data []byte) error {
	ret := UpdateMerchantMetadata{}
	rr := bytes.NewReader(data)

	// MerchantID
	ret.MerchantID = &BlockHash{}
	_, err := io.ReadFull(rr, ret.MerchantID[:])
	if err != nil {
		return errors.Wrapf(err, "UpdateMerchantMetadata.FromBytes: Problem converting input txnData.MerchantID")
	}

	// NewPublicKey
	{
		pkLen, err := ReadUvarint(rr)
		if err != nil {
			return errors.Wrapf(err, "UpdateMerchantMetadata.FromBytes: Problem reading NewPublicKey length")
		}
		if pkLen != 0 {
			if pkLen != btcec.PubKeyBytesLenCompressed {
				return fmt.Errorf("UpdateMerchantMetadata.FromBytes: Public key has "+
					"invalid length %d should be %d", pkLen, btcec.PubKeyBytesLenCompressed)
			}
			ret.NewPublicKey = make([]byte, pkLen)
			_, err = io.ReadFull(rr, ret.NewPublicKey[:])
			if err != nil {
				return errors.Wrapf(err, "UpdateMerchantMetadata.FromBytes: Problem converting input txnData.NewPublicKey")
			}
		}
	}

	// NewUsername
	{
		usernameLen, err := ReadUvarint(rr)
		if err != nil {
			return errors.Wrapf(err, "UpdateMerchantMetadata.FromBytes: Problem reading NewUsername length")
		}
		if usernameLen > MaxUsernameLengthBytes {
			return fmt.Errorf("UpdateMerchantMetadata.FromBytes: NewUsername has "+
				"invalid length %d should be %d", usernameLen, MaxUsernameLengthBytes)
		}
		ret.NewUsername = make([]byte, usernameLen)
		_, err = io.ReadFull(rr, ret.NewUsername[:])
		if err != nil {
			return errors.Wrapf(err, "UpdateMerchantMetadata.FromBytes: Problem converting input txnData.NewUsername")
		}
	}

	// NewDescription
	{
		descriptionLen, err := ReadUvarint(rr)
		if err != nil {
			return errors.Wrapf(err, "UpdateMerchantMetadata.FromBytes: Problem reading NewDescription length")
		}
		if descriptionLen > MaxMerchantDescriptionLengthBytes {
			return fmt.Errorf("UpdateMerchantMetadata.FromBytes: NewDescription has "+
				"invalid length %d should be %d", descriptionLen, MaxUsernameLengthBytes)
		}
		ret.NewDescription = make([]byte, descriptionLen)
		_, err = io.ReadFull(rr, ret.NewDescription[:])
		if err != nil {
			return errors.Wrapf(err, "UpdateMerchantMetadata.FromBytes: Problem converting input txnData.NewDescription")
		}
	}

	// BurnAmountNanos
	burnAmountNanos, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "UpdateMerchantMetadata.FromBytes: Problem reading BurnAmountNanos")
	}
	ret.BurnAmountNanos = burnAmountNanos

	*txnData = ret

	return nil
}

// New ...
func (txnData *UpdateMerchantMetadata) New() UltranetTxnMetadata {
	return &UpdateMerchantMetadata{}
}

// ==================================================================
// BitcoinExchangeMetadata
// ==================================================================

// BitcoinExchangeMetadata ...
type BitcoinExchangeMetadata struct {
	// The Bitcoin transaction that sends Bitcoin to the designated burn address.
	BitcoinTransaction *wire.MsgTx
	// The hash of the Bitcoin block in which the Bitcoin transaction was mined.
	BitcoinBlockHash *BlockHash
	// The Bitcoin mekle root corresponding to the block in which the BitcoinTransaction
	// above was mined. Note that it is not strictly necessary to include this field
	// since we can look it up from the Bitcoin header if we know the BitcoinBlockHash.
	// However, having it here is convenient and allows us to do more validation prior
	// to looking up the header in the Bitcoin header chain.
	BitcoinMerkleRoot *BlockHash
	// The hash of the BitcoinTransaction above. This will be used as the starting
	// point for the Merkle proof. It is the leaf of the transaction merkle tree.
	BitcoinTransactionHash *BlockHash
	// This is a merkle proof that shows that the BitcoinTransaction above, with
	// hash equal to BitcoinTransactionHash, exists in the block with hash equal
	// to BitcoinBlockHash. This is effectively a path through a Merkle tree starting
	// from BitcoinTransactionHash as a leaf node and finishing with BitcoinMerkleRoot
	// as the root.
	BitcoinMerkleProof []*merkletree.ProofPart
}

// GetTxnType ...
func (txnData *BitcoinExchangeMetadata) GetTxnType() TxnType {
	return TxnTypeBitcoinExchange
}

// ToBytes ...
func (txnData *BitcoinExchangeMetadata) ToBytes(preSignature bool) ([]byte, error) {
	data := []byte{}

	// BitcoinTransaction
	txnBytes := bytes.Buffer{}
	if err := txnData.BitcoinTransaction.Serialize(&txnBytes); err != nil {
		return nil, errors.Wrapf(err, "BitcoinExchangeMetadata.ToBytes: Problem "+
			"serializing BitcoinTransaction: ")
	}
	data = append(data, UintToBuf(uint64(len(txnBytes.Bytes())))...)
	data = append(data, txnBytes.Bytes()...)

	// BitcoinBlockHash
	data = append(data, txnData.BitcoinBlockHash[:]...)

	// BitcoinMerkleRoot
	data = append(data, txnData.BitcoinMerkleRoot[:]...)

	// BitcoinTransactionHash
	data = append(data, txnData.BitcoinTransactionHash[:]...)

	// BitcoinMerkleProof
	//
	// Encode the number of proof parts followed by all the proof parts.
	numProofParts := uint64(len(txnData.BitcoinMerkleProof))
	data = append(data, UintToBuf(numProofParts)...)
	for _, pf := range txnData.BitcoinMerkleProof {
		// ProofParts have a specific length so no need to encode the length.
		pfBytes, err := pf.Serialize()
		if err != nil {
			return nil, errors.Wrapf(err, "BitcoinExchangeMetadata.ToBytes")
		}

		data = append(data, pfBytes...)
	}

	return data, nil
}

// FromBytes ...
func (txnData *BitcoinExchangeMetadata) FromBytes(data []byte) error {
	ret := BitcoinExchangeMetadata{}
	rr := bytes.NewReader(data)

	// BitcoinTransaction
	txnBytesLen, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "BitcoinExchangeMetadata.FromBytes: Problem "+
			"decoding BitcoinTransaction length")
	}
	if txnBytesLen > MaxMessagePayload {
		return fmt.Errorf("BitcoinExchangeMetadata.FromBytes: txnBytesLen %d "+
			"exceeds max %d", txnBytesLen, MaxMessagePayload)
	}
	txnBytes := make([]byte, txnBytesLen)
	_, err = io.ReadFull(rr, txnBytes)
	if err != nil {
		return fmt.Errorf("BitcoinExchangeMetadata.FromBytes: Error reading txnBytes: %v", err)
	}
	ret.BitcoinTransaction = &wire.MsgTx{}
	err = ret.BitcoinTransaction.Deserialize(bytes.NewBuffer(txnBytes))
	if err != nil {
		return errors.Wrapf(err, "BitcoinExchangeMetadata.FromBytes: Problem parsing txnBytes: ")
	}

	// BitcoinBlockHash
	ret.BitcoinBlockHash = &BlockHash{}
	_, err = io.ReadFull(rr, ret.BitcoinBlockHash[:])
	if err != nil {
		return errors.Wrapf(err, "BitcoinExchangeMetadata.FromBytes: Problem reading BitcoinBlockHash: ")
	}

	// BitcoinMerkleRoot
	ret.BitcoinMerkleRoot = &BlockHash{}
	_, err = io.ReadFull(rr, ret.BitcoinMerkleRoot[:])
	if err != nil {
		return errors.Wrapf(err, "BitcoinExchangeMetadata.FromBytes: Problem reading BitcoinMerkleRoot: ")
	}

	// BitcoinTransactionHash
	ret.BitcoinTransactionHash = &BlockHash{}
	_, err = io.ReadFull(rr, ret.BitcoinTransactionHash[:])
	if err != nil {
		return errors.Wrapf(err, "BitcoinExchangeMetadata.FromBytes: Problem reading BitcoinTransactionHash: ")
	}

	// BitcoinMerkleProof
	numProofParts, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "BitcoinExchangeMetadata.FromBytes: Problem reading numProofParts: ")
	}
	for ii := uint64(0); ii < numProofParts; ii++ {
		pfBytes := make([]byte, merkletree.ProofPartSerializeSize)
		_, err = io.ReadFull(rr, pfBytes[:])
		if err != nil {
			return errors.Wrapf(err, "BitcoinExchangeMetadata.FromBytes: Problem reading ProofPart %d: ", ii)
		}
		pf := &merkletree.ProofPart{}
		if err := pf.Deserialize(pfBytes); err != nil {
			return errors.Wrapf(err, "BitcoinExchangeMetadata.FromBytes: Problem parsing ProofPart %d: ", ii)
		}

		ret.BitcoinMerkleProof = append(ret.BitcoinMerkleProof, pf)
	}

	*txnData = ret

	return nil
}

// New ...
func (txnData *BitcoinExchangeMetadata) New() UltranetTxnMetadata {
	return &BitcoinExchangeMetadata{}
}

// ==================================================================
// PrivateMessageMetadata
//
// A private message is a message from one user on the platform to
// another user on the platform. It is generally treated as a normal
// transaction would be except that the public key of the top-level
// MsgUltranetTxn is assumed to be the sender of the message and the
// metadata contains a messange encrypted with the receiver's public
// key.
// ==================================================================

// PrivateMessageMetadata ...
type PrivateMessageMetadata struct {
	// The sender of the message is assumed to be the originator of the
	// top-level transaction.

	// The public key of the recipient of the message.
	RecipientPublicKey []byte

	// The content of the message. It is encrypted with the recipient's
	// public key using ECIES.
	EncryptedText []byte

	// A timestamp used for ordering messages when displaying them to
	// users. The timestamp must be unique. Note that we use a nanosecond
	// timestamp because it makes it easier to deal with the uniqueness
	// constraint technically (e.g. If one second spacing is required
	// as would be the case with a standard Unix timestamp then any code
	// that generates these transactions will need to potentially wait
	// or else risk a timestamp collision. This complexity is avoided
	// by just using a nanosecond timestamp). Note that the timestamp is
	// an unsigned int as opposed to a signed int, which means times
	// before the zero time are not represented which doesn't matter
	// for our purposes. Restricting the timestamp in this way makes
	// lexicographic sorting based on bytes easier in our database which
	// is one of the reasons we do it.
	TimestampNanos uint64
}

// GetTxnType ...
func (txnData *PrivateMessageMetadata) GetTxnType() TxnType {
	return TxnTypePrivateMessage
}

// ToBytes ...
func (txnData *PrivateMessageMetadata) ToBytes(preSignature bool) ([]byte, error) {
	// Validate the metadata before encoding it.
	//
	// Public key must be included and must have the expected length.
	if len(txnData.RecipientPublicKey) != btcec.PubKeyBytesLenCompressed {
		return nil, fmt.Errorf("PrivateMessageMetadata.ToBytes: RecipientPublicKey "+
			"has length %d != %d", len(txnData.RecipientPublicKey), btcec.PubKeyBytesLenCompressed)
	}

	data := []byte{}

	// RecipientPublicKey
	//
	// We know the public key is set and has the expected length so we don't need
	// to encode the length here.
	data = append(data, txnData.RecipientPublicKey...)

	// EncryptedText
	data = append(data, UintToBuf(uint64(len(txnData.EncryptedText)))...)
	data = append(data, txnData.EncryptedText...)

	// TimestampNanos
	data = append(data, UintToBuf(txnData.TimestampNanos)...)

	return data, nil
}

// FromBytes ...
func (txnData *PrivateMessageMetadata) FromBytes(data []byte) error {
	ret := PrivateMessageMetadata{}
	rr := bytes.NewReader(data)

	// RecipientPublicKey
	ret.RecipientPublicKey = make([]byte, btcec.PubKeyBytesLenCompressed)
	_, err := io.ReadFull(rr, ret.RecipientPublicKey)
	if err != nil {
		return fmt.Errorf("PrivateMessageMetadata.FromBytes: Error reading RecipientPublicKey: %v", err)
	}

	// EncryptedText
	encryptedTextLen, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "PrivateMessageMetadata.FromBytes: Problem "+
			"decoding EncryptedText length")
	}
	if encryptedTextLen > MaxMessagePayload {
		return fmt.Errorf("PrivateMessageMetadata.FromBytes: encryptedTextLen %d "+
			"exceeds max %d", encryptedTextLen, MaxMessagePayload)
	}
	ret.EncryptedText = make([]byte, encryptedTextLen)
	_, err = io.ReadFull(rr, ret.EncryptedText)
	if err != nil {
		return fmt.Errorf("PrivateMessageMetadata.FromBytes: Error reading EncryptedText: %v", err)
	}

	// TimestampNanos
	ret.TimestampNanos, err = ReadUvarint(rr)
	if err != nil {
		return fmt.Errorf("PrivateMessageMetadata.FromBytes: Error reading TimestampNanos: %v", err)
	}

	*txnData = ret

	return nil
}

// New ...
func (txnData *PrivateMessageMetadata) New() UltranetTxnMetadata {
	return &PrivateMessageMetadata{}
}
