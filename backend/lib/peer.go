package lib

import (
	"fmt"
	"math"
	"net"
	"sync/atomic"
	"time"

	"github.com/btcsuite/btcd/wire"
	"github.com/golang/glog"
	"github.com/pkg/errors"
	"github.com/sasha-s/go-deadlock"
)

// peer.go defines an interface for connecting to and managing an Ultranet
// peer. Each peer a node is connected to is represented by a Peer object,
// and the Peer object is how messages are sent and received to/from the
// peer. A good place to start is inHandler and outHandler in this file.

// ExpectedResponse is a struct used to enforce timeouts on peers. For example,
// if we send a GetBlocks message, we would expect a response within a given
// window and disconnect from the Peer if we don't get that response.
type ExpectedResponse struct {
	TimeExpected time.Time
	MessageType  MsgType
}

// Peer is an object that holds all of the state for a connection to another node.
// Any communication with other nodes happens via this object, which maintains a
// queue of messages to send to the other node.
type Peer struct {
	// These stats should be accessed atomically.
	bytesReceived uint64
	bytesSent     uint64
	totalMessages uint64
	lastRecv      int64
	lastSend      int64

	// Stats that should be accessed using the mutex below.
	StatsMtx       deadlock.RWMutex
	timeOffsetSecs int64
	timeConnected  time.Time
	startingHeight uint32
	ID             uint64
	// Ping-related fields.
	LastPingNonce  uint64
	LastPingTime   time.Time
	LastPingMicros int64

	// Connection info.
	cmgr                *ConnectionManager
	conn                net.Conn
	isOutbound          bool
	isPersistent        bool
	stallTimeoutSeconds uint64
	// A hack to make it so that we can allow an API endpoint to manually
	// delete a peer.
	peerManuallyRemovedFromConnectionManager bool

	// In order to complete a version negotiation successfully, the peer must
	// reply to the initial version message we send them with a verack message
	// containing the nonce from that initial version message. This ensures that
	// the peer's IP isn't being spoofed since the only way to actually produce
	// a verack with the appropriate response is to actually own the IP that
	// the peer claims it has. As such, we maintain the version nonce we sent
	// the peer and the version nonce they sent us here.
	//
	// TODO: The way we synchronize the version nonce is currently a bit
	// messy; ideally we could do it without keeping global state.
	versionNonceSent     uint64
	versionNonceReceived uint64

	// A pointer to the Server
	srv *Server

	// Basic state.
	PeerInfoMtx               deadlock.Mutex
	serviceFlags              ServiceFlag
	addrStr                   string
	netAddr                   *wire.NetAddress
	jsonAPIPort               uint16
	userAgent                 string
	advertisedProtocolVersion uint64
	negotiatedProtocolVersion uint64
	versionNegotiated         bool
	minTxFeeRateNanosPerKB    uint64
	// Messages for which we are expecting a reply within a fixed
	// amount of time. This list is always sorted by ExpectedTime,
	// with the item having the earliest time at the front.
	expectedResponses []*ExpectedResponse

	// The addresses this peer is aware of.
	knownAddressMapLock deadlock.RWMutex
	knownAddressesmap   map[string]bool

	// Output queue for messages that need to be sent to the peer.
	outputQueue chan UltranetMessage

	// Set to zero until Disconnect has been called on the Peer. Used to make it
	// so that the logic in Disconnect will only be executed once.
	disconnected int32
	// Signals that the peer is now in the stopped state.
	quit chan interface{}

	// Each Peer is only allowed to have certain number of blocks being sent
	// to them at any gven time. We use
	// this value to enforce that constraint. The reason we need to do this is without
	// it one peer could theoretically clog our Server by issuing many GetBlocks
	// requests that ultimately don't get delivered. This way the number of blocks
	// being sent is limited to a multiple of the number of Peers we have.
	blocksToSendMtx deadlock.Mutex
	blocksToSend    map[BlockHash]bool

	// Inventory stuff.
	// The inventory that we know the peer already has.
	knownInventory *mruInventoryMap
}

// NewPeer creates a new Peer object.
func NewPeer(_conn net.Conn, _isOutbound bool, _netAddr *wire.NetAddress,
	_isPersistent bool, _stallTimeoutSeconds uint64, _minFeeRateNanosPerKB uint64,
	_cmgr *ConnectionManager, _srv *Server) *Peer {

	pp := Peer{
		cmgr:                   _cmgr,
		srv:                    _srv,
		conn:                   _conn,
		addrStr:                _conn.RemoteAddr().String(),
		netAddr:                _netAddr,
		isOutbound:             _isOutbound,
		isPersistent:           _isPersistent,
		ID:                     atomic.AddUint64(&_cmgr.peerIndex, 1),
		outputQueue:            make(chan UltranetMessage),
		quit:                   make(chan interface{}),
		knownInventory:         newMruInventoryMap(maxKnownInventory),
		blocksToSend:           make(map[BlockHash]bool),
		stallTimeoutSeconds:    _stallTimeoutSeconds,
		minTxFeeRateNanosPerKB: _minFeeRateNanosPerKB,
		knownAddressesmap:      make(map[string]bool),
	}

	// TODO: Before, we would give each Peer its own Logger object. Now we
	// have a much better way of debugging which is that we include a nonce
	// in all messages related to a Peer (i.e. PeerID=%d) that allows us to
	// pipe the output to a file and inspect it (and if we choose to filter on
	// a PeerID= then we can see exclusively that Peer's related messages).
	// Still, we're going to leave this logic here for a little while longer in
	// case a situation arises where commenting it in seems like it would be
	// useful.
	//
	// Each peer gets its own log directory. Name the directory with
	// IP:PORT_ID to ensure it's identifiable but also unique. The higher
	// the ID the more recently the peer connection was established.
	/*
		logDir := fmt.Sprintf("%s.%05d_%d.log", addrmgr.NetAddressKey(_netAddr), pp.ID, time.Now().UnixNano())
		resetLogDir := false
		pp.Logger = glog.NewLogger(logDir, resetLogDir)
		// Don't log peer information to stderr.
		pp.Logger.AlsoToStderr = false
	*/
	return &pp
}

// MinFeeRateNanosPerKB returns the minimum fee rate this peer requires in order to
// accept transactions into its mempool. We should generally not send a peer a
// transaction below this fee rate.
func (pp *Peer) MinFeeRateNanosPerKB() uint64 {
	pp.StatsMtx.RLock()
	defer pp.StatsMtx.RUnlock()

	return pp.minTxFeeRateNanosPerKB
}

// StartingBlockHeight is the height of the peer's blockchain tip.
func (pp *Peer) StartingBlockHeight() uint32 {
	pp.StatsMtx.RLock()
	defer pp.StatsMtx.RUnlock()
	return pp.startingHeight
}

// PushInvVect enqueues an inventory vector to be sent to the peer.
func (pp *Peer) PushInvVect(invVect *InvVect, maxInvPerMsg int) {
	pp.PushInvMsg(&MsgUltranetInv{
		InvList: []*InvVect{invVect},
	}, maxInvPerMsg)
}

func (pp *Peer) _filterInvMsg(invMsg *MsgUltranetInv) *MsgUltranetInv {
	filteredInvMsg := &MsgUltranetInv{
		// Preserve the value of this field.
		IsSyncResponse: invMsg.IsSyncResponse,
	}
	for _, invVect := range invMsg.InvList {
		if !pp.knownInventory.Exists(invVect) {
			filteredInvMsg.InvList = append(filteredInvMsg.InvList, invVect)
		}
	}

	return filteredInvMsg
}

func _breakUpInvMsg(invMsg *MsgUltranetInv, maxInvPerMsg int) []*MsgUltranetInv {
	brokenUpInvs := []*MsgUltranetInv{}

	for len(invMsg.InvList) > maxInvPerMsg {
		smallInvMsg := &MsgUltranetInv{
			// Preserve the value of this field.
			IsSyncResponse: invMsg.IsSyncResponse,
		}
		smallInvMsg.InvList = invMsg.InvList[:maxInvPerMsg]
		invMsg.InvList = invMsg.InvList[maxInvPerMsg:]

		brokenUpInvs = append(brokenUpInvs, smallInvMsg)
	}

	// If we get here we might have some messages left.
	// Don't queue anything if the inv list is empty after filtering.
	if len(invMsg.InvList) > 0 {
		brokenUpInvs = append(brokenUpInvs, invMsg)
	}

	return brokenUpInvs
}

// Lack of generics is killing us here...
func _breakUpHashes(hashList []*BlockHash, maxHashesPerList int) [][]*BlockHash {
	brokenUpHashes := [][]*BlockHash{}

	for len(hashList) > maxHashesPerList {
		brokenUpHashes = append(brokenUpHashes, hashList[:maxHashesPerList])
		hashList = hashList[maxHashesPerList:]
	}

	// If we get here we might have some messages left.
	// Don't queue anything if the inv list is empty after filtering.
	if len(hashList) > 0 {
		brokenUpHashes = append(brokenUpHashes, hashList)
	}

	return brokenUpHashes
}

// PushInvMsg enqueues an InvMsg to be sent to the peer.
func (pp *Peer) PushInvMsg(invMsg *MsgUltranetInv, maxInvPerMsg int) {
	// Filter out the inventory that the peer already has. This is a minor
	// optimization to avoid having large amounts of inventory queued up.
	filteredInvMsg := pp._filterInvMsg(invMsg)

	// Break up the filtered message and send each piece.
	for _, brokenUpInv := range _breakUpInvMsg(filteredInvMsg, maxInvPerMsg) {
		//glog.Tracef("Peer.PushInvMsg: Enqueuing message: %v", spew.Sdump(brokenUpInv))
		pp.QueueMessage(brokenUpInv)
	}
}

// PushTransactionBundleMsg enqueues a transaction bundle to be sent to the peer.
// It's the caller's responsibility to make sure the message doesn't have
// too many transactions in it.
func (pp *Peer) PushTransactionBundleMsg(res *MsgUltranetTransactionBundle) {
	pp.QueueMessage(res)
}

// PushListingBundleMsg enqueues a listing bundle message to be sent to the peer.
// It's the caller's responsibility to make sure the message doesn't have
// too many transactions in the response.
func (pp *Peer) PushListingBundleMsg(res *MsgUltranetListingBundle) {
	pp.QueueMessage(res)
}

// PushHeaderBundlesMsg ...
func (pp *Peer) PushHeaderBundlesMsg(headers []*MsgUltranetHeader, tipHash *BlockHash, tipHeight uint32) {
	pp.QueueMessage(&MsgUltranetHeaderBundle{
		Headers:   headers,
		TipHash:   tipHash,
		TipHeight: tipHeight,
	})
}

// PushGetHeadersMsg ...
func (pp *Peer) PushGetHeadersMsg(blockLocator []*BlockHash, stopHash *BlockHash) {
	// Construct the GetHeaders message.
	getHeadersMsg := &MsgUltranetGetHeaders{
		StopHash:     stopHash,
		BlockLocator: blockLocator,
	}

	// Put it onto the outputQueue.
	pp.QueueMessage(getHeadersMsg)
}

// PushGetTransactionsMsg ...
func (pp *Peer) PushGetTransactionsMsg(txHashes []*BlockHash) {
	if len(txHashes) == 0 {
		// If there are no transactions to fetch then do nothing.
		glog.Debugf("Peer.PushGetTransactionsMsg: No txHashes from Peer %v", pp)
		return
	}

	for _, hashList := range _breakUpHashes(txHashes, MaxTxnsPerGetTransactionsMsg) {
		glog.Debugf("Peer.PushGetTransactionsMsg: Enqueuing txHashes: %v for Peer %v", hashList, pp)
		pp.QueueMessage(&MsgUltranetGetTransactions{
			HashList: hashList,
		})
	}
}

// PushGetListingsMsg ...
func (pp *Peer) PushGetListingsMsg(listingHashes []*BlockHash) {
	if len(listingHashes) == 0 {
		// If there are no listings to fetch then do nothing.
		glog.Debugf("Peer.PushGetListingsMsg: No listingHashes from Peer %v", pp)
		return
	}

	for _, hashList := range _breakUpHashes(listingHashes, MaxListingsPerGetListingsMsg) {
		glog.Debugf("Peer.PushGetListingsMsg: Enqueuing listingHashes: %v for Peer %v", hashList, pp)
		pp.QueueMessage(&MsgUltranetGetListings{
			HashList: hashList,
		})
	}
}

// PushGetBlocksMsg ...
func (pp *Peer) PushGetBlocksMsg(blockHashesToFetch []*BlockHash) {
	// Construct the GetData message and put it onto the outputQueue.
	pp.QueueMessage(&MsgUltranetGetBlocks{
		HashList: blockHashesToFetch,
	})
}

// NumBlocksToSend is the number of blocks the Peer has requested from
// us that we have yet to send them.
func (pp *Peer) NumBlocksToSend() uint32 {
	pp.blocksToSendMtx.Lock()
	defer pp.blocksToSendMtx.Unlock()

	return uint32(len(pp.blocksToSend))
}

// PushBlockMsg ...
func (pp *Peer) PushBlockMsg(blk *MsgUltranetBlock) {
	pp.QueueMessage(blk)
}

const (
	// maxKnownInventory is the maximum number of items to keep in the known
	// inventory cache.
	maxKnownInventory = 1000

	// pingInterval is the interval of time to wait in between sending ping
	// messages.
	pingInterval = 2 * time.Minute

	// idleTimeout is the duration of inactivity before we time out a peer.
	idleTimeout = 5 * time.Minute
)

// handlePingMsg is invoked when a peer receives a ping message. It replies with a pong
// message.
func (pp *Peer) handlePingMsg(msg *MsgUltranetPing) {
	// Include nonce from ping so pong can be identified.
	glog.Tracef("Peer.handlePingMsg: Received ping from peer %v: %v", pp, msg)
	// Queue up a pong message.
	pp.QueueMessage(&MsgUltranetPong{Nonce: msg.Nonce})
}

// handlePongMsg is invoked when a peer receives a pong message.  It
// updates the ping statistics.
func (pp *Peer) handlePongMsg(msg *MsgUltranetPong) {
	// Arguably we could use a buffered channel here sending data
	// in a fifo manner whenever we send a ping, or a list keeping track of
	// the times of each ping. For now we just make a best effort and
	// only record stats if it was for the last ping sent. Any preceding
	// and overlapping pings will be ignored. It is unlikely to occur
	// without large usage of the ping call since we ping infrequently
	// enough that if they overlap we would have timed out the peer.
	glog.Tracef("Peer.handlePongMsg: Received pong from peer %v: %v", msg, pp)
	pp.StatsMtx.Lock()
	defer pp.StatsMtx.Unlock()
	if pp.LastPingNonce != 0 && msg.Nonce == pp.LastPingNonce {
		pp.LastPingMicros = time.Since(pp.LastPingTime).Nanoseconds()
		pp.LastPingMicros /= 1000 // convert to usec.
		pp.LastPingNonce = 0
		glog.Tracef("Peer.handlePongMsg: LastPingMicros(%d) from Peer %v", pp.LastPingMicros, pp)
	}
}

func (pp *Peer) pingHandler() {
	glog.Debugf("Peer.pingHandler: Starting ping handler for Peer %v", pp)
	pingTicker := time.NewTicker(pingInterval)
	defer pingTicker.Stop()

out:
	for {
		select {
		case <-pingTicker.C:
			glog.Tracef("Peer.pingHandler: Initiating ping for Peer %v", pp)
			nonce, err := wire.RandomUint64()
			if err != nil {
				glog.Errorf("Not sending ping to Peer %v: %v", pp, err)
				continue
			}
			// Update the ping stats when we initiate a ping.
			//
			// TODO: Setting LastPingTime here means that we're technically measuring the time
			// between *queueing* the ping and when we receive a pong vs the time between when
			// a ping is actually sent and when the pong is received. To fix it we'd have to
			// detect a ping message in the outHandler and set the stats there instead.
			pp.StatsMtx.Lock()
			pp.LastPingNonce = nonce
			pp.LastPingTime = time.Now()
			pp.StatsMtx.Unlock()
			// Queue the ping message to be sent.
			pp.QueueMessage(&MsgUltranetPing{Nonce: nonce})

		case <-pp.quit:
			break out
		}
	}
}

// String ...
func (pp *Peer) String() string {
	isDisconnected := ""
	if pp.disconnected != 0 {
		isDisconnected = ", DISCONNECTED"
	}
	return fmt.Sprintf("[Peer: < PeerID=%d Remote Address: %v%s, "+
		"Blocks Being Sent: %d >]", pp.ID, pp.addrStr, isDisconnected, len(pp.blocksToSend))
}

// Connected ...
func (pp *Peer) Connected() bool {
	return atomic.LoadInt32(&pp.disconnected) == 0
}

// QueueMessage ...
func (pp *Peer) QueueMessage(ultranetMessage UltranetMessage) {
	// If the peer is disconnected, don't queue anything.
	if !pp.Connected() {
		return
	}

	pp.outputQueue <- ultranetMessage
	return
}

func (pp *Peer) _handleOutExpectedResponse(msg UltranetMessage) {
	pp.PeerInfoMtx.Lock()
	defer pp.PeerInfoMtx.Unlock()

	// If we're sending the peer a GetBlocks message, we expect to receive the
	// blocks at minimum within a few seconds of each other.
	stallTimeout := time.Duration(int64(pp.stallTimeoutSeconds) * int64(time.Second))
	if msg.GetMsgType() == MsgTypeGetBlocks {
		getBlocks := msg.(*MsgUltranetGetBlocks)
		// We have one block expected for each entry in the message.
		for ii := range getBlocks.HashList {
			pp._addExpectedResponse(&ExpectedResponse{
				TimeExpected: time.Now().Add(
					stallTimeout + time.Duration(int64(ii)*int64(stallTimeout))),
				MessageType: MsgTypeBlock,
			})
		}
	}

	// If we're sending a GetHeaders message, the Peer should respond within
	// a few seconds with a HeaderBundle.
	if msg.GetMsgType() == MsgTypeGetHeaders {
		pp._addExpectedResponse(&ExpectedResponse{
			TimeExpected: time.Now().Add(stallTimeout),
			MessageType:  MsgTypeHeaderBundle,
		})
	}

	// If we're sending a GetTransactions message, the Peer should respond within
	// a few seconds with a TransactionBundle. Every GetTransactions message should
	// receive a TransactionBundle in response. The
	// Server handles situations in which we request certain hashes but only get
	// back a subset of them in the response (i.e. a case in which we received a
	// timely reply but the reply was incomplete).
	if msg.GetMsgType() == MsgTypeGetTransactions {
		pp._addExpectedResponse(&ExpectedResponse{
			TimeExpected: time.Now().Add(stallTimeout),
			MessageType:  MsgTypeTransactionBundle,
			// The Server handles situations in which the Peer doesn't send us all of
			// the hashes we were expecting using timeouts on requested hashes.
		})
	}

	// Every GetListings message should be replied to with a ListingBundle message.
	// If we don't get the latter in a timely manner we disconnect the Peer. The
	// Server handles situations in which we request certain hashes but only get
	// back a subset of them in the response (i.e. a case in which we received a
	// timely reply but the reply was incomplete).
	if msg.GetMsgType() == MsgTypeGetListings {
		pp._addExpectedResponse(&ExpectedResponse{
			TimeExpected: time.Now().Add(stallTimeout),
			MessageType:  MsgTypeListingBundle,
		})
	}
}

func (pp *Peer) _filterAddrMsg(addrMsg *MsgUltranetAddr) *MsgUltranetAddr {
	pp.knownAddressMapLock.Lock()
	defer pp.knownAddressMapLock.Unlock()

	filteredAddrMsg := &MsgUltranetAddr{}
	for _, addr := range addrMsg.AddrList {
		if _, hasAddr := pp.knownAddressesmap[addr.String(false /*includePort*/)]; hasAddr {
			continue
		}

		// If we get here this is an address the peer hasn't seen before so
		// don't filter it out. Also add it to the known address map.
		filteredAddrMsg.AddrList = append(filteredAddrMsg.AddrList, addr)
		pp.knownAddressesmap[addr.String(false /*includePort*/)] = true
	}

	return filteredAddrMsg
}

func (pp *Peer) _setKnownAddressesMap(key string, val bool) {
	pp.knownAddressMapLock.Lock()
	defer pp.knownAddressMapLock.Unlock()

	pp.knownAddressesmap[key] = val
}

func (pp *Peer) outHandler() {
	glog.Debugf("Peer.outHandler: Starting outHandler for Peer %v", pp)
	stallTicker := time.NewTicker(time.Second)
out:
	for {
		select {
		case msg := <-pp.outputQueue:
			// Wire up the responses we expect from the Peer depending on what
			// type of message it is.
			pp._handleOutExpectedResponse(msg)

			if msg.GetMsgType() == MsgTypeInv {
				invMsg := msg.(*MsgUltranetInv)
				// If the message is an inv then filter out the peer's known inventory
				// before sending. Note we do this when we initially queue the inv, but
				// we do it again here because the peer could have sent something between
				// when the inv was queued and now.
				filteredInvMsg := pp._filterInvMsg(invMsg)
				glog.Tracef("Peer.outHandler: Filtered inv message: %v for Peer %v", filteredInvMsg, pp)

				if len(filteredInvMsg.InvList) == 0 {
					// Don't send anything if the inv list is empty after filtering.
					continue
				}

				// Add the new inventory to the peer's knownInventory.
				for _, invVect := range filteredInvMsg.InvList {
					pp.knownInventory.Add(invVect)
				}

				msg = filteredInvMsg
			}

			// If we're sending a block, remove it from our blocksToSend map to allow
			// the peer to request more blocks after receiving this one.
			if msg.GetMsgType() == MsgTypeBlock {
				pp.blocksToSendMtx.Lock()
				hash, _ := msg.(*MsgUltranetBlock).Hash()
				delete(pp.blocksToSend, *hash)
				pp.blocksToSendMtx.Unlock()
			}

			// Before we send an addr message to the peer, filter out the addresses
			// the peer is already aware of.
			if msg.GetMsgType() == MsgTypeAddr {
				msg = pp._filterAddrMsg(msg.(*MsgUltranetAddr))

				// Don't send anything if we managed to filter out all the addresses.
				if len(msg.(*MsgUltranetAddr).AddrList) == 0 {
					continue
				}
			}

			// If we have a problem sending a message to a peer then disconnect them.
			if err := pp.WriteUltranetMessage(msg); err != nil {
				glog.Errorf("Peer.outHandler: Problem sending message to peer: %v: %v", pp, err)
				pp.Disconnect()
			}
		case <-stallTicker.C:
			// Every second take a look to see if there's something that the peer should
			// have responded to that they're delinquent on. If there is then error and
			// disconnect the Peer.
			if len(pp.expectedResponses) == 0 {
				// If there are no expected responses, nothing to do.
				continue
			}
			// The expected responses are sorted by when the corresponding requests were
			// made. As such, if the first entry is not past the deadline then nothing is.
			firstEntry := pp.expectedResponses[0]
			nowTime := time.Now()
			if nowTime.After(firstEntry.TimeExpected) {
				glog.Errorf("Peer.outHandler: Peer %v took too long to response to "+
					"reqest. Expected MsgType=%v at time %v but it is now time %v",
					pp, firstEntry.MessageType, firstEntry.TimeExpected, nowTime)
				pp.Disconnect()
			}

		case <-pp.quit:
			break out
		}
	}

	glog.Debugf("Peer.outHandler: Quitting outHandler for Peer %v", pp)
}

func (pp *Peer) _maybeAddBlocksToSend(msg UltranetMessage) error {
	// If the input is not a GetBlocks message, don't do anything.
	if msg.GetMsgType() != MsgTypeGetBlocks {
		return nil
	}

	// At this point, we're sure this is a GetBlocks message. Acquire the
	// blocksToSend mutex and cast the message.
	pp.blocksToSendMtx.Lock()
	defer pp.blocksToSendMtx.Unlock()
	getBlocks := msg.(*MsgUltranetGetBlocks)

	// When blocks have been requested, add them to the list of blocks we're
	// in the process of sending to the Peer.
	for _, hash := range getBlocks.HashList {
		pp.blocksToSend[*hash] = true
	}

	// If the peer has exceeded the number of blocks she is allowed to request
	// then disconnect her.
	if len(pp.blocksToSend) > MaxBlocksInFlight {
		pp.Disconnect()
		return fmt.Errorf("_maybeAddBlocksToSend: Disconnecting peer %v because she requested %d "+
			"blocks, which is more than the %d blocks allowed "+
			"in flight", pp, len(pp.blocksToSend), MaxBlocksInFlight)
	}

	return nil
}

func (pp *Peer) _removeEarliestExpectedResponse(msgType MsgType) *ExpectedResponse {
	pp.PeerInfoMtx.Lock()
	defer pp.PeerInfoMtx.Unlock()

	// Just remove the first instance we find of the passed-in message
	// type and return.
	for ii, res := range pp.expectedResponses {
		if res.MessageType == msgType {
			// We found the first occurrence of the message type so remove
			// that message since we're no longer waiting on it.
			left := append([]*ExpectedResponse{}, pp.expectedResponses[:ii]...)
			pp.expectedResponses = append(left, pp.expectedResponses[ii+1:]...)

			// Return so we stop processing.
			return res
		}
	}

	return nil
}

func (pp *Peer) _addExpectedResponse(item *ExpectedResponse) {
	if len(pp.expectedResponses) == 0 {
		pp.expectedResponses = []*ExpectedResponse{item}
		return
	}

	// Usually the item will need to be added at the end so start
	// from there.
	index := len(pp.expectedResponses)
	for index > 0 &&
		pp.expectedResponses[index-1].TimeExpected.After(item.TimeExpected) {

		index--
	}

	left := append([]*ExpectedResponse{}, pp.expectedResponses[:index]...)
	right := pp.expectedResponses[index:]
	pp.expectedResponses = append(append(left, item), right...)
	return
}

func (pp *Peer) _handleInExpectedResponse(rmsg UltranetMessage) error {
	// Let the Peer off the hook if the response is one we were waiting for.
	// Do this in a separate switch to keep things clean.
	msgType := rmsg.GetMsgType()
	if msgType == MsgTypeBlock ||
		msgType == MsgTypeHeaderBundle ||
		msgType == MsgTypeTransactionBundle ||
		msgType == MsgTypeListingBundle {

		expectedResponse := pp._removeEarliestExpectedResponse(msgType)
		if expectedResponse == nil {
			// We should never get one of these types of messages unless we've previously
			// requested it so disconnect the Peer in this case.
			errRet := fmt.Errorf("_handleInExpectedResponse: Received unsolicited message "+
				"of type %v %v from peer %v -- disconnecting", msgType, rmsg, pp)
			glog.Debugf(errRet.Error())
			return errRet
		}
		// If we get here then we managed to dequeue a message we were
		// expecting, which is good.
	}

	return nil
}

// inHandler handles all incoming messages for the peer. It must be run as a
// goroutine.
func (pp *Peer) inHandler() {
	glog.Debugf("Peer.inHandler: Starting inHandler for Peer %v", pp)

	// The timer is stopped when a new message is received and reset after it
	// is processed.
	idleTimer := time.AfterFunc(idleTimeout, func() {
		glog.Debugf("Peer.inHandler: Peer %v no answer for %v -- disconnecting", pp, idleTimeout)
		pp.Disconnect()
	})

out:
	for {
		// Read a message and stop the idle timer as soon as the read
		// is done. The timer is reset below for the next iteration if
		// needed.
		rmsg, err := pp.ReadUltranetMessage()
		idleTimer.Stop()
		if err != nil {
			glog.Errorf("Peer.inHandler: Can't read message from peer %v: %v", pp, err)

			break out
		}

		// Adjust what we expect our Peer to send us based on what we're now
		// receiving with this message.
		if err := pp._handleInExpectedResponse(rmsg); err != nil {
			break out
		}

		// If we get an addr message, add all of the addresses to the known addresses
		// for the peer.
		if rmsg.GetMsgType() == MsgTypeAddr {
			addrMsg := rmsg.(*MsgUltranetAddr)
			for _, addr := range addrMsg.AddrList {
				pp._setKnownAddressesMap(addr.String(false /*includePort*/), true)
			}
		}

		// If we receive a control message from a Peer then that Peer is misbehaving
		// and we should disconnect. Control messages should never originate from Peers.
		if IsControlMessage(rmsg.GetMsgType()) {
			glog.Errorf("Peer.inHandler: Received control message of type %v from "+
				"Peer %v; this should never happen. Disconnecting the Peer", rmsg.GetMsgType(), pp)
			break out
		}

		// Potentially adjust blocksToSend to account for blocks the Peer is
		// currently requesting from us. Disconnect the Peer if she's requesting too many
		// blocks now.
		if err := pp._maybeAddBlocksToSend(rmsg); err != nil {
			glog.Errorf(err.Error())
			break out
		}

		// This switch actually processes the message. For most messages, we just
		// pass them onto the Server.
		switch msg := rmsg.(type) {
		case *MsgUltranetVersion:
			// We always receive the VERSION from the Peer before starting this select
			// statement, so getting one here is an error.

			glog.Errorf("Peer.inHandler: Already received 'version' from peer %v -- disconnecting", pp)
			break out

		case *MsgUltranetVerack:
			// We always receive the VERACK from the Peer before starting this select
			// statement, so getting one here is an error.

			glog.Debugf("Peer.inHandler: Already received 'verack' from peer %v -- disconnecting", pp)
			break out

		case *MsgUltranetPing:
			// Respond to a ping with a pong.
			pp.handlePingMsg(msg)

		case *MsgUltranetPong:
			// Measure the ping time when we receive a pong.
			pp.handlePongMsg(msg)

		case *MsgUltranetNewPeer, *MsgUltranetDonePeer, *MsgUltranetBlockMainChainConnected,
			*MsgUltranetBlockMainChainDisconnected, *MsgUltranetBlockAccepted,
			*MsgUltranetBitcoinManagerUpdate, *MsgUltranetQuit:

			// We should never receive control messages from a Peer. Disconnect if we do.
			glog.Debugf("Peer.inHandler: Received control message of type %v from "+
				"Peer %v which should never happen -- disconnecting", msg.GetMsgType(), pp)
			break out

		default:
			// All other messages just forward back to the Server to handle them.
			glog.Tracef("Peer.inHandler: Received message of type %v from %v", rmsg.GetMsgType(), pp)
			pp.cmgr.serverMessageQueue <- &ServerMessage{
				Peer: pp,
				Msg:  msg,
			}
		}

		// A message was received so reset the idle timer.
		idleTimer.Reset(idleTimeout)
	}

	// Ensure the idle timer is stopped to avoid leaking the resource.
	idleTimer.Stop()

	// Disconnect the Peer if it isn't already.
	pp.Disconnect()

	glog.Debugf("Peer.inHandler: done for peer: %v", pp)
}

// Start ...
func (pp *Peer) Start() {
	glog.Infof("Peer.Start: Starting peer %v", pp)
	// The protocol has been negotiated successfully so start processing input
	// and output messages.
	go pp.pingHandler()
	go pp.outHandler()
	go pp.inHandler()

	// If the address manager needs more addresses, then send a GetAddr message
	// to the peer. This is best-effort.
	if pp.cmgr.addrMgr.NeedMoreAddresses() {
		go func() {
			pp.QueueMessage(&MsgUltranetGetAddr{})
		}()
	}

	// Send our verack message now that the IO processing machinery has started.
	return
}

// IsSyncCandidate ...
func (pp *Peer) IsSyncCandidate() bool {
	return (pp.serviceFlags & SFFullNode) != 0
}

// WriteUltranetMessage ...
func (pp *Peer) WriteUltranetMessage(msg UltranetMessage) error {
	payload, err := WriteMessage(pp.conn, msg, pp.cmgr.params.NetworkType)
	if err != nil {
		return errors.Wrapf(err, "WriteUltranetMessage: ")
	}

	// Only track the payload sent in the statistics we track.
	atomic.AddUint64(&pp.bytesSent, uint64(len(payload)))
	atomic.StoreInt64(&pp.lastSend, time.Now().Unix())

	/*
		// Useful for debugging.
		messageSeq := atomic.AddUint64(&pp.totalMessages, 1)
		glog.Tracef("SENDING(seq=%d) message of type: %v to peer %v: %s",
			messageSeq, msg.GetMsgType(), pp, spew.Sdump(msg))
	*/

	return nil
}

// ReadUltranetMessage ...
func (pp *Peer) ReadUltranetMessage() (UltranetMessage, error) {
	msg, payload, err := ReadMessage(pp.conn, pp.cmgr.params.NetworkType)
	if err != nil {
		return nil, errors.Wrapf(err, "ReadUltranetMessage: ")
	}

	// Only track the payload received in the statistics we track.
	msgLen := uint64(len(payload))
	atomic.AddUint64(&pp.bytesReceived, msgLen)
	atomic.StoreInt64(&pp.lastRecv, time.Now().Unix())

	/*
		// Useful for debugging.
		messageSeq := atomic.AddUint64(&pp.totalMessages, 1)
		glog.Tracef("RECEIVED(seq=%d) message of type: %v from peer %v: %s",
			messageSeq, msg.GetMsgType(), pp, spew.Sdump(msg))
	*/

	return msg, nil
}

// NewVersionMessage ...
func (pp *Peer) NewVersionMessage(params *UltranetParams) *MsgUltranetVersion {
	ver := NewMessage(MsgTypeVersion).(*MsgUltranetVersion)

	ver.Version = params.ProtocolVersion
	ver.TstampSecs = time.Now().Unix()
	// We use an int64 instead of a uint64 for convenience but
	// this should be fine since we're just looking to generate a
	// unique value.
	ver.Nonce = uint64(RandInt64(math.MaxInt64))
	ver.UserAgent = params.UserAgent
	// TODO: Right now all peers are full nodes. Later on we'll want to change this,
	// at which point we'll need to do a little refactoring.
	ver.Services = SFFullNode

	// When a node asks you for what height you have, you should reply with
	// the height of the latest actual block you have. This makes it so that
	// peers who have up-to-date headers but missing blocks won't be considered
	// for initial block download.
	//
	// TODO: This is ugly. It would be nice if the Peer required zero knowledge of the
	// Server and the Blockchain.
	ver.StartBlockHeight = pp.srv.blockchain.blockTip().Header.Height

	// Set the minimum fee rate the peer will accept.
	ver.MinFeeRateNanosPerKB = pp.minTxFeeRateNanosPerKB

	// Set the JSON API port to whatever we have.
	ver.JSONAPIPort = pp.cmgr.jsonPort

	return ver
}

func (pp *Peer) sendVerack() error {
	verackMsg := NewMessage(MsgTypeVerack)
	// Include the nonce we received in the peer's version message so
	// we can validate that we actually control our IP address.
	verackMsg.(*MsgUltranetVerack).Nonce = pp.versionNonceReceived
	if err := pp.WriteUltranetMessage(verackMsg); err != nil {
		return errors.Wrap(err, "sendVerack: ")
	}

	return nil
}

func (pp *Peer) readVerack() error {
	msg, err := pp.ReadUltranetMessage()
	if err != nil {
		return errors.Wrap(err, "readVerack: ")
	}
	if msg.GetMsgType() != MsgTypeVerack {
		return fmt.Errorf(
			"readVerack: Received message with type %s but expected type VERACK. ",
			msg.GetMsgType().String())
	}
	verackMsg := msg.(*MsgUltranetVerack)
	if verackMsg.Nonce != pp.versionNonceSent {
		return fmt.Errorf(
			"readVerack: Received VERACK message with nonce %d but expected nonce %d",
			verackMsg.Nonce, pp.versionNonceSent)
	}

	return nil
}

func (pp *Peer) sendVersion() error {
	// For an outbound peer, we send a version message and then wait to
	// hear back for one.
	verMsg := pp.NewVersionMessage(pp.cmgr.params)

	// Record the nonce of this version message before we send it so we can
	// detect self connections and so we can validate that the peer actually
	// controls the IP she's supposedly communicating to us from.
	pp.versionNonceSent = verMsg.Nonce
	pp.cmgr.sentNonces.Add(pp.versionNonceSent)

	if err := pp.WriteUltranetMessage(verMsg); err != nil {
		return errors.Wrap(err, "sendVersion: ")
	}

	return nil
}

func (pp *Peer) readVersion() error {
	msg, err := pp.ReadUltranetMessage()
	if err != nil {
		return errors.Wrap(err, "readVersion: ")
	}

	verMsg, ok := msg.(*MsgUltranetVersion)
	if !ok {
		return fmt.Errorf(
			"readVersion: Received message with type %s but expected type VERSION. "+
				"The VERSION message must preceed all others.",
			msg.GetMsgType().String())
	}
	if verMsg.Version < pp.cmgr.params.MinProtocolVersion {
		return fmt.Errorf("readVersion: Peer's protocol version too low: %d (min: %v)",
			verMsg.Version, pp.cmgr.params.MinProtocolVersion)
	}

	// If we've sent this nonce before then return an error since this is
	// a connection from ourselves.
	msgNonce := verMsg.Nonce
	if pp.cmgr.sentNonces.Exists(msgNonce) {
		pp.cmgr.sentNonces.Delete(msgNonce)
		return fmt.Errorf("readVersion: Rejecting connection to self")
	}
	// Save the version nonce so we can include it in our verack message.
	pp.versionNonceReceived = msgNonce

	// Set the peer info-related fields.
	pp.PeerInfoMtx.Lock()
	pp.userAgent = verMsg.UserAgent
	pp.serviceFlags = verMsg.Services
	pp.advertisedProtocolVersion = verMsg.Version
	negotiatedVersion := pp.cmgr.params.ProtocolVersion
	if pp.advertisedProtocolVersion < pp.cmgr.params.ProtocolVersion {
		negotiatedVersion = pp.advertisedProtocolVersion
	}
	pp.negotiatedProtocolVersion = negotiatedVersion
	pp.jsonAPIPort = verMsg.JSONAPIPort
	pp.PeerInfoMtx.Unlock()

	// Set the stats-related fields.
	pp.StatsMtx.Lock()
	pp.startingHeight = verMsg.StartBlockHeight
	pp.minTxFeeRateNanosPerKB = verMsg.MinFeeRateNanosPerKB
	pp.timeConnected = time.Unix(verMsg.TstampSecs, 0)
	pp.timeOffsetSecs = verMsg.TstampSecs - time.Now().Unix()
	pp.StatsMtx.Unlock()

	// Update the timeSource now that we've gotten a version message from the
	// peer.
	pp.cmgr.timeSource.AddTimeSample(pp.addrStr, pp.timeConnected)

	return nil
}

func (pp *Peer) readWithTimeout(readFunc func() error, readTimeout time.Duration) error {
	errChan := make(chan error)
	go func() {
		errChan <- readFunc()
	}()
	select {
	case err := <-errChan:
		{
			return err
		}
	case <-time.After(readTimeout):
		{
			return fmt.Errorf("readWithTimeout: Timed out reading message from peer: (%v)", pp)
		}
	}
}

func (pp *Peer) negotiateVersion() error {
	if pp.isOutbound {
		// Write a version message.
		if err := pp.sendVersion(); err != nil {
			return errors.Wrapf(err, "negotiateVersion: Problem sending version to Peer %v", pp)
		}
		// Read the peer's version.
		if err := pp.readWithTimeout(
			pp.readVersion,
			pp.cmgr.params.VersionNegotiationTimeout); err != nil {

			return errors.Wrapf(err, "negotiateVersion: Problem reading OUTBOUND peer version for Peer %v", pp)
		}
	} else {
		// Read the version first since this is an inbound peer.
		if err := pp.readWithTimeout(
			pp.readVersion,
			pp.cmgr.params.VersionNegotiationTimeout); err != nil {

			return errors.Wrapf(err, "negotiateVersion: Problem reading INBOUND peer version for Peer %v", pp)
		}
		if err := pp.sendVersion(); err != nil {
			return errors.Wrapf(err, "negotiateVersion: Problem sending version to Peer %v", pp)
		}
	}

	// After sending and receiving a compatible version, complete the
	// negotiation by sending and receiving a verack message.
	if err := pp.sendVerack(); err != nil {
		return errors.Wrapf(err, "negotiateVersion: Problem sending verack to Peer %v", pp)
	}
	if err := pp.readWithTimeout(
		pp.readVerack,
		pp.cmgr.params.VersionNegotiationTimeout); err != nil {

		return errors.Wrapf(err, "negotiateVersion: Problem reading VERACK message from Peer %v", pp)
	}
	pp.versionNegotiated = true

	// At this point we have sent a version and validated our peer's
	// version. So the negotiation should be complete.
	return nil
}

// Disconnect closes a peer's network connection.
func (pp *Peer) Disconnect() {
	// Only run the logic the first time Disconnect is called.
	if atomic.AddInt32(&pp.disconnected, 1) != 1 {
		glog.Debugf("Peer.Disconnect: Disconnect call ignored since it was already called before for Peer %v", pp)
		return
	}

	glog.Debugf("Peer.Disconnect: Running Disconnect for the first time for Peer %v", pp)

	// Close the connection object.
	pp.conn.Close()

	// Signaling the quit channel allows all the other goroutines to stop running.
	close(pp.quit)

	// Add the Peer to donePeers so that the ConnectionManager and Server can do any
	// cleanup they need to do.
	pp.cmgr.donePeerChan <- pp
}

func (pp *Peer) _logVersionSuccess() {
	inboundStr := "INBOUND"
	if pp.isOutbound {
		inboundStr = "OUTBOUND"
	}
	persistentStr := "PERSISTENT"
	if !pp.isPersistent {
		persistentStr = "NON-PERSISTENT"
	}
	logStr := fmt.Sprintf("SUCCESS version negotiation for (%s) (%s) peer (%v).", inboundStr, persistentStr, pp)
	glog.Debug(logStr)
}

func (pp *Peer) _logAddPeer() {
	inboundStr := "INBOUND"
	if pp.isOutbound {
		inboundStr = "OUTBOUND"
	}
	persistentStr := "PERSISTENT"
	if !pp.isPersistent {
		persistentStr = "NON-PERSISTENT"
	}
	logStr := fmt.Sprintf("ADDING (%s) (%s) peer (%v)", inboundStr, persistentStr, pp)
	glog.Debug(logStr)
}
