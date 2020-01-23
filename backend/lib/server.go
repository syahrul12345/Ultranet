package lib

import (
	"encoding/hex"
	"fmt"
	"net"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/btcsuite/btcd/addrmgr"
	chainlib "github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/wire"
	"github.com/davecgh/go-spew/spew"
	"github.com/dgraph-io/badger"
	"github.com/golang/glog"
	"github.com/pkg/errors"
	"github.com/sasha-s/go-deadlock"
)

// ServerMessage is the core data structure processed by the Server in its main
// loop.
type ServerMessage struct {
	Peer      *Peer
	Msg       UltranetMessage
	ReplyChan chan *ServerReply
}

// GetDataRequestInfo is a data structure used to keep track of which transactions
// we've requested from a Peer.
type GetDataRequestInfo struct {
	PeerWhoSentInv *Peer
	TimeRequested  time.Time
}

// ServerReply is used to signal to outside programs that a particuler ServerMessage
// they may have been waiting on has been processed.
type ServerReply struct {
}

// Server is the core of the Ultranet node. It effectively runs a single-threaded
// main loop that processes transactions from other peers and responds to them
// accordingly. Probably the best place to start looking is the messageHandler
// function.
type Server struct {
	cmgr           *ConnectionManager
	blockchain     *Blockchain
	bitcoinManager *BitcoinManager
	listingManager *ListingManager
	mempool        *TxPool
	miner          *UltranetMiner

	// All messages received from peers get sent from the ConnectionManager to the
	// Server through this channel.
	//
	// Generally, the
	// ConnectionManager is responsible for managing the connections to all the peers,
	// but when it receives a message from one of them, it forwards it to the Server
	// on this channel to actually process (acting as a router in that way).
	//
	// In addition to messages from peers, the ConnectionManager will also send control
	// messages to notify the Server e.g. when a Peer connects or disconnects so that
	// the Server can take action appropriately.
	incomingMessages chan *ServerMessage
	// inventoryBeingProcessed keeps track of the inventory (hashes of blocks and
	// transactions) that we've recently processed from peers. It is useful for
	// avoiding situations in which we re-fetch the same data from many peers.
	// For example, if we get the same Block inv message from multiple peers,
	// adding it to this map and checking this map before replying will make it
	// so that we only send a reply to the first peer that sent us the inv, which
	// is more efficient.
	inventoryBeingProcessed *mruInventoryMap
	// syncInventory keeps track of inventory that was received as part of an
	// initial sync. This prevents us from relaying this inventory unnecessarily
	// to peers who may already have it.
	syncInventory *mruInventoryMap
	// hasRequestedSync indicates whether we've bootstrapped our mempool
	// and our listings by requesting all mempool transactions and listings from a
	// peer. It's initially false
	// when the server boots up but gets set to true after we make a Mempool and
	// ListingSync request once we're fully synced.
	hasRequestedSync bool
	// The waitGroup is used to manage the cleanup of the Server.
	waitGroup deadlock.WaitGroup

	// During initial block download, we request headers and blocks from a single
	// peer. Note: These fields should only be accessed from the messageHandler thread.
	//
	// TODO: This could be much faster if we were to download blocks in parallel
	// rather than from a single peer but it won't be a problem until later, at which
	// point we can make the optimization.
	syncPeer *Peer
	// How long we wait on a listing or transaction we're fetching before giving
	// up on it. Note this doesn't apply to blocks because they have their own
	// process for retrying that differs from transactions and listings, which are
	// more best-effort than blocks.
	requestTimeoutSeconds uint32

	// dataLock protects requestedTxns and requestedBlocks
	dataLock deadlock.Mutex
	// requestedBlocks is a global data structure that allows us to determine what
	// blocks we have currently requested. This information is useful when we're
	// trying to figure out which blocks we should request from a Peer, for example
	// in GetBlocks.
	requestedBlocks map[BlockHash]*ServerMessage

	// requestedTransactions contains hashes of transactions for which we have
	// requested data but have not yet received a response.
	requestedTransactions map[BlockHash]*GetDataRequestInfo

	// queuedListings contains hashes from inv messages sent by our Peers that we
	// have not yet requested data for. Note a few interesting things:
	// - A queue like this is not needed for blocks because the blocks we need are computable
	//   by taking the diff between our best header chain and our best block chain.
	//   Such an analogue doesn't exist for listings because they're generally
	//   independent of each other.
	// - A queue like this is not needed for transactions because there are generally so few of
	//   them (on the order of 100MB or less if we take the entire mempool) that
	//   queueing them up and sending them in batches like we do here isn't necessary.
	queuedListings map[BlockHash]*Peer
	// requestedListings contains hashes of listings for which we have requested
	// data but have not yet received a response.
	requestedListings map[BlockHash]*GetDataRequestInfo

	// addrsToBroadcast is a list of all the addresses we've received from valid addr
	// messages that we intend to broadcast to our peers. It is organized as:
	// <recipient address> -> <list of addresses we received from that recipient>.
	//
	// It is organized in this way so that we can limit the number of addresses we
	// are distributing for a single peer to avoid a DOS attack.
	addrsToBroadcastLock deadlock.RWMutex
	addrsToBroadcastt    map[string][]*SingleAddr
}

// ResetRequestQueues resets all the request queues.
func (srv *Server) ResetRequestQueues() {
	srv.dataLock.Lock()
	defer srv.dataLock.Unlock()

	glog.Tracef("Server.ResetRequestQueues: Resetting request queues")

	srv.requestedBlocks = make(map[BlockHash]*ServerMessage)
	srv.requestedTransactions = make(map[BlockHash]*GetDataRequestInfo)
	srv.queuedListings = make(map[BlockHash]*Peer)
	srv.requestedListings = make(map[BlockHash]*GetDataRequestInfo)
}

// dataLock must be acquired for writing before calling this function.
func (srv *Server) _removeRequestt(hash *BlockHash) {
	// Just be lazy and remove the hash from everything indiscriminantly to
	// make sure it's good and purged.
	delete(srv.requestedTransactions, *hash)
	delete(srv.queuedListings, *hash)
	delete(srv.requestedListings, *hash)
	srv.inventoryBeingProcessed.DeleteTxHash(hash)
}

// dataLock must be acquired for writing before calling this function.
func (srv *Server) _expireRequests() {
	// TODO: It could in theory get slow to do brute force iteration over everything
	// we've requested but not yet received, which is what we do below. But we'll
	// wait until we actually have an issue with it before optimizing it, since it
	// could also be fine. Just watch out for it.

	timeoutSeconds := time.Duration(int64(srv.requestTimeoutSeconds) * int64(time.Second))
	for hashIter, requestInfo := range srv.requestedTransactions {
		// Note that it's safe to use the hash iterator here because _removeRequestt
		// doesn't take a reference to it.
		if requestInfo.TimeRequested.Add(timeoutSeconds).After(time.Now()) {
			srv._removeRequestt(&hashIter)
		}
	}

	for hashIter, requestInfo := range srv.requestedListings {
		// Note that it's safe to use the hash iterator here because _removeRequestt
		// doesn't take a reference to it.
		if requestInfo.TimeRequested.Add(timeoutSeconds).After(time.Now()) {
			srv._removeRequestt(&hashIter)
		}
	}
}

// ExpireRequests checks to see if any requests have expired and removes them if so.
func (srv *Server) ExpireRequests() {
	srv.dataLock.Lock()
	defer srv.dataLock.Unlock()

	srv._expireRequests()
}

// GetBlockchain is... I hate myself for doing this; I can't even write this comment.
// TODO: The hallmark of a messy non-law-of-demeter-following interface...
func (srv *Server) GetBlockchain() *Blockchain {
	return srv.blockchain
}

// GetListingManager is... I hate myself for doing this; I can't even write this comment.
// TODO: The hallmark of a messy non-law-of-demeter-following interface...
func (srv *Server) GetListingManager() *ListingManager {
	return srv.listingManager
}

// NewServer initializes all of the internal data structures. Right now this basically
// looks as follows:
// - ConnectionManager starts and keeps track of peers.
// - When messages are received from peers, they get forwarded on a channel to
//   the Server to handle them. In that sense the ConnectionManager is basically
//   just acting as a router.
// - When the Server receives a message from a peer, it can do any of the following:
//   * Take no action.
//   * Use the Blockchain data structure to validate the transaction or update the.
//     Blockchain data structure.
//   * Use the ListingManager data structure to validate the transaction or update the
//     ListingManager data structure.
//   * Send a new message. This can be a message directed back to that actually sent this
//     message or it can be a message to another peer for whatever reason. When a message
//     is sent in this way it can also have a deadline on it that the peer needs to
//     respond by or else it will be disconnected.
//   * Disconnect the peer. In this case the ConnectionManager gets notified about the
//     disconnection and may opt to replace the now-disconnected peer with a  new peer.
//     This happens for example when an outbound peer is disconnected in order to
//     maintain TargetOutboundPeers.
// - The server could also receive a control message that a peer has been disconnected.
//   This can be userful to the server if, for example, it was expecting a response from
//   a particular peer, which could be the case in initial block download where a single
//   sync peer is used.
//
// TODO: Refactor all these arguments into a config object or something.
func NewServer(_params *UltranetParams, _listeners []net.Listener,
	_ultranetAddrMgr *addrmgr.AddrManager, _connectIPNetAddrs []*wire.NetAddress, _db *badger.DB,
	_targetOutboundPeers uint32, _maxInboundPeers uint32, _minerPublicKeys []string,
	_numMiningThreads int, _limitOneInboundConnectionPerIP bool,
	_rateLimitFeerateNanosPerKB uint64, _minFeeRateNanosPerKB uint64,
	_stallTimeoutSeconds uint64, _bitcoinDataDir string,
	_jsonPort uint16) (*Server, error) {

	// Create an empty Server object here so we can pass a reference to it to the
	// ConnectionManager.
	srv := &Server{}

	// The same timesource is used in the chain data structure and in the connection
	// manager. It just takes and keeps track of the median time among our peers so
	// we can keep a consistent clock.
	timesource := chainlib.NewMedianTime()

	// Create a new connection manager but note that it won't be initialized until Start().
	_incomingMessages := make(chan *ServerMessage, (_targetOutboundPeers+_maxInboundPeers)*3)
	_cmgr := NewConnectionManager(
		_params, _ultranetAddrMgr, _listeners, _connectIPNetAddrs, timesource,
		_targetOutboundPeers, _maxInboundPeers, _limitOneInboundConnectionPerIP,
		_stallTimeoutSeconds, _minFeeRateNanosPerKB,
		_incomingMessages, _jsonPort, srv)

	// Create a BitcoinManager so that transactions that exchange Ultra for Bitcoin
	// can be properly validated.
	_bitcoinManager, err := NewBitcoinManager(
		_db, _params, timesource, _bitcoinDataDir, _incomingMessages)
	if err != nil {
		return nil, errors.Wrapf(err, "NewServer: Problem initializing BitcoinManager")
	}

	// Set up the blockchain data structure. This is responsible for accepting new
	// blocks, keeping track of the best chain, and keeping all of that state up
	// to date on disk.
	//
	// If this is the first time this data structure is being initialized, it will
	// contain only the genesis block. Otherwise it loads all of the block headers
	// (actually BlockNode's) from the db into memory, which is a somewhat heavy-weight
	// operation.
	//
	// TODO: Would be nice if this heavier-weight operation were moved to Start() to
	// keep this constructor fast.
	_chain, err := NewBlockchain(_params, timesource, _db, _bitcoinManager, _incomingMessages)
	if err != nil {
		return nil, errors.Wrapf(err, "NewServer: Problem initializing blockchain")
	}
	glog.Debugf("Initialized chain: Best Header Height: %d, Header Hash: %s, Header CumWork: %s, Best Block Height: %d, Block Hash: %s, Block CumWork: %s",
		_chain.headerTip().Height,
		hex.EncodeToString(_chain.headerTip().Hash[:]),
		hex.EncodeToString(BigintToHash(_chain.headerTip().CumWork)[:]),
		_chain.blockTip().Height,
		hex.EncodeToString(_chain.blockTip().Hash[:]),
		hex.EncodeToString(BigintToHash(_chain.blockTip().CumWork)[:]))

	// Creates a ListingManager but note that it won't be initialized until we call Start().
	_listingManager, err := NewListingManager(_db, _chain, _params)
	if err != nil {
		return nil, errors.Wrapf(err, "NewServer: Problem initializing ListingManager: ")
	}

	// Create a mempool to store transactions until they're ready to be mined into
	// blocks.
	_mempool := NewTxPool(_chain, _rateLimitFeerateNanosPerKB, _minFeeRateNanosPerKB)

	// Useful for debugging. Every second, it outputs the contents of the mempool
	// and the contents of the addrmanager.
	/*
		go func() {
			time.Sleep(3 * time.Second)
			for {
				glog.Tracef("Current mempool txns: ")
				counter := 0
				for kk, txD := range _mempool.poolMap {
					kkCopy := kk
					glog.Tracef("\t%d: < %v: %v >", counter, &kkCopy, txD)
					counter++
				}
				glog.Tracef("Current addrs: ")
				for ii, na := range srv.cmgr.addrMgr.GetAllAddrs() {
					glog.Tracef("Addr %d: <%s:%d>", ii, na.IP.String(), na.Port)
				}
				time.Sleep(1 * time.Second)
			}
		}()
	*/

	// Create a miner that will be started in Start(). Note that the miner will
	// only mine blocks if one or more public keys are provided.
	if _numMiningThreads <= 0 {
		_numMiningThreads = runtime.NumCPU()
	}
	_miner, err := NewUltranetMiner(_minerPublicKeys, uint32(_numMiningThreads), _mempool, _chain, _bitcoinManager, _params)
	if err != nil {
		return nil, errors.Wrapf(err, "NewServer: ")
	}

	// Set all the fields on the Server object.
	srv.cmgr = _cmgr
	srv.blockchain = _chain
	srv.bitcoinManager = _bitcoinManager
	srv.listingManager = _listingManager
	srv.mempool = _mempool
	srv.miner = _miner
	srv.incomingMessages = _incomingMessages
	// Make this hold a multiple of what we hold for individual peers.
	srv.inventoryBeingProcessed = newMruInventoryMap(10 * maxKnownInventory)
	// Make this pretty big since it basically needs to hold all the hashes we
	// receive during a mempool and listing sync combined.
	srv.syncInventory = newMruInventoryMap(100 * maxKnownInventory)
	srv.requestTimeoutSeconds = 10

	// Initialize the addrs to broadcast map.
	srv.addrsToBroadcastt = make(map[string][]*SingleAddr)

	// This will initialize the request queues.
	srv.ResetRequestQueues()

	return srv, nil
}

func (srv *Server) _handleGetHeaders(pp *Peer, msg *MsgUltranetGetHeaders) {
	glog.Debugf("Server._handleGetHeadersMessage: called with locator: (%v), "+
		"stopHash: (%v) from Peer %v", msg.BlockLocator, msg.StopHash, pp)

	// Ignore GetHeaders requests we're still syncing.
	if srv.blockchain.IsSyncing() {
		chainState := srv.blockchain.ChainState()
		glog.Debugf("Server._handleGetHeadersMessage: Ignoring GetHeaders from Peer %v"+
			"because node is syncing with ChainState (%v)", pp, chainState)
		return
	}

	// Find the most recent known block in the best block chain based
	// on the block locator and fetch all of the headers after it until either
	// MaxHeadersPerMsg have been fetched or the provided stop
	// hash is encountered. Note that the headers we return are based on
	// our best *block* chain not our best *header* chain. The reaason for
	// this is that the peer will likely follow up this request by asking
	// us for the blocks corresponding to the headers and we need to be
	// able to deliver them in this case.
	//
	// Use the block after the genesis block if no other blocks in the
	// provided locator are known. This does mean the client will start
	// over with the genesis block if unknown block locators are provided.
	headers := srv.blockchain.LocateBestBlockChainHeaders(msg.BlockLocator, msg.StopHash)

	// Send found headers to the requesting peer.
	blockTip := srv.blockchain.BlockTip()
	go func() {
		pp.PushHeaderBundlesMsg(headers, blockTip.Hash, blockTip.Height)
	}()
	glog.Tracef("Server._handleGetHeadersMessage: Replied to GetHeaders request "+
		"with response headers: (%v), tip hash (%v), tip height (%d) from Peer %v",
		headers, blockTip.Hash, blockTip.Height, pp)
}

// GetListings gets any listings that we need.
// dataLock must be acquired before calling this function.
func (srv *Server) GetListings() {
	// Expire any listings that we've been waiting too long on. Also remove them
	// from inventoryProcessed in case another Peer wants to send them to us in
	// the future.
	srv._expireRequests()

	// Compute the number of listings we need to fetch.
	numListingsToFetch := MaxListingsInFlight - len(srv.requestedListings)
	if numListingsToFetch == 0 {
		// If there are already too many listing requests in flight, just return.
		return
	}

	// Since we have room to fetch some listings, see if we have any to
	// fetch. Rack them up in the maps below and move them from queuedListings
	// to requestedListings.
	peerIDToPeer := make(map[uint64]*Peer)
	peerIDToListingHashes := make(map[uint64][]*BlockHash)
	numHashesAdded := 0
	for iterHash, peerForListing := range srv.queuedListings {
		if !peerForListing.Connected() {
			// If we have a Peer that is not connected, ignore her. Soon enough
			// her requestst will either be deleted from the queue or reassigned.
			continue
		}
		listingHash := &BlockHash{}
		copy(listingHash[:], iterHash[:])
		if numHashesAdded == numListingsToFetch {
			break
		}
		numHashesAdded++

		// Remove the hash from the queuedListings.
		delete(srv.queuedListings, *listingHash)

		// Add the hash to the requestedListings since we're going to request
		// it from the corresponding Peer.
		srv.requestedListings[*listingHash] = &GetDataRequestInfo{
			PeerWhoSentInv: peerForListing,
			TimeRequested:  time.Now(),
		}

		// Add the hash and the Peer to the local maps so we can make our request
		// out of the loop later.
		peerIDToPeer[peerForListing.ID] = peerForListing
		listingHashSlice, isInitialized := peerIDToListingHashes[peerForListing.ID]
		if !isInitialized {
			listingHashSlice = []*BlockHash{}
		}
		listingHashSlice = append(listingHashSlice, listingHash)
		peerIDToListingHashes[peerForListing.ID] = listingHashSlice
	}

	// Fetch all the listings we can from the associated Peers.
	for peerID, listingsToFetch := range peerIDToListingHashes {
		peerToFetchFrom := peerIDToPeer[peerID]

		// Queue a request for the listings from the corresponding peer.
		go func() {
			peerToFetchFrom.PushGetListingsMsg(listingsToFetch)
		}()

		glog.Debugf("GetListings: Downloading %d listings from peer %v",
			len(listingsToFetch), peerToFetchFrom)
	}

	return
}

// GetBlocks computes what blocks we need to fetch and asks for them from the
// corresponding peer. It is typically called after we have exited
// SyncStateSyncingHeaders.
func (srv *Server) GetBlocks(pp *Peer, maxHeight int) {
	// Do not fetch blocks if the BitcoinManager is not time-synced. Getting blocks
	// before the BitcoinManager is synced is a waste of time since we will generally
	// not be able to validate them before this point. Note that when BitcoinManager
	// eventually does become time-synced it will signal the Server with a
	// BitcoinManagerUpdate message. This will trigger a getheaders message to be sent
	// to one of our Peers, which will eventually trigger GetBlocks again (most likely
	// via a HeaderBundle response from the Peer).
	//
	// Note this check is not strictly necessary since messageHandler will ultimately
	// not allow blocks to be processed if the BitcoinManager is not synced, but checking
	// this here allows for the optimization of not requesting them in the first place.
	if !srv.bitcoinManager.IsCurrent(false /*considerCumWork*/) {
		glog.Debugf("Server.GetBlocks: Not calling GetBlocks on Peer %v because "+
			"BitcoinManager is not time-current", pp)
		return
	}

	// Fetch as many blocks as we can from this peer.
	numBlocksToFetch := MaxBlocksInFlight - len(srv.requestedBlocks)
	blockNodesToFetch := srv.blockchain.GetBlockNodesToFetch(numBlocksToFetch, maxHeight, srv.requestedBlocks)
	if len(blockNodesToFetch) == 0 {
		// This can happen if, for example, we're already requesting the maximum
		// number of blocks we can. Just return in this case.
		return
	}

	// Add the blocks to the requestBlocks list with nil values. They'll stay
	// that way until the blocks are actually received from the peer.
	for _, nodeToFetch := range blockNodesToFetch {
		srv.requestedBlocks[*nodeToFetch.Hash] = &ServerMessage{
			Peer: pp,
			Msg:  nil,
		}
	}

	// If we're here then we have some blocks to fetch so fetch them.
	hashList := []*BlockHash{}
	for _, node := range blockNodesToFetch {
		hashList = append(hashList, node.Hash)
	}
	go func() {
		pp.PushGetBlocksMsg(hashList)
	}()

	glog.Debugf("GetBlocks: Downloading %d blocks from header %v to header %v from peer %v",
		len(blockNodesToFetch),
		blockNodesToFetch[0].Header,
		blockNodesToFetch[len(blockNodesToFetch)-1].Header,
		pp)
	return
}

func (srv *Server) _handleHeaderBundle(pp *Peer, msg *MsgUltranetHeaderBundle) {
	glog.Debugf("Server._handleHeaderBundle: Received header bundle with headers: (%v) "+
		"in state %s from peer %v while our header tip is %v",
		msg.Headers, srv.blockchain.ChainState(), pp,
		srv.blockchain.HeaderTip().Header)

	// Start by processing all of the headers given to us. They should start
	// right after the tip of our header chain ideally. While going through them
	// tally up the number that we actually process.
	numNewHeaders := 0
	for _, headerReceived := range msg.Headers {
		// If we encounter a duplicate header while we're still syncing then
		// the peer is misbehaving. Disconnect so we can find one that won't
		// have this issue. Hitting duplicates after we're done syncing is
		// fine and can happen in certain cases.
		headerHash, _ := headerReceived.Hash()
		if srv.blockchain.HasHeader(headerHash) {
			if srv.blockchain.IsSyncing() {

				glog.Warningf("Server._handleHeaderBundle: Duplicate header received from peer %v "+
					"in state %s. Local header tip height %d "+
					"hash %s with duplicate %v",
					pp, srv.blockchain.ChainState(), srv.blockchain.HeaderTip().Height,
					hex.EncodeToString(srv.blockchain.HeaderTip().Hash[:]), headerHash)

				// TODO: This logic should really be commented back in, but there was a bug that
				// arises when a program is killed forcefully whereby a partial write leads to this
				// logic causing the sync to stall. As such, it's more trouble than it's worth
				// at the moment but we should consider being more strict about it in the future.
				/*
					pp.Disconnect()
					return
				*/
			}

			// Don't process duplicate headers.
			continue
		}

		// If we get here then we have a header we haven't seen before.
		numNewHeaders++

		// Process the header, as we haven't seen it before.
		_, isOrphan, err := srv.blockchain.ProcessHeader(headerReceived, headerHash)

		// If this header is an orphan or we encoutnered an error for any reason,
		// disconnect from the peer. Because every header is sent in response to
		// a GetHeaders request, the peer should know enough to never send us
		// orphans unless it's misbehaving.
		if err != nil || isOrphan {
			glog.Errorf("Server._handleHeaderBundle: Disconnecting from peer %v in state %s "+
				"because error occurred processing header: %v, isOrphan: %v",
				pp, srv.blockchain.ChainState(), err, isOrphan)

			pp.Disconnect()
			return
		}
	}

	// After processing all the headers this will check to see if we are fully current
	// and send a request to our Peer to start a Mempool and Listing sync if so.
	//
	// This statement makes it so that if we boot up our node such that
	// its initial state is fully current we'll always bootstrap our mempool and listings with a
	// mempool request. The alternative is that our state is not fully current
	// when we boot up, and we cover this second case in the _handleBlock function.
	srv._maybeRequestSync(pp)

	// If there were headers in the message but we didn't process any of them, just
	// return at this point. This can sometimes happen if we do getheaders on multiple
	// peers at the same time after receiving an inv and is a minor optimization to
	// prevent duplicate processing when that happens.
	//
	// Note if the number of headers
	// in the message is zero then we still want to do the steps that follow since not
	// doing this would cause us not to fetch blocks in an edge case during bootstrapping.
	if len(msg.Headers) != 0 && numNewHeaders == 0 {
		glog.Debugf("Server._handleHeaderBundle: Returning because the message "+
			"contained no new headers from Peer %v", pp)
		return
	}

	// At this point we should have processed all the headers. Now we will
	// make a decision on whether to request more headers from this peer based
	// on how many headers we received in this message. Since every HeaderBundle
	// is a response to a GetHeaders request from us with a HeaderLocator embedded in it, receiving
	// anything less than MaxHeadersPerMsg headers from a peer is sufficient to
	// make us think that the peer doesn't have any more interesting headers for us.
	// On the other hand, if the request contains MaxHeadersPerMsg, it is highly
	// likely we have not hit the tip of our peer's chain, and so requesting more
	// headers from the peer would likely be useful.
	if uint32(len(msg.Headers)) < MaxHeadersPerMsg {
		// If we have exhausted the peer's headers but our header chain still isn't
		// current it means the peer we chose isn't current either. So disconnect
		// from her and try to sync with someone else.
		if srv.blockchain.ChainState() == SyncStateSyncingHeaders {
			glog.Debugf("Server._handleHeaderBundle: Disconnecting from peer %v because "+
				"we have exhausted their headers but our tip is still only "+
				"at time=%v height=%d", pp,
				time.Unix(int64(srv.blockchain.HeaderTip().Header.TstampSecs), 0),
				srv.blockchain.HeaderTip().Header.Height)
			pp.Disconnect()
			return
		}

		// If we have exhausted the peer's headers but our blocks aren't current,
		// send a GetBlocks message to the peer for as many blocks as we can get.
		if srv.blockchain.ChainState() == SyncStateSyncingBlocks {
			// A maxHeight of -1 tells GetBlocks to fetch as many blocks as we can
			// from this peer without worrying about how many blocks the peer actually
			// has. We can do that in this case since this usually happens dring sync
			// before we've made any GetBlocks requests to the peer.
			blockTip := srv.blockchain.blockTip()
			glog.Debugf("Server._handleHeaderBundle: *Syncing* blocks starting at "+
				"height %d out of %d from peer %v",
				blockTip.Header.Height+1, msg.TipHeight, pp)
			maxHeight := -1
			srv.GetBlocks(pp, maxHeight)
			return
		}

		// If we have exhausted the peer's headers and our blocks are current but
		// we still need a few more blocks to line our block chain up with
		// our header chain, send the peer a GetBlocks message for blocks we're
		// positive she has.
		if srv.blockchain.ChainState() == SyncStateNeedBlocksss {
			// If the peer's tip is not in our blockchain then we don't request
			// any blocks from them because they're on some kind of fork that
			// we're either not aware of or that we don't think is the best chain.
			// Doing things this way makes it so that when we request blocks we
			// are 100% positive the peer has them.
			if !srv.blockchain.HasHeader(msg.TipHash) {
				glog.Debugf("Server._handleHeaderBundle: Peer's tip is not in our "+
					"blockchain so not requesting anything else from them. Our block "+
					"tip %v, their tip %v:%d, peer: %v",
					srv.blockchain.BlockTip().Header, msg.TipHash, msg.TipHeight, pp)
				return
			}

			// At this point, we have verified that the peer's tip is in our main
			// header chain. This implies that any blocks we would request from
			// them should be available as long as they don't exceed the peer's
			// tip height.
			blockTip := srv.blockchain.blockTip()
			glog.Debugf("Server._handleHeaderBundle: *Downloading* blocks starting at "+
				"block tip %v out of %d from peer %v",
				blockTip.Header, msg.TipHeight, pp)
			srv.GetBlocks(pp, int(msg.TipHeight))
			return
		}

		// If we get here it means we have all the headers and blocks we need
		// so there's nothing more to do.
		glog.Debugf("Server._handleHeaderBundle: Tip is up-to-date so no "+
			"need to send anything. Our block tip: %v, their tip: %v:%d, Peer: %v",
			srv.blockchain.BlockTip().Header, msg.TipHash, msg.TipHeight, pp)
		return
	}

	// If we get here it means the peer sent us a full header bundle where at
	// least one of the headers contained in the bundle was new to us. When
	// this happens it means the peer likely has more headers for us to process
	// so follow up with another GetHeaders request. Set the block locator for
	// this request using the node corresponding to the last header in this
	// message. Not doing this and using our header tip instead, for example,
	// would result in us not being able to switch away from our current chain
	// even if the peer has a long fork with more work than our current header
	// chain.
	lastHash, _ := msg.Headers[len(msg.Headers)-1].Hash()
	locator, err := srv.blockchain.HeaderLocatorWithNodeHash(lastHash)
	if err != nil {
		glog.Warningf("Server._handleHeaderBundle: Disconnecting peer %v because "+
			"she indicated that she has more headers but the last hash %v in "+
			"the header bundle does not correspond to a block in our index.",
			pp, lastHash)
		pp.Disconnect()
		return
	}
	go func() {
		pp.PushGetHeadersMsg(locator, &BlockHash{})
	}()
	headerTip := srv.blockchain.headerTip()
	glog.Debugf("Server._handleHeaderBundle: *Syncing* headers for blocks starting at "+
		"header tip %v out of %d from peer %v",
		headerTip.Header, msg.TipHeight, pp)
}

func (srv *Server) _handleGetBlocks(pp *Peer, msg *MsgUltranetGetBlocks) {
	glog.Debugf("srv._handleGetBlocks: Called with message %v from Peer %v", msg, pp)

	// Nothing to do if the request is empty.
	if len(msg.HashList) == 0 {
		glog.Debugf("Server._handleGetBlocks: Received empty GetBlocks "+
			"request. No response needed for Peer %v", pp)
		return
	}

	// Verify that we have all of the blocks before honoring the request. This
	// check is cheap if we're limited to MaxBlocksInFlight so we can afford
	// to do it every time.
	for _, blockHash := range msg.HashList {
		// Peers should only ask us for blocks after they know we have them, which
		// they can and should find out with a GetHeaders request first.
		if !srv.blockchain.HasBlock(blockHash) {
			glog.Errorf("Server._handleGetBlocks: Disconnecting peer %v because "+
				"she asked for a block with hash %v that we don't have", pp, blockHash)
			pp.Disconnect()
			return
		}
	}

	// At this point we are positive that we have all of the blocks requested
	// and we know there is at least one block in the request.

	// Fetch and enqueue each block the Peer has requested.
	go func() {
		// For each block the Peer has requested, fetch it and queue it to
		// be sent. It takes some time to fetch the blocks which is why we
		// do it in a goroutine. This might also block if the Peer's send
		// queue is full.
		//
		// Note that the requester should generally ask for the blocks in the
		// order they'd like to receive them as we will typically honor this
		// ordering.
		for _, hashToSend := range msg.HashList {
			blockToSend := srv.blockchain.GetBlock(hashToSend)
			if blockToSend == nil {
				// Don't ask us for blocks before verifying that we have them with a
				// GetHeaders request.
				glog.Errorf("Server._handleGetBlocks: Disconnecting peer %v because "+
					"she asked for a block with hash %v that we don't have", pp, msg.HashList[0])
				pp.Disconnect()
				return
			}
			pp.PushBlockMsg(blockToSend)
			glog.Debugf("srv._handleGetBlocks: Queued block %v for sending to Peer %v", blockToSend, pp)
		}
	}()
}

func (srv *Server) _startSync() {
	// Return now if we're already syncing.
	if srv.syncPeer != nil {
		glog.Tracef("Server._startSync: Not running because syncPeer != nil")
		return
	}
	glog.Debugf("Server._startSync: Attempting to start sync")

	// Set our tip to be the best header tip rather than the best block tip. Using
	// the block tip instead might cause us to select a peer who is missing blocks
	// for the headers we've downloaded.
	bestTip := srv.blockchain.HeaderTip()

	// Find a peer with StartingHeight bigger than our best header tip.
	var bestPeer *Peer
	for _, peer := range srv.cmgr.GetAllPeers() {
		if !peer.IsSyncCandidate() {
			continue
		}

		if peer.StartingBlockHeight() < bestTip.Header.Height {
			continue
		}

		// TODO: Choose best peers based on ping time and/or the highest
		// starting block height. For now, keeping it simple and just choosing
		// the last one we iterate over with a block height larger than our best.
		bestPeer = peer
	}

	if bestPeer == nil {
		glog.Debugf("Server._startSync: No sync peer candidates available")
		return
	}

	// Note we don't need to reset requestedBlocks when the syncPeer changes
	// since we update requestedBLocks when a Peer disconnects to remove any
	// blocks that are currently being requested. This means that either a
	// still-connected Peer will eventually deliver the blocks OR we'll eventually
	// disconnect from that Peer, removing the blocks we requested from her from
	// requestedBlocks, which will cause us to re-download them again after.

	// Regardless of what our SyncState is, always start by sending a GetHeaders
	// message to our syncPeer. This ensures that our header chains are in-sync
	// before we start requesting blocks. If we were to go directly to fetching
	// blocks from our syncPeer without doing this first, we wouldn't be 100%
	// sure that she has them.
	glog.Debugf("Server._startSync: Syncing headers to height %d from peer %v",
		bestPeer.StartingBlockHeight(), bestPeer)

	// Send a GetHeaders message to the Peer to start the headers sync.
	// Note that we include an empty BlockHash as the stopHash to indicate we want as
	// many headers as the Peer can give us.
	locator := srv.blockchain.LatestHeaderLocator()
	go func() {
		bestPeer.PushGetHeadersMsg(locator, &BlockHash{})
	}()
	glog.Debugf("Server._startSync: Downloading headers for blocks starting at "+
		"header tip %v from peer %v", bestTip.Header, bestPeer)
	srv.syncPeer = bestPeer
}

func (srv *Server) _handleNewPeer(pp *Peer) {
	isSyncCandidate := pp.IsSyncCandidate()
	isSyncing := srv.blockchain.IsSyncing()
	chainState := srv.blockchain.ChainState()
	glog.Debugf("Server._handleNewPeer: Processing NewPeer: (%v); IsSyncCandidate(%v), syncPeerIsNil=(%v), IsSyncing=(%v), ChainState=(%v)",
		pp, isSyncCandidate, (srv.syncPeer == nil), isSyncing, chainState)
	// Start syncing by choosing the best candidate if we're not current.
	if isSyncCandidate && srv.syncPeer == nil && isSyncing {

		srv._startSync()
	}
}

func (srv *Server) _cleanupDonePeerPeerState(pp *Peer) {
	// Grab the dataLock since we'll be modifying requestedBlocks
	srv.dataLock.Lock()
	defer srv.dataLock.Unlock()

	// Remove requested blocks from the global maps so that they will be
	// fetched from elsewhere next time we get an inv.
	for blockHash, serverMessage := range srv.requestedBlocks {
		if serverMessage.Peer != nil && serverMessage.Peer.ID == pp.ID {
			delete(srv.requestedBlocks, blockHash)
			srv.inventoryBeingProcessed.DeleteBlockHash(&blockHash)
		}
	}

	// Choose a new Peer to switch our queued and in-flight requests to. If no Peer is
	// found, just remove any requests queued or in-flight for the disconnecting Peer
	// and return.
	//
	// If we find a newPeer, reassign in-flight and queued requests to this Peer and
	// re-request them if we have room in our in-flight list.

	// If the newPeer exists but doesn't have these listings or transactions, they will
	// simply reply with an empty ListingBundle or TransactionBundle respectively
	// for each GetListings/GetTransactions we send them. This will result in the
	// requests eventually expiring, which will cause us to remove them from
	// inventoryProcessed and potentially get the data from another Peer in the future.
	//
	// TODO: Sending a sync/mempool message to a random Peer periodically seems like it would
	// be a good way to fill any gaps.
	newPeer := srv.cmgr.RandomPeer()
	if newPeer == nil {
		// If we don't have a new Peer, remove everything that was destined for
		// this Peer. Note we don't need to copy the iterator because everything
		// below doesn't take a reference to it.
		for hash, peer := range srv.queuedListings {
			if peer.ID == pp.ID {
				srv._removeRequestt(&hash)
			}
		}
		for hash, requestInfo := range srv.requestedListings {
			if requestInfo.PeerWhoSentInv.ID == pp.ID {
				srv._removeRequestt(&hash)
			}
		}
		for hash, requestInfo := range srv.requestedTransactions {
			if requestInfo.PeerWhoSentInv.ID == pp.ID {
				srv._removeRequestt(&hash)
			}
		}
		return
	}

	// If we get here then we know we have a valid newPeer so re-assign all the
	// queued requests to newPeer.
	for listingHash, listingPeer := range srv.queuedListings {
		// Don't do anything if the requests are not meant for the Peer
		// we're disconnecting.
		if listingPeer.ID != pp.ID {
			continue
		}
		// Make it so we will send this request to the new peer.
		srv.queuedListings[listingHash] = newPeer
	}
	// For requests that are in-flight, delete them from the in-flight map and
	// move them to the queued map if they were destined for the Peer we're
	// disconnecting.
	for inFlightListingHash, requestInfo := range srv.requestedListings {
		// Don't do anything if the requests are not meant for the Peer
		// we're disconnecting.
		if requestInfo.PeerWhoSentInv.ID != pp.ID {
			continue
		}
		// If we get here it means we had a request for this hash in-flight to
		// the Peer we're disconnecting. It's OK to use a pointer to the iterator
		// here because _removeRequest does not take a reference to it.
		srv._removeRequestt(&inFlightListingHash)
		srv.queuedListings[inFlightListingHash] = newPeer
	}
	// Now that we've presumably taken some listings out of flight and
	// reassigned them to be downloaded from newPeer, call GetListings() to see
	// if we want to request anything right now.
	srv.GetListings()

	// Now deal with transactions. They don't have a queue and so all we need to do
	// is reassign the requests that were in-flight to the old Peer and then make
	// the requests to the newPeer.
	txnHashesReassigned := []*BlockHash{}
	for hashIter, requestInfo := range srv.requestedTransactions {
		// Don't do anything if the requests are not meant for the Peer
		// we're disconnecting to the new Peer.
		if requestInfo.PeerWhoSentInv.ID != pp.ID {
			continue
		}
		// Make a copy of the hash so we can take a pointer to it.
		hashCopy := &BlockHash{}
		copy(hashCopy[:], hashIter[:])

		// We will be sending this request to the new peer so update the info
		// to reflect that.
		requestInfo.PeerWhoSentInv = newPeer
		requestInfo.TimeRequested = time.Now()
		txnHashesReassigned = append(txnHashesReassigned, hashCopy)
	}
	// Request any hashes we might have reassigned in a goroutine to keep things
	// moving. Note we don't need to do this for listings because, unlike listings,
	// transactions don't have a queue so we can just fire off a simple request.
	go func() {
		newPeer.PushGetTransactionsMsg(txnHashesReassigned)
	}()
}

func (srv *Server) _handleBitcoinManagerUpdate(bmUpdate *MsgUltranetBitcoinManagerUpdate) {
	glog.Debugf("Server._handleBitcoinManagerUpdate: Being called")

	// Regardless of whether the Ultranet chain is in-sync, consider adding any BitcoinExchange
	// transactions we've found to our mempool. We do this to minimize the chances that the
	// network ever loses track of someone's BitcoinExchange.
	if len(bmUpdate.TransactionsFound) > 0 {
		go func() {
			glog.Tracef("Server._handleBitcoinManagerUpdate: BitcoinManager "+
				"found %d BitcoinExchange transactions for us to consider",
				len(bmUpdate.TransactionsFound))

			// Put all the transactions through some validation to see if they're
			// worth our time. This saves us from getting spammed by _addNewTxnAndRelay
			// when processing stale blocks.
			validTransactions := []*MsgUltranetTxn{}
			for _, burnTxn := range bmUpdate.TransactionsFound {
				err := srv.blockchain.ValidateTransaction(
					burnTxn, srv.blockchain.BlockTip().Height+1, true, /*verifySignatures*/
					true, /*verifyMerchantMerkleRoot*/
					false /*enforceBitcoinMinBurnWork*/, srv.mempool)
				if err == nil {
					validTransactions = append(validTransactions, burnTxn)
				} else {
					glog.Debugf("Server._handleBitcoinManagerUpdate: Problem adding Bitcoin "+
						"burn transaction: %v", err)
				}
			}

			glog.Tracef("Server._handleBitcoinManagerUpdate: Processing %d out of %d "+
				"transactions that were actually valid", len(validTransactions),
				len(bmUpdate.TransactionsFound))

			totalAdded := 0
			for _, validTx := range validTransactions {
				// This shouldn't care about the min burn work because it tries to add to
				// the mempool directly. We should never get an error here because we've already
				// validated all of the transactions.
				txDs, err := srv._addNewTxnAndRelay(
					nil, validTx, true /*rateLimit*/, true /*verifySignatures*/)
				totalAdded += len(txDs)

				if err != nil {
					glog.Errorf("Server._handleBitcoinManagerUpdate: Problem adding Bitcoin "+
						"burn transaction during _addNewTxnAndRelay: %v", err)
				}
			}

			glog.Tracef("Server._handleBitcoinManagerUpdate: Successfully added %d out of %d "+
				"transactions", totalAdded, len(bmUpdate.TransactionsFound))
		}()
	}

	// If the BitcoinManager is current and if the blockchain is no longer syncing,
	// give the mempool an opportunity to update any bitcoin-related information.
	if srv.bitcoinManager.IsCurrent(false /*considerCumWork*/) &&
		!srv.blockchain.IsSyncing() && srv.hasRequestedSync {
		glog.Tracef("Server._handleBitcoinManagerUpdate: Doing mempool update")

		newlyAcceptedTxns := srv.mempool.UpdateAfterBitcoinManagerNotification(
			true /*allowOrphan*/, true /*rateLimit*/, true /*verifySignatures*/)

		// Relay the newly accepted transactions in a goroutine to avoid holding
		// up the main thread.
		go func() {
			srv._relayTransactions(newlyAcceptedTxns)
		}()
	}

	// If we don't have a syncPeer right now, kick off a sync if we can. No need to
	// check if we're syncing or not since all this does is send a getheaders to a
	// Peer who's available.
	if srv.syncPeer == nil {
		glog.Debugf("Server._handleBitcoinManagerUpdate: syncPeer is nil; calling startSync")
		srv._startSync()
		return
	}

	// If we get here it means we have a syncPeer set. If the BitcoinManager is
	// time-current and we're done with the Ultranet sync, shoot them a getheaders just
	// for good measure in case there's anything to update. This will be the case
	// if it took longer to download Bitcoin
	// headers than to download Ultranet headers, and in this case this GetHeaders request
	// will initiate the download of Ultranet blocks to match the corresponding headers.
	//
	// Note that if we're in the middle of an Ultranet header sync and if the SyncPeer
	// is set then we don't send the GetHeaders since the node is presumably already
	// in the middle of processing them. Once the Ultranet header sync is complete, assuming the
	// Bitcoin header chain is also still in-sync, the rest of the Ultranet sync, including
	// block download, will proceed.
	if srv.bitcoinManager.IsCurrent(false /*considerCumWork*/) &&
		!srv.blockchain.IsSyncing() {

		glog.Debugf("Server._handleBitcoinManagerUpdate: syncPeer is NOT nil and " +
			"BitcoinManager is time-current; sending " +
			"Ultranet getheaders for good measure")
		locator := srv.blockchain.LatestHeaderLocator()
		go func() {
			srv.syncPeer.PushGetHeadersMsg(locator, &BlockHash{})
		}()
	}

	// Note there is an edge case where we may be stuck in state SyncingBlocks. Calilng
	// GetBlocks when we're in this state fixes the edge case and doesn't have any
	// negative side-effects otherwise.
	if srv.blockchain.ChainState() == SyncStateSyncingBlocks ||
		srv.blockchain.ChainState() == SyncStateNeedBlocksss {

		glog.Debugf("Server._handleBitcoinManagerUpdate: syncPeer is NOT nil and " +
			"BitcoinManager is time-current; node is in SyncStateSyncingBlocks. Calling " +
			"GetBlocks for good measure.")
		// Setting maxHeight = -1 gets us as many blocks as we can get from our
		// peer, which is OK because we can assume the peer has all of them when
		// we're syncing.
		maxHeight := -1
		srv.GetBlocks(srv.syncPeer, maxHeight)
		return
	}
}

func (srv *Server) _handleDonePeer(pp *Peer) {
	glog.Debugf("Server._handleDonePeer: Processing DonePeer: %v", pp)

	srv._cleanupDonePeerPeerState(pp)

	// Attempt to find a new peer to sync from if the quitting peer is the
	// sync peer and if our blockchain isn't current.
	if srv.syncPeer == pp && srv.blockchain.IsSyncing() {

		srv.syncPeer = nil
		srv._startSync()
	}
}

func (srv *Server) _relayListings(listingMessages []*MsgUltranetListing) {
	glog.Debugf("Server._relayListings: listing messages %d: %v", len(listingMessages), listingMessages)

	// If there are no listings to relay then just return.
	if len(listingMessages) == 0 {
		return
	}

	// Construct an inv containing the listing ids for all peers.
	invMsg := &MsgUltranetInv{}
	for _, messageToRelay := range listingMessages {
		listingHash := messageToRelay.Hash()
		invVect := &InvVect{
			Type: InvTypeListing,
			Hash: *listingHash,
		}
		// Don't relay listings if we received them as part of a sync since in
		// this case it's highly likely that other peers have them.
		if srv.syncInventory.Exists(invVect) {
			glog.Tracef("Server._relayListings: Filtering LISTING syncInventory inv: %v", spew.Sdump(invVect))
			continue
		}
		invMsg.InvList = append(invMsg.InvList, invVect)
	}

	if len(invMsg.InvList) == 0 {
		// If we don't have any invs to send just return early.
		glog.Tracef("Server._relayListings: No invs left to send after filtering")
		return
	}

	// Relay listings to all peers.
	allPeers := srv.cmgr.GetAllPeers()
	for _, pp := range allPeers {
		glog.Tracef("Server._relayListings: Sending INV %v to peer %v", spew.Sdump(invMsg), pp)
		go func(gofuncPeer *Peer) {
			// Note that this will break up the message and filter out invs if it
			// thinks the Peer already has them.
			gofuncPeer.PushInvMsg(invMsg, MaxInvPerMsg)
		}(pp)
	}
}

func (srv *Server) _relayTransactions(newlyAcceptedTxns []*TxDesc) {
	glog.Debugf("Server._relayTransactions: txDesc list: %v", newlyAcceptedTxns)

	// If there are no transactions to relay then just return.
	if len(newlyAcceptedTxns) == 0 {
		return
	}

	// Relay all newly-accepted transactions to all peers subject to the Peer's
	// minimum transaction fee constraints.
	allPeers := srv.cmgr.GetAllPeers()
	for _, pp := range allPeers {
		// For each peer construct an inventory message that excludes transactions
		// for which the minimum fee is below what the Peer will allow.
		invMsg := &MsgUltranetInv{}
		for _, newTxn := range newlyAcceptedTxns {
			// Don't add the transaction if it's below the min fee.
			minFeeAllowed := pp.MinFeeRateNanosPerKB() * newTxn.TxSizeBytes / 1000
			if newTxn.FeePerKB < minFeeAllowed {
				glog.Tracef("Server._relayTransactions: Not relaying transaction to Peer "+
					"because feePerKB %d is lower than Peer's minFee %d: < Inv: %v, Peer: %v >",
					newTxn.FeePerKB, minFeeAllowed, invMsg, pp)
				continue
			}
			invVect := &InvVect{
				Type: InvTypeTx,
				Hash: *newTxn.Hash,
			}
			// Don't relay transactions if we received them as part of a sync since in
			// this case it's highly likely that other peers have them.
			if srv.syncInventory.Exists(invVect) {
				glog.Tracef("Server._relayTransactions: Filtering TRANSACTION syncInventory inv: %v", spew.Sdump(invVect))
				continue
			}
			invMsg.InvList = append(invMsg.InvList, invVect)
		}

		glog.Tracef("Server._relayTransactions: Sending INV %v to peer %v", spew.Sdump(invMsg), pp)
		go func(gofuncPeer *Peer) {
			// Note that this will break up the message and filter out invs if it
			// thinks the Peer already has them.
			gofuncPeer.PushInvMsg(invMsg, MaxInvPerMsg)
		}(pp)
	}
}

func (srv *Server) _addNewTxnAndRelay(
	pp *Peer, txn *MsgUltranetTxn, rateLimit bool, verifySignatures bool) ([]*TxDesc, error) {

	srv.blockchain.ChainLock.RLock()
	defer srv.blockchain.ChainLock.RUnlock()

	glog.Debugf("Server._addNewTxnAndRelay: txn: %v, peer: %v", txn, pp)

	// Try and add the transaction to the mempool.
	peerID := uint64(0)
	if pp != nil {
		peerID = pp.ID
	}
	newlyAcceptedTxns, err := srv.mempool.ProcessTransaction(
		txn, true /*allowOrphan*/, rateLimit, peerID, verifySignatures)
	if err != nil {
		return nil, errors.Wrapf(err, "Server._handleTransaction: Problem adding transaction to mempool: ")
	}

	glog.Debugf("Server._addNewTxnAndRelay: newlyAcceptedTxns: %v, Peer: %v", newlyAcceptedTxns, pp)

	// If adding the transaction was successful, broadcast an inv
	// for all of the accepted transactions to our peers in a goroutine
	// to avoid holding up the main thread.
	go func() {
		srv._relayTransactions(newlyAcceptedTxns)
	}()

	return newlyAcceptedTxns, nil
}

func (srv *Server) _handleBlockMainChainConnected(blk *MsgUltranetBlock) {
	// Lock the blockchain for reading.
	srv.blockchain.ChainLock.RLock()
	defer srv.blockchain.ChainLock.RUnlock()

	// Don't do anything mempool-related until our best block chain is done
	// syncing.
	if srv.blockchain.isSyncing() {
		return
	}

	// If we're current, update the mempool to remove the transactions
	// in this block from it. We can't do this in a goroutine because we
	// need each mempool update to happen in the same order as that in which
	// we connected the blocks and this wouldn't be guaranteed if we kicked
	// off a goroutine for each update.
	newlyAcceptedTxns := srv.mempool.UpdateAfterConnectBlock(blk)

	// Relay the newly accepted transactions in a goroutine to avoid holding
	// up the main thread.
	go func() {
		srv._relayTransactions(newlyAcceptedTxns)
	}()

	// Update the listing manager in a goroutine to avoid holding up the main
	// thread.
	go func() {
		if err := srv.listingManager.Update(); err != nil {
			glog.Errorf("Server._handleBlockMainChainConnected: Problem updating "+
				"ListingManager after block connected to main chain: %v", err)
		}
	}()

	blockHash, _ := blk.Header.Hash()
	glog.Debugf("_handleBlockMainChainConnected: Block %s height %d connected to "+
		"main chain and chain is current.", hex.EncodeToString(blockHash[:]), blk.Header.Height)
}

func (srv *Server) _handleBlockMainChainDisconnected(blk *MsgUltranetBlock) {
	// Lock the blockchain for reading.
	srv.blockchain.ChainLock.RLock()
	defer srv.blockchain.ChainLock.RUnlock()

	// Don't do anything mempool-related until our best block chain is done
	// syncing.
	if srv.blockchain.isSyncing() {
		return
	}

	// If we're current, update the mempool to add back the transactions
	// in this block. We can't do this in a goroutine because we
	// need each mempool update to happen in the same order as that in which
	// we connected the blocks and this wouldn't be guaranteed if we kicked
	// off a goroutine for each update.
	srv.mempool.UpdateAfterDisconnectBlock(blk)

	// Update the listing manager in a goroutine to avoid holding up the main
	// thread.
	go func() {
		if err := srv.listingManager.Update(); err != nil {
			glog.Errorf("Server._handleBlockMainChainConnected: Problem updating "+
				"ListingManager after block connected to main chain: %v", err)
		}
	}()

	blockHash, _ := blk.Header.Hash()
	glog.Debugf("_handleBlockMainChainDisconnect: Block %s height %d disconnected from "+
		"main chain and chain is current.", hex.EncodeToString(blockHash[:]), blk.Header.Height)
}

func (srv *Server) _maybeRequestSync(pp *Peer) {
	// Note that we gate this on the BitcoinManager being time-current since if it is not then
	// we will not be able to properly process new transactions and potentially listings
	// as well. Generally, if we get to the point where the Ultranet chain is fully current
	// then the BitcoinManager should generally also be time-current, so this check is a bit
	// paranoid but that's OK.
	if srv.blockchain.chainState() == SyncStateFullyCurrent &&
		srv.bitcoinManager.IsCurrent(false /*considerCumWork*/) &&
		!srv.hasRequestedSync {
		glog.Tracef("server._maybeRequestSync: Server is in need of sync from Peer %v: "+
			"(ChainState: %v, BitcoinManager.IsCurrent: %v hasRequestedSync: %v)",
			pp, srv.blockchain.chainState(), srv.bitcoinManager.IsCurrent(false), srv.hasRequestedSync)

		// Choose a peer to get the mempool transactions from if we don't have
		// one passed-in.
		if pp == nil {
			pp = srv.syncPeer
		}
		if pp == nil {
			pp = srv.cmgr.RandomPeer()
		}
		if pp != nil {
			srv.hasRequestedSync = true
			// Clear the inventoryBeingProcessed so that we re-fetch transactions that
			// we may have rejected due to not being fully current.
			srv.inventoryBeingProcessed.Reset()
			go func() {
				glog.Debugf("Server._maybeRequestSync: Sending MEMPOOL message to Peer %v", pp)
				pp.QueueMessage(&MsgUltranetMempool{})
			}()
			go func() {
				glog.Debugf("Server._maybeRequestSync: Sending LISTING_SYNC message to Peer %v", pp)
				pp.QueueMessage(&MsgUltranetListingSync{})
			}()
		} else {
			// If we couldn't get a Peer to get mempool transactions from, then don't
			// do the mempool sync yet.
			glog.Debugf("Server._maybeRequestSync: Node is FULLY_SYNCED but " +
				"can't find a Peer to source Mempool transactions and Listings from")
		}
	} else {
		glog.Tracef("server._maybeRequestSync: Not sending sync message to Peer %v: "+
			"(ChainState: %v, BitcoinManager.IsCurrent: %v hasRequestedSync: %v)",
			pp, srv.blockchain.chainState(), srv.bitcoinManager.IsCurrent(false), srv.hasRequestedSync)
	}
}

func (srv *Server) _handleBlockAccepted(blk *MsgUltranetBlock) {
	// Lock the blockchain for reading.
	srv.blockchain.ChainLock.RLock()
	defer srv.blockchain.ChainLock.RUnlock()

	// Don't relay blocks until our best block chain is done syncing.
	if srv.blockchain.isSyncing() {
		return
	}

	// If we're fully current after accepting all the blocks but we have not
	// yet requested all of the mempool transactions and listings from one of our peers, do
	// that now. This covers the case where our node is behind when it boots
	// up, making it so that right at the end of the node's initial sync, after
	// everything has been connected, we then bootstrap our mempool.
	srv._maybeRequestSync(nil)

	// Construct an inventory vector to relay to peers.
	blockHash, _ := blk.Header.Hash()
	invVect := &InvVect{
		Type: InvTypeBlock,
		Hash: *blockHash,
	}

	// Iterate through all the peers and relay the InvVect to them. This will only
	// actually be relayed if it's not already in the peer's knownInventory.
	allPeers := srv.cmgr.GetAllPeers()
	for _, pp := range allPeers {
		pp.PushInvVect(invVect, MaxInvPerMsg)
	}
}

func _printNodeMap(mm map[BlockHash]*MsgUltranetBlock) string {
	strList := []string{}
	for kk, vv := range mm {
		strList = append(strList, fmt.Sprintf("< %v: %v>", &kk, vv))
	}
	return strings.Join(strList, ", ")
}

func _printBlockMap(mm map[BlockHash]*MsgUltranetBlock) string {
	strList := []string{}
	for kkIter, vv := range mm {
		kkCopy := kkIter
		strList = append(strList, fmt.Sprintf("< %v: %v>", &kkCopy, vv))
	}
	return strings.Join(strList, ", ")
}

func _printServerMessageMap(mm map[BlockHash]*ServerMessage) string {
	strList := []string{}
	for kkIter, vv := range mm {
		kk := kkIter
		strList = append(strList, fmt.Sprintf("< peer: %v, blockhash: %v, message: %v>", vv.Peer, &kk, vv.Msg))
	}
	return strings.Join(strList, ", ")
}

func (srv *Server) _logAndDisconnectPeer(pp *Peer, blockMsg *MsgUltranetBlock, suffix string) {
	// Disconnect the Peer. Generally-speaking, disconnecting from the peer will cause its
	// requested blocks and txns to be removed from the global maps and cause it to be
	// replaced by another peer. Furthermore,
	// if we're in the process of syncing our node, the startSync process will also
	// be restarted as a resul. If we're not syncing our peer and have instead reached
	// the steady-state, then the next interesting inv message should cause us to
	// fetch headers, blocks, etc. So we'll be back.
	glog.Errorf("Server._handleBlock: Encountered an error processing "+
		"block %v. Disconnecting from peer %v: %s", blockMsg, pp, suffix)
	pp.Disconnect()
	return
}

func (srv *Server) _handleBlock(pp *Peer, blk *MsgUltranetBlock) {
	glog.Tracef("Server._handleBlock: Received block %v from Peer %v", blk, pp)

	// Pull out the header for easy access.
	blockHeader := blk.Header
	if blockHeader == nil {
		// Should never happen but check it nevertheless.
		srv._logAndDisconnectPeer(pp, blk, "Header was nil")
		return
	}
	// Compute the hash of the block.
	blockHash, err := blk.Header.Hash()
	if err != nil {
		// This should never happen if we got this far but log the error, clear the
		// requestedBlocks, disconnect from the peer and return just in case.
		srv._logAndDisconnectPeer(
			pp, blk, "Problem computing block hash")
		return
	}
	// If the block isn't in requestedBlocks then disconnect from the peer and
	// return. The Server should only process blocks from peers if it has first
	// requested them. Anything internal that wants to process a block, like the
	// miner for example, should call ProcessBlock directly. This will trigger
	// callbacks on the Server to relay the block, among other things.
	// TODO: This API could be a lot cleaner.
	requestMessage, isRequested := srv.requestedBlocks[*blockHash]
	if !isRequested || requestMessage == nil {
		srv._logAndDisconnectPeer(
			pp, blk,
			fmt.Sprintf("Received block from peer that was never requested; "+
				"requestedBlocks: %v", _printServerMessageMap(srv.requestedBlocks)))
		return
	}

	// Mark the block as "received" in our requestedBlocks map. This amounts to
	// associating the block with its entry in the map, which would have been
	// nil before.
	requestMessage.Msg = blk

	// As long as we can accept one of the blocks we've received, which includes
	// taking it in as a side-chain block, keep doing so while removing the blocks
	// from the requestedBlocks map as we go.
	didAcceptBlock := true
	for didAcceptBlock {
		didAcceptBlock = false
		// Iterate over the blocks we've requested that that we've received. This list
		// should generally be short and processing the blocks that are orphans
		// should take almost no time.
		for currentHashIter, messageToProcess := range srv.requestedBlocks {
			// Make a copy since the iteratr could change from under us.
			currentHash := currentHashIter

			// None of the keys in requestBlocks should be nil ever.
			if messageToProcess == nil {
				srv._logAndDisconnectPeer(
					pp, blk,
					fmt.Sprintf("Message for block hash %v in requestBlocks was nil: %v",
						&currentHash, _printServerMessageMap(srv.requestedBlocks)))
			}
			// We haven't received this block yet so don't try to process it.
			if messageToProcess.Msg == nil {
				continue
			}
			blockToProcess := messageToProcess.Msg.(*MsgUltranetBlock)
			verifySignatures := true
			_, isOrphan, err := srv.blockchain.ProcessBlock(blockToProcess, verifySignatures)
			// If we hit an error then abort mission entirely. We should generally never
			// see an error with a block from a peer. No need to check an error on the hash
			// below because everything in our list should have already been checked.
			if err != nil {
				if strings.Contains(err.Error(), "RuleErrorDuplicateBlock") {
					// Just warn on duplicate blocks but don't disconnect the peer.
					// TODO: This assuages a bug similar to the one referenced in the duplicate
					// headers comment above but in the future we should probably try and figure
					// out a way to be more strict about things.
					glog.Warningf("Got duplicate block %v from peer %v", blockToProcess, pp)
				} else {
					srv._logAndDisconnectPeer(
						pp, blk,
						errors.Wrapf(err, "Error while processing block: ").Error())
					return
				}
			}
			if isOrphan {
				// If the block is an orphan then we're not ready to acept it
				// yet. Try the next one.
				continue
			}

			// If we get here then we managed to accept the block. Remove it from
			// requestedBlocks since it has officially been processed and restart
			// the whole iteration over again.
			delete(srv.requestedBlocks, currentHash)
			didAcceptBlock = true
			break
		}
	}

	// At this point, we should have accepted all the blocks we're capable of
	// accepting from requestedBlocks.

	// At this point if requestedBlocks is non-empty but we've fetched all of
	// the blocks we requested, this is an error state. This is the case because
	// whenever we request a batch of blocks, we are 100% certain that the batch
	// as a whole does not contain any orphans (even though we might temporarily
	// have some orphans because we process them out of order). Having blocks
	// we can't accept after fully fetching a batch thus violates the assumption
	// that there are no orphans, and so the node is acting up.
	if len(srv.requestedBlocks) != 0 {
		// If there are no nil values, it means we've fetched everything yet
		// still can't accept some blocks. This is the error condition referenced
		// above.
		foundNilValue := false
		for _, requestMessage := range srv.requestedBlocks {
			if requestMessage == nil || requestMessage.Msg == nil {
				foundNilValue = true
				break
			}
		}
		if !foundNilValue {
			srv._logAndDisconnectPeer(
				pp, blk,
				"Downloaded all blocks that were requested yet we still "+
					"have orphans. This should never happen.")
		}
	}

	// At this point we have either accepted all of the blocks we requested
	// or we have some blocks we still need to wait to receive. Take action
	// depending on the state we're in.

	// We shouldn't be receiving blocks while syncing headers.
	if srv.blockchain.ChainState() == SyncStateSyncingHeaders {
		srv._logAndDisconnectPeer(
			pp, blk,
			"We should never get blocks when we're syncing headers")
		return
	}

	// If we're syncing blocks, call GetBlocks and try to get as many blocks
	// from our peer as we can. This allows the initial block download to be
	// more incremental since every time we're able to accept a block (or
	// group of blocks) we indicate this to our peer so they can send us more.
	if srv.blockchain.ChainState() == SyncStateSyncingBlocks {
		// Setting maxHeight = -1 gets us as many blocks as we can get from our
		// peer, which is OK because we can assume the peer has all of them when
		// we're syncing.
		maxHeight := -1
		srv.GetBlocks(pp, maxHeight)
		return
	}

	if srv.blockchain.ChainState() == SyncStateNeedBlocksss {
		// If we don't have any blocks to wait for anymore, hit the peer with
		// a GetHeaders request to see if there are any more headers we should
		// be aware of. This will generally happen in two cases:
		// - With our sync peer after we’re almost at the end of syncing blocks.
		//   In this case, calling GetHeaders once the requestedblocks is almost
		//   gone will result in us getting all of the remaining blocks right up
		//   to the tip and then stopping, which is exactly what we want.
		// - With a peer that sent us an inv. In this case, the peer could have
		//   more blocks for us or it could not. Either way, it’s good to check
		//   and worst case the peer will return an empty header bundle that will
		//   result in us not sending anything back because there won’t be any new
		//   blocks to request.
		if len(srv.requestedBlocks) == 0 {
			locator := srv.blockchain.LatestHeaderLocator()
			go func() {
				pp.PushGetHeadersMsg(locator, &BlockHash{})
			}()
		}
		return
	}

	// If we get here, it means we're in SyncStateFullySynced, which is great.
	// In this case we can relax and wait for invs to come in.
}

func _deleteOne(m map[BlockHash]*ServerMessage) *BlockHash {
	for txHash := range m {
		// Remove a random entry from the map.  For most compilers, Go's
		// range statement iterates starting at a random item although
		// that is not 100% guaranteed by the spec.  The iteration order
		// is not important here because an adversary would have to be
		// able to pull off preimage attacks on the hashing function in
		// order to target eviction of specific entries anyways.
		delete(m, txHash)
		// Make a copy so the iterator doesn't change beneath us.
		hashDeleted := txHash
		return &hashDeleted
	}
	return nil
}

func (srv *Server) _handleInv(peer *Peer, msg *MsgUltranetInv) {
	// Ignore invs while we're still syncing and before we've requested
	// all mempool transactions from one of our peers to bootstrap.
	if srv.blockchain.IsSyncing() || !srv.hasRequestedSync {
		glog.Tracef("Server._handleInv: Ignoring INV while syncing from Peer %v", peer)
		return
	}

	// Expire any listings or transactions that we've been waiting too long on.
	// Also remove them from inventoryProcessed in case another Peer wants to send
	// them to us in the future.
	srv.ExpireRequests()

	// Iterate through the message. Gather the transactions and the
	// blocks we don't already have into separate inventory lists.
	glog.Tracef("Server._handleInv: Processing INV message %v from peer %v", spew.Sdump(msg), peer)
	txHashList := []*BlockHash{}
	blockHashList := []*BlockHash{}
	listingHashList := []*BlockHash{}

	for _, invVect := range msg.InvList {
		// No matter what, add the inv to the peer's known inventory.
		peer.knownInventory.Add(invVect)

		// If this is a hash we are currently processing, no need to do anything.
		// This check serves to fill the gap between the time when we've decided
		// to ask for the data corresponding to an inv and when we actually receive
		// that data. Without this check, the following would happen:
		// - Receive inv from peer1
		// - Get data for inv from peer1
		// - Receive same inv from peer2
		// - Get same data for same inv from peer2 before we've received
		//   a response from peer1
		// Instead, because of this check, the following happens instead:
		// - Receive inv from peer1
		// - Get data for inv from peer1 *and* add it to inventoryBeingProcessed.
		// - Receive same inv from peer2
		// - Notice second inv is already in inventoryBeingProcessed so don't
		//   request data for it.
		if srv.inventoryBeingProcessed.Exists(invVect) {
			continue
		}

		// Extract a copy of the block hash to avoid the iterator changing the
		// value underneath us.
		currentHash := BlockHash{}
		copy(currentHash[:], invVect.Hash[:])

		if invVect.Type == InvTypeTx {
			// For transactions, check that the transaction isn't in the
			// mempool and that it isn't currently being requested.
			_, requestIsInFlight := srv.requestedTransactions[currentHash]
			if requestIsInFlight || srv.mempool.IsTransactionInPool(&currentHash) {
				continue
			}

			txHashList = append(txHashList, &currentHash)
		} else if invVect.Type == InvTypeBlock {
			// For blocks, we check that the hash isn't known to us either in our
			// main header chain or in side chains.
			if srv.blockchain.HasHeader(&currentHash) {
				continue
			}

			blockHashList = append(blockHashList, &currentHash)
		} else if invVect.Type == InvTypeListing {
			// For listings, check to make sure that we haven't already queued
			// this listing to be requested.
			_, requestIsQueued := srv.queuedListings[currentHash]
			_, requestIsInFlight := srv.requestedListings[currentHash]
			if requestIsQueued || requestIsInFlight || srv.listingManager.HasHash(&currentHash) {
				continue
			}

			listingHashList = append(listingHashList, &currentHash)
		}

		// If we made it here, it means the inventory was added to one of the
		// lists so mark it as processed on the Server.
		srv.inventoryBeingProcessed.Add(invVect)
		// If the inventory was sent as part of a sync, track that so that we
		// can avoid relaying the transaction in these situations.
		if msg.IsSyncResponse {
			srv.syncInventory.Add(invVect)
		}
	}

	// If there were any transactions we don't yet have, request them using
	// a GetTransactions message.
	if len(txHashList) > 0 {
		// Add all the transactions we think we need to the list of transactions
		// requested (i.e. in-flight) since we're about to request them.
		//
		// TODO: The same problem that afflicts queuedListings below also affects
		// requestedTransactions because we don't put a cap on it. The fix to this
		// is easy: Implement a cap and purge transactions (and peers) when the cap
		// is hit so you don't OOM as mentioned below.
		for _, txHash := range txHashList {
			srv.requestedTransactions[*txHash] = &GetDataRequestInfo{
				PeerWhoSentInv: peer,
				TimeRequested:  time.Now(),
			}
		}
		go func() {
			peer.PushGetTransactionsMsg(txHashList)
		}()
	}

	// If the peer has sent us any block hashes that are new to us then send
	// a GetHeaders message to her to get back in sync with her. The flow
	// for this is generally:
	// - Receive an inv message from a peer for a block we don't have.
	// - Send them a GetHeaders message with our most up-to-date block locator.
	// - Receive back from them all the headers they're aware of that can be
	//   accepted into our chain.
	// - We will then request from them all of the block data for the new headers
	//   we have if they affect our main chain.
	// - When the blocks come in, we process them by adding them to the chain
	//   one-by-one.
	if len(blockHashList) > 0 {
		locator := srv.blockchain.LatestHeaderLocator()
		go func() {
			peer.PushGetHeadersMsg(locator, &BlockHash{})
		}()
	}

	if len(listingHashList) > 0 {
		// Add the listing hashes we just found to queued listings and call GetListings
		// to process them. GetListings takes into consideration how many listing requests
		// are in-flight so we don't overwhelm any peers (or ourselves). We don't need
		// to run it in a goroutine because its work is quick and it kicks off all network
		// requests in goroutines.
		//
		// TODO: Right now it is possible for queuedListings to grow without bound if,
		// for example, a Peer sends us a lot of garbage inv messages. An easy way to
		// thwart this is to:
		// - See if queuedMessages is above some ridiculous threshold in terms of size
		//   like 100 * MaxMerchants * MaxListingsPerMerchant (which would still only
		//   make it a few hundred MB in size even though it can clearly only happen
		//   if someone is attacking us).
		// - If it is above the threshold, look through it and disconnect any Peers
		//   who have more than   MaxMerchants * MaxListingsPerMerchant invs. These
		//   Peers are clearly just sending us fake invs.
		for _, listingHash := range listingHashList {
			srv.queuedListings[*listingHash] = peer
		}
		srv.GetListings()
	}
}

func (srv *Server) _handleGetListings(pp *Peer, msg *MsgUltranetGetListings) {
	glog.Debugf("Server._handleGetListings: Received GetListings message %v from Peer %v", msg, pp)

	// If there are too many listings being requested, disconnect the
	// Peer.
	if len(msg.HashList) > MaxListingsPerGetListingsMsg {
		glog.Errorf(fmt.Sprintf("Server._handleGetListings: Listing hashes "+
			"requested %d exceeds maximum allowed %d -- disconnecting Peer %v",
			len(msg.HashList), MaxListingsPerGetListingsMsg, pp))
		pp.Disconnect()
		return
	}

	// For each listing hash requested, attempt to fetch it from the ListingManager.
	listingBundle := &MsgUltranetListingBundle{}
	for _, listingHash := range msg.HashList {
		listingMessage := srv.listingManager.GetListingForHash(listingHash)
		if listingMessage != nil {
			listingBundle.Listings = append(listingBundle.Listings, listingMessage)
		}
	}

	// At this point the response should have all of the listings that
	// we had available from the request. It should also be below the limit
	// for number of listings since the request itself was below the
	// limit. So push the bundle to the Peer. Do this in a goroutine so
	// we don't hold up the main thread.
	glog.Tracef("Server._handleGetListings: Calling PushListingBundleMsg with %v for peer %v", msg, pp)
	go func() {
		pp.PushListingBundleMsg(listingBundle)
	}()
}

func (srv *Server) _handleGetTransactions(pp *Peer, msg *MsgUltranetGetTransactions) {
	glog.Debugf("Server._handleGetTransactions: Received GetTransactions "+
		"message %v from Peer %v", msg, pp)

	// If there are too many transactions being requested, disconnect the
	// Peer.
	if len(msg.HashList) > MaxTxnsPerGetTransactionsMsg {
		glog.Errorf(fmt.Sprintf("Server._handleGetTransactions: Transaction hashes "+
			"requested %d exceeds maximum allowed %d -- disconnecting Peer %v",
			len(msg.HashList), MaxTxnsPerGetTransactionsMsg, pp))
		pp.Disconnect()
		return
	}

	// Get all the transactions we have from the mempool.
	glog.Tracef("Server._handleGetTransactions: Processing MsgUltranetGetTransactions %v from peer %v", msg, pp)
	txDescs := []*TxDesc{}
	for _, txHash := range msg.HashList {
		txD := srv.mempool.FetchTransaction(txHash)
		// If the transaction isn't in the pool, just continue without adding
		// it. It is generally OK to respond with only a subset of the transactions
		// that were requested.
		if txD == nil {
			continue
		}

		txDescs = append(txDescs, txD)
	}

	// Sort the transactions in the order in which they were added to the mempool.
	// Doing this helps the Peer when they go to add the transactions by reducing
	// orphans and transactions being rejected due to missing dependencies.
	sort.Slice(txDescs, func(ii, jj int) bool {
		return txDescs[ii].Added.Before(txDescs[jj].Added)
	})

	// Add all of the fetched transactions to a response.
	res := &MsgUltranetTransactionBundle{}
	for _, txD := range txDescs {
		res.Transactions = append(res.Transactions, txD.Tx)
	}

	// At this point the response should have all of the transactions that
	// we had available from the request. It should also be below the limit
	// for number of transactions since the request itself was below the
	// limit. So push the bundle to the Peer. Do this in a goroutine so
	// we don't hold up the main thread.
	glog.Tracef("Server._handleGetTransactions: Calling PushTransactionBundleMsg with %v for peer %v", msg, pp)
	go func() {
		pp.PushTransactionBundleMsg(res)
	}()
}

func (srv *Server) _handleListingBundle(pp *Peer, msg *MsgUltranetListingBundle) {
	glog.Debugf("Server._handleListingBundle: Received ListingBundle message %v from Peer %v", msg, pp)

	// If there are too many listings being returned, disconnect the
	// Peer.
	if len(msg.Listings) > MaxListingsPerGetListingsMsg {
		glog.Errorf(fmt.Sprintf("Server._handleListingBundle: Number of "+
			"listings in bundle %d exceeds maximum allowed %d -- disconnecting Peer",
			len(msg.Listings), MaxListingsPerGetListingsMsg))
		pp.Disconnect()
	}

	// Call ProcessListing on all of the listings. Queue the listings that pass
	// so we can relay them to other Peers.
	glog.Tracef("Server._handleListingBundle: Processing message %v from peer %v", msg, pp)
	listingsToRelay := []*MsgUltranetListing{}
	for _, listingMessage := range msg.Listings {
		err := srv.listingManager.ProcessListing(listingMessage, true)
		if err != nil {
			glog.Debugf(fmt.Sprintf("Server._handleListingBundle: Rejected "+
				"listing %v from peer %v: %v", listingMessage, pp, err))
			continue
		}

		// If we had no error, queue the listing for relay.
		listingsToRelay = append(listingsToRelay, listingMessage)
	}

	// Remove all the listings we received from requestedListings now
	// that we've processed them. Don't remove them from inventoryBeingProcessed,
	// since that will guard against reprocessing listings that had errors while
	// processing.
	for _, lisingMessage := range msg.Listings {
		listingHash := lisingMessage.Hash()
		delete(srv.requestedListings, *listingHash)
	}

	// Since we just removed a bunch of listings from the queue, go ahead and
	// request some more if we have any.
	srv.GetListings()

	// Relay all the listings that were accepted without error.
	srv._relayListings(listingsToRelay)

	// At this point we should have attempted to add all the listings to our
	// mempool so return.
	return

}

func (srv *Server) _handleTransactionBundle(pp *Peer, msg *MsgUltranetTransactionBundle) {
	glog.Debugf("Server._handleTransactionBundle: Received TransactionBundle "+
		"message %v from Peer %v", msg, pp)

	// If there are too many transactions being returned, disconnect the
	// Peer.
	if len(msg.Transactions) > MaxTxnsPerGetTransactionsMsg {
		glog.Errorf(fmt.Sprintf("Server._handleTransactionBundle: Number of "+
			"transactions in bundle %d exceeds maximum allowed %d -- disconnecting Peer",
			len(msg.Transactions), MaxTxnsPerGetTransactionsMsg))
		pp.Disconnect()
	}

	// Try and add all the transactions to our mempool in the order we received
	// them. If any fail to get added, just log an error.
	//
	// TODO: It would be nice if we did something fancy here like if we kept
	// track of rejected transactions and retried them every time we connected
	// a block. Doing something like this would make it so that if a transaction
	// was initially rejected due to us not having its dependencies, then we
	// will eventually add it as opposed to just forgetting about it.
	glog.Tracef("Server._handleTransactionBundle: Processing message %v from peer %v", msg, pp)
	transactionsToRelay := []*TxDesc{}
	for _, txn := range msg.Transactions {
		// Process the transaction with rate-limiting while allowing orphans and
		// verifying signatures.
		newlyAcceptedTxns, err := srv.mempool.ProcessTransaction(
			txn, true /*allowOrphan*/, true /*rateLimit*/, pp.ID, true /*verifySignatures*/)
		if err != nil {
			glog.Debugf(fmt.Sprintf("Server._handleTransactionBundle: Rejected "+
				"transaction %v from peer %v from mempool: %v", txn, pp, err))
			// A peer should know better than to send us a transaction that's below
			// our min feerate, which they see when we send them a version message.
			if err == TxErrorInsufficientFeeMinFee {
				glog.Errorf(fmt.Sprintf("Server._handleTransactionBundle: Disconnecting "+
					"Peer %v for sending us a transaction %v with fee below the minimum fee %d",
					pp, txn, srv.mempool.minFeeRateNanosPerKB))
				pp.Disconnect()
			}

			// Don't do anything else if we got an error.
			continue
		}

		// If we get here then the transaction was accepted into our mempool.
		// Queue the transactions that were accepted them for relay to all of the peers
		// who don't yet have them.
		transactionsToRelay = append(transactionsToRelay, newlyAcceptedTxns...)
	}

	// Remove all the transactions we received from requestedTransactions now
	// that we've processed them. Don't remove them from inventoryBeingProcessed,
	// since that will guard against reprocessing transactions that had errors while
	// processing.
	for _, txn := range msg.Transactions {
		txHash := txn.Hash()
		delete(srv.requestedTransactions, *txHash)
	}

	// Relay all the transactions that were accepted.
	srv._relayTransactions(transactionsToRelay)

	// At this point we should have attempted to add all the transactions to our
	// mempool so return.
	return
}

func (srv *Server) _handleMempool(pp *Peer, msg *MsgUltranetMempool) {
	glog.Debugf("Server._handleMempool: Received Mempool message from Peer %v", pp)

	// When you get a mempool message from a Peer, forget everything you know
	// about her inventory.
	pp.knownInventory.Reset()

	// When we get a mempool message, just send the peer everything that we
	// have in the mempool sorted by when each transaction was added. Do it
	// in a goroutine so we don't hold up the main thread.
	go func() {
		// Get all of the transactions from the mempool sorted.
		txDescs, orphanTxns, err := srv.mempool._getTransactionsOrderedByTimeAdded()
		if err != nil {
			// If we have a problem fetching the mempool transactions, just log an
			// error and move on.
			glog.Debugf(fmt.Sprintf("Server._handleMempool: Problem fetching transactions from "+
				"mempool in response to MEMPOOL request for Peer %v: %v", pp, err))
			return
		}

		// Construct an inv message from all the transactions. If any transaction
		// has a fee below the Peer's min fee then don't include it.
		invMsg := &MsgUltranetInv{
			IsSyncResponse: true,
		}
		for _, txD := range txDescs {
			// Don't add the transaction if it's below the min fee.
			minFeeAllowed := pp.MinFeeRateNanosPerKB() * txD.TxSizeBytes / 1000
			if txD.FeePerKB < minFeeAllowed {
				continue
			}
			invMsg.InvList = append(invMsg.InvList, &InvVect{
				Type: InvTypeTx,
				Hash: *txD.Hash,
			})
		}
		// Include orphan transactions at the end as well.
		for _, oTx := range orphanTxns {
			txHash := oTx.tx.Hash()
			invMsg.InvList = append(invMsg.InvList, &InvVect{
				Type: InvTypeTx,
				Hash: *txHash,
			})
		}

		glog.Tracef("Server._handleMempool: Sending invs %v to Peer %v", spew.Sdump(invMsg), pp)

		// At this point the invMsg should contain everything we have. The
		// Peer's method below will break it up into appropriately-sized
		// chunks so we don't overwhelm the Peer.
		pp.PushInvMsg(invMsg, MaxInvPerMsg)
	}()
	// Send them in chunks via inv.
}
func (srv *Server) _handleListingSync(pp *Peer, msg *MsgUltranetListingSync) {
	glog.Debugf("Server._handleListingSync: Received ListingSync message from Peer %v", pp)

	// When you get a ListingSync message from a Peer, forget everything you know
	// about her inventory.
	pp.knownInventory.Reset()

	// When we get a ListingSync message, just send the peer everything that we
	// have in the db. Do it in a goroutine so we don't hold up the main thread.
	go func() {
		hashes, err := srv.listingManager.GetAllListingHashes()
		if err != nil {
			glog.Errorf("Problem getting listing hashes for syncing: %v", hashes)
			return
		}

		// Construct an inv message from all the transactions. If any transaction
		// has a fee below the Peer's min fee then don't include it.
		invMsg := &MsgUltranetInv{
			// Specify that this is a response to a sync message so the Peer can do
			// some book-keeping to avoid relaying the response.
			IsSyncResponse: true,
		}
		for _, hash := range hashes {
			invMsg.InvList = append(invMsg.InvList, &InvVect{
				Type: InvTypeListing,
				Hash: *hash,
			})
		}

		glog.Tracef("Server._handleListingSync: Sending invs %v to Peer %v", spew.Sdump(invMsg), pp)

		// At this point the invMsg should contain everything we have. The
		// Peer's method below will break it up into appropriately-sized
		// chunks so we don't overwhelm the Peer.
		pp.PushInvMsg(invMsg, MaxInvPerMsg)
	}()
	// Send them in chunks via inv.
}

func (srv *Server) _handleAddrMessage(pp *Peer, msg *MsgUltranetAddr) {
	srv.addrsToBroadcastLock.Lock()
	defer srv.addrsToBroadcastLock.Unlock()

	glog.Debugf("Server._handleAddrMessage: Received Addr from peer %v with addrs %v", pp, spew.Sdump(msg.AddrList))

	// If this addr message contains more than the maximum allowed number of addresses
	// then disconnect this peer.
	if len(msg.AddrList) > MaxAddrsPerAddrMsg {
		glog.Errorf(fmt.Sprintf("Server._handleAddrMessage: Disconnecting "+
			"Peer %v for sending us an addr message with %d transactions, which exceeds "+
			"the max allowed %d",
			pp, len(msg.AddrList), MaxAddrsPerAddrMsg))
		pp.Disconnect()
		return
	}

	// Add all the addresses we received to the addrmgr.
	netAddrsReceived := []*wire.NetAddress{}
	for _, addr := range msg.AddrList {
		addrAsNetAddr := wire.NewNetAddressIPPort(addr.IP, addr.Port, (wire.ServiceFlag)(addr.Services))
		if !addrmgr.IsRoutable(addrAsNetAddr) {
			glog.Debugf("Dropping address %v from peer %v because it is not routable", addr, pp)
			continue
		}

		netAddrsReceived = append(
			netAddrsReceived, addrAsNetAddr)
	}
	srv.cmgr.addrMgr.AddAddresses(netAddrsReceived, pp.netAddr)

	// If the message had <= 10 addrs in it, then queue all the addresses for relaying
	// on the next cycle.
	if len(msg.AddrList) <= 10 {
		glog.Debugf("Server._handleAddrMessage: Queueing %d addrs for forwarding from "+
			"peer %v", len(msg.AddrList), pp)
		sourceAddr := &SingleAddr{
			Timestamp: time.Now(),
			IP:        pp.netAddr.IP,
			Port:      pp.netAddr.Port,
			Services:  pp.serviceFlags,
		}
		listToAddTo, hasSeenSource := srv.addrsToBroadcastt[sourceAddr.String(false /*includePort*/)]
		if !hasSeenSource {
			listToAddTo = []*SingleAddr{}
		}
		// If this peer has been sending us a lot of little crap, evict a lot of their
		// stuff but don't disconnect.
		if len(listToAddTo) > MaxAddrsPerAddrMsg {
			listToAddTo = listToAddTo[:MaxAddrsPerAddrMsg/2]
		}
		for _, addr := range msg.AddrList {
			listToAddTo = append(listToAddTo, addr)
		}
		srv.addrsToBroadcastt[sourceAddr.String(false /*includePort*/)] = listToAddTo
	}
}

func (srv *Server) _handleGetAddrMessage(pp *Peer, msg *MsgUltranetGetAddr) {
	glog.Debugf("Server._handleGetAddrMessage: Received GetAddr from peer %v", pp)
	// When we get a GetAddr message, choose MaxAddrsPerMsg from the AddrMgr
	// and send them back to the peer.
	netAddrsFound := srv.cmgr.addrMgr.AddressCache()
	if len(netAddrsFound) > MaxAddrsPerAddrMsg {
		netAddrsFound = netAddrsFound[:MaxAddrsPerAddrMsg]
	}

	// Convert the list to a SingleAddr list.
	res := &MsgUltranetAddr{}
	for _, netAddr := range netAddrsFound {
		singleAddr := &SingleAddr{
			Timestamp: time.Now(),
			IP:        netAddr.IP,
			Port:      netAddr.Port,
			Services:  (ServiceFlag)(netAddr.Services),
		}
		res.AddrList = append(res.AddrList, singleAddr)
	}

	go func() {
		glog.Debugf("Server._handleGetAddrMessage: Sending Addr message to Peer "+
			"%v with addrs %v", pp, spew.Sdump(res.AddrList))
		pp.QueueMessage(res)
	}()
}

func (srv *Server) _handleControlMessages(serverMessage *ServerMessage) (_shouldQuit bool) {
	switch msg := serverMessage.Msg.(type) {
	// Control messages used internally to signal to the server.
	case *MsgUltranetNewPeer:
		srv._handleNewPeer(serverMessage.Peer)
	case *MsgUltranetDonePeer:
		srv._handleDonePeer(serverMessage.Peer)
	case *MsgUltranetBlockMainChainConnected:
		srv._handleBlockMainChainConnected(msg.block)
	case *MsgUltranetBlockMainChainDisconnected:
		srv._handleBlockMainChainDisconnected(msg.block)
	case *MsgUltranetBlockAccepted:
		srv._handleBlockAccepted(msg.block)
	case *MsgUltranetBitcoinManagerUpdate:
		srv._handleBitcoinManagerUpdate(msg)
	case *MsgUltranetQuit:
		return true
	}

	return false
}

func (srv *Server) _handlePeerMessages(serverMessage *ServerMessage) {
	// Handle all non-control message types from our Peers.
	switch msg := serverMessage.Msg.(type) {
	// Messages sent among peers.
	case *MsgUltranetBlock:
		srv._handleBlock(serverMessage.Peer, msg)
	case *MsgUltranetGetHeaders:
		srv._handleGetHeaders(serverMessage.Peer, msg)
	case *MsgUltranetHeaderBundle:
		srv._handleHeaderBundle(serverMessage.Peer, msg)
	case *MsgUltranetGetBlocks:
		srv._handleGetBlocks(serverMessage.Peer, msg)
	case *MsgUltranetGetTransactions:
		srv._handleGetTransactions(serverMessage.Peer, msg)
	case *MsgUltranetTransactionBundle:
		srv._handleTransactionBundle(serverMessage.Peer, msg)
	case *MsgUltranetMempool:
		srv._handleMempool(serverMessage.Peer, msg)
	case *MsgUltranetGetListings:
		srv._handleGetListings(serverMessage.Peer, msg)
	case *MsgUltranetListingBundle:
		srv._handleListingBundle(serverMessage.Peer, msg)
	case *MsgUltranetListingSync:
		srv._handleListingSync(serverMessage.Peer, msg)
	case *MsgUltranetInv:
		srv._handleInv(serverMessage.Peer, msg)
	}
}

// Note that messageHandler is single-threaded and so all of the handle* functions
// it calls can assume they can access the Server's variables without concurrency
// issues.
func (srv *Server) messageHandler() {
	for {
		serverMessage := <-srv.incomingMessages
		glog.Tracef("Server.messageHandler: Handling message of type %v from Peer %v",
			serverMessage.Msg.GetMsgType(), serverMessage.Peer)

		// If the message is an addr message we handle it independent of whether or
		// not the BitcoinManager is synced.
		if serverMessage.Msg.GetMsgType() == MsgTypeAddr {
			srv._handleAddrMessage(serverMessage.Peer, serverMessage.Msg.(*MsgUltranetAddr))
			continue
		}
		// If the message is a GetAddr message we handle it independent of whether or
		// not the BitcoinManager is synced.
		if serverMessage.Msg.GetMsgType() == MsgTypeGetAddr {
			srv._handleGetAddrMessage(serverMessage.Peer, serverMessage.Msg.(*MsgUltranetGetAddr))
			continue
		}

		// The Server behaves differently before and after the BitcoinManager has
		// reached a time-synced state. Before the BitcoinManager is time-synced,
		// the Server will only react to control messages and HeaderBundle messages.
		// After the BitcoinManager is synced, it handles all messages.
		if srv.bitcoinManager.IsCurrent(false /*considerCumWork*/) {
			glog.Tracef("Server.messageHandler: BitcoinManager is time-current")

			// If the BitcoinManager is synced, handle non-control messages.
			srv._handlePeerMessages(serverMessage)

		} else {
			glog.Tracef("Server.messageHandler: BitcoinManager is NOT time-current")

			// When the BitcoinManager is not time-current, make sure all of the request
			// queues are cleared.
			srv.ResetRequestQueues()

			// Handle header bundle message if applicable. We handle HeaderBundle messages
			// before the Server is time-synced because we can process and validate headers
			// without relying on the Bitcoin chain.
			if serverMessage.Msg.GetMsgType() == MsgTypeHeaderBundle {
				srv._handleHeaderBundle(
					serverMessage.Peer, serverMessage.Msg.(*MsgUltranetHeaderBundle))
			}
		}

		// Always check for and handle control messages regardless of whether the
		// BitcoinManager is synced. Note that we filter control messages out in a
		// Peer's inHander so any control message we get at this point should be bona fide.
		shouldQuit := srv._handleControlMessages(serverMessage)
		if shouldQuit {
			break
		}

		// Signal to whatever sent us this message that we're done processing
		// the block.
		if serverMessage.ReplyChan != nil {
			serverMessage.ReplyChan <- &ServerReply{}
		}
	}

	// If we broke out of the select statement then it's time to allow things to
	// clean up.
	srv.waitGroup.Done()
	glog.Trace("Server.Start: Server done")
}

func (srv *Server) _getAddrsToBroadcast() []*SingleAddr {
	srv.addrsToBroadcastLock.Lock()
	defer srv.addrsToBroadcastLock.Unlock()

	// If there's nothing in the map, return.
	if len(srv.addrsToBroadcastt) == 0 {
		return []*SingleAddr{}
	}

	// If we get here then we have some addresses to broadcast.
	addrsToBroadcast := []*SingleAddr{}
	for len(addrsToBroadcast) < 10 && len(srv.addrsToBroadcastt) > 0 {
		// Choose a key at random. This works because map iteration is random in golang.
		bucket := ""
		for kk := range srv.addrsToBroadcastt {
			bucket = kk
			break
		}

		// Remove the last element from the slice for the given bucket.
		currentAddrList, _ := srv.addrsToBroadcastt[bucket]
		lastIndex := len(currentAddrList) - 1
		currentAddr := currentAddrList[lastIndex]
		currentAddrList = currentAddrList[:lastIndex]
		if len(currentAddrList) == 0 {
			delete(srv.addrsToBroadcastt, bucket)
		} else {
			srv.addrsToBroadcastt[bucket] = currentAddrList
		}

		addrsToBroadcast = append(addrsToBroadcast, currentAddr)
	}

	return addrsToBroadcast
}

// Must be run inside a goroutine. Relays addresses to peers at regular intervals
// and relays our own address to peers once every 24 hours.
func (srv *Server) _startAddressRelayer() {
	for numMinutesPassed := 0; ; numMinutesPassed++ {
		// For the first ten minutes after the server starts, relay our address to all
		// peers. After the first ten minutes, do it once every 24 hours.
		glog.Debugf("Server.Start._startAddressRelayer: Relaying our own addr to peers")
		if numMinutesPassed < 10 || numMinutesPassed%(RebroadcastNodeAddrIntervalMinutes) == 0 {
			for _, pp := range srv.cmgr.GetAllPeers() {
				bestAddress := srv.cmgr.addrMgr.GetBestLocalAddress(pp.netAddr)
				if bestAddress != nil {
					glog.Tracef("Server.Start._startAddressRelayer: Relaying address %v to "+
						"peer %v", bestAddress.IP.String(), pp)
					go func() {
						pp.QueueMessage(&MsgUltranetAddr{
							AddrList: []*SingleAddr{
								&SingleAddr{
									Timestamp: time.Now(),
									IP:        bestAddress.IP,
									Port:      bestAddress.Port,
									Services:  (ServiceFlag)(bestAddress.Services),
								},
							},
						})
					}()
				}
			}
		}

		glog.Tracef("Server.Start._startAddressRelayer: Seeing if there are addrs to relay...")
		// Broadcast the addrs we have to all of our peers.
		addrsToBroadcast := srv._getAddrsToBroadcast()
		if len(addrsToBroadcast) == 0 {
			glog.Tracef("Server.Start._startAddressRelayer: No addrs to relay.")
			time.Sleep(AddrRelayIntervalSeconds * time.Second)
			continue
		}

		glog.Tracef("Server.Start._startAddressRelayer: Found %d addrs to "+
			"relay: %v", len(addrsToBroadcast), spew.Sdump(addrsToBroadcast))
		// Iterate over all our peers and broadcast the addrs to all of them.
		for _, pp := range srv.cmgr.GetAllPeers() {
			go func(gofuncPeer *Peer) {
				msg := &MsgUltranetAddr{}
				msg.AddrList = addrsToBroadcast
				gofuncPeer.QueueMessage(msg)
			}(pp)
		}
		time.Sleep(AddrRelayIntervalSeconds * time.Second)
		continue
	}
}

// Stop ...
func (srv *Server) Stop() {
	glog.Info("Server.Stop: Gracefully shutting down Server")

	// Iterate through all the peers and flush their logs before we quit.
	glog.Info("Server.Stop: Flushing logs for all peers")

	// Stop the ConnectionManager
	srv.cmgr.Stop()
	// Stop the ListingManager
	srv.listingManager.Stop()

	// Stop the miner if we have one running.
	if srv.miner != nil {
		srv.miner.Stop()
	}

	// This will signal any goroutines to quit. Note that enqueing this after stopping
	// the ConnectionManager seems like it should cause the Server to process any remaining
	// messages before calling waitGroup.Done(), which seems like a good thing.
	go func() {
		srv.incomingMessages <- &ServerMessage{
			// Peer is ignored for MsgUltranetQuit.
			Peer: nil,
			Msg:  &MsgUltranetQuit{},
		}
	}()

	// Wait for the server to fully shut down.
	srv.waitGroup.Wait()
	glog.Info("Server.Stop: Successfully shut down Server")
}

// Start actually kicks off all of the management processes. Among other things, it causes
// the ConnectionManager to actually start connecting to peers and receiving messages. If
// requested, it also starts the miner.
func (srv *Server) Start() {
	// Start the Server so that it will be ready to process messages once the ConnectionManager
	// finds some Peers.
	glog.Info("Server.Start: Starting Server")
	srv.waitGroup.Add(1)
	go srv.messageHandler()

	go srv._startAddressRelayer()

	// Once the ConnectionManager is started, peers will be found and connected to and
	// messages will begin to flow in to be processed.
	go srv.cmgr.Start()

	// Start the ListingManager.
	go srv.listingManager.Start()

	if srv.miner != nil {
		go srv.miner.Start()
	}

	go srv.bitcoinManager.Start()
}
