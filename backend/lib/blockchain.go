package lib

import (
	"container/list"
	"encoding/hex"
	"fmt"
	"math"
	"math/big"
	"reflect"
	"sort"
	"strings"
	"time"

	chainlib "github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcec"
	"github.com/davecgh/go-spew/spew"
	"github.com/dgraph-io/badger"
	"github.com/golang/glog"
	merkletree "github.com/laser/go-merkle-tree"
	"github.com/pkg/errors"
	"github.com/sasha-s/go-deadlock"
)

// blockchain.go is the work-horse for validating Ultranet blocks and updating the
// database after each block is processed. The ProcessBlock function is probably
// a good place to start to understand this file.

const (
	// MaxOrphansInMemory is the maximum number of orphan blocks that we're willing to keep in memory. We set
	// a maximum here in order to prevent memory exhaustion from someone sending us too
	// many orphans.
	MaxOrphansInMemory = 100

	// MaxBlockIndexNodes needs to allow the block index to grow large enough to accommodate multiple
	// forks of material length while allowing us to avoid an out-of-memory issue due to
	// a "disk-fill" attack. Notice that because we will only ever download blocks
	// after we have a header chain that has beaten all other header chains we're aware
	// of, the common case for an attack will be someone sending us long useless header
	// chains that we never actually download blocks for. This results in the block index
	// bloating up (indefinitely if we don't prune it) due to storing useless headers
	// but not resulting in the downloading of any blocks, which is a good thing.
	//
	// At ten minute block times, 5,000,000 comes out to roughly 95 years worth of blocks,
	// which seems like a reasonable limit for now (if we had 25 years of blocks, we'd still
	// have room for multiple forks each an entire history's length with this value). If
	// each node takes up 100 bytes of space this amounts to around 500MB, which also seems
	// like a reasonable size.
	MaxBlockIndexNodes = 5000000
)

// BlockStatus ...
type BlockStatus uint32

const (
	// StatusNone ...
	StatusNone BlockStatus = 0

	// StatusHeaderValidated ...
	// Headers must always be Validated or ValidateFailed. We
	// don't store orphan headers and therefore any header that we do
	// have in our node index will be known definitively to be valid or
	// invalid one way or the other.
	StatusHeaderValidated = 1 << iota
	// StatusHeaderValidateFailed ...
	StatusHeaderValidateFailed

	// StatusBlockProcessed ...
	StatusBlockProcessed
	// StatusBlockStored ...
	StatusBlockStored
	// StatusBlockValidated ...
	StatusBlockValidated
	// StatusBlockValidateFailed ...
	StatusBlockValidateFailed

	// These statuses are only used for Bitcoin header blocks in the BitcoinManager,
	// not Ultranet blocks. As such, you should only see these referenced in the BitcoinManager.
	// We include them here because overloading the Ultranet data structures to make it
	// so that the BitcoinManager can use them is easier than defining whole new data
	// structures that are incompatible with existing methods like latestLocator(). If
	// Go supported generics, this would probably not be necessary but it doesn't and
	// so this is the path of least resistance.
	StatusBitcoinHeaderValidated
	StatusBitcoinHeaderValidateFailed
)

func (blockStatus BlockStatus) String() string {
	if blockStatus == 0 {
		return "NONE"
	}

	statuses := []string{}
	if blockStatus&StatusHeaderValidated != 0 {
		statuses = append(statuses, "HEADER_VALIDATED")
		blockStatus ^= StatusHeaderValidated
	}
	if blockStatus&StatusHeaderValidateFailed != 0 {
		statuses = append(statuses, "HEADER_VALIDATE_FAILED")
		blockStatus ^= StatusHeaderValidateFailed
	}
	if blockStatus&StatusBlockProcessed != 0 {
		statuses = append(statuses, "BLOCK_PROCESSED")
		blockStatus ^= StatusBlockProcessed
	}
	if blockStatus&StatusBlockStored != 0 {
		statuses = append(statuses, "BLOCK_STORED")
		blockStatus ^= StatusBlockStored
	}
	if blockStatus&StatusBlockValidated != 0 {
		statuses = append(statuses, "BLOCK_VALIDATED")
		blockStatus ^= StatusBlockValidated
	}
	if blockStatus&StatusBlockValidateFailed != 0 {
		statuses = append(statuses, "BLOCK_VALIDATE_FAILED")
		blockStatus ^= StatusBlockValidateFailed
	}

	// If at this point the blockStatus isn't zeroed out then
	// we have an unknown status remaining.
	if blockStatus != 0 {
		statuses = append(statuses, "ERROR_UNKNOWN_STATUS!")
	}

	return strings.Join(statuses, " | ")
}

// BlockNode ...
//
// Add some fields in addition to the header to aid in the selection
// of the best chain.
type BlockNode struct {
	// Pointer to a node representing the block's parent.
	Parent *BlockNode

	// The hash computed on this block.
	Hash *BlockHash

	// Height is the position in the block chain.
	Height uint32

	// The difficulty target for this block. Used to compute the next
	// block's difficulty target so it can be validated.
	DifficultyTarget *BlockHash

	// A computation of the total amount of work that has been performed
	// on this chain, including the current node.
	CumWork *big.Int

	// The block header.
	Header *MsgUltranetHeader

	// Status holds the validation state for the block and whether or not
	// it's stored in the database.
	Status BlockStatus
}

func (nn *BlockNode) String() string {
	var parentHash *BlockHash
	if nn.Parent != nil {
		parentHash = nn.Parent.Hash
	}
	tstamp := uint32(0)
	if nn.Header != nil {
		tstamp = nn.Header.TstampSecs
	}
	return fmt.Sprintf("< TstampSecs: %d, Height: %d, Hash: %s, ParentHash %s, Status: %s, CumWork: %v>",
		tstamp, nn.Header.Height, nn.Hash, parentHash, nn.Status, nn.CumWork)
}

// NewBlockNode ...
// TODO: Height not needed in this since it's in the header.
func NewBlockNode(
	parent *BlockNode,
	hash *BlockHash,
	height uint32,
	difficultyTarget *BlockHash,
	cumWork *big.Int,
	header *MsgUltranetHeader,
	status BlockStatus) *BlockNode {

	return &BlockNode{
		Parent:           parent,
		Hash:             hash,
		Height:           height,
		DifficultyTarget: difficultyTarget,
		CumWork:          cumWork,
		Header:           header,
		Status:           status,
	}
}

// Ancestor ...
func (nn *BlockNode) Ancestor(height uint32) *BlockNode {
	if height < 0 || height > nn.Height {
		return nil
	}

	node := nn
	for ; node != nil && node.Height != height; node = node.Parent {
		// Keep iterating node until the condition no longer holds.
	}

	return node
}

// RelativeAncestor returns the ancestor block node a relative 'distance' blocks
// before this node. This is equivalent to calling Ancestor with the node's
// height minus provided distance.
//
// This function is safe for concurrent access.
func (nn *BlockNode) RelativeAncestor(distance uint32) *BlockNode {
	return nn.Ancestor(nn.Height - distance)
}

// CalcNextDifficultyTarget computes the difficulty target expected of the
// next block.
func CalcNextDifficultyTarget(lastNode *BlockNode, params *UltranetParams) (*BlockHash, error) {
	// Compute the blocks in each difficulty cycle.
	blocksPerRetarget := uint32(params.TimeBetweenDifficultyRetargets / params.TimeBetweenBlocks)

	// We effectively skip the first difficulty retarget by returning the default
	// difficulty value for the first cycle. Not doing this (or something like it)
	// would cause the genesis block's timestamp, which could be off by several days
	// to significantly skew the first cycle in a way that is mostly annoying for
	// testing but also suboptimal for the mainnet.
	minDiffBytes, err := hex.DecodeString(params.MinDifficultyTargetHex)
	if err != nil {
		return nil, errors.Wrapf(err, "CalcNextDifficultyTarget: Problem computing min difficulty")
	}
	var minDiffHash BlockHash
	copy(minDiffHash[:], minDiffBytes)
	if lastNode == nil || lastNode.Height <= blocksPerRetarget {
		return &minDiffHash, nil
	}

	// If we get here we know we are dealing with a block whose height exceeds
	// the height of the first difficulty adjustment (that is
	//   lastNode.Height > blocksPerRetarget

	// If we're not at a difficulty retarget point, return the previous
	// block's difficulty.
	if lastNode.Height%blocksPerRetarget != 0 {
		return lastNode.DifficultyTarget, nil
	}

	// If we get here it means we reached a difficulty retarget point.
	targetSecs := int64(params.TimeBetweenDifficultyRetargets / time.Second)
	minRetargetTimeSecs := targetSecs / params.MaxDifficultyRetargetFactor
	maxRetargetTimeSecs := targetSecs * params.MaxDifficultyRetargetFactor

	firstNodeHeight := lastNode.Height - blocksPerRetarget
	firstNode := lastNode.Ancestor(firstNodeHeight)
	if firstNode == nil {
		return nil, fmt.Errorf("CalcNextDifficultyTarget: Problem getting block at "+
			"beginning of retarget interval at height %d during retarget from height %d",
			firstNodeHeight, lastNode.Height)
	}

	actualTimeDiffSecs := int64(lastNode.Header.TstampSecs - firstNode.Header.TstampSecs)
	clippedTimeDiffSecs := actualTimeDiffSecs
	if actualTimeDiffSecs < minRetargetTimeSecs {
		clippedTimeDiffSecs = minRetargetTimeSecs
	} else if actualTimeDiffSecs > maxRetargetTimeSecs {
		clippedTimeDiffSecs = maxRetargetTimeSecs
	}

	numerator := new(big.Int).Mul(
		HashToBigint(lastNode.DifficultyTarget),
		big.NewInt(clippedTimeDiffSecs))
	nextDiffBigint := numerator.Div(numerator, big.NewInt(targetSecs))

	// If the next difficulty is nil or if it passes the min difficulty, set it equal
	// to the min difficulty. This should never happen except for weird instances where
	// we're testing edge cases.
	if nextDiffBigint == nil || nextDiffBigint.Cmp(HashToBigint(&minDiffHash)) > 0 {
		nextDiffBigint = HashToBigint(&minDiffHash)
	}

	return BigintToHash(nextDiffBigint), nil
}

// OrphanBlock ...
type OrphanBlock struct {
	Block *MsgUltranetBlock
	Hash  *BlockHash
}

// Blockchain ...
type Blockchain struct {
	db             *badger.DB
	bitcoinManager *BitcoinManager
	timeSource     chainlib.MedianTimeSource
	params         *UltranetParams
	// blockNotificationChannel gets ServerMessage events enqueued onto it
	// whenever a block is connected to the main chain, disconnected from the
	// main chain, or accepted (not necessarily onto the main chain). This
	// is useful for letting the Server know that it can/should relay messages
	// for the corresponding block to other peers, among other things.
	blockNotificationChannel chan<- *ServerMessage

	// Protects most of the fields below this point.
	ChainLock deadlock.RWMutex

	// These should only be accessed after acquiring the ChainLock.
	//
	// An in-memory index of the "tree" of blocks we are currently aware of.
	// This index includes forks and side-chains but does not include orphans.
	blockIndex map[BlockHash]*BlockNode
	// An in-memory slice of the blocks on the main chain only. The end of
	// this slice is the best known tip that we have at any given time.
	bestChainn   []*BlockNode
	bestChainMap map[BlockHash]*BlockNode

	bestHeaderChain    []*BlockNode
	bestHeaderChainMap map[BlockHash]*BlockNode

	// We keep track of orphan blocks with the following data structures. Orphans
	// are not written to disk and are only cached in memory. Moreover we only keep
	// up to MaxOrphansInMemory of them in order to prevent memory exhaustion.
	orphanList *list.List
}

// _initChain initializes the in-memory data structures for the Blockchain object
// by reading from the database. If the database has never been initialized before
// then _initChain will initialize it to contain only the genesis block before
// proceeding to read from it.
func (bc *Blockchain) _initChain() error {
	// See if we have a best chain hash stored in the db.
	bestBlockHash := DbGetBestHash(bc.db, ChainTypeUltranetBlock)
	// When we load up initially, the best header hash is just the tip of the best
	// block chain, since we don't store headers for which we don't have corresponding
	// blocks.
	bestHeaderHash := bestBlockHash

	// If there is no best chain hash in the db then it means we've never
	// initialized anything so take the time to do it now.
	if bestBlockHash == nil || bestHeaderHash == nil {
		err := InitDbWithUltranetGenesisBlock(bc.params, bc.db)
		if err != nil {
			return errors.Wrapf(err, "_initChain: Problem initializing db with genesis block")
		}

		// After initializing the db to contain only the genesis block,
		// set the best hash we're aware of equal to it.
		bestBlockHash = NewBlockHash(bc.params.GenesisBlockHashHex)
		bestHeaderHash = bestBlockHash
	}

	// At this point we should have bestHashes set and the db should have been
	// initialized to contain a block index and a best chain that we can read
	// in.

	// Read in the nodes using the (<height, hash> -> node) index. The nodes will
	// be iterated over starting with height 0 and ending with the height of the
	// longest chain we're aware of. As we go, check that all the blocks connect
	// to previous blocks we've read in and error if they don't. This works because
	// reading blocks in height order as we do here ensures that we'll always
	// add a block's parents, if they exist, before adding the block itself.
	var err error
	bc.blockIndex, err = GetBlockIndex(bc.db, false /*bitcoinNodes*/)
	if err != nil {
		return errors.Wrapf(err, "_initChain: Problem reading block index from db")
	}

	// At this point the blockIndex should contain a full node tree with all
	// nodes pointing to valid parent nodes.

	{
		// Find the tip node with the best node hash.
		tipNode := bc.blockIndex[*bestBlockHash]
		if tipNode == nil {
			return fmt.Errorf("_initChain(block): Best hash (%#v) not found in block index", bestBlockHash)
		}

		// Walk back from the best node to the genesis block and store them all
		// in bestChain.
		bc.bestChainn, err = GetBestChain(tipNode, bc.blockIndex)
		for _, bestChainNode := range bc.bestChainn {
			bc.bestChainMap[*bestChainNode.Hash] = bestChainNode
		}
		if err != nil {
			return errors.Wrapf(err, "_initChain(block): Problem reading best chain from db")
		}
	}

	// TODO: This code is a bit repetitive but this seemed clearer than factoring it out.
	{
		// Find the tip node with the best node hash.
		tipNode := bc.blockIndex[*bestHeaderHash]
		if tipNode == nil {
			return fmt.Errorf("_initChain(header): Best hash (%#v) not found in block index", bestHeaderHash)
		}

		// Walk back from the best node to the genesis block and store them all
		// in bestChain.
		bc.bestHeaderChain, err = GetBestChain(tipNode, bc.blockIndex)
		for _, bestHeaderChainNode := range bc.bestHeaderChain {
			bc.bestHeaderChainMap[*bestHeaderChainNode.Hash] = bestHeaderChainNode
		}
		if err != nil {
			return errors.Wrapf(err, "_initChain(header): Problem reading best chain from db")
		}
	}

	return nil
}

// NewBlockchain returns a new blockchain object. It initializes some in-memory
// data structures by reading from the db. It also initializes the db if it hasn't
// been initialized in the past. This function should only be called once per
// db, and one should never run two blockhain objects over the same db at the same
// time as they will likely step on each other and become inconsistent.
func NewBlockchain(_params *UltranetParams, _timeSource chainlib.MedianTimeSource, _db *badger.DB, _bitcoinManager *BitcoinManager, _blockNotificationChannel chan<- *ServerMessage) (*Blockchain, error) {
	bc := &Blockchain{
		db:                       _db,
		bitcoinManager:           _bitcoinManager,
		timeSource:               _timeSource,
		params:                   _params,
		blockNotificationChannel: _blockNotificationChannel,

		blockIndex:   make(map[BlockHash]*BlockNode),
		bestChainMap: make(map[BlockHash]*BlockNode),

		bestHeaderChainMap: make(map[BlockHash]*BlockNode),

		orphanList: list.New(),
	}

	// Hold the chain lock whenever we modify this object from now on.
	bc.ChainLock.Lock()
	defer bc.ChainLock.Unlock()

	// Initialize all the in-memory data structures by loading our state
	// from the db. This function creates an initial database state containing
	// only the genesis block if we've never initialized the database before.
	if err := bc._initChain(); err != nil {
		return nil, errors.Wrapf(err, "NewBlockchain: ")
	}

	return bc, nil
}

// log2FloorMasks defines the masks to use when quickly calculating
// floor(log2(x)) in a constant log2(32) = 5 steps, where x is a uint32, using
// shifts.  They are derived from (2^(2^x) - 1) * (2^(2^x)), for x in 4..0.
var log2FloorMasks = []uint32{0xffff0000, 0xff00, 0xf0, 0xc, 0x2}

// fastLog2Floor calculates and returns floor(log2(x)) in a constant 5 steps.
func fastLog2Floor(n uint32) uint8 {
	rv := uint8(0)
	exponent := uint8(16)
	for i := 0; i < 5; i++ {
		if n&log2FloorMasks[i] != 0 {
			rv += exponent
			n >>= exponent
		}
		exponent >>= 1
	}
	return rv
}

// locateInventory returns the node of the block after the first known block in
// the locator along with the number of subsequent nodes needed to either reach
// the provided stop hash or the provided max number of entries.
//
// In addition, there are two special cases:
//
// - When no locators are provided, the stop hash is treated as a request for
//   that block, so it will either return the node associated with the stop hash
//   if it is known, or nil if it is unknown
// - When locators are provided, but none of them are known, nodes starting
//   after the genesis block will be returned
//
// This is primarily a helper function for the locateBlocks and locateHeaders
// functions.
//
// This function MUST be called with the chain state lock held (for reads).
func locateInventory(locator []*BlockHash, stopHash *BlockHash, maxEntries uint32,
	blockIndex map[BlockHash]*BlockNode, bestChainList []*BlockNode,
	bestChainMap map[BlockHash]*BlockNode) (*BlockNode, uint32) {

	// There are no block locators so a specific block is being requested
	// as identified by the stop hash.
	stopNode, stopNodeExists := blockIndex[*stopHash]
	if len(locator) == 0 {
		if !stopNodeExists {
			// No blocks with the stop hash were found so there is
			// nothing to do.
			return nil, 0
		}
		return stopNode, 1
	}

	// Find the most recent locator block hash in the main chain. In the
	// case none of the hashes in the locator are in the main chain, fall
	// back to the genesis block.
	startNode := bestChainList[0]
	for _, hash := range locator {
		node, bestChainContainsNode := bestChainMap[*hash]
		if bestChainContainsNode {
			startNode = node
			break
		}
	}

	// Start at the block after the most recently known block. When there
	// is no next block it means the most recently known block is the tip of
	// the best chain, so there is nothing more to do.
	nextNodeHeight := startNode.Header.Height + 1
	if uint32(len(bestChainList)) <= nextNodeHeight {
		return nil, 0
	}
	startNode = bestChainList[nextNodeHeight]

	// Calculate how many entries are needed.
	tip := bestChainList[len(bestChainList)-1]
	total := uint32((tip.Header.Height - startNode.Header.Height) + 1)
	if stopNodeExists && stopNode.Header.Height >= startNode.Header.Height {

		_, bestChainContainsStopNode := bestChainMap[*stopNode.Hash]
		if bestChainContainsStopNode {
			total = uint32((stopNode.Header.Height - startNode.Header.Height) + 1)
		}
	}
	if total > maxEntries {
		total = maxEntries
	}

	return startNode, total
}

// locateHeaders returns the headers of the blocks after the first known block
// in the locator until the provided stop hash is reached, or up to the provided
// max number of block headers.
//
// See the comment on the exported function for more details on special cases.
//
// This function MUST be called with the ChainLock held (for reads).
func locateHeaders(locator []*BlockHash, stopHash *BlockHash, maxHeaders uint32,
	blockIndex map[BlockHash]*BlockNode, bestChainList []*BlockNode,
	bestChainMap map[BlockHash]*BlockNode) []*MsgUltranetHeader {

	// Find the node after the first known block in the locator and the
	// total number of nodes after it needed while respecting the stop hash
	// and max entries.
	node, total := locateInventory(locator, stopHash, maxHeaders,
		blockIndex, bestChainList, bestChainMap)
	if total == 0 {
		return nil
	}

	// Populate and return the found headers.
	headers := make([]*MsgUltranetHeader, 0, total)
	for ii := uint32(0); ii < total; ii++ {
		headers = append(headers, node.Header)
		if uint32(len(headers)) == total {
			break
		}
		node = bestChainList[node.Header.Height+1]
	}
	return headers
}

// LocateBestBlockChainHeaders returns the headers of the blocks after the first known block
// in the locator until the provided stop hash is reached, or up to a max of
// wire.MaxBlockHeadersPerMsg headers. Note that it returns the best headers
// considering only headers for which we have blocks (that is, it considers the
// best *block* chain we have rather than the best *header* chain). This is
// the correct thing to do because in general this function is called in order
// to serve a response to a peer's GetHeaders request.
//
// In addition, there are two special cases:
//
// - When no locators are provided, the stop hash is treated as a request for
//   that header, so it will either return the header for the stop hash itself
//   if it is known, or nil if it is unknown
// - When locators are provided, but none of them are known, headers starting
//   after the genesis block will be returned
//
// This function is safe for concurrent access.
func (bc *Blockchain) LocateBestBlockChainHeaders(locator []*BlockHash, stopHash *BlockHash) []*MsgUltranetHeader {
	bc.ChainLock.RLock()
	defer bc.ChainLock.RUnlock()

	headers := locateHeaders(locator, stopHash, MaxHeadersPerMsg,
		bc.blockIndex, bc.bestChainn, bc.bestChainMap)

	return headers
}

// latestLocator returns a block locator for the passed block node. The passed
// node can be nil in which case the block locator for the current tip
// associated with the view will be returned.
//
// BlockLocator is used to help locate a specific block.  The algorithm for
// building the block locator is to add the hashes in reverse order until
// the genesis block is reached.  In order to keep the list of locator hashes
// to a reasonable number of entries, first the most recent previous 12 block
// hashes are added, then the step is doubled each loop iteration to
// exponentially decrease the number of hashes as a function of the distance
// from the block being located.
//
// For example, assume a block chain with a side chain as depicted below:
// 	genesis -> 1 -> 2 -> ... -> 15 -> 16  -> 17  -> 18
// 	                              \-> 16a -> 17a
//
// The block locator for block 17a would be the hashes of blocks:
// [17a 16a 15 14 13 12 11 10 9 8 7 6 4 genesis]
//
// Caller is responsible for acquiring the ChainLock before calling this function.
func latestLocator(tip *BlockNode, bestChainList []*BlockNode, bestChainMap map[BlockHash]*BlockNode) []*BlockHash {
	// Calculate the max number of entries that will ultimately be in the
	// block locator.  See the description of the algorithm for how these
	// numbers are derived.
	var maxEntries uint8
	if tip.Header.Height <= 12 {
		maxEntries = uint8(tip.Header.Height) + 1
	} else {
		// Requested hash itself + previous 10 entries + genesis block.
		// Then floor(log2(height-10)) entries for the skip portion.
		adjustedHeight := uint32(tip.Header.Height) - 10
		maxEntries = 12 + fastLog2Floor(adjustedHeight)
	}
	locator := make([]*BlockHash, 0, maxEntries)

	step := int32(1)
	for tip != nil {
		locator = append(locator, tip.Hash)

		// Nothing more to add once the genesis block has been added.
		if tip.Header.Height == 0 {
			break
		}

		// Calculate height of previous node to include ensuring the
		// final node is the genesis block.
		height := int32(tip.Header.Height) - step
		if height < 0 {
			height = 0
		}

		// When the node is in the current chain view, all of its
		// ancestors must be too, so use a much faster O(1) lookup in
		// that case.  Otherwise, fall back to walking backwards through
		// the nodes of the other chain to the correct ancestor.
		if _, exists := bestChainMap[*tip.Hash]; exists {
			tip = bestChainList[height]
		} else {
			tip = tip.Ancestor(uint32(height))
		}

		// Once 11 entries have been included, start doubling the
		// distance between included hashes.
		if len(locator) > 10 {
			step *= 2
		}
	}

	return locator
}

// HeaderLocatorWithNodeHash ...
func (bc *Blockchain) HeaderLocatorWithNodeHash(blockHash *BlockHash) ([]*BlockHash, error) {
	node, exists := bc.blockIndex[*blockHash]
	if !exists {
		return nil, fmt.Errorf("Blockchain.HeaderLocatorWithNodeHash: Node for hash %v is not in our blockIndex", blockHash)
	}

	return latestLocator(node, bc.bestHeaderChain, bc.bestHeaderChainMap), nil
}

// LatestHeaderLocator calls latestLocator in order to fetch a locator
// for the best header chain.
func (bc *Blockchain) LatestHeaderLocator() []*BlockHash {
	bc.ChainLock.Lock()
	defer bc.ChainLock.Unlock()

	return latestLocator(bc.headerTip(), bc.bestHeaderChain, bc.bestHeaderChainMap)
}

// GetBlockNodesToFetch ...
func (bc *Blockchain) GetBlockNodesToFetch(numBlocks int, _maxHeight int, ignoreBlocks map[BlockHash]*ServerMessage) []*BlockNode {
	// Hold the ChainLock for reading.
	bc.ChainLock.RLock()
	defer bc.ChainLock.RUnlock()

	// If the maxHeight is set to < 0, then we don't want to use it as a constraint.
	maxHeight := uint32(math.MaxUint32)
	if _maxHeight >= 0 {
		maxHeight = uint32(_maxHeight)
	}

	// Get the tip of the main block chain.
	bestBlockTip := bc.blockTip()

	// If the tip of the best block chain is in the main header chain, make that
	// the start point for our fetch.
	headerNodeStart, blockTipExistsInBestHeaderChain := bc.bestHeaderChainMap[*bestBlockTip.Hash]
	if !blockTipExistsInBestHeaderChain {
		// If the hash of the tip of the best blockchain is not in the best header chain, then
		// this is a case where the header chain has forked off from the best block
		// chain. In this situation, the best header chain is taken as the source of truth
		// and so we iterate backward over the best header chain starting at the tip
		// until we find the first block that has StatusBlockProcessed. Then we fetch
		// blocks starting from there. Note that, at minimum, the genesis block has
		// StatusBlockProcessed so this loop is guaranteed to terminate successfully.
		headerNodeStart = bc.headerTip()
		for headerNodeStart != nil && (headerNodeStart.Status&StatusBlockProcessed) == 0 {
			headerNodeStart = headerNodeStart.Parent
		}

		if headerNodeStart == nil {
			// If for some reason we ended up with the headerNode being nil, log
			// an error and set it to the genesis block.
			glog.Errorf("GetBlockToFetch: headerNode was nil after iterating " +
				"backward through best header chain; using genesis block")
			headerNodeStart = bc.bestHeaderChain[0]
		}
	}

	// At this point, headerNodeStart should point to a node in the best header
	// chain that has StatusBlockProcessed set. As such, the blocks we need to
	// fetch are those right after this one. Fetch the desired number.
	currentHeight := headerNodeStart.Height + 1
	blockNodesToFetch := []*BlockNode{}
	heightLimit := maxHeight
	if heightLimit >= uint32(len(bc.bestHeaderChain)) {
		heightLimit = uint32(len(bc.bestHeaderChain) - 1)
	}
	for currentHeight <= heightLimit &&
		len(blockNodesToFetch) < numBlocks {

		// Get the current hash and increment the height.
		currentNode := bc.bestHeaderChain[currentHeight]
		currentHeight++

		// If we're instructed to ignore this block, do so.
		if _, exists := ignoreBlocks[*currentNode.Hash]; exists {
			continue
		}

		blockNodesToFetch = append(blockNodesToFetch, currentNode)
	}

	// Return the nodes for the blocks we should fetch.
	return blockNodesToFetch
}

// HasHeader ...
func (bc *Blockchain) HasHeader(headerHash *BlockHash) bool {
	bc.ChainLock.RLock()
	defer bc.ChainLock.RUnlock()

	_, exists := bc.blockIndex[*headerHash]
	return exists
}

func (bc *Blockchain) HeaderAtHeight(blockHeight uint32) *BlockNode {
	bc.ChainLock.RLock()
	defer bc.ChainLock.RUnlock()

	if blockHeight >= uint32(len(bc.bestHeaderChain)) {
		return nil
	}

	return bc.bestHeaderChain[blockHeight]
}

// HasBlock ...
func (bc *Blockchain) HasBlock(blockHash *BlockHash) bool {
	bc.ChainLock.RLock()
	defer bc.ChainLock.RUnlock()

	node, nodeExists := bc.blockIndex[*blockHash]
	if !nodeExists {
		glog.Tracef("Blockchain.HasBlock: Node with hash %v does not exist in node index", blockHash)
		return false
	}

	if (node.Status & StatusBlockProcessed) == 0 {
		glog.Tracef("Blockchain.HasBlock: Node %v does not have StatusBlockProcessed so we don't have the block", node)
		return false
	}

	// Node exists with StatusBlockProcess set means we have it.
	return true
}

// GetBlock ...
func (bc *Blockchain) GetBlock(blockHash *BlockHash) *MsgUltranetBlock {
	bc.ChainLock.RLock()
	defer bc.ChainLock.RUnlock()

	blk, err := GetBlock(blockHash, bc.db)
	if err != nil {
		glog.Tracef("Blockchain.GetBlock: Failed to fetch node with hash %v from the db: %v", blockHash, err)
		return nil
	}

	return blk
}

func (bc *Blockchain) isTipCurrent(tip *BlockNode) bool {
	minChainWorkBytes, _ := hex.DecodeString(bc.params.MinChainWorkHex)

	// Not current if the cumulative work is below the threshold.
	if tip.CumWork.Cmp(BytesToBigint(minChainWorkBytes)) < 0 {
		//glog.Tracef("Blockchain.isTipCurrent: Tip not current because "+
		//"CumWork (%v) is less than minChainWorkBytes (%v)",
		//tip.CumWork, BytesToBigint(minChainWorkBytes))
		return false
	}

	// Not current if the tip has a timestamp older than the maximum
	// tip age.
	tipTime := time.Unix(int64(tip.Header.TstampSecs), 0)
	oldestAllowedTipTime := bc.timeSource.AdjustedTime().Add(-1 * bc.params.MaxTipAge)
	if tipTime.Before(oldestAllowedTipTime) {
		//glog.Tracef("Blockchain.isTipCurrent: Tip not current because "+
		//"tip timestamp (%v) is older than the oldest allowed timestamp (%v)",
		//tipTime, oldestAllowedTipTime)
		return false
	}

	// Tip is current if none of the above thresholds triggered.
	return true
}

// SyncState ...
type SyncState uint8

const (
	// SyncStateSyncingHeaders indicates that our header chain is not current.
	// This is the state a node will start in when it hasn't downloaded
	// anything from its peers. Because we always download headers and
	// validate them before we download blocks, SyncingHeaders implies that
	// the block tip is also not current yet.
	SyncStateSyncingHeaders SyncState = iota
	// SyncStateSyncingBlocks indicates that our header chain is current but
	// that the block chain we have is not current yet. In particular, it
	// means, among other things, that the tip of the block chain is still
	// older than max tip age.
	SyncStateSyncingBlocks
	// SyncStateNeedBlocksss indicates that our header chain is current and our
	// block chain is current but that there are headers in our main chain for
	// which we have not yet processed blocks.
	SyncStateNeedBlocksss
	// SyncStateFullyCurrent indicates that our header chain is current and that
	// we've fetched all the blocks corresponding to this chain.
	SyncStateFullyCurrent
)

func (ss SyncState) String() string {
	switch ss {
	case SyncStateSyncingHeaders:
		return "SYNCING_HEADERS"
	case SyncStateSyncingBlocks:
		return "SYNCING_BLOCKS"
	case SyncStateNeedBlocksss:
		return "NEED_BLOCKS"
	case SyncStateFullyCurrent:
		return "FULLY_CURRENT"
	default:
		return fmt.Sprintf("UNRECOGNIZED(%d) - make sure String() is up to date", ss)
	}
}

// chainState ...
//  - Latest block height is after the latest checkpoint (if enabled)
//  - Latest block has a timestamp newer than 24 hours ago
//
// This function MUST be called with the ChainLock held (for reads).
func (bc *Blockchain) chainState() SyncState {
	// If the header is not current, then we're in the SyncStateSyncingHeaders.
	headerTip := bc.headerTip()
	if !bc.isTipCurrent(headerTip) {
		return SyncStateSyncingHeaders
	}

	// If the header tip is current but the block tip isn't then we're in
	// the SyncStateSyncingBlocks state.
	blockTip := bc.blockTip()
	if !bc.isTipCurrent(blockTip) {
		return SyncStateSyncingBlocks
	}

	// If the header tip is current and the block tip is current but the block
	// tip is not equal to the header tip then we're in SyncStateNeedBlocks.
	if *blockTip.Hash != *headerTip.Hash {
		return SyncStateNeedBlocksss
	}

	// If none of the checks above returned it means we're current.
	return SyncStateFullyCurrent
}

// ChainState ...
//
// This function is safe for concurrent access.
func (bc *Blockchain) ChainState() SyncState {
	bc.ChainLock.RLock()
	defer bc.ChainLock.RUnlock()

	return bc.chainState()
}

func (bc *Blockchain) isSyncing() bool {
	syncState := bc.chainState()
	return syncState == SyncStateSyncingHeaders || syncState == SyncStateSyncingBlocks
}

// IsSyncing ...
func (bc *Blockchain) IsSyncing() bool {
	bc.ChainLock.RLock()
	defer bc.ChainLock.RUnlock()

	return bc.isSyncing()
}

// headerTip returns the tip of the header chain. Because we fetch headers
// before we fetch blocks, we track a chain for headers as separate from the
// main chain for blocks, which is why separate functions are required for
// each of them.
func (bc *Blockchain) headerTip() *BlockNode {
	if len(bc.bestHeaderChain) == 0 {
		return nil
	}

	// Note this should always work because we should have the genesis block
	// in here.
	return bc.bestHeaderChain[len(bc.bestHeaderChain)-1]
}

// HeaderTip is the same as headerTip only it acquires the ChainLock.
func (bc *Blockchain) HeaderTip() *BlockNode {
	bc.ChainLock.RLock()
	defer bc.ChainLock.RUnlock()

	return bc.headerTip()
}

// BlockTip ...
func (bc *Blockchain) BlockTip() *BlockNode {
	bc.ChainLock.RLock()
	defer bc.ChainLock.RUnlock()

	return bc.blockTip()
}

// blockTip returns the tip of the main block chain. We fetch headers first
// and then, once the header chain looks good, we fetch blocks. As such, we
// store two separate "best" chains: One containing the best headers, and
// the other containing the best blocks. The header chain is essentially a
// trail-blazer, validating headers as fast as it can before later fetching
// blocks for the headers that seem legitimate and adding them to the "real"
// best chain. If, while adding blocks to the best block chain, we realize
// some of the blocks are invalid, the best header chain is then adjusted to
// invalidate and chop off the headers corresponding to those blocks and
// their ancestors so the two generally stay in sync.
func (bc *Blockchain) blockTip() *BlockNode {
	var tip *BlockNode

	if len(bc.bestChainn) == 0 {
		return nil
	}

	tip = bc.bestChainn[len(bc.bestChainn)-1]

	return tip
}

func (bc *Blockchain) _validateOrphanBlock(ultranetBlock *MsgUltranetBlock) error {
	// Error if the block is missing a parent hash or header.
	if ultranetBlock.Header == nil {
		return fmt.Errorf("_validateOrphanBlock: Block is missing header")
	}
	parentHash := ultranetBlock.Header.PrevBlockHash
	if parentHash == nil {
		return fmt.Errorf("_validateOrphanBlock: Block is missing parent hash")
	}

	// Check that the block size isn't bigger than the max allowed. This prevents
	// an attack vector where someone might try and send us very large orphan blocks in
	// an attempt to exhaust our memory.
	serializedBlock, err := ultranetBlock.ToBytes(false)
	if err != nil {
		return fmt.Errorf("_validateOrphanBlock: Could not serialize block")
	}
	if uint64(len(serializedBlock)) > bc.params.MaxBlockSizeBytes {
		return RuleErrorBlockTooBig
	}

	// No more validation is needed since the orphan will be properly validated
	// if and when we ever end up adding it to our block index either on the main
	// chain or on a side chain.
	//
	// TODO: It would be nice to do some kind of PoW check on orphans, but it
	// seems useless because anyone who has access to MaxOrphansInMemory orphan
	// blocks has the ability to fill our orphan lists with garbage. Put another
	// way, a simple PoW check on orphan blocks doesn't seem to increase the cost
	// of an attack materially and could have negative effects if e.g. legitimate orphans
	// earlier in the chain get filtered out because their difficulty is too low.
	// Moreover, while being attacked would be a minor inconvenience it doesn't
	// stop the node from reaching consensus eventually. So we'll punt on defending
	// against it unless/until it actually becomes a problem.

	return nil
}

// ProcessOrphanBlock runs some very basic validation on the orphan block and adds
// it to our orphan data structure if it passes. If there are too many orphan blocks
// in our data structure, it also evicts the oldest block to make room for this one.
//
// TODO: Currently we only remove orphan blocks if we have too many. This means in
// a steady state we are potentially keeping MaxOrphansInMemory at all times, which
// is wasteful of resources. Better would be to clean up orphan blocks once they're
// too old or something like that.
func (bc *Blockchain) ProcessOrphanBlock(ultranetBlock *MsgUltranetBlock, blockHash *BlockHash) error {
	err := bc._validateOrphanBlock(ultranetBlock)
	if err != nil {
		return errors.Wrapf(err, "ProcessOrphanBlock: Problem validating orphan block")
	}

	// If this block is already in the orphan list then don't add it.
	//
	// TODO: We do a basic linear search here because there are so few orphans
	// in our list. If we want to track more orphans in the future we would probably
	// want to manage this with a map.
	for orphanElem := bc.orphanList.Front(); orphanElem != nil; orphanElem = orphanElem.Next() {
		orphanBlock := orphanElem.Value.(*OrphanBlock)
		if *orphanBlock.Hash == *blockHash {
			return RuleErrorDuplicateOrphan
		}
	}

	// At this point we know we are adding a new orphan to the list.

	// If we are at capacity remove an orphan block by simply deleting the front
	// element of the orphan list, which is also the oldest orphan.
	if bc.orphanList.Len() >= MaxOrphansInMemory {
		elemToRemove := bc.orphanList.Front()
		bc.orphanList.Remove(elemToRemove)
	}

	// Add the orphan block to our data structure. We can also assume the orphan
	// is not a duplicate and therefore simply add a new entry to the end of the list.
	bc.orphanList.PushBack(&OrphanBlock{
		Block: ultranetBlock,
		Hash:  blockHash,
	})

	return nil
}

// MarkBlockInvalid ...
func (bc *Blockchain) MarkBlockInvalid(node *BlockNode) {
	// Mark the node's block as invalid.
	node.Status |= StatusBlockValidateFailed

	// If this node happens to be in the main header chain, mark
	// every node after this one in the header chain as invalid and
	// remove these nodes from the header chain to keep it in sync.
	if _, nodeInHeaderChain := bc.bestHeaderChainMap[*node.Hash]; nodeInHeaderChain {
		for ii := node.Height; ii < uint32(len(bc.bestHeaderChain)); ii++ {
			// Update the status of the node. Mark it as processed since that's used
			// to determine whether we shoudl fetch the block.
			headerNode := bc.bestHeaderChain[ii]
			headerNode.Status |= (StatusBlockProcessed & StatusBlockValidateFailed)
			if err := PutHeightHashToNodeInfo(headerNode, bc.db, false /*bitcoinNodes*/); err != nil {
				// Log if an error occurs but no need to return it.
				glog.Error(errors.Wrapf(err,
					"MarkBlockInvalid: Problem calling PutHeightHashToNodeInfo on header node"))
			}

			delete(bc.bestHeaderChainMap, *headerNode.Hash)
		}
		// Chop off the nodes now that we've updated the status of all of them.
		bc.bestHeaderChain = bc.bestHeaderChain[:node.Height]

		// Note there is no need to update the db for the header chain because we don't
		// store nodes for headers on the db.

		// At this point the header main chain should be fully updated in memory
		// and in the db to reflect that all nodes from this one onward are invalid
		// and should no longer be considered as part of the main chain.
	}

	// Update the node on the db to reflect the status change.
	//
	// Put the node in our node index in the db under the
	//   <height uin32, blockhash BlockHash> -> <node info>
	// index.
	if err := PutHeightHashToNodeInfo(node, bc.db, false /*bitcoinNodes*/); err != nil {
		// Log if an error occurs but no need to return it.
		glog.Error(errors.Wrapf(err,
			"MarkBlockInvalid: Problem calling PutHeightHashToNodeInfo"))
	}
	return
}

func _FindCommonAncestor(node1 *BlockNode, node2 *BlockNode) *BlockNode {
	if node1 == nil || node2 == nil {
		// If either node is nil then there can't be a common ancestor.
		return nil
	}

	// Get the two nodes to be at the same height.
	if node1.Height > node2.Height {
		node1 = node1.Ancestor(node2.Height)
	} else if node1.Height < node2.Height {
		node2 = node2.Ancestor(node1.Height)
	}

	// Iterate the nodes backward until they're either the same or we
	// reach the end of the lists. We only need to check node1 for nil
	// since they're the same height and we are iterating both back
	// in tandem.
	for node1 != nil && node1 != node2 {
		node1 = node1.Parent
		node2 = node2.Parent
	}

	// By now either node1 == node2 and we found the common ancestor or
	// both nodes are nil, which means we reached the bottom without finding
	// a common ancestor.
	return node1
}

// CheckTransactionSanity ...
func CheckTransactionSanity(txn *MsgUltranetTxn) error {
	// We don't check the sanity of block reward transactions.
	if txn.TxnMeta.GetTxnType() == TxnTypeBlockReward {
		return nil
	}

	// All transactions are required to have a valid public key set unless they are one
	// of the following:
	// - BitcoinExchange transactions don't need a PublicKey because the public key can
	//   easily be derived from the BitcoinTransaction embedded in the TxnMeta.
	requiresPublicKey := txn.TxnMeta.GetTxnType() != TxnTypeBitcoinExchange
	if requiresPublicKey {
		if len(txn.PublicKey) != btcec.PubKeyBytesLenCompressed {
			return errors.Wrapf(RuleErrorTransactionMissingPublicKey, "CheckTransactionSanity: ")
		}
		_, err := btcec.ParsePubKey(txn.PublicKey, btcec.S256())
		if err != nil {
			return errors.Wrapf(RuleErrorParsePublicKey, "CheckTransactionSanity: Parse error: %v", err)
		}
	}

	// Every txn must have at least one input unless it is one of the following
	// transaction types.
	// - BitcoinExchange transactions will be rejected if they're duplicates in
	//   spite of the fact that they don't have inputs or outputs.
	// - RegisterMerchant transactions will be rejected if the same Public Key tries
	//   to register twice, which means we don't need to guard against them not having
	//   inputs/outputs.
	// - CancelOrder doesn't need to worry about duplicates because cancellation is
	//   a terminal state. Once an order is cancelled it can't be recancellend and so
	//   there is no risk of replaying a transaction with no inputs.
	// - RejectOrder can have zero inputs by the same argument as for CancelOrder.
	// - ConfirmOrder is more subtle but it can have zero inputs because there is no
	//   harm in re-confirming an order after it has been initially confirmed. We do
	//   insist, however, that it have more than zero outputs.
	//
	// Note this function isn't run on BlockReward transactions, but that they're
	// allowed to have zero inputs as well. In the case of BlockRewards, they could
	// have duplicates if someone uses the same public key without changing the
	// ExtraNonce field, but this is not the default behavior, and in general the
	// only thing a duplicate will do is make a previous transaction invalid, so
	// there's not much incentive to do it.
	//
	// TODO: The above is easily fixed by requiring something like block height to
	// be present in the ExtraNonce field.
	canHaveZeroInputs := (txn.TxnMeta.GetTxnType() == TxnTypeBitcoinExchange ||
		txn.TxnMeta.GetTxnType() == TxnTypeRegisterMerchant ||
		txn.TxnMeta.GetTxnType() == TxnTypeCancelOrder ||
		txn.TxnMeta.GetTxnType() == TxnTypeRejectOrder ||
		txn.TxnMeta.GetTxnType() == TxnTypeConfirmOrder ||
		txn.TxnMeta.GetTxnType() == TxnTypeFulfillOrder ||
		txn.TxnMeta.GetTxnType() == TxnTypePrivateMessage)
	if len(txn.TxInputs) == 0 && !canHaveZeroInputs {
		glog.Tracef("CheckTransactionSanity: Txn needs at least one input: %v", spew.Sdump(txn))
		return RuleErrorTxnMustHaveAtLeastOneInput
	}
	// Every txn must have at least one output unless it is one of the following transaction
	// types.
	// - PlaceOrder can have zero outputs because the Ultra being paid as input is generally
	//   intended to be locked in the order until a merchant confirms the order or until
	//   it is rejected or cancelled.
	// - FulfillOrder can have zero outputs because replaying a fulfillment has no effect
	//   on an order after it has reached the "fulfilled" state.
	// - RegisterMerchant and UpdateMerchant can have zero outputs by a similar argument
	//   in cases where all of the input is burned to bolster the merchant's reputation.
	// - BitcoinExchange transactions are deduped using the hash of the Bitcoin transaction
	//   embedded in them and having an output adds no value because the output is implied
	//   by the Bitcoin transaction embedded in it. In particular, the output is automatically
	//   assumed to be the public key of the the first input in the Bitcoin transaction and
	//   the fee is automatically assumed to be some percentage of the Ultra being created
	//   (10bps at the time of this writing).
	canHaveZeroOutputs := (txn.TxnMeta.GetTxnType() == TxnTypeRegisterMerchant ||
		txn.TxnMeta.GetTxnType() == TxnTypeUpdateMerchant ||
		txn.TxnMeta.GetTxnType() == TxnTypePlaceOrder ||
		txn.TxnMeta.GetTxnType() == TxnTypeFulfillOrder ||
		txn.TxnMeta.GetTxnType() == TxnTypeBitcoinExchange ||
		txn.TxnMeta.GetTxnType() == TxnTypePrivateMessage)
	if len(txn.TxOutputs) == 0 && !canHaveZeroOutputs {
		glog.Tracef("CheckTransactionSanity: Txn needs at least one output: %v", spew.Sdump(txn))
		return RuleErrorTxnMustHaveAtLeastOneOutput
	}

	// Loop through the outputs and do a few sanity checks.
	var totalOutNanos uint64
	for _, txout := range txn.TxOutputs {
		// Check that each output's amount is not bigger than the max as a
		// sanity check.
		if txout.AmountNanos > MaxNanos {
			return RuleErrorOutputExceedsMax
		}
		// Check that this output doesn't overflow the total as a sanity
		// check. This is frankly impossible since our maximum limit is
		// not close to the max size of a uint64 but check it nevertheless.
		if totalOutNanos >= math.MaxUint64-txout.AmountNanos {
			return RuleErrorOutputOverflowsTotal
		}
		// Check that the total isn't bigger than the max supply.
		if totalOutNanos > MaxNanos {
			return RuleErrorTotalOutputExceedsMax
		}
	}

	// Loop through the inputs and do a few sanity checks.
	existingInputs := make(map[UltranetInput]bool)
	for _, txin := range txn.TxInputs {
		if _, exists := existingInputs[*txin]; exists {
			return RuleErrorDuplicateInputs
		}
		existingInputs[*txin] = true
	}

	return nil
}

func getReorgBlocks(tip *BlockNode, newNode *BlockNode) (_commonAncestor *BlockNode, _detachNodes []*BlockNode, _attachNodes []*BlockNode) {
	// Find the common ancestor of this block and the main header chain.
	commonAncestor := _FindCommonAncestor(tip, newNode)
	// Log a warning if the reorg is going to be a big one.
	numBlocks := tip.Height - commonAncestor.Height
	if numBlocks > 10 {
		glog.Warningf("getReorgBlocks: Proceeding with reorg of (%d) blocks from "+
			"block (%v) at height (%d) to block (%v) at height of (%d)",
			numBlocks, tip, tip.Height, newNode, newNode.Height)
	}

	// Get the blocks to detach. Start at the tip and work backwards to the
	// common ancestor (but don't include the common ancestor since we don't
	// need to roll that back).
	//
	// detachBlocks will have the current tip as its first element and parents
	// of the tip thereafter.
	detachBlocks := []*BlockNode{}
	for currentBlock := tip; *currentBlock.Hash != *commonAncestor.Hash; currentBlock = currentBlock.Parent {
		detachBlocks = append(detachBlocks, currentBlock)
	}

	// Get the blocks to attach. Start at the new node and work backwards to
	// the common ancestor (but don't include the common ancestor since we'll
	// be using it as the new tip after we detach all the blocks from the current
	// tip).
	//
	// attachNodes will have the new node as its first element and work back to
	// the node right after the common ancestor as its last element.
	attachBlocks := []*BlockNode{}
	for currentBlock := newNode; *currentBlock.Hash != *commonAncestor.Hash; currentBlock = currentBlock.Parent {
		attachBlocks = append(attachBlocks, currentBlock)
	}
	// Reverse attachBlocks so that the node right after the common ancestor
	// will be the first element and the node at the end of the list will be
	// the new node.
	for i, j := 0, len(attachBlocks)-1; i < j; i, j = i+1, j-1 {
		attachBlocks[i], attachBlocks[j] = attachBlocks[j], attachBlocks[i]
	}

	return commonAncestor, detachBlocks, attachBlocks
}

func updateBestChainInMemory(mainChainList []*BlockNode, mainChainMap map[BlockHash]*BlockNode, detachBlocks []*BlockNode, attachBlocks []*BlockNode) (
	chainList []*BlockNode, chainMap map[BlockHash]*BlockNode) {

	// Remove the nodes we detached from the end of the best chain node list.
	tipIndex := len(mainChainList) - 1
	for blockOffset := 0; blockOffset < len(detachBlocks); blockOffset++ {
		blockIndex := tipIndex - blockOffset
		delete(mainChainMap, *mainChainList[blockIndex].Hash)
	}
	mainChainList = mainChainList[:len(mainChainList)-len(detachBlocks)]

	// Add the nodes we attached to the end of the list. Note that this loop iterates
	// forward because because attachBlocks has the node right after the common ancestor
	// first, with the new tip at the end.
	for _, attachNode := range attachBlocks {
		mainChainList = append(mainChainList, attachNode)
		mainChainMap[*attachNode.Hash] = attachNode
	}

	return mainChainList, mainChainMap
}

// processHeader ...
// Caller must acquire the ChainLock for writing prior to calling this.
func (bc *Blockchain) processHeader(blockHeader *MsgUltranetHeader, headerHash *BlockHash) (_isMainChain bool, _isOrphan bool, _err error) {
	// Start by checking if the header already exists in our node
	// index. If it does, then return an error. We should generally
	// expect that processHeader will only be called on headers we
	// haven't seen before.
	_, nodeExists := bc.blockIndex[*headerHash]
	if nodeExists {
		return false, false, HeaderErrorDuplicateHeader
	}

	// If we're here then it means we're processing a header we haven't
	// seen before.

	// Reject the header if it is more than N seconds in the future.
	tstampDiff := int64(blockHeader.TstampSecs) - bc.timeSource.AdjustedTime().Unix()
	if tstampDiff > int64(bc.params.MaxTstampOffsetSeconds) {
		glog.Debugf("HeaderErrorBlockTooFarInTheFuture: tstampDiff %d > "+
			"MaxTstampOffsetSeconds %d. blockHeader.TstampSecs=%d; adjustedTime=%d",
			tstampDiff, bc.params.MaxTstampOffsetSeconds, blockHeader.TstampSecs,
			bc.timeSource.AdjustedTime().Unix())
		return false, false, HeaderErrorBlockTooFarInTheFuture
	}

	// Try to find this header's parent in our block index.
	// If we can't find the parent then this header is an orphan and we
	// can return early because we don't process orphans.
	// TODO: Should we just return an error if the header is an orphan?
	if blockHeader.PrevBlockHash == nil {
		return false, false, HeaderErrorNilPrevHash
	}
	parentNode, parentNodeExists := bc.blockIndex[*blockHeader.PrevBlockHash]
	if !parentNodeExists {
		// This block is an orphan if its parent doesn't exist and we don't
		// process orphans.
		return false, true, nil
	}

	// If the parent node is invalid then this header is invalid as well. Note that
	// if the parent node exists then its header must either be Validated or
	// ValidateFailed.
	parentHeader := parentNode.Header
	if parentHeader == nil || (parentNode.Status&(StatusHeaderValidateFailed|StatusBlockValidateFailed)) != 0 {
		return false, false, HeaderErrorInvalidParent
	}

	// Verify that the height is one greater than the parent.
	prevHeight := parentHeader.Height
	if blockHeader.Height != prevHeight+1 {
		glog.Errorf("processHeader: Height of block (=%d) is not equal to one greater "+
			"than the parent height (=%d)", blockHeader.Height, prevHeight)
		return false, false, HeaderErrorHeightInvalid
	}

	// Make sure the block timestamp is greater than the previous block's timestamp.
	// Note Bitcoin checks that the timestamp is greater than the median
	// of the last 11 blocks. While this seems to work for Bitcoin for now it seems
	// vulnerable to a "time warp" attack (requires 51%) and
	// we can do a little better by forcing a harder constraint of making
	// sure a timestamp is larger than the of the previous block. It seems
	// the only real downside of this is some complexity on the miner side
	// of having to account for what happens if a block appears that is from
	// some nearby time in the future rather than the current time. But this
	// burden seems worth it in order to
	// preclude a known and fairly damaging attack from being possible. Moreover,
	// while there are more complicated schemes to fight other attacks based on
	// timestamp manipulation, their benefits seem marginal and not worth the
	// added complexity they entail for now.
	//
	// Discussion of time warp attack and potential fixes for BTC:
	// https://lists.linuxfoundation.org/pipermail/bitcoin-dev/2018-August/016342.html
	// Discussion of more complex attacks and potential fixes:
	// https://github.com/zawy12/difficulty-algorithms/issues/30
	//
	// TODO: Consider a per-block difficulty adjustment scheme like Ethereum has.
	// This commentary is useful to consider with regard to that:
	//   https://github.com/zawy12/difficulty-algorithms/issues/45
	if blockHeader.TstampSecs <= parentHeader.TstampSecs {
		glog.Warningf("processHeader: Rejecting header because timestamp %v is "+
			"before timestamp of previous block %v",
			time.Unix(int64(blockHeader.TstampSecs), 0),
			time.Unix(int64(parentHeader.TstampSecs), 0))
		return false, false, HeaderErrorTimestampTooEarly
	}

	// Check that the proof of work beats the difficulty as calculated from
	// the parent block. Note that if the parent block is in the block index
	// then it has necessarily had its difficulty validated, and so using it to
	// do this check makes sense.
	diffTarget, err := CalcNextDifficultyTarget(parentNode, bc.params)
	if err != nil {
		return false, false, errors.Wrapf(err,
			"ProcessBlock: Problem computing difficulty "+
				"target from parent block %s", hex.EncodeToString(parentNode.Hash[:]))
	}
	diffTargetBigint := HashToBigint(diffTarget)
	blockHashBigint := HashToBigint(headerHash)
	if diffTargetBigint.Cmp(blockHashBigint) < 0 {
		return false, false, HeaderErrorBlockDifficultyAboveTarget
	}

	// At this point the header seems sane so we store it in the db and add
	// it to our in-memory block index. Note we're not doing this atomically.
	// Worst-case, we have a block in our db with no pointer to it in our index,
	// which isn't a big deal.
	//
	// Note in the calculation of CumWork below we are adding the work specified
	// in the difficulty *target* rather than the work actually done to mine the
	// block. There is a very good reason for this, which is that it materially
	// increases a miner's incentive to reveal their block immediately after it's
	// been mined as opposed to try and play games where they withhold their block
	// and try to mine on top of it before revealing it to everyone.
	newWork := BytesToBigint(ExpectedWorkForBlockHash(diffTarget)[:])
	cumWork := newWork.Add(newWork, parentNode.CumWork)
	newNode := NewBlockNode(
		parentNode,
		headerHash,
		blockHeader.Height,
		diffTarget,
		cumWork,
		blockHeader,
		StatusHeaderValidated)

	// Note that we don't store a node for this header on the db until we have downloaded
	// a corresponding block. This has the effect of preventing us against disk-fill
	// attacks. If we instead stored headers on the db then we'd have to deal with an
	// attack that looks as follows:
	// - Attacker makes us download a lot of low-difficulty headers until we eventually
	//   get current and disconnect because the chainwork is too low (having stored all
	//   of those header nodes on the db).
	// - Attacker repeats this over and over again until our db on disk is really full.
	//
	// The above is mitigated because we don't download blocks until we have a header chain
	// with enough work, which means we won't store anything that doesn't have a lot of work
	// built on it.

	// If all went well with storing the header, set it in our in-memory
	// index.
	bc.blockIndex[*newNode.Hash] = newNode

	// Update the header chain if this header has more cumulative work than
	// the header chain's tip. Note that we can assume all ancestors of this
	// header are valid at this point.
	isMainChain := false
	headerTip := bc.headerTip()
	if headerTip.CumWork.Cmp(newNode.CumWork) < 0 {
		isMainChain = true

		_, detachBlocks, attachBlocks := getReorgBlocks(headerTip, newNode)
		bc.bestHeaderChain, bc.bestHeaderChainMap = updateBestChainInMemory(
			bc.bestHeaderChain, bc.bestHeaderChainMap, detachBlocks, attachBlocks)

		// Note that we don't store the best header hash here and so this is an
		// in-memory-only adjustment. See the comment above on preventing attacks.
	}

	return isMainChain, false, nil
}

// ProcessHeader is a wrapper around processHeader, which does the leg-work, that
// acquires the ChainLock first.
func (bc *Blockchain) ProcessHeader(blockHeader *MsgUltranetHeader, headerHash *BlockHash) (_isMainChain bool, _isOrphan bool, _err error) {
	bc.ChainLock.Lock()
	defer bc.ChainLock.Unlock()

	return bc.processHeader(blockHeader, headerHash)
}

// ProcessBlock ...
//
// Note: It is the caller's responsibility to ensure that the BitcoinManager is
// time-current prior to calling ProcessBlock on any transactions that require the
// BitcoinManager for validation (e.g. BitcoinExchange transactions). Failure to
// do so will cause ProcessBlock to error on blocks that could otherwise be valid
// if a time-current BitcoinManager were available. If it is known for sure that
// no BitcoinExchange transactions need to be validated then it is OK for the
// BitcoinManager to not be time-current and even for it to be nil entirely. This
// is useful e.g. for tests where we want to exercise ProcessBlock without setting
// up a time-current BitcoinManager.
func (bc *Blockchain) ProcessBlock(ultranetBlock *MsgUltranetBlock, verifySignatures bool) (_isMainChain bool, _isOrphan bool, _err error) {
	// TODO: Move this to be more isolated.
	bc.ChainLock.Lock()
	defer bc.ChainLock.Unlock()

	if ultranetBlock == nil {
		return false, false, fmt.Errorf("ProcessBlock: Block is nil")
	}

	// Start by getting and validating the block's header.
	blockHeader := ultranetBlock.Header
	if blockHeader == nil {
		return false, false, fmt.Errorf("ProcessBlock: Block header was nil")
	}
	blockHash, err := blockHeader.Hash()
	if err != nil {
		return false, false, errors.Wrapf(err, "ProcessBlock: Problem computing block hash")
	}
	// See if a node for the block exists in our node index.
	nodeToValidate, nodeExists := bc.blockIndex[*blockHash]
	// If the node exists and it has its block status set to StatusBlockProcessed, then it
	// means this block has already been successfully processed before. Return
	// an error in this case so we don't redundantly reprocess it.
	if nodeExists && (nodeToValidate.Status&StatusBlockProcessed) != 0 {
		glog.Debugf("ProcessBlock: Node exists with StatusBlockProcessed (%v)", nodeToValidate)
		return false, false, RuleErrorDuplicateBlock
	}
	// If no node exists for this block at all, then process the header
	// first before we do anything. This should create a node and set
	// the header validation status for it.
	if !nodeExists {
		_, isOrphan, err := bc.processHeader(blockHeader, blockHash)
		if err != nil {
			// If an error occurred processing the header, then the header
			// should be marked as invalid, which should be sufficient.
			return false, false, err
		}
		// If the header is an orphan, return early. We don't process orphan
		// blocks. If the block and its header are truly legitimate then we
		// should re-request it and its parents from a peer and reprocess it
		// once it is no longer an orphan.
		if isOrphan {
			return false, true, nil
		}

		// Reset the pointers after having presumably added the header to the
		// block index.
		nodeToValidate, nodeExists = bc.blockIndex[*blockHash]
	}
	// At this point if the node still doesn't exist or if the header's validation
	// failed then we should return an error for the block. Note that at this point
	// the header must either be Validated or ValidateFailed.
	if !nodeExists || (nodeToValidate.Status&StatusHeaderValidated) == 0 {
		return false, false, RuleErrorInvalidBlockHeader
	}

	// At this point, we are sure that the block's header is not an orphan and
	// that its header has been properly validated. The block itself could still
	// be an orphan, however, for example if we've processed the header of the parent but
	// not the parent block itself.
	//
	// Find the parent node in our block index. If the node doesn't exist or if the
	// node exists without StatusBlockProcessed, then the current block is an orphan.
	// In this case go ahead and return early. If its parents are truly legitimate then we
	// should re-request it and its parents from a node and reprocess it
	// once it is no longer an orphan.
	parentNode, parentNodeExists := bc.blockIndex[*blockHeader.PrevBlockHash]
	if !parentNodeExists || (parentNode.Status&StatusBlockProcessed) == 0 {
		return false, true, nil
	}

	// At this point, because we know the block isn't an orphan, go ahead and mark
	// it as processed. This flag is basically used to avoid situations in which we
	// continuously try to fetch and reprocess a block because we forgot to mark
	// it as invalid (which would be a bug but this behavior allows us to handle
	// it more gracefully).
	nodeToValidate.Status |= StatusBlockProcessed
	if err := PutHeightHashToNodeInfo(nodeToValidate, bc.db, false /*bitcoinNodes*/); err != nil {
		return false, false, errors.Wrapf(
			err, "ProcessBlock: Problem calling PutHeightHashToNodeInfo with StatusBlockProcessed")
	}

	// Reject the block if any of the following apply to the parent:
	// - Its header is nil.
	// - Its header or its block validation failed.
	if parentNode.Header == nil ||
		(parentNode.Status&(StatusHeaderValidateFailed|StatusBlockValidateFailed)) != 0 {

		bc.MarkBlockInvalid(nodeToValidate)
		return false, false, RuleErrorPreviousBlockInvalid
	}

	// At this point, we know that we are processing a block we haven't seen
	// before and we know that the parent block is stored and not invalid.

	// Make sure the block size is not too big.
	serializedBlock, err := ultranetBlock.ToBytes(false)
	if err != nil {
		// Don't mark the block invalid here since the serialization is
		// potentially a network issue not an issue with the actual block.
		return false, false, fmt.Errorf("ProcessBlock: Problem serializing block")
	}
	if uint64(len(serializedBlock)) > bc.params.MaxBlockSizeBytes {
		bc.MarkBlockInvalid(nodeToValidate)
		return false, false, RuleErrorBlockTooBig
	}

	// Block must have at least one transaction.
	if len(ultranetBlock.Txns) == 0 {
		bc.MarkBlockInvalid(nodeToValidate)
		return false, false, RuleErrorNoTxns
	}

	// The first transaction in a block must be a block reward.
	firstTxn := ultranetBlock.Txns[0]
	if firstTxn.TxnMeta.GetTxnType() != TxnTypeBlockReward {
		return false, false, RuleErrorFirstTxnMustBeBlockReward
	}

	// Do some txn sanity checks.
	for _, txn := range ultranetBlock.Txns[1:] {
		// There shouldn't be more than one block reward in the transaction list.
		if txn.TxnMeta.GetTxnType() == TxnTypeBlockReward {
			bc.MarkBlockInvalid(nodeToValidate)
			return false, false, RuleErrorMoreThanOneBlockReward
		}

		if err := CheckTransactionSanity(txn); err != nil {
			bc.MarkBlockInvalid(nodeToValidate)
			return false, false, err
		}
	}

	// Compute and check the merkle root of all the txns.
	merkleRoot, txHashes, err := ComputeMerkleRoot(ultranetBlock.Txns)
	if err != nil {
		// Don't mark the block invalid here since the serialization is
		// potentially a network issue not an issue with the actual block.
		return false, false, errors.Wrapf(err, "ProcessBlock: Problem computing merkle root")
	}
	if *merkleRoot != *blockHeader.TransactionMerkleRoot {
		bc.MarkBlockInvalid(nodeToValidate)
		glog.Errorf("ProcessBlock: Merkle root in block %v does not match computed "+
			"merkle root %v", blockHeader.TransactionMerkleRoot, merkleRoot)
		return false, false, RuleErrorInvalidTxnMerkleRoot
	}

	// Check for duplicate txns now that they're hashed.
	existingTxns := make(map[BlockHash]bool)
	for ii := range ultranetBlock.Txns {
		currentHash := *txHashes[ii]
		if _, exists := existingTxns[currentHash]; exists {
			bc.MarkBlockInvalid(nodeToValidate)
			return false, false, RuleErrorDuplicateTxn
		}
		existingTxns[currentHash] = true
	}

	// Try and store the block and its corresponding node info since it has passed
	// basic validation.
	nodeToValidate.Status |= StatusBlockStored
	err = bc.db.Update(func(txn *badger.Txn) error {
		// Store the new block in the db under the
		//   <blockHash> -> <serialized block>
		// index.
		if err := PutBlockWithTxn(txn, ultranetBlock); err != nil {
			return errors.Wrapf(err, "ProcessBlock: Problem calling PutBlock")
		}

		// Store the new block's node in our node index in the db under the
		//   <height uin32, blockhash BlockHash> -> <node info>
		// index.
		if err := PutHeightHashToNodeInfoWithTxn(txn, nodeToValidate, false /*bitcoinNodes*/); err != nil {
			return errors.Wrapf(err,
				"ProcessBlock: Problem calling PutHeightHashToNodeInfo before validation")
		}

		return nil
	})
	if err != nil {
		return false, false, errors.Wrapf(
			err, "ProcessBlock: Problem storing block after basic validation")
	}

	// Now we try and add the block to the main block chain (note that it should
	// already be on the main header chain if we've made it this far).

	// Get the current tip.
	currentTip := bc.blockTip()

	// Only verify the merchant merkle root if we're current. Otherwise, it's a waste
	// of computation.
	verifyMerchantMerkleRoot := false
	if bc.isTipCurrent(currentTip) {
		verifyMerchantMerkleRoot = true
	}

	// See if the current tip is equal to the block's parent.
	isMainChain := false
	if *parentNode.Hash == *currentTip.Hash {
		// Create a new UtxoView representing the current tip.
		//
		// TODO: An optimization can be made here where we pre-load all the inputs this txn
		// requires into the view before-hand. This basically requires two passes over
		// the txns to account for txns that spend previous txns in the block, but it would
		// almost certainly be more efficient than doing a separate db call for each input
		// and output.
		utxoView, err := NewUtxoView(bc.db, bc.params, bc.bitcoinManager)
		if err != nil {
			return false, false, errors.Wrapf(err, "ProcessBlock: Problem initializing UtxoView in simple connect to tip")
		}
		// Verify that the utxo view is pointing to the current tip.
		if *utxoView.TipHash != *currentTip.Hash {
			return false, false, fmt.Errorf("ProcessBlock: Tip hash for utxo view (%v) is "+
				"not the current tip hash (%v)", *utxoView.TipHash, *currentTip)
		}

		utxoOpsForBlock, err := utxoView.ConnectBlock(
			ultranetBlock, txHashes, verifySignatures, verifyMerchantMerkleRoot)
		if err != nil {
			if IsRuleError(err) {
				// If we have a RuleError, mark the block as invalid before
				// returning.
				bc.MarkBlockInvalid(nodeToValidate)
				return false, false, err
			}

			// If the error wasn't a RuleError, return without marking the
			// block as invalid, since this means the block may benefit from
			// being reprocessed in the future, which will happen if a reorg
			// puts this block on the main chain.
			return false, false, err
		}
		// If all of the above passed it means the block is valid. So set the
		// status flag on the block to indicate that and write the status to disk.
		nodeToValidate.Status |= StatusBlockValidated

		// Now that we have a valid block that we know is connecting to the tip,
		// update our data structures to actually make this connection. Do this
		// in a transaction so that it is atomic.
		err = bc.db.Update(func(txn *badger.Txn) error {
			// This will update the node's status.
			if err := PutHeightHashToNodeInfoWithTxn(txn, nodeToValidate, false /*bitcoinNodes*/); err != nil {
				return errors.Wrapf(
					err, "ProcessBlock: Problem calling PutHeightHashToNodeInfo after validation")
			}

			// Set the best node hash to this one. Note the header chain should already
			// be fully aware of this block so we shouldn't update it here.
			if err := PutBestHashWithTxn(txn, blockHash, ChainTypeUltranetBlock); err != nil {
				return err
			}

			// Write the modified utxo set to the view.
			if err := utxoView.FlushToDbWithTxn(txn); err != nil {
				return errors.Wrapf(err, "ProcessBlock: Problem writing utxo view to db on simple add to tip")
			}

			// Write the utxo operations for this block to the db so we can have the
			// ability to roll it back in the future.
			if err := PutUtxoOperationsForBlockWithTxn(txn, blockHash, utxoOpsForBlock); err != nil {
				return errors.Wrapf(err, "ProcessBlock: Problem writing utxo operations to db on simple add to tip")
			}

			return nil
		})

		if err != nil {
			return false, false, errors.Wrapf(err, "ProcessBlock: Problem writing block info to db on simple add to tip")
		}

		// Now that we've set the best chain in the db, update our in-memory data
		// structure to reflect this. Do a quick check first to make sure it's consistent.
		lastIndex := len(bc.bestChainn) - 1
		if *bc.bestChainn[lastIndex].Hash != *nodeToValidate.Header.PrevBlockHash {
			return false, false, fmt.Errorf("ProcessBlock: Last block in bestChain "+
				"data structure (%v) is not equal to parent hash of block being "+
				"added to tip (%v)", *bc.bestChainn[lastIndex].Hash, *nodeToValidate.Header.PrevBlockHash)
		}
		bc.bestChainn = append(bc.bestChainn, nodeToValidate)
		bc.bestChainMap[*nodeToValidate.Hash] = nodeToValidate

		// This node is on the main chain so set this variable.
		isMainChain = true

		// At this point we should have the following:
		// * The block has been written to disk.
		// * The block is in our in-memory node tree data structure.
		// * The node tree has been updated on disk.
		// * The block is on our in-memory main chain data structure.
		// * The on-disk data structure should be updated too:
		//   - The best hash should now be set to this block.
		//   - The <height -> hash> index representing the main chain should be updated
		//     to have this block.
		//   - The utxo db should be updated to reflect the effects of adding this block.
		//   - The utxo operations performed for this block should also be stored so we
		//     can roll the block back in the future if needed.

		// Signal to the server that the block has been connected to the main
		// chain. Do this in a goroutine so that if ProcessBlock is called by
		// a consumer of incomingMessages we don't have any risk of deadlocking.
		go func(blk *MsgUltranetBlock) {
			bc.blockNotificationChannel <- &ServerMessage{
				Msg: &MsgUltranetBlockMainChainConnected{
					block: blk,
				},
			}
		}(ultranetBlock)

	} else if nodeToValidate.CumWork.Cmp(currentTip.CumWork) <= 0 {
		// A block has less cumulative work than our tip. In this case, we just ignore
		// the block for now. It is stored in our <hash -> block_data> map on disk as well
		// as in our in-memory node tree data structure (which is also stored on disk).
		// Eventually, if enough work gets added to the block, then we'll
		// add it via a reorg.
	} else {
		// In this case the block is not attached to our tip and the cumulative work
		// of the block is greater than our tip. This means we have a fork that has
		// the potential to become our new main chain so we need to do a reorg to
		// process it. A reorg consists of the following:
		// 1) Find the common ancecstor of this block and the main chain.
		// 2) Roll back all of the main chain blocks back to this common ancestor.
		// 3) Verify and add the new blocks up to this one.
		//
		// Note that if verification fails while trying to add the new blocks then
		// we will not wind up accepting the changes. For this reason all of the
		// above steps are processed using an in-memory view before writing anything
		// to the database.

		// Find the common ancestor of this block and the main chain.
		commonAncestor, detachBlocks, attachBlocks := getReorgBlocks(currentTip, nodeToValidate)
		// Log a warning if the reorg is going to be a big one.
		numBlocks := currentTip.Height - commonAncestor.Height
		if numBlocks > 10 {
			glog.Warningf("ProcessBlock: Proceeding with reorg of (%d) blocks from "+
				"block (%v) at height (%d) to block (%v) at height of (%d)",
				numBlocks, currentTip, currentTip.Height, nodeToValidate, nodeToValidate.Height)
		}

		// Create an empty view referencing the current tip.
		//
		// TODO: An optimization can be made here where we pre-load all the inputs this txn
		// requires into the view before-hand. This basically requires two passes over
		// the txns to account for txns that spend previous txns in the block, but it would
		// almost certainly be more efficient than doing a separate db call for each input
		// and output
		utxoView, err := NewUtxoView(bc.db, bc.params, bc.bitcoinManager)
		if err != nil {
			return false, false, errors.Wrapf(err, "processblock: Problem initializing UtxoView in reorg")
		}
		// Verify that the utxo view is pointing to the current tip.
		if *utxoView.TipHash != *currentTip.Hash {
			return false, false, fmt.Errorf("ProcessBlock: Tip hash for utxo view (%v) is "+
				"not the current tip hash (%v)", *utxoView.TipHash, *currentTip)
		}

		// Go through and detach all of the blocks down to the common ancestor. We
		// shouldn't encounter any errors but if we do, return without marking the
		// block as invalid.
		for _, nodeToDetach := range detachBlocks {
			// Fetch the utxo operations for the block we're detaching. We need these
			// in order to be able to detach the block.
			utxoOps, err := GetUtxoOperationsForBlock(bc.db, nodeToDetach.Hash)
			if err != nil {
				return false, false, errors.Wrapf(err, "ProcessBlock: Problem fetching "+
					"utxo operations during detachment of block (%v) "+
					"in reorg", nodeToDetach)
			}

			// Fetch the block itself since we need some info from it to roll
			// it back.
			blockToDetach, err := GetBlock(nodeToDetach.Hash, bc.db)
			if err != nil {
				return false, false, errors.Wrapf(err, "ProcessBlock: Problem fetching "+
					"block (%v) during detach in reorg", nodeToDetach)
			}

			// Compute the hashes for all the transactions.
			txHashes, err := ComputeTransactionHashes(blockToDetach.Txns)
			if err != nil {
				return false, false, errors.Wrapf(err, "ProcessBlock: Problem computing "+
					"transaction hashes during detachment of block (%v)", nodeToDetach)
			}

			// Now roll the block back in the view.
			if err := utxoView.DisconnectBlock(blockToDetach, txHashes, utxoOps); err != nil {
				return false, false, errors.Wrapf(err, "ProcessBlock: Problem rolling back "+
					"block (%v) during detachment in reorg", nodeToDetach)
			}
			// Double-check that the view's hash is now at the block's parent.
			if *utxoView.TipHash != *blockToDetach.Header.PrevBlockHash {
				return false, false, fmt.Errorf("ProcessBlock: Block hash in utxo view (%v) "+
					"does not match parent block hash (%v) after executing "+
					"DisconnectBlock", utxoView.TipHash, blockToDetach.Header.PrevBlockHash)
			}
		}

		// If we made it here, we were able to successfully detach all of the blocks
		// such that the view is now at the common ancestor. Double-check that this is
		// the case.
		if *utxoView.TipHash != *commonAncestor.Hash {
			return false, false, fmt.Errorf("ProcessBlock: Block hash in utxo view (%v) "+
				"does not match common ancestor hash (%v) after executing "+
				"DisconnectBlock", utxoView.TipHash, commonAncestor.Hash)
		}

		// Now that the view has the common ancestor as the tip, we can try and attach
		// each new block to it to see if the reorg will work.
		//
		// Keep track of the utxo operations we get from attaching the blocks.
		utxoOpsForAttachBlocks := [][][]*UtxoOperation{}
		// Also keep track of any errors that we might have come across.
		ruleErrorsFound := []RuleError{}
		// The first element will be the node right after the common ancestor and
		// the last element will be the new node we need to attach.
		for _, attachNode := range attachBlocks {

			// Fetch the block itself since we need some info from it to try and
			// connect it.
			blockToAttach, err := GetBlock(attachNode.Hash, bc.db)
			if err != nil {
				return false, false, errors.Wrapf(err, "ProcessBlock: Problem fetching "+
					"block (%v) during attach in reorg", attachNode)
			}

			// If the parent node has been marked as invalid then mark this node as
			// invalid as well.
			if (attachNode.Parent.Status & StatusBlockValidateFailed) != 0 {
				bc.MarkBlockInvalid(attachNode)
				continue
			}

			// Compute the tx hashes for the block since we need them to perform
			// the connection.
			txHashes, err := ComputeTransactionHashes(blockToAttach.Txns)
			if err != nil {
				return false, false, errors.Wrapf(err, "ProcessBlock: Problem computing "+
					"transaction hashes during attachment of block (%v) in reorg", blockToAttach)
			}

			// Initialize the utxo operations slice.
			utxoOps, err := utxoView.ConnectBlock(
				blockToAttach, txHashes, verifySignatures, verifyMerchantMerkleRoot)
			if err != nil {
				if IsRuleError(err) {
					// If we have a RuleError, mark the block as invalid. But don't return
					// yet because we need to mark all of the child blocks as invalid as
					// well first.
					bc.MarkBlockInvalid(attachNode)
					ruleErrorsFound = append(ruleErrorsFound, err.(RuleError))
					continue
				} else {
					// If the error wasn't a RuleError, return without marking the
					// block as invalid, since this means the block may benefit from
					// being reprocessed in the future.
					return false, false, errors.Wrapf(err, "ProcessBlock: Problem trying to attach block (%v) in reorg", attachNode)
				}
			}

			// If we made it here then we were able to connect the block successfully.
			// So mark its status as valid and update the node index accordingly.
			attachNode.Status |= StatusBlockValidated
			if err := PutHeightHashToNodeInfo(attachNode, bc.db, false /*bitcoinNodes*/); err != nil {
				return false, false, errors.Wrapf(
					err, "ProcessBlock: Problem calling PutHeightHashToNodeInfo after validation in reorg")
			}

			// Add the utxo operations to our list.
			utxoOpsForAttachBlocks = append(utxoOpsForAttachBlocks, utxoOps)
		}

		// At this point, either we were able to attach all of the blocks OR the block
		// we are processing is invalid (possibly due to one of its parents to being
		// invalid). Regardless, because the attach worked if and only if the block we
		// are processing is valid, it is sufficient to use this block's validity to decide
		// if we want to perform this reorg.
		//
		// Recall that newNode is the node at the tip of the new chain we're trying to
		// reorg to which is also the last node in attachBlocks.
		newTipNode := attachBlocks[len(attachBlocks)-1]
		if (newTipNode.Status & StatusBlockValidateFailed) != 0 {
			// In the case where the new tip is invalid, we encountered an error while
			// processing. Return the first error we encountered. Note we should already
			// have marked all the blocks as invalid so no need to do it here.
			return false, false, ruleErrorsFound[0]
		}

		// If we made it this far, we know the reorg will succeed and the view contains
		// the state after applying the reorg. With this information, it is possible to
		// roll back the blocks and fast forward the db to the post-reorg state with a
		// single transaction.
		err = bc.db.Update(func(txn *badger.Txn) error {
			// Set the best node hash to the new tip.
			if err := PutBestHashWithTxn(txn, newTipNode.Hash, ChainTypeUltranetBlock); err != nil {
				return err
			}

			for _, detachNode := range detachBlocks {
				// Delete the utxo operations for the blocks we're detaching since we don't need
				// them anymore.
				DeleteUtxoOperationsForBlockWithTxn(txn, detachNode.Hash)

				// Note we could be even more aggressive here by deleting the nodes and
				// corresponding blocks from the db here (i.e. not storing any side chain
				// data on the db). But this seems like a minor optimization that comes at
				// the minor cost of side chains not being retained by the network as reliably.
			}

			for ii, attachNode := range attachBlocks {
				// Add the utxo operations for the blocks we're attaching so we can roll them back
				// in the future if necessary.
				PutUtxoOperationsForBlockWithTxn(txn, attachNode.Hash, utxoOpsForAttachBlocks[ii])
			}

			// Write the modified utxo set to the view.
			utxoView.FlushToDbWithTxn(txn)

			return nil
		})

		// Now the the db has been updated, update our in-memory best chain. Note that there
		// is no need to update the node index because it was updated as we went along.
		bc.bestChainn, bc.bestChainMap = updateBestChainInMemory(
			bc.bestChainn, bc.bestChainMap, detachBlocks, attachBlocks)

		// If we made it here then this block is on the main chain.
		isMainChain = true

		// Signal to the server about all the blocks that were disconnected and
		// connected as a result of this operation. Do this in a goroutine so that
		// if ProcessBlock is called by a consumer of incomingMessages we don't
		// have any risk of deadlocking.
		for _, nodeToDetach := range detachBlocks {
			// Fetch the block itself since we need some info from it to roll
			// it back.
			blockToDetach, err := GetBlock(nodeToDetach.Hash, bc.db)
			if err != nil {
				return false, false, errors.Wrapf(err, "ProcessBlock: Problem fetching "+
					"block (%v) during detach in server signal", nodeToDetach)
			}
			go func(blk *MsgUltranetBlock) {
				bc.blockNotificationChannel <- &ServerMessage{
					Msg: &MsgUltranetBlockMainChainDisconnected{
						block: blk,
					},
				}
			}(blockToDetach)
		}
		for _, attachNode := range attachBlocks {

			// Fetch the block itself since we need some info from it to try and
			// connect it.
			blockToAttach, err := GetBlock(attachNode.Hash, bc.db)
			if err != nil {
				return false, false, errors.Wrapf(err, "ProcessBlock: Problem fetching "+
					"block (%v) during attach in server signal", attachNode)
			}
			go func(blk *MsgUltranetBlock) {
				bc.blockNotificationChannel <- &ServerMessage{
					Msg: &MsgUltranetBlockMainChainConnected{
						block: blk,
					},
				}
			}(blockToAttach)
		}

		go func(blk *MsgUltranetBlock) {
			bc.blockNotificationChannel <- &ServerMessage{
				Msg: &MsgUltranetBlockMainChainConnected{
					block: blk,
				},
			}
		}(ultranetBlock)
	}

	// If we've made it this far, the block has been validated and we have either added
	// the block to the tip, done nothing with it (because its cumwork isn't high enough)
	// or added it via a reorg and the db and our in-memory data structures reflect this
	// change.
	//
	// Now that we've done all of the above, we need to signal to the server that we've
	// accepted the block

	// Signal the server that we've accepted this block in some way.
	go func(blk *MsgUltranetBlock) {
		bc.blockNotificationChannel <- &ServerMessage{
			Msg: &MsgUltranetBlockAccepted{
				block: blk,
			},
		}
	}(ultranetBlock)

	// At this point, the block we were processing originally should have been added
	// to our data structures and any orphans that are no longer orphans should have
	// also been processed.
	return isMainChain, false, nil
}

// ValidateTransaction creates a UtxoView and sees if the transaction can be connected
// to it. If a mempool is provided, this function tries to find dependencies of the
// passed-in transaction in the pool and connect them before trying to connect the
// passed-in transaction.
func (bc *Blockchain) ValidateTransaction(
	txnMsg *MsgUltranetTxn, blockHeight uint32, verifySignatures bool,
	verifyMerchantMerkleRoot bool,
	enforceMinBitcoinBurnWork bool, mempool *TxPool) error {

	bc.ChainLock.RLock()
	defer bc.ChainLock.RUnlock()

	// Create a new UtxoView. If we have access to a mempool object, use it to
	// get an augmented view that factors in pending transactions.
	utxoView, err := NewUtxoView(bc.db, bc.params, bc.bitcoinManager)
	if err != nil {
		return errors.Wrapf(err, "ValidateTransaction: Problem Problem creating new utxo view: ")
	}
	if mempool != nil {
		utxoView, err = mempool.GetAugmentedUtxoViewForPublicKey(txnMsg.PublicKey)
		if err != nil {
			return errors.Wrapf(err, "ValidateTransaction: Problem getting augmented UtxoView from mempool: ")
		}
	}

	// Hash the transaction.
	txHash := txnMsg.Hash()
	if err != nil {
		return errors.Wrapf(err, "ValidateTransaction: Problem serializing txn: ")
	}

	// We don't care about the utxoOps or the fee it returns.
	_, _, _, _, err = utxoView._connectTransaction(
		txnMsg,
		txHash,
		blockHeight,
		verifySignatures,
		verifyMerchantMerkleRoot,
		enforceMinBitcoinBurnWork,
	)
	if err != nil {
		return errors.Wrapf(err, "ValidateTransaction: Problem validating transaction: ")
	}

	return nil
}

var (
	maxHash = BlockHash{
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff}
	maxHashBigint = HashToBigint(&maxHash)
	bigOne        = big.NewInt(1)
)

// ExpectedWorkForBlockHash ...
// The number of hashing attempts in expectation it would take to produce the
// hash passed in. This is computed as:
//    E(min(X_i, ..., X_n)) where:
//    - n = (number of attempted hashes) and
//    - the X_i are all U(0, MAX_HASH)
// -> E(min(X_i, ..., X_n)) = MAX_HASH / (n + 1)
// -> E(n) ~= MAX_HASH / min_hash - 1
//    - where min_hash is the block hash
//
// We approximate this as MAX_HASH / (min_hash + 1), adding 1 to min_hash in
// order to mitigate the possibility of a divide-by-zero error.
//
// The value returned is the expected number of hashes performed to produce
// the input hash formatted as a big-endian big integer that uses the
// BlockHash type for convenience (though it is likely to be much lower
// in terms of magnitude than a typical BlockHash object).
func ExpectedWorkForBlockHash(hash *BlockHash) *BlockHash {
	hashBigint := HashToBigint(hash)
	ratioBigint := new(big.Int)
	ratioBigint.Div(maxHashBigint, hashBigint.Add(hashBigint, bigOne))
	return BigintToHash(ratioBigint)
}

// Compute the next power of 2 for a number.
// Ex: 3 -> 4, 4 -> 4, 5->8
func _nextPowerOfTwo(n int) int {
	if n&(n-1) == 0 {
		return n
	}

	exponent := uint(math.Log2(float64(n))) + 1
	// 2^exponent
	return 1 << exponent
}

func _hashMerkleBranches(left *BlockHash, right *BlockHash) *BlockHash {
	var concatedHash [HashSizeBytes * 2]byte
	copy(concatedHash[:HashSizeBytes], left[:])
	copy(concatedHash[HashSizeBytes:], right[:])

	newHash := Sha256DoubleHash(concatedHash[:])
	return newHash
}

// ComputeTransactionHashes ...
func ComputeTransactionHashes(txns []*MsgUltranetTxn) ([]*BlockHash, error) {
	txHashes := make([]*BlockHash, len(txns))

	for ii, currentTxn := range txns {
		txHashes[ii] = currentTxn.Hash()
	}

	return txHashes, nil
}

// ComputeMerkleRoot ...
func ComputeMerkleRoot(txns []*MsgUltranetTxn) (_merkle *BlockHash, _txHashes []*BlockHash, _err error) {
	if len(txns) == 0 {
		return nil, nil, fmt.Errorf("ComputeMerkleRoot: Block must contain at least one txn")
	}

	// Compute the hashes of all the transactions.
	hashes := [][]byte{}
	for _, txn := range txns {
		txHash := txn.Hash()
		hashes = append(hashes, txHash[:])
	}

	merkleTree := merkletree.NewTreeFromHashes(merkletree.Sha256DoubleHash, hashes)

	rootHash := &BlockHash{}
	copy(rootHash[:], merkleTree.Root.GetHash()[:])

	txHashes := []*BlockHash{}
	for _, leafNode := range merkleTree.Rows[0] {
		currentHash := &BlockHash{}
		copy(currentHash[:], leafNode.GetHash())
		txHashes = append(txHashes, currentHash)
	}

	return rootHash, txHashes, nil
}

// GetSpendableUtxosForPublicKey ...
func (bc *Blockchain) GetSpendableUtxosForPublicKey(spendPublicKeyBytes []byte, mempool *TxPool) ([]*UtxoEntry, error) {
	// If we have access to a mempool, use it to account for utxos we might not
	// get otherwise.
	utxoView, err := NewUtxoView(bc.db, bc.params, bc.bitcoinManager)
	if err != nil {
		return nil, errors.Wrapf(err, "Blockchain.GetSpendableUtxosForPublicKey: Problem initializing UtxoView: ")
	}
	if mempool != nil {
		utxoView, err = mempool.GetAugmentedUtxoViewForPublicKey(spendPublicKeyBytes)
		if err != nil {
			return nil, errors.Wrapf(err, "Blockchain.GetSpendableUtxosForPublicKey: Problem getting augmented UtxoView from mempool: ")
		}
	}

	// Get unspent utxos from the view.
	utxoEntriesFound, err := utxoView.GetUnspentUtxoEntrysForPublicKey(spendPublicKeyBytes)
	if err != nil {
		return nil, errors.Wrapf(err, "Blockchain.GetSpendableUtxosForPublicKey: Problem getting spendable utxos from UtxoView: ")
	}

	// Sort the UTXOs putting the smallest amounts first.
	//
	// TODO: There has generally been a lot of discussion and thought about
	// what the optimal coin selection algorithm should be over the years.
	// Here, we choose to keep things simple and just use the smallest UTXOs
	// first. It has its drawbacks and we should revisit it at some point,
	// but for now it seems like it should be fine, and the reduction of the
	// size of the UTXO set seems like a reasonable benefit of using it. See below
	// for more discussion:
	// https://bitcoin.stackexchange.com/questions/32145/what-are-the-trade-offs-between-the-different-algorithms-for-deciding-which-utxo
	sort.Slice(utxoEntriesFound, func(ii, jj int) bool {
		return utxoEntriesFound[ii].AmountNanos < utxoEntriesFound[jj].AmountNanos
	})

	// Add UtxoEntrys to our list filtering out ones that aren't valid for various
	// reasons.
	spendableUtxoEntries := []*UtxoEntry{}
	for _, utxoEntry := range utxoEntriesFound {
		// If the utxo is an immature block reward, skip it. Use the block chain height
		// not the header chain height since the transaction will need to be validated
		// against existing transactions which are present only if we have blocks.
		//
		// Note we add one to the current block height since it is presumed this
		// transaction will at best be mined into the next block.
		blockHeight := bc.blockTip().Height + 1
		if _isEntryImmatureBlockReward(utxoEntry, blockHeight, bc.params) {
			continue
		}

		// Don't consider utxos that are already consumed by the mempool.
		if mempool != nil && mempool.CheckSpend(*utxoEntry.utxoKey) != nil {
			continue
		}

		// If we get here we know the utxo is spendable so add it to our list.
		spendableUtxoEntries = append(spendableUtxoEntries, utxoEntry)
	}

	return spendableUtxoEntries, nil
}

// Define a helper function for computing the upper bound of the size
// of a transaction and associated fees. This basically serializes the
// transaction without the signature and then accounts for the maximum possible
// size the signature could be.
func _computeMaxTxSize(_tx *MsgUltranetTxn) uint64 {
	// Compute the size of the transaction without the signature.
	txBytesNoSignature, _ := _tx.ToBytes(true /*preSignature*/)
	// Return the size the transaction would be if the signature had its
	// absolute maximum length.
	return uint64(len(txBytesNoSignature)) + btcec.MaxDERSigLen
}

// A helper for computing the max fee given a txn. Assumes the longest signature
// length.
func _computeMaxTxFee(_tx *MsgUltranetTxn, minFeeRateNanosPerKB uint64) uint64 {
	maxSizeBytes := _computeMaxTxSize(_tx)
	return maxSizeBytes * minFeeRateNanosPerKB / 1000
}

func _newUtxoView(db *badger.DB, params *UltranetParams, bitcoinManager *BitcoinManager,
	optionalPublicKey []byte, optionalMempool *TxPool) (*UtxoView, error) {

	utxoView, err := NewUtxoView(db, params, bitcoinManager)
	if err != nil {
		return nil, errors.Wrapf(err, "Blockchain._newUtxoView: Problem initializing UtxoView: ")
	}
	if optionalMempool != nil && len(optionalPublicKey) != 0 {
		utxoView, err = optionalMempool.GetAugmentedUtxoViewForPublicKey(optionalPublicKey)
		if err != nil {
			return nil, errors.Wrapf(err, "Blockchain._newUtxoView: Problem getting augmented UtxoView from mempool: ")
		}
	}
	return utxoView, nil
}

func (bc *Blockchain) CreateRefundOrderTxn(
	merchantPublicKey []byte, buyerPublicKey []byte, orderID *BlockHash,
	minFeeRateNanosPerKB uint64, mempool *TxPool) (
	_txn *MsgUltranetTxn, _totalInput uint64, _buyerRefundAmount uint64, _changeAmount uint64, _fees uint64, _err error) {

	// Get a UtxoView, potentially augmenting it with mempool transactions
	// for the merchant public key.
	utxoView, err := _newUtxoView(bc.db, bc.params, bc.bitcoinManager,
		merchantPublicKey, mempool)
	if err != nil {
		return nil, 0, 0, 0, 0, errors.Wrapf(err, "Blockchain.CreateRefundOrderTxn: Problem getting UtxoView: ")
	}

	// Get the OrderEntry for the OrderID from the view. This will hit the db
	// only if there were no modifications to the order in the mempool, which
	// is exactly what we want.
	orderEntry := utxoView._getOrderEntryForOrderID(orderID)
	if orderEntry == nil {
		return nil, 0, 0, 0, 0, fmt.Errorf("Blockchain.CreateRefundOrderTxn: OrderEntry not found for OrderID %v", err)
	}

	// A refund must pay the buyer the revenue the merchant earned from
	// the transaction in order to be valid. Note the commissions do not
	// get paid back and stay locked in the order forever. This is to prevent
	// situations in which merchants create a lot of fake orders with themselves
	// and then refund themselves back all the money.
	_, revenueNanos, err := _computeCommissionsAndRevenueFromPayment(
		orderEntry.PaymentAmountNanos, bc.params.CommissionBasisPoints)
	if err != nil {
		return nil, 0, 0, 0, 0, fmt.Errorf("Blockchain.CreateRefundOrderTxn: Problem computing revenue from order: %v", err)
	}

	// Compute the fee based on the size of the order with just one output
	// collecting the money on behalf of the merchant.
	txn := &MsgUltranetTxn{
		TxInputs: []*UltranetInput{},
		TxOutputs: []*UltranetOutput{
			&UltranetOutput{
				PublicKey:   buyerPublicKey,
				AmountNanos: revenueNanos,
			},
		},
		PublicKey: merchantPublicKey,
		TxnMeta: &RefundOrderMetadata{
			OrderID: orderID,
		},

		// We wait to compute the signature until we've added all the
		// inputs and change.
	}

	totalInput, spendAmount, changeAmount, fees, err :=
		bc.AddInputsAndChangeToTransaction(txn, minFeeRateNanosPerKB, mempool)
	if err != nil {
		return nil, 0, 0, 0, 0, errors.Wrapf(err, "Blockchain.CreateRefundOrderTxn: Problem adding inputs: ")
	}

	return txn, totalInput, spendAmount, changeAmount, fees, nil
}

func (bc *Blockchain) CreateFulfillOrderTxn(
	merchantPublicKey []byte, orderID *BlockHash, minFeeRateNanosPerKB uint64, mempool *TxPool) (
	_txn *MsgUltranetTxn, _totalInput uint64, _changeAmount uint64, _fees uint64, _err error) {

	// Get a UtxoView, potentially augmenting it with mempool transactions
	// for the merchant public key.
	utxoView, err := _newUtxoView(bc.db, bc.params, bc.bitcoinManager, merchantPublicKey, mempool)
	if err != nil {
		return nil, 0, 0, 0, errors.Wrapf(err, "Blockchain.CreateFulfillOrderTxn: Problem getting UtxoView: ")
	}

	// Get the OrderEntry for the OrderID from the view. This will hit the db
	// only if there were no modifications to the order in the mempool, which
	// is exactly what we want.
	orderEntry := utxoView._getOrderEntryForOrderID(orderID)
	if orderEntry == nil {
		return nil, 0, 0, 0, fmt.Errorf("Blockchain.CreateFulfillOrderTxn: OrderEntry not found for OrderID %v", err)
	}

	// Compute the fee based on the size of the order with just one output
	// collecting the money on behalf of the merchant.
	txn := &MsgUltranetTxn{
		TxInputs:  []*UltranetInput{},
		TxOutputs: []*UltranetOutput{},
		PublicKey: merchantPublicKey,
		TxnMeta: &FulfillOrderMetadata{
			OrderID: orderID,
		},

		// We wait to compute the signature until we've added all the
		// inputs and change.
	}

	totalInput, _, changeAmount, fees, err :=
		bc.AddInputsAndChangeToTransaction(txn, minFeeRateNanosPerKB, mempool)
	if err != nil {
		return nil, 0, 0, 0, errors.Wrapf(err, "Blockchain.CreateFulfillOrderTxn: Problem adding inputs: ")
	}

	return txn, totalInput, changeAmount, fees, nil
}

func (bc *Blockchain) CreateReviewOrderTxn(
	buyerPublicKey []byte, orderID *BlockHash, reviewType ReviewType, reviewText []byte,
	minFeeRateNanosPerKB uint64, mempool *TxPool) (
	_txn *MsgUltranetTxn, _totalInput uint64, _changeAmount uint64, _fees uint64, _err error) {

	// Get a UtxoView, potentially augmenting it with mempool transactions
	// for the merchant public key.
	utxoView, err := _newUtxoView(bc.db, bc.params, bc.bitcoinManager, buyerPublicKey, mempool)
	if err != nil {
		return nil, 0, 0, 0, errors.Wrapf(err, "Blockchain.CreateReviewOrderTxn: Problem getting UtxoView: ")
	}

	// Get the OrderEntry for the OrderID from the view. This will hit the db
	// only if there were no modifications to the order in the mempool, which
	// is exactly what we want.
	orderEntry := utxoView._getOrderEntryForOrderID(orderID)
	if orderEntry == nil {
		return nil, 0, 0, 0, fmt.Errorf("Blockchain.CreateReviewOrderTxn: OrderEntry not found for OrderID %v", err)
	}

	// Compute the fee based on the size of the order with just one output
	// collecting the money on behalf of the merchant.
	txn := &MsgUltranetTxn{
		TxInputs:  []*UltranetInput{},
		TxOutputs: []*UltranetOutput{},
		PublicKey: buyerPublicKey,
		TxnMeta: &ReviewOrderMetadata{
			OrderID:    orderID,
			ReviewType: reviewType,
			ReviewText: reviewText,
		},

		// We wait to compute the signature until we've added all the
		// inputs and change.
	}

	totalInput, _, changeAmount, fees, err :=
		bc.AddInputsAndChangeToTransaction(txn, minFeeRateNanosPerKB, mempool)
	if err != nil {
		return nil, 0, 0, 0, errors.Wrapf(err, "Blockchain.CreateReviewOrderTxn: Problem adding inputs: ")
	}

	return txn, totalInput, changeAmount, fees, nil
}

func (bc *Blockchain) CreateConfirmOrderTxn(
	merchantPublicKey []byte, orderID *BlockHash, minFeeRateNanosPerKB uint64, mempool *TxPool) (
	_txn *MsgUltranetTxn, _merchantOutput uint64, _commissionsBeingPaid uint64, _transactionFee uint64, _err error) {

	// Get a UtxoView, potentially augmenting it with mempool transactions
	// for the merchant public key.
	utxoView, err := _newUtxoView(bc.db, bc.params, bc.bitcoinManager, merchantPublicKey, mempool)
	if err != nil {
		return nil, 0, 0, 0, errors.Wrapf(err, "Blockchain.CreateConfirmOrder: Problem getting UtxoView: ")
	}

	// Get the OrderEntry for the OrderID from the view. This will hit the db
	// only if there were no modifications to the order in the mempool, which
	// is exactly what we want.
	orderEntry := utxoView._getOrderEntryForOrderID(orderID)
	if orderEntry == nil {
		return nil, 0, 0, 0, fmt.Errorf("Blockchain.CreateConfirmOrder: OrderEntry not found for OrderID %v", err)
	}

	// Compute the commissions and revenue the transaction requires.
	commissionNanos, revenueNanos, err := _computeCommissionsAndRevenueFromPayment(
		orderEntry.PaymentAmountNanos, bc.params.CommissionBasisPoints)

	if err != nil {
		return nil, 0, 0, 0, errors.Wrapf(err, "Blockchain.CreateConfirmOrder: Problem computing "+
			"commission and revenue: ")
	}

	// Compute the fee based on the size of the order with just one output
	// collecting the money on behalf of the merchant.
	txn := &MsgUltranetTxn{
		TxInputs: []*UltranetInput{},
		TxOutputs: []*UltranetOutput{
			&UltranetOutput{
				PublicKey: merchantPublicKey,
				// Set to zero initially so that no inputs are fetched for
				// this output.
				AmountNanos: revenueNanos,
			},
		},
		PublicKey: merchantPublicKey,
		TxnMeta: &ConfirmOrderMetadata{
			OrderID: orderID,
		},

		// We wait to compute the signature until we've added all the
		// inputs and change.
	}

	// Compute a fee for the transaction.
	maxFee := _computeMaxTxFee(txn, minFeeRateNanosPerKB)
	if maxFee > revenueNanos {
		return nil, 0, 0, 0, fmt.Errorf("Blockchain.CreateConfirmOrderTxn: Order confirmation "+
			"transaction fee %d exceeds the amount that would be earned %d "+
			"which means the order is not worth confirming", maxFee, revenueNanos)
	}

	// Now that we know the fee is less than the amount the merchant is earning
	// off of the transaction, deduct the fee from
	// the output, which was initially refunding the full amount locked.
	txn.TxOutputs[0].AmountNanos -= maxFee

	return txn, txn.TxOutputs[0].AmountNanos, commissionNanos, maxFee, nil
}

func (bc *Blockchain) CreatePlaceOrderTxn(
	buyerPk []byte, merchantID *BlockHash, amountLockedNanos uint64, buyerMessage string,
	minFeeRateNanosPerKB uint64, mempool *TxPool) (
	_txn *MsgUltranetTxn, _totalInput uint64, _spendAmount uint64, _changeAmount uint64,
	_fee uint64, _err error) {

	// Assemble the transaction so that inputs can be found and fees can
	// be computed. Note we assume there will be no outputs for this type of
	// transaction.
	txn := &MsgUltranetTxn{
		// The inputs will be set below.
		TxInputs:  []*UltranetInput{},
		TxOutputs: []*UltranetOutput{},
		PublicKey: buyerPk,
		TxnMeta: &PlaceOrderMetadata{
			MerchantID:        merchantID,
			AmountLockedNanos: amountLockedNanos,
			BuyerMessage:      []byte(buyerMessage),
		},

		// We wait to compute the signature until we've added all the
		// inputs and change.
	}

	totalInput, spendAmount, changeAmount, fees, err :=
		bc.AddInputsAndChangeToTransaction(txn, minFeeRateNanosPerKB, mempool)
	if err != nil {
		return nil, 0, 0, 0, 0, errors.Wrapf(err, "Blockchain.CreatePlaceOrderTxn: Problem adding inputs: ")
	}

	return txn, totalInput, spendAmount, changeAmount, fees, nil
}

// CreateCancelOrderTxn creates an order cancellation transaction from the
// latest OrderEntry according to the db or, if passed in, according to the
// mempool. It effectively refunds the user the amount locked in the order
// minus the transaction fee required to broadcast the order.
func (bc *Blockchain) CreateCancelOrderTxn(
	buyerPk []byte, orderID *BlockHash, minFeeRateNanosPerKB uint64, mempool *TxPool) (
	_txn *MsgUltranetTxn, _refundAmount uint64, _fee uint64, _err error) {

	// If we have access to a mempool, use it to account for changes to the order
	// that may not yet be confirmed but that the user nonetheless would care about.
	utxoView, err := _newUtxoView(bc.db, bc.params, bc.bitcoinManager, buyerPk, mempool)
	if err != nil {
		return nil, 0, 0, errors.Wrapf(err, "Blockchain.CreateCancelOrderTxn: Problem getting UtxoView: ")
	}

	// Get the OrderEntry for the OrderID from the view. This will hit the db
	// only if there were no modifications to the order in the mempool, which
	// is exactly what we want.
	orderEntry := utxoView._getOrderEntryForOrderID(orderID)

	// We can only cancel an order in the Placed state and only if the PublicKey
	// is the same as the buyerpk.
	if orderEntry.State != OrderStatePlaced {
		return nil, 0, 0, fmt.Errorf("Blockchain.CreateCancelOrderTxn: Order being canceled is not in Placed state: %v", orderEntry)
	}
	if !reflect.DeepEqual(orderEntry.BuyerPk, buyerPk) {
		return nil, 0, 0, fmt.Errorf("Blockchain.CreateCancelOrderTxn: Order being canceled "+
			"has different public key %s than public key passed in %s",
			PkToString(orderEntry.BuyerPk, bc.params), PkToString(buyerPk, bc.params))
	}

	// Compute the fee based on the size of the order with just one output
	// refunding the buyer.
	txn := &MsgUltranetTxn{
		// The inputs will be set below.
		TxInputs: []*UltranetInput{},
		TxOutputs: []*UltranetOutput{
			&UltranetOutput{
				PublicKey: buyerPk,
				// Set to zero initially to the amount we expect to be
				// refunded.
				AmountNanos: orderEntry.AmountLockedNanos,
			},
		},
		PublicKey: buyerPk,
		TxnMeta: &CancelOrderMetadata{
			OrderID: orderID,
		},

		// We wait to compute the signature until we've added all the
		// inputs and change.
	}
	// Compute a fee for the transaction.
	maxFee := _computeMaxTxFee(txn, minFeeRateNanosPerKB)
	if maxFee > orderEntry.AmountLockedNanos {
		return nil, 0, 0, fmt.Errorf("Blockchain.CreateCancelOrderTxn: Order cancellation "+
			"transaction fee %d exceeds the amount that would be refunded %d "+
			"which means the order is not worth canceling", maxFee, orderEntry.AmountLockedNanos)
	}

	// Now that we know the fee is less than the amount locked, deduct the fee from
	// the output, which was initially refunding the full amount locked.
	txn.TxOutputs[0].AmountNanos -= maxFee

	return txn, txn.TxOutputs[0].AmountNanos, maxFee, nil
}

func (bc *Blockchain) CreateRejectOrderTxn(
	merchantPublicKey []byte, rejectReason string, orderID *BlockHash, minFeeRateNanosPerKB uint64, mempool *TxPool) (
	_txn *MsgUltranetTxn, _fee uint64, _err error) {

	// Get a UtxoView, potentially augmenting it with mempool transactions
	// for the merchant public key.
	utxoView, err := _newUtxoView(bc.db, bc.params, bc.bitcoinManager, merchantPublicKey, mempool)
	if err != nil {
		return nil, 0, errors.Wrapf(err, "Blockchain.CreateRejectOrder: Problem getting UtxoView: ")
	}

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
				PublicKey: orderEntry.BuyerPk,
				// Set to zero initially so that no inputs are fetched for
				// this output.
				AmountNanos: 0,
			},
		},
		PublicKey: merchantPublicKey,
		TxnMeta: &RejectOrderMetadata{
			OrderID:      orderID,
			RejectReason: []byte(rejectReason),
		},

		// We wait to compute the signature until we've added all the
		// inputs and change.
	}

	_, _, _, fees, err :=
		bc.AddInputsAndChangeToTransaction(txn, minFeeRateNanosPerKB, mempool)

	// Set the refund amount appropriately.
	txn.TxOutputs[0].AmountNanos = orderEntry.AmountLockedNanos

	return txn, fees, nil
}

func (bc *Blockchain) CreatePrivateMessageTxn(
	senderPublicKey []byte, recipientPublicKey []byte, unencryptedMessageText string,
	tstampNanos uint64,
	minFeeRateNanosPerKB uint64, mempool *TxPool) (
	_txn *MsgUltranetTxn, _totalInput uint64, _changeAmount uint64, _fees uint64, _err error) {

	// Encrypt the passed-in message text with the recipient's public key.
	//
	// Parse the recipient public key.
	recipientPk, err := btcec.ParsePubKey(recipientPublicKey, btcec.S256())
	if err != nil {
		return nil, 0, 0, 0, errors.Wrapf(err, "CreatePrivateMessageTxn: Problem parsing "+
			"recipient public key: ")
	}
	encryptedText, err := EncryptBytesWithPublicKey(
		[]byte(unencryptedMessageText), recipientPk.ToECDSA())
	if err != nil {
		return nil, 0, 0, 0, errors.Wrapf(err, "CreatePrivateMessageTxn: Problem "+
			"encrypting message text: ")
	}
	// Don't allow encryptedText to be nil.
	if len(encryptedText) == 0 {
		encryptedText = []byte{}
	}

	// Create a transaction containing the encrypted message text.
	// A PrivateMessage transaction doesn't need any inputs or outputs.
	txn := &MsgUltranetTxn{
		PublicKey: senderPublicKey,
		TxnMeta: &PrivateMessageMetadata{
			RecipientPublicKey: recipientPublicKey,
			EncryptedText:      encryptedText,
			TimestampNanos:     tstampNanos,
		},

		// We wait to compute the signature until we've added all the
		// inputs and change.
	}

	totalInput, spendAmount, changeAmount, fees, err :=
		bc.AddInputsAndChangeToTransaction(txn, minFeeRateNanosPerKB, mempool)
	if err != nil {
		return nil, 0, 0, 0, errors.Wrapf(err, "CreatePrivateMessageTxn: Problem adding inputs: ")
	}

	// Sanity-check that the spendAmount is zero.
	if spendAmount != 0 {
		return nil, 0, 0, 0, fmt.Errorf("CreatePrivateMessageTxn: Spend amount "+
			"should be zero but was %d instead: ", spendAmount)
	}

	return txn, totalInput, changeAmount, fees, nil
}

func (bc *Blockchain) CreateMaxSpend(
	senderPkBytes []byte, recipientPkBytes []byte, minFeeRateNanosPerKB uint64,
	mempool *TxPool) (
	_txn *MsgUltranetTxn, _totalInputAdded uint64, _spendAmount uint64, _fee uint64, _err error) {
	bc.ChainLock.RLock()
	defer bc.ChainLock.RUnlock()

	txn := &MsgUltranetTxn{
		PublicKey: senderPkBytes,
		TxnMeta:   &BasicTransferMetadata{},
		// Set a single output with the maximum possible size to ensure we don't
		// underestimate the fee. Note it must be a max size output because outputs
		// are encoded as uvarints.
		TxOutputs: []*UltranetOutput{&UltranetOutput{
			PublicKey:   recipientPkBytes,
			AmountNanos: math.MaxUint64,
		}},
		// TxInputs and TxOutputs will be set below.
		// This function does not compute a signature.
	}

	// Get the spendable UtxoEntrys.
	spendableUtxos, err := bc.GetSpendableUtxosForPublicKey(senderPkBytes, mempool)
	if err != nil {
		return nil, 0, 0, 0, errors.Wrapf(err, "CreateMaxSpend: Problem getting spendable UtxoEntrys: ")
	}

	totalInput := uint64(0)
	for _, utxoEntry := range spendableUtxos {
		totalInput += utxoEntry.AmountNanos
		txn.TxInputs = append(txn.TxInputs, (*UltranetInput)(utxoEntry.utxoKey))

		// Avoid creating transactions that are ridiculously huge. Note this is smaller
		// than what AddInputsAndChangeToTransaction will allow because we want to leave
		// some breathing room to avoid this transaction getting rejected.
		currentTxnSize := _computeMaxTxSize(txn)
		if currentTxnSize > bc.params.MaxBlockSizeBytes/3 {
			if len(txn.TxInputs) > 0 {
				// Cut off the last input if the transaction just became too large.
				txn.TxInputs = txn.TxInputs[:len(txn.TxInputs)-1]
			}
			break
		}
	}

	txnFee := _computeMaxTxFee(txn, minFeeRateNanosPerKB)

	if totalInput < txnFee {
		return nil, 0, 0, 0, fmt.Errorf("CreateMaxSpend: Total input value %d would "+
			"be less than the fee required to spend it %d", totalInput, txnFee)
	}

	// We just have one output paying the receiver whatever is left after subtracting off
	// the fee. We can just set the value of the dummy output we set up earlier.
	txn.TxOutputs[0].AmountNanos = totalInput - txnFee

	return txn, totalInput, totalInput - txnFee, txnFee, nil
}

// AddInputsAndChangeToTransaction fetches and adds utxos to the transaction passed
// in to meet the desired spend amount while also satisfying the desired minimum fee
// rate. Additionally, if it's worth it, this function will add a change output
// sending excess Ultra back to the spend public key. Note that the final feerate of the
// transaction after calling this function may exceed the minimum feerate requested.
// This can happen if the signature occupies fewer bytes than the expected maximum
// number of bytes or if the change output occupies fewer bytes than the expected
// maximum (though there could be other ways for this to happen).
//
// The transaction passed in should not have any inputs on it before calling this
// function (an error is returned if it does). Additionally, the output of the
// transaction passed in is assumed to be the amount the caller wishes us to find
// inputs for.
//
// An error is returned if there is not enough input associated with this
// public key to satisfy the transaction's output (subject to the minimum feerate).
func (bc *Blockchain) AddInputsAndChangeToTransaction(
	txArg *MsgUltranetTxn, minFeeRateNanosPerKB uint64, mempool *TxPool) (
	_totalInputAdded uint64, _spendAmount uint64, _totalChangeAdded uint64, _fee uint64, _err error) {

	return bc.AddInputsAndChangeToTransactionWithSubsidy(txArg, minFeeRateNanosPerKB, 0, mempool)
}

func (bc *Blockchain) AddInputsAndChangeToTransactionWithSubsidy(
	txArg *MsgUltranetTxn, minFeeRateNanosPerKB uint64, inputSubsidy uint64, mempool *TxPool) (
	_totalInputAdded uint64, _spendAmount uint64, _totalChangeAdded uint64, _fee uint64, _err error) {
	bc.ChainLock.RLock()
	defer bc.ChainLock.RUnlock()

	// The transaction we're working with should never have any inputs
	// set since we'll be setting the inputs here and dealing with a case where
	// inputs are partially set before-hand would significantly complicate this
	// function. So return an error if we find any inputs.
	if len(txArg.TxInputs) > 0 {
		return 0, 0, 0, 0, fmt.Errorf("_computeInputsForTxn: Transaction passed in "+
			"txArg should not have any inputs set but found the found %d inputs",
			len(txArg.TxInputs))
	}

	// The output of the transaction is assumed to be the desired amount the
	// caller wants to find inputs for. Start by computing it.
	spendAmount := uint64(0)
	for _, ultranetOutput := range txArg.TxOutputs {
		spendAmount += ultranetOutput.AmountNanos
	}
	// If this is a RegisterMerchant transaction, provision for the burn amount.
	if txArg.TxnMeta.GetTxnType() == TxnTypeRegisterMerchant {
		spendAmount += txArg.TxnMeta.(*RegisterMerchantMetadata).BurnAmountNanos
	}
	// If this is an UpdateMerchant transaction, provision for the burn amount.
	if txArg.TxnMeta.GetTxnType() == TxnTypeUpdateMerchant {
		spendAmount += txArg.TxnMeta.(*UpdateMerchantMetadata).BurnAmountNanos
	}
	// If this is a PlaceOrder transaction, provision for the amount we're locking
	// up.
	if txArg.TxnMeta.GetTxnType() == TxnTypePlaceOrder {
		spendAmount += txArg.TxnMeta.(*PlaceOrderMetadata).AmountLockedNanos
	}

	// The public key of the transaction is assumed to be the one set at its
	// top level.
	spendPublicKeyBytes := txArg.PublicKey

	// Make a copy of the transaction. This makes it so that we don't need
	// to modify the passed-in transaction until we're absolutely sure we don't
	// have an error.
	txCopyWithChangeOutput, err := txArg.Copy()
	if err != nil {
		return 0, 0, 0, 0, errors.Wrapf(err, "AddInputsAndChangeToTransaction: ")
	}
	// Since we generally want to compute an upper bound on the transaction
	// size, add a change output to the transaction to factor in the
	// worst-case situation in which a change output is required. This
	// assignment and ones like it that follow should leave the original
	// transaction's outputs/slices unchanged.
	changeOutput := &UltranetOutput{
		PublicKey: make([]byte, btcec.PubKeyBytesLenCompressed),
		// Since we want an upper bound on the transaction size, set the amount
		// to the maximum value since that will induce the serializer to encode
		// a maximum-sized uvarint.
		AmountNanos: math.MaxUint64,
	}
	txCopyWithChangeOutput.TxOutputs = append(txCopyWithChangeOutput.TxOutputs, changeOutput)

	// Get the spendable UtxoEntrys.
	spendableUtxos, err := bc.GetSpendableUtxosForPublicKey(spendPublicKeyBytes, mempool)
	if err != nil {
		return 0, 0, 0, 0, errors.Wrapf(err, "AddInputsAndChangeToTransaction: Problem getting spendable UtxoEntrys: ")
	}

	// Add input utxos to the transaction until we have enough total input to cover
	// the amount we want to spend plus the maximum fee (or until we've exhausted
	// all the utxos available).
	utxoEntriesBeingUsed := []*UtxoEntry{}
	totalInput := inputSubsidy
	for _, utxoEntry := range spendableUtxos {
		// As an optimization, don't worry about the fee until the total input has
		// definitively exceeded the amount we want to spend. We do this because computing
		// the fee each time we add an input would result in N^2 behavior.
		maxAmountNeeded := spendAmount
		if totalInput >= spendAmount {
			maxAmountNeeded += _computeMaxTxFee(txCopyWithChangeOutput, minFeeRateNanosPerKB)
		}

		// If the amount of input we have isn't enough to cover our upper bound on
		// the total amount we could need, add an input and continue.
		if totalInput < maxAmountNeeded {
			txCopyWithChangeOutput.TxInputs = append(txCopyWithChangeOutput.TxInputs, (*UltranetInput)(utxoEntry.utxoKey))
			utxoEntriesBeingUsed = append(utxoEntriesBeingUsed, utxoEntry)
			totalInput += utxoEntry.AmountNanos
			continue
		}

		// If we get here, we know we have enough input to cover the upper bound
		// estimate of our amount needed so break.
		break
	}

	// At this point, utxoEntriesBeingUsed should contain enough to cover the
	// maximum amount we'd need in a worst-case scenario (or as close as we could
	// get to that point). Now we add these utxos to a new transaction in order
	// to properly compute the change we might need.

	// Re-copy the passed-in transaction and re-add all the inputs we deemed
	// were necessary but this time don't add a change output unless it's strictly
	// necessary.
	finalTxCopy, _ := txArg.Copy()
	for _, utxoEntry := range utxoEntriesBeingUsed {
		finalTxCopy.TxInputs = append(finalTxCopy.TxInputs, (*UltranetInput)(utxoEntry.utxoKey))
	}
	maxFeeWithoutChange := _computeMaxTxFee(finalTxCopy, minFeeRateNanosPerKB)
	if totalInput < (spendAmount + maxFeeWithoutChange) {
		// In this case the total input we were able to gather for the
		// transaction is insufficient to cover the amount we want to
		// spend plus the fee. Return an error in this case so that
		// either the spend amount or the fee rate can be adjusted.
		return 0, 0, 0, 0, fmt.Errorf("AddInputsAndChangeToTransaction: Sanity check failed: Total "+
			"input %d is not sufficient to "+
			"cover the spend amount (=%d) plus the fee (=%d, feerate=%d, txsize=%d), "+
			"total=%d", totalInput, spendAmount, maxFeeWithoutChange, minFeeRateNanosPerKB,
			_computeMaxTxSize(finalTxCopy), spendAmount+maxFeeWithoutChange)
	}

	// Now that we know the input will cover the spend amount plus the fee, add
	// a change output if the value of including one definitely exceeds the cost.
	//
	// Note this is an approximation that will result in change not being included
	// in circumstances where the value of including it is very marginal but that
	// seems OK. It also will short-change the user a bit if their output is not
	// at the maximum size but that seems OK as well. In all of these circumstances
	// the user will get a slightly higher feerate than they asked for which isn't
	// really a problem.
	maxChangeFee := MaxUltranetOutputSizeBytes * minFeeRateNanosPerKB / 1000
	changeAmount := int64(totalInput) - int64(spendAmount) - int64(maxFeeWithoutChange) - int64(maxChangeFee)
	if changeAmount > 0 {
		finalTxCopy.TxOutputs = append(finalTxCopy.TxOutputs, &UltranetOutput{
			PublicKey:   spendPublicKeyBytes,
			AmountNanos: uint64(changeAmount),
		})
	} else {
		changeAmount = 0
	}

	// The final fee is what's left after subtracting the spend amount and the
	// change from the total input.
	finalFee := totalInput - spendAmount - uint64(changeAmount)

	// If the final transaction is absolutely huge, return an error.
	finalTxnSize := _computeMaxTxSize(finalTxCopy)
	if finalTxnSize > bc.params.MaxBlockSizeBytes/2 {
		return 0, 0, 0, 0, fmt.Errorf("AddInputsAndChangeToTransaction: "+
			"Transaction size (%d bytes) exceeds the maximum sane amount "+
			"allowed (%d bytes)", finalTxnSize, bc.params.MaxBlockSizeBytes/2)
	}

	// At this point, the inputs cover the (spend amount plus transaction fee)
	// and the change output has been added if needed, with the total fees of
	// the transaction set such that the feerate exceeds the minFeeRatePerKB
	// passed in. Set the inputs and outputs of the transaction passed in and
	// return.
	txArg.TxInputs = finalTxCopy.TxInputs
	txArg.TxOutputs = finalTxCopy.TxOutputs

	return totalInput, spendAmount, uint64(changeAmount), finalFee, nil
}

func (bc *Blockchain) EstimateDefaultFeeRateNanosPerKB(
	medianThreshold float64, minFeeRateNanosPerKB uint64) uint64 {

	// Lock to blockchain during this computation. We need to do this so
	// that the tip does not become obsolete after we fetch a reference to it.
	bc.ChainLock.RLock()
	defer bc.ChainLock.RUnlock()

	// Get the block at the tip of our block chain.
	tipNode := bc.blockTip()
	blk, err := GetBlock(tipNode.Hash, bc.db)
	if err != nil {
		return minFeeRateNanosPerKB
	}

	// If the block is less than X% full, use the min fee rate.
	blockBytes, err := blk.ToBytes(false /*preSignature*/)
	if err != nil {
		return minFeeRateNanosPerKB
	}
	numBytes := len(blockBytes)
	if float64(numBytes)/float64(bc.params.MaxBlockSizeBytes) < medianThreshold {
		return minFeeRateNanosPerKB
	}

	// If the block is more than X% full, use the maximum between the min
	// fee rate and the median fees of all the transactions in the block.
	utxoView, err := NewUtxoView(bc.db, bc.params, bc.bitcoinManager)
	if err != nil {
		return minFeeRateNanosPerKB
	}
	utxoOps, err := GetUtxoOperationsForBlock(bc.db, tipNode.Hash)
	if err != nil {
		return minFeeRateNanosPerKB
	}
	// Compute the hashes for all the transactions.
	txHashes, err := ComputeTransactionHashes(blk.Txns)
	if err != nil {
		return minFeeRateNanosPerKB
	}
	if err := utxoView.DisconnectBlock(blk, txHashes, utxoOps); err != nil {
		return minFeeRateNanosPerKB
	}

	allFeesNanosPerKB := []uint64{}
	for _, txn := range blk.Txns {
		txnBytes, err := txn.ToBytes(false /*preSignature*/)
		if err != nil {
			return minFeeRateNanosPerKB
		}
		numBytesInTxn := len(txnBytes)
		_, _, _, fees, err := utxoView.ConnectTransaction(
			txn, txn.Hash(), tipNode.Height, false, /*verifySignatures*/
			false /*verifyMerchantMerkleRoot*/)
		if err != nil {
			return minFeeRateNanosPerKB
		}
		allFeesNanosPerKB = append(
			allFeesNanosPerKB, uint64(fees)*1000/uint64(numBytesInTxn))
	}

	// Sort all the fees.
	sort.Slice(allFeesNanosPerKB, func(ii, jj int) bool {
		return allFeesNanosPerKB[ii] < allFeesNanosPerKB[jj]
	})

	// Choose a fee at the middle of the range, which represents the median.
	medianPos := len(allFeesNanosPerKB) / 2

	// Useful for debugging.
	/*
		for _, val := range allFeesNanosPerKB {
			fmt.Printf("%d ", val)
		}
		fmt.Println()
	*/

	if minFeeRateNanosPerKB > allFeesNanosPerKB[medianPos] {
		return minFeeRateNanosPerKB
	}
	return allFeesNanosPerKB[medianPos]
}
