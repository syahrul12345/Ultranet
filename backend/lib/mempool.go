package lib

import (
	"container/heap"
	"container/list"
	"fmt"
	"math"
	"sort"
	"sync/atomic"
	"time"

	"github.com/btcsuite/btcd/btcec"
	"github.com/davecgh/go-spew/spew"
	"github.com/golang/glog"
	"github.com/pkg/errors"
	"github.com/sasha-s/go-deadlock"
)

// mempool.go contains all of the mempool logic for the Ultranet node. It functions
// basically as a fancy priority queue of transactions where the priority function
// is the transaction's fee rate. The miner selects transactions from this pool to
// include them in blocks.

const (
	// orphanTTL is the maximum amount of time an orphan is allowed to
	// stay in the orphan pool before it expires and is evicted during the
	// next scan.
	orphanTTL = time.Minute * 15

	// orphanExpireScanInterval is the minimum amount of time in between
	// scans of the orphan pool to evict expired transactions.
	orphanExpireScanInterval = time.Minute * 5

	// MaxOrphanTransactions ...
	MaxOrphanTransactions = 500
	// MaxOrphanTxSize ...
	MaxOrphanTxSize = 10000
	// FreeBlockSpaceBytes ...
	FreeBlockSpaceBytes = 50000

	// MaxTotalTransactionSizeBytes is the maximum number of bytes the pool can store
	// across all of its transactions. Once this limit is reached, transactions must
	// be evicted from the pool based on their feerate before new transactions can be
	// added.
	// TODO: This limit is initially low because the miner can't handle a mempool that
	// is excessively large. Once we make performance improvements there and in other
	// places we should be able to increase this substantially.
	MaxTotalTransactionSizeBytes = 1500000 // 1.5MB

	// MaxImmatureBitcoinTxns ...
	MaxImmatureBitcoinTxns = 500
)

// Make these variables so that it can be manipulated by tests.
// TODO: Not very clean...
var (
	// LowFeeTxLimitBytesPerTenMinutes defines the number of bytes per 10 minutes of "low fee"
	// transactions the mempool will tolerate before it starts rejecting transactions
	// that fail to meet the MinTxFeePerKBNanos threshold.
	LowFeeTxLimitBytesPerTenMinutes = 150000 // Allow 150KB per minute in low-fee txns.

	// MaxTransactionDependenciesToProcess is the maximum number of transaction
	// dependencies allowed. This is used to prevent a degradation into N^2 behavior
	// when adding transactions to the mempool, which could happen in certain
	// pathalogical insertion cases.
	MaxTransactionDependenciesToProcess = 25
)

// TxDesc is a descriptor about a transaction in the mempool along with
// additional metadata.
type TxDesc struct {
	// Tx is the transaction associated with the entry.
	Tx *MsgUltranetTxn

	// Hash is a hash of the transaction so we don't have to recompute
	// it all the time.
	Hash *BlockHash

	// TxSizeBytes is the cached size of the transaction.
	TxSizeBytes uint64

	// Added is the time when the entry was added to the mempool.
	Added time.Time

	// Height is the block height when the entry was added to the the mempool.
	Height uint32

	// Fee is the total fee the transaction associated with the entry pays.
	Fee uint64

	// FeePerKB is the fee the transaction pays in nanos per 1000 bytes.
	FeePerKB uint64

	// index is used by the heap logic to allow for modification in-place.
	index int
}

func (txD *TxDesc) String() string {
	return fmt.Sprintf("< Added: %v, index: %d, Fee: %d", txD.Added, txD.index, txD.Fee)
}

// TxDescFeeMinHeap ...
type TxDescFeeMinHeap []*TxDesc

// Len ...
func (pq TxDescFeeMinHeap) Len() int { return len(pq) }

// Less ...
func (pq TxDescFeeMinHeap) Less(i, j int) bool {
	// We want Pop to give us the lowest-fee transactions so we use < here.
	return pq[i].FeePerKB < pq[j].FeePerKB
}

// Swap ...
func (pq TxDescFeeMinHeap) Swap(i, j int) {
	pq[i], pq[j] = pq[j], pq[i]
	pq[i].index = i
	pq[j].index = j
}

// Push ...
func (pq *TxDescFeeMinHeap) Push(x interface{}) {
	n := len(*pq)
	item := x.(*TxDesc)
	item.index = n
	*pq = append(*pq, item)
}

// Pop ...
func (pq *TxDescFeeMinHeap) Pop() interface{} {
	old := *pq
	n := len(old)
	item := old[n-1]
	old[n-1] = nil  // avoid memory leak
	item.index = -1 // for safety
	*pq = old[0 : n-1]
	return item
}

// OrphanTx is a normal transaction that references an ancestor transaction
// that is not yet available. It also contains additional information related
// to it such as an expiration time to help prevent caching the orphan forever.
type OrphanTx struct {
	tx *MsgUltranetTxn
	// The ID of the Peer who initially sent the orphan. Useful for removing orphan
	// transactions when a Peer disconnects.
	peerID     uint64
	expiration time.Time
}

// TxPool is used as a source of transactions that need to be mined into blocks
// and relayed to other peers. It is safe for concurrent access from multiple
// peers.
type TxPool struct {
	// The following variables must only be used atomically.
	//
	// The last time pool was updated
	lastUpdated int64

	// A reference to a blockchain object that can be used to validate transactions before
	// adding them to the pool.
	bc *Blockchain

	// Transactions with a feerate below this threshold are outright rejected.
	minFeeRateNanosPerKB uint64

	// rateLimitFeeRateNanosPerKB defines the minimum transaction feerate in "nanos per KB"
	// before a transaction is considered for rate-limiting. Note that even if a
	// transaction with a feerate below this threshold is not rate-limited, it must
	// still have a high enough feerate to be considered as part of the mempool.
	rateLimitFeeRateNanosPerKB uint64

	mtx deadlock.RWMutex

	// poolMap contains all of the transactions that have been validated by the pool.
	// Transactions in poolMap should be directly consumable by a miner and formed into
	// a block by taking them in order of when they were Added.
	poolMap map[BlockHash]*TxDesc
	// txFeeMinHeap organizes transactions stored in poolMap by their FeePerKB. It is used
	// in order to prevent the pool from exhausing memory due to having to store too
	// many low-fee transactions.
	txFeeMinheap TxDescFeeMinHeap
	// totalTxSizeBytes is the total size of all of the transactions stored in poolMap. We
	// use it to determine when the pool is nearing memory-exhaustion so we can start
	// evicting transactions.
	totalTxSizeBytes uint64
	// Stores the inputs for every transaction stored in poolMap. Used to quickly check
	// if a transaction is double-spending.
	outpoints map[UtxoKey]*MsgUltranetTxn
	// orphans contains transactions whose inputs reference UTXOs that are not yet
	// present in either our UTXO database or the transactions stored in pool.
	orphans map[BlockHash]*OrphanTx
	// Organizes orphans by their UTXOs. Used when adding a transaction to determine
	// which orphans are no longer missing parents.
	orphansByPrev map[UtxoKey]map[BlockHash]*MsgUltranetTxn
	// An exponentially-decayed accumulator of "low-fee" transactions we've relayed.
	// This is used to prevent someone from flooding the network with low-fee
	// transactions.
	lowFeeTxSizeAccumulator float64
	// The UNIX time (in seconds) when the last "low-fee" transaction was relayed.
	lastLowFeeTxUnixTime int64

	// outputPubKeyToTxnMap stores a mapping from the public key of outputs added
	// to the mempool to the corresponding transaction that resulted in their
	// addition. It is useful for figuring out how much Ultra a particular public
	// key has available to spend.
	outputPubKeyToTxnMap map[PkMapKey]map[BlockHash]*TxDesc

	// We need to also organize transactions in the pool by their OrderID and by
	// their MerchantID so we can apply them as dependencies before checking whether a
	// transaction is valid.
	//
	// Note this map only tracks transactions actually in the pool, not orphans.
	//
	// Note that the pool map above is
	// a superset of this map such that every txn in this map is also stored by the pool
	// map. In that sense, the pool map is the "source of truth" map and this map is
	// just de-normalizing the pool map to make dependency lookups more efficient.
	txnsByMetadataID map[BlockHash]map[BlockHash]*TxDesc

	// BitcoinExchange transactions that would fail validation because their referenced
	// block is not yet present in our BitcoinManager's best chain.
	immatureBitcoinTxns map[BlockHash]*OrphanTx

	// nextExpireScan is the time after which the orphan pool will be
	// scanned in order to evict orphans. This is NOT a hard deadline as
	// the scan will only run when an orphan is added to the pool as opposed
	// to on an unconditional timer.
	nextExpireScan time.Time
}

// GetMetadataIDForTxn returns an identifier that groups transactions based on their
// metadata. For merchant-related transactions it returns a MerchantID. For order-related
// transactions it returns an OrderID. And for all other types of transactions it returns
// nil. This is very useful when trying to compute the dependencies of
// a transaction since in general transactions that have the same MetadataID, as it's
// defined here, will be dependent on one another.
func GetMetadataIDForTxn(txn *MsgUltranetTxn, txHash *BlockHash) (*BlockHash, error) {
	txMeta := txn.TxnMeta

	if txMeta.GetTxnType() == TxnTypeUnset ||
		txMeta.GetTxnType() == TxnTypeBlockReward ||
		txMeta.GetTxnType() == TxnTypeBasicTransfer ||
		txMeta.GetTxnType() == TxnTypeBitcoinExchange ||
		txMeta.GetTxnType() == TxnTypePrivateMessage {
		// These transactions only deal with UTXOs so we give them a nil MetadataID.
		return nil, nil

	} else if txMeta.GetTxnType() == TxnTypePlaceOrder ||
		txMeta.GetTxnType() == TxnTypeRegisterMerchant {
		// For these types of transactions, a MerchantID or OrderID is created using the
		// txHash so return that.
		return txHash, nil

	} else if txMeta.GetTxnType() == TxnTypeUpdateMerchant {
		return txMeta.(*UpdateMerchantMetadata).MerchantID, nil

	} else if txMeta.GetTxnType() == TxnTypeCancelOrder {
		return txMeta.(*CancelOrderMetadata).OrderID, nil

	} else if txMeta.GetTxnType() == TxnTypeRejectOrder {
		return txMeta.(*RejectOrderMetadata).OrderID, nil

	} else if txMeta.GetTxnType() == TxnTypeConfirmOrder {
		return txMeta.(*ConfirmOrderMetadata).OrderID, nil

	} else if txMeta.GetTxnType() == TxnTypeFulfillOrder {
		return txMeta.(*FulfillOrderMetadata).OrderID, nil

	} else if txMeta.GetTxnType() == TxnTypeReviewOrder {
		return txMeta.(*ReviewOrderMetadata).OrderID, nil

	} else if txMeta.GetTxnType() == TxnTypeRefundOrder {
		return txMeta.(*RefundOrderMetadata).OrderID, nil
	}

	// If we get here then we're dealing with an unrecognized transaction type.
	errorStr := fmt.Sprintf("GetMetadataIDForTxn: Unrecognized MetadataID %d found; make sure you've updated GetMetadataIDForTxn if you've added a TxnType", txMeta.GetTxnType())
	glog.Warning(errorStr)
	return nil, fmt.Errorf(errorStr)
}

// GetDependentMetadataIDs returns the MetadataIDs that this transaction may depend on.
// For example, an order placement may depend on a merchant registration, in which case
// we would want to return the MerchantID as well as the OrderID. Note that the
// blockchain's ChainLock must be held for reads before this function is called.
func (mp *TxPool) _getDependentMetadataIDs(txn *MsgUltranetTxn) ([]*BlockHash, error) {
	txMeta := txn.TxnMeta

	var orderID *BlockHash
	if txMeta.GetTxnType() == TxnTypeUnset ||
		txMeta.GetTxnType() == TxnTypeBlockReward ||
		txMeta.GetTxnType() == TxnTypeBasicTransfer ||
		txMeta.GetTxnType() == TxnTypeBitcoinExchange ||
		txMeta.GetTxnType() == TxnTypePrivateMessage {
		// These transactions only deal with UTXOs so we return an empty slice.
		return nil, nil

	} else if txMeta.GetTxnType() == TxnTypeRegisterMerchant {
		// Merchant registration is not dependent on anything so return nil.
		return nil, nil

	} else if txMeta.GetTxnType() == TxnTypeUpdateMerchant {
		// Merchant update transactions are dependent on all prior transactions related to
		// the MerchantID being updated.
		return []*BlockHash{txMeta.(*UpdateMerchantMetadata).MerchantID}, nil

	} else if txMeta.GetTxnType() == TxnTypePlaceOrder {
		// Order placement is dependent on all transactions having to do with the merchant
		// this order concerns. It is not dependent on an OrderID because it is the first
		// transaction corresponding to an order.
		return []*BlockHash{txMeta.(*PlaceOrderMetadata).MerchantID}, nil

	} else if txMeta.GetTxnType() == TxnTypeCancelOrder {
		// Grab the OrderID being referenced. More work to do later.
		orderID = txMeta.(*CancelOrderMetadata).OrderID

	} else if txMeta.GetTxnType() == TxnTypeRejectOrder {
		// Grab the OrderID being referenced. More work to do later.
		orderID = txMeta.(*RejectOrderMetadata).OrderID

	} else if txMeta.GetTxnType() == TxnTypeConfirmOrder {
		// Grab the OrderID being referenced. More work to do later.
		orderID = txMeta.(*ConfirmOrderMetadata).OrderID

	} else if txMeta.GetTxnType() == TxnTypeFulfillOrder {
		// Grab the OrderID being referenced. More work to do later.
		orderID = txMeta.(*FulfillOrderMetadata).OrderID

	} else if txMeta.GetTxnType() == TxnTypeReviewOrder {
		// Grab the OrderID being referenced. More work to do later.
		orderID = txMeta.(*ReviewOrderMetadata).OrderID

	} else if txMeta.GetTxnType() == TxnTypeRefundOrder {
		// Grab the OrderID being referenced. More work to do later.
		orderID = txMeta.(*RefundOrderMetadata).OrderID

	} else {
		errorStr := fmt.Sprintf("GetDependentMetadataIDs: Unrecognized MetadataID %d found; make sure you've updated GetMetadataIDForTxn if you've added a TxnType", txMeta.GetTxnType())
		glog.Warning(errorStr)
		return nil, fmt.Errorf(errorStr)
	}

	if orderID == nil {
		return nil, fmt.Errorf("GetDependentMetadataIDs: Missing OrderID in order-related transaction: %v", txn)
	}

	// Look up the order entry. If the PlaceOrder corresponding to this transaction has
	// been mined into a block, the OrderEntry should be found this way. If, however, the
	// PlaceOrder is still in the mempool, then this will return nil. That is OK, however,
	// because if the PlaceOrder is indeed in the mempool then returning the OrderID will
	// cause the eventual lookup of the PlaceOrder, which will result in the OrderEntry,
	// and the MerchantID being discovered as a dependency.
	orderEntry := DbGetOrderEntryForOrderID(mp.bc.db, orderID)
	if orderEntry == nil {
		return []*BlockHash{orderID}, nil
	}

	// Order-related transactions other than PlaceOrder are dependent on all operations
	// related to the merchant being referenced and all operations related to the order
	// being referenced.
	return []*BlockHash{orderEntry.MerchantID, orderID}, nil
}

// removeOrphan is the internal function which implements the public
// RemoveOrphan. See the comment for RemoveOrphan for more details.
//
// This function MUST be called with the mempool lock held (for writes).
func (mp *TxPool) removeOrphan(tx *MsgUltranetTxn, removeRedeemers bool) {
	// Nothing to do if passed tx is not an orphan.
	txHash := tx.Hash()
	if txHash == nil {
		// If an error occurs hashing the transaction then there's nothing to do. Just
		// log and reteurn.
		glog.Error("removeOrphan: Problem hashing txn: ")
		return
	}
	otx, exists := mp.orphans[*txHash]
	if !exists {
		return
	}

	// Remove the reference from the previous orphan index.
	for _, txIn := range otx.tx.TxInputs {
		orphans, exists := mp.orphansByPrev[UtxoKey(*txIn)]
		if exists {
			delete(orphans, *txHash)

			// Remove the map entry altogether if there are no
			// longer any orphans which depend on it.
			if len(orphans) == 0 {
				delete(mp.orphansByPrev, UtxoKey(*txIn))
			}
		}
	}

	// Remove any orphans that redeem outputs from this one if requested.
	if removeRedeemers {
		prevOut := UltranetInput{TxID: *txHash}
		for txOutIdx := range tx.TxOutputs {
			prevOut.Index = uint32(txOutIdx)
			for _, orphan := range mp.orphansByPrev[UtxoKey(prevOut)] {
				mp.removeOrphan(orphan, true)
			}
		}
	}

	// Remove the transaction from the orphan pool.
	delete(mp.orphans, *txHash)
}

// ResetPool replaces all of the internal data associated with a pool object with the
// data of the pool object passed in. It's useful when we want to do a "scorch the earth"
// update of the pool by re-processing all of its transactions into a new pool object
// first.
func (mp *TxPool) ResetPool(newPool *TxPool) {
	// Replace the internal mappings of the original pool with the mappings of the new
	// pool.
	mp.lastUpdated = newPool.lastUpdated
	mp.poolMap = newPool.poolMap
	mp.txFeeMinheap = newPool.txFeeMinheap
	mp.totalTxSizeBytes = newPool.totalTxSizeBytes
	mp.outpoints = newPool.outpoints
	mp.outputPubKeyToTxnMap = newPool.outputPubKeyToTxnMap
	mp.orphans = newPool.orphans
	mp.orphansByPrev = newPool.orphansByPrev
	mp.txnsByMetadataID = newPool.txnsByMetadataID
	mp.immatureBitcoinTxns = newPool.immatureBitcoinTxns
	mp.nextExpireScan = newPool.nextExpireScan

	// Don't adjust the lowFeeTxSizeAccumulator or the lastLowFeeTxUnixTime since
	// the old values should be unaffected.
}

// UpdateAfterConnectBlock updates the mempool after a block has been added to the
// blockchain. It does this by basically removing all known transactions in the block
// from the mempool as follows:
// - Build a map of all of the transactions in the block indexed by their hash.
// - Create a new mempool object.
// - Iterate through all the transactions in the mempool and add the transactions
//   to the new pool object *only if* they don't appear in the block. Do this for
//   transactions in the pool and in the orphan pool.
// - Compute which transactions were newly-accepted into the pool by effectively diffing
//   the new pool's transactions with the old pool's transactions.
// - Once the new pool object is up-to-date, the fields of the new pool object
//   replace the fields of the original pool object.
// - Return the newly added transactions computed earlier.
//
// TODO: This is fairly inefficient but the story is the same as for
// UpdateAfterDisconnectBlock.
func (mp *TxPool) UpdateAfterConnectBlock(blk *MsgUltranetBlock) (_txnsAddedToMempool []*TxDesc) {
	// Protect concurrent access.
	mp.mtx.Lock()
	defer mp.mtx.Unlock()

	// Make a map of all the txns in the block except the block reward.
	txnsInBlock := make(map[BlockHash]bool)
	for _, txn := range blk.Txns[1:] {
		txHash := txn.Hash()
		txnsInBlock[*txHash] = true
	}

	// Create a new pool object. No need to set the min fees as we're just using this
	// as a temporary data structure for validation.
	newPool := NewTxPool(mp.bc, 0 /* rateLimitFeeRateNanosPerKB */, 0 /* minFeeRateNanosPerKB */)

	// Get all the transactions from the old pool object.
	oldMempoolTxns, oldMempoolOrphans, err := mp._getTransactionsOrderedByTimeAdded()
	if err != nil {
		glog.Warning(errors.Wrapf(err, "UpdateAfterConnectBlock: "))
	}

	// Add all the txns from the old pool into the new pool unless they are already
	// present in the block.
	for _, txD := range oldMempoolTxns {
		if _, exists := txnsInBlock[*txD.Hash]; exists {
			continue
		}

		// If the transaction wasn't covered by the block then try and add it to the
		// new pool. Note the PeerID doesn't matter because this transaction shouldn't
		// be an orphan.
		rateLimit := false
		allowOrphans := false
		peerID := uint64(0)
		verifySignatures := false
		_, err := newPool.processTransaction(txD.Tx, allowOrphans, rateLimit, peerID, verifySignatures)
		if err != nil {
			glog.Warning(errors.Wrapf(err, "UpdateAfterConnectBlock: "))
		}
	}

	// Add all the orphans from the old pool into the new pool unles they are already
	// present in the block.
	for _, oTx := range oldMempoolOrphans {
		// Only add transactions to the pool if they haven't already been added by the
		// block.
		orphanHash := oTx.tx.Hash()
		if _, exists := txnsInBlock[*orphanHash]; exists {
			continue
		}

		rateLimit := false
		allowOrphans := true
		verifySignatures := false
		_, err := newPool.processTransaction(oTx.tx, allowOrphans, rateLimit, oTx.peerID, verifySignatures)
		if err != nil {
			glog.Warning(errors.Wrapf(err, "UpdateAfterConnectBlock: "))
		}
	}

	// At this point, the new pool should contain an up-to-date view of the transactions
	// that should be in the mempool after connecting this block.

	// Figure out what transactions are in the new pool but not in the old pool. These
	// are transactions that were newly-added as a result of this block clearing up some
	// dependencies and so we will likely want to relay these transactions.
	newlyAcceptedTxns := []*TxDesc{}
	for poolHash, newTxDesc := range newPool.poolMap {
		// No need to copy poolHash since nothing saves a reference to it.
		if _, txExistsInOldPool := mp.poolMap[poolHash]; !txExistsInOldPool {
			newlyAcceptedTxns = append(newlyAcceptedTxns, newTxDesc)
		}
	}

	// Now set the fields on the old pool to match the new pool.
	mp.ResetPool(newPool)

	// Return the newly accepted transactions now that we've fully updated our mempool.
	return newlyAcceptedTxns
}

// UpdateAfterDisconnectBlock updates the mempool to reflect that a block has been
// disconnected from the blockchain. It does this by basically adding all the
// transactions in the block back to the mempool as follows:
// - A new pool object is created containing no transactions.
// - The block's transactions are added to this new pool object. This is done in order
//   to minimize dependency-related conflicts with transactions already in the mempool.
// - Then the transactions in the original pool are layered on top of the block's
//   transactions in the new pool object. Again this is done to avoid dependency
//   issues since the ordering of <block txns> followed by <original mempool txns>
//   is much less likely to have issues.
// - Then, once the new pool object is up-to-date, the fields of the new pool object
//   replace the fields of the original pool object.
//
// This function is safe for concurrent access. It is assumed the ChainLock is
// held before this function is a accessed.
//
// TODO: This is fairly inefficient and basically only necessary because computing a
// transaction's dependencies is a little shaky. If we end up making the dependency
// detection logic more robust then we could come back here and change this so that
// we're not effectively reprocessing the entire mempool every time we have a new block.
// But until then doing it this way significantly reduces complexity and should hold up
// for a while.
func (mp *TxPool) UpdateAfterDisconnectBlock(blk *MsgUltranetBlock) {
	// Protect concurrent access.
	mp.mtx.Lock()
	defer mp.mtx.Unlock()

	// Create a new TxPool. No need to set the min fees since we're just using
	// this as a temporary data structure for validation.
	newPool := NewTxPool(mp.bc, 0 /* rateLimitFeeRateNanosPerKB */, 0 /* minFeeRateNanosPerKB */)

	// Add the transactions from the block to the new pool (except for the block reward,
	// which should always be the first transaction). Break out if we encounter
	// an error.
	for _, txn := range blk.Txns[1:] {
		// For transactions being added from the block just set the peerID to zero. It
		// shouldn't matter since these transactions won't be orphans.
		rateLimit := false
		allowOrphans := false
		peerID := uint64(0)
		verifySignatures := false
		_, err := newPool.processTransaction(txn, allowOrphans, rateLimit, peerID, verifySignatures)
		if err != nil {
			// Log errors but don't stop adding transactions. We do this because we'd prefer
			// to drop a transaction here or there rather than lose the whole block because
			// of one bad apple.
			glog.Warning(errors.Wrapf(err, "UpdateAfterDisconnectBlock: "))
		}
	}

	// At this point the block txns have been added to the new pool. Now we need to
	// add the txns from the original pool. Start by fetching them in slice form.
	oldMempoolTxns, oldMempoolOrphans, err := mp._getTransactionsOrderedByTimeAdded()
	if err != nil {
		glog.Warning(errors.Wrapf(err, "UpdateAfterDisconnectBlock: "))
	}
	// Iterate through the pool transactions and add them to our new pool.
	for _, txD := range oldMempoolTxns {
		rateLimit := false
		allowOrphans := false
		peerID := uint64(0)
		verifySignatures := false
		_, err := newPool.processTransaction(txD.Tx, allowOrphans, rateLimit, peerID, verifySignatures)
		if err != nil {
			glog.Warning(errors.Wrapf(err, "UpdateAfterDisconnectBlock: "))
		}
	}

	// Iterate through the orphans and add them to our new pool as well.
	for _, oTx := range oldMempoolOrphans {
		rateLimit := false
		allowOrphans := true
		verifySignatures := false
		_, err := newPool.processTransaction(oTx.tx, allowOrphans, rateLimit, oTx.peerID, verifySignatures)
		if err != nil {
			glog.Warning(errors.Wrapf(err, "UpdateAfterDisconnectBlock: "))
		}
	}

	// At this point the new mempool should be a duplicate of the original mempool but with
	// the block's transactions added (with timestamps set before the transactions that
	// were in the original pool.

	// Replace the internal mappings of the original pool with the mappings of the new
	// pool.
	mp.ResetPool(newPool)
}

// GetTransactionsOrderedByTimeAdded eturns all transactions in the mempool ordered
// by when they were added to the mempool.
func (mp *TxPool) _getTransactionsOrderedByTimeAdded() (_poolTxns []*TxDesc, _orphanTxns []*OrphanTx, _err error) {
	poolTxns := []*TxDesc{}
	for _, txD := range mp.poolMap {
		poolTxns = append(poolTxns, txD)
	}
	// Sort the list based on when the transactions were added.
	sort.Slice(poolTxns, func(ii, jj int) bool {
		return poolTxns[ii].Added.Before(poolTxns[jj].Added)
	})

	orphanTxns := []*OrphanTx{}
	for _, oTx := range mp.orphans {
		orphanTxns = append(orphanTxns, oTx)
	}

	return poolTxns, orphanTxns, nil
}

// RemoveOrphan removes the passed orphan transaction from the orphan pool and
// previous orphan index.
//
// This function is safe for concurrent access.
func (mp *TxPool) RemoveOrphan(tx *MsgUltranetTxn) {
	mp.mtx.Lock()
	mp.removeOrphan(tx, false)
	mp.mtx.Unlock()
}

// RemoveOrphansByPeerID removes all orphan transactions tagged with the provided
// identifier.
//
// This function is safe for concurrent access.
func (mp *TxPool) RemoveOrphansByPeerID(peerID uint64) uint64 {
	var numEvicted uint64
	mp.mtx.Lock()
	for _, otx := range mp.orphans {
		if otx.peerID == peerID {
			mp.removeOrphan(otx.tx, true)
			numEvicted++
		}
	}
	mp.mtx.Unlock()
	return numEvicted
}

// limitNumOrphans limits the number of orphan transactions by evicting a random
// orphan if adding a new one would cause it to overflow the max allowed.
//
// This function MUST be called with the mempool lock held (for writes).
func (mp *TxPool) limitNumOrphans() error {
	// Scan through the orphan pool and remove any expired orphans when it's
	// time. This is done for efficiency so the scan only happens
	// periodically instead of on every orphan added to the pool.
	if now := time.Now(); now.After(mp.nextExpireScan) {
		origNumOrphans := len(mp.orphans)
		for _, orphanTxn := range mp.orphans {
			if now.After(orphanTxn.expiration) {
				// Remove redeemers too because the missing
				// parents are very unlikely to ever materialize
				// since the orphan has already been around more
				// than long enough for them to be delivered.
				mp.removeOrphan(orphanTxn.tx, true)
			}
		}

		// Set next expiration scan to occur after the scan interval.
		mp.nextExpireScan = now.Add(orphanExpireScanInterval)

		numOrphans := len(mp.orphans)
		if numExpired := origNumOrphans - numOrphans; numExpired > 0 {
			glog.Debugf("Expired %d orphans (remaining: %d)", numExpired, numOrphans)
		}
	}

	// Nothing to do if adding another orphan will not cause the pool to
	// exceed the limit.
	if len(mp.orphans)+1 <= MaxOrphanTransactions {
		return nil
	}

	// Remove a random entry from the map. The iteration order
	// is not important here because an adversary would have to be
	// able to pull off preimage attacks on the hashing function in
	// order to target eviction of specific entries anyways.
	for _, otx := range mp.orphans {
		// Don't remove redeemers in the case of a random eviction since
		// it is quite possible it might be needed again shortly.
		mp.removeOrphan(otx.tx, false)
		break
	}

	return nil
}

// addOrphan adds an orphan transaction to the orphan pool.
//
// This function MUST be called with the mempool lock held (for writes).
func (mp *TxPool) addOrphan(tx *MsgUltranetTxn, peerID uint64) {
	// Nothing to do if no orphans are allowed.
	if MaxOrphanTransactions <= 0 {
		return
	}

	// Limit the number orphan transactions to prevent memory exhaustion.
	// This will periodically remove any expired orphans and evict a random
	// orphan if space is still needed.
	mp.limitNumOrphans()

	txHash := tx.Hash()
	if txHash == nil {
		// If we have an error just log it and return.
		glog.Error(fmt.Errorf("addOrphan: Problem hashing txn: "))
		return
	}
	mp.orphans[*txHash] = &OrphanTx{
		tx:         tx,
		peerID:     peerID,
		expiration: time.Now().Add(orphanTTL),
	}
	for _, txIn := range tx.TxInputs {
		if _, exists := mp.orphansByPrev[UtxoKey(*txIn)]; !exists {
			mp.orphansByPrev[UtxoKey(*txIn)] =
				make(map[BlockHash]*MsgUltranetTxn)
		}
		mp.orphansByPrev[UtxoKey(*txIn)][*txHash] = tx
	}

	glog.Debugf("Stored orphan transaction %v (total: %d)", txHash, len(mp.orphans))
}

// maybeAddOrphan potentially adds an orphan to the orphan pool.
//
// This function MUST be called with the mempool lock held (for writes).
func (mp *TxPool) maybeAddOrphan(tx *MsgUltranetTxn, peerID uint64) error {
	// Ignore orphan transactions that are too large. This helps avoid
	// a memory exhaustion attack based on sending a lot of really large
	// orphans. In the case there is a valid transaction larger than this,
	// it will ultimtely be rebroadcast after the parent transactions
	// have been mined or otherwise received.
	//
	// Note that the number of orphan transactions in the orphan pool is
	// also limited, so this equates to a maximum memory used of
	// MaxOrphanTxSize * MaxOrphanTransactions (which is ~5MB
	// using the default values at the time this comment was written).
	txBytes, err := tx.ToBytes(false)
	if err != nil {
		return errors.Wrapf(err, "maybeAddOrphan: Problem serializing txn: ")
	}
	serializedLen := len(txBytes)
	if serializedLen > MaxOrphanTxSize {
		return TxErrorTooLarge
	}

	// Add the orphan if the none of the above disqualified it.
	mp.addOrphan(tx, peerID)

	return nil
}

// removeOrphanDoubleSpends removes all orphans which spend outputs spent by the
// passed transaction from the orphan pool. Removing those orphans then leads
// to removing all orphans which rely on them, recursively. This is necessary
// when a transaction is added to the main pool because it may spend outputs
// that orphans also spend.
//
// This function MUST be called with the mempool lock held (for writes).
func (mp *TxPool) removeOrphanDoubleSpends(tx *MsgUltranetTxn) {
	for _, txIn := range tx.TxInputs {
		for _, orphan := range mp.orphansByPrev[UtxoKey(*txIn)] {
			mp.removeOrphan(orphan, true)
		}
	}
}

// isTransactionInPool returns whether or not the passed transaction already
// exists in the main pool.
//
// This function MUST be called with the mempool lock held (for reads).
func (mp *TxPool) isTransactionInPool(hash *BlockHash) bool {
	if _, exists := mp.poolMap[*hash]; exists {
		return true
	}

	return false
}

// IsTransactionInPool returns whether or not the passed transaction already
// exists in the main pool.
//
// This function is safe for concurrent access.
func (mp *TxPool) IsTransactionInPool(hash *BlockHash) bool {
	// Protect concurrent access.
	mp.mtx.RLock()
	defer mp.mtx.RUnlock()
	inPool := mp.isTransactionInPool(hash)

	return inPool
}

// isOrphanInPool returns whether or not the passed transaction already exists
// in the orphan pool.
//
// This function MUST be called with the mempool lock held (for reads).
func (mp *TxPool) isOrphanInPool(hash *BlockHash) bool {
	if _, exists := mp.orphans[*hash]; exists {
		return true
	}

	return false
}

// IsOrphanInPool returns whether or not the passed transaction already exists
// in the orphan pool.
//
// This function is safe for concurrent access.
func (mp *TxPool) IsOrphanInPool(hash *BlockHash) bool {
	// Protect concurrent access.
	mp.mtx.RLock()
	inPool := mp.isOrphanInPool(hash)
	mp.mtx.RUnlock()

	return inPool
}

// haveTransaction returns whether or not the passed transaction already exists
// in the main pool or in the orphan pool.
//
// This function MUST be called with the mempool lock held (for reads).
func (mp *TxPool) haveTransaction(hash *BlockHash) bool {
	return mp.isTransactionInPool(hash) || mp.isOrphanInPool(hash)
}

// HaveTransaction returns whether or not the passed transaction already exists
// in the main pool or in the orphan pool.
//
// This function is safe for concurrent access.
func (mp *TxPool) HaveTransaction(hash *BlockHash) bool {
	// Protect concurrent access.
	mp.mtx.RLock()
	haveTx := mp.haveTransaction(hash)
	mp.mtx.RUnlock()

	return haveTx
}

func (mp *TxPool) _removeTxnFromMetadataMap(txn *MsgUltranetTxn, txHash *BlockHash) {
	metadataID, err := GetMetadataIDForTxn(txn, txHash)
	if err != nil {
		glog.Error(errors.Wrapf(err, "_removeTxnFromMetadataMap: "))
		return
	}
	if metadataID == nil {
		// Nothing to do if this txn doesn't have metadata.
		return
	}

	// Find the txn in the txnsByMetadataID map if it's there and remove it. Potentially
	// delete the entry for this metadataID if this is the last transaction in the map
	// for this metadataID
	if txMap, txMapExists := mp.txnsByMetadataID[*metadataID]; txMapExists {
		delete(txMap, *txHash)
		// If the map corresponding to this metadataID is now empty, delete it as well.
		if len(txMap) == 0 {
			delete(mp.txnsByMetadataID, *metadataID)
		}
	}

	return
}

func (mp *TxPool) _removeTransactionFromPubKeyOutputTxDescMap(txn *MsgUltranetTxn, txHash *BlockHash) {
	for _, ultranetOutput := range txn.TxOutputs {
		pkMapKey := PkMapKey{}
		copy(pkMapKey[:], ultranetOutput.PublicKey)
		outputMap, _ := mp.outputPubKeyToTxnMap[pkMapKey]
		delete(outputMap, *txHash)
		if len(outputMap) == 0 {
			delete(mp.outputPubKeyToTxnMap, pkMapKey)
		}
	}

	// If the transaction has an overall public key set, then remove that mapping.
	if len(txn.PublicKey) == btcec.PubKeyBytesLenCompressed {
		pkMapKey := PkMapKey{}
		copy(pkMapKey[:], txn.PublicKey)
		outputMap, _ := mp.outputPubKeyToTxnMap[pkMapKey]
		delete(outputMap, *txHash)
		if len(outputMap) == 0 {
			delete(mp.outputPubKeyToTxnMap, pkMapKey)
		}
	}

	// If the transaction is a BitcoinExchange transaction, add a mapping
	// for the implicit output created by it.
	if txn.TxnMeta.GetTxnType() == TxnTypeBitcoinExchange {
		txnMeta := txn.TxnMeta.(*BitcoinExchangeMetadata)
		publicKey, err := _extractBitcoinPublicKeyFromBitcoinTransactionInputs(
			txnMeta.BitcoinTransaction, mp.bc.params.BitcoinBtcdParams)
		if err != nil {
			glog.Errorf("_removeTransactionFromPubKeyOutputTxDescMap: Problem extracting public key "+
				"from Bitcoin transaction for txnMeta %v", txnMeta)
			return
		}

		pkMapKey := PkMapKey{}
		copy(pkMapKey[:], publicKey.SerializeCompressed()[:])
		outputMap, _ := mp.outputPubKeyToTxnMap[pkMapKey]
		delete(outputMap, *txHash)
		if len(outputMap) == 0 {
			delete(mp.outputPubKeyToTxnMap, pkMapKey)
		}
	}
}

// removeTransaction is the internal function which implements the public
// RemoveTransaction. See the comment for RemoveTransaction for more details.
//
// This function MUST be called with the mempool lock held (for writes).
func (mp *TxPool) removeTransaction(tx *MsgUltranetTxn, removeRedeemers bool) error {
	txHash := tx.Hash()
	if txHash == nil {
		return fmt.Errorf("removeTransaction: Problem hashing txn")
	}
	if removeRedeemers {
		// Remove any transactions which rely on this one.
		for ii := uint32(0); ii < uint32(len(tx.TxOutputs)); ii++ {
			prevOut := UltranetInput{TxID: *txHash, Index: ii}
			if txRedeemer, exists := mp.outpoints[UtxoKey(prevOut)]; exists {
				mp.removeTransaction(txRedeemer, true)
			}
		}
	}

	// Remove the transaction if needed.
	if txDesc, exists := mp.poolMap[*txHash]; exists {
		// Mark the referenced outpoints as unspent by the pool.
		for _, txIn := range txDesc.Tx.TxInputs {
			delete(mp.outpoints, UtxoKey(*txIn))
		}
		delete(mp.poolMap, *txHash)

		// Remove it from the metadata map if it has an entry there.
		mp._removeTxnFromMetadataMap(tx, txHash)

		// Remove it from the transaction heap.
		heap.Remove(&mp.txFeeMinheap, txDesc.index)

		// Remove the transaction from the pub key output map.
		mp._removeTransactionFromPubKeyOutputTxDescMap(tx, txHash)

		// Adjust the total size to reflect that this transaction has been removed.
		mp.totalTxSizeBytes -= txDesc.TxSizeBytes

		atomic.StoreInt64(&mp.lastUpdated, time.Now().Unix())
	}

	return nil
}

// RemoveTransaction removes the passed transaction from the mempool. When the
// removeRedeemers flag is set, any transactions that redeem outputs from the
// removed transaction will also be removed recursively from the mempool, as
// they would otherwise become orphans.
//
// TODO: Removing transactions is a little sketchy because it is currently
// possible to have situations where the removal of transaction A from the mempool
// causes transaction B to become invalid without having B actually removed from
// the mempool. A concrete example is as follows:
// - Merchant registers with public key A
// - Order is placed with merchant using public key A
// - Merchant updates public key to B
// If we were to mine the two merchant transactions into a block, the order
// transaction would become invalid but we wouldn't know to remove it from the
// mempool until later. We have multiple ways of coping with this issue right
// now:
// - When memepool transactions are used as the basis for mining a block, we
//   make sure to re-validate all the transactions we want to mine by running
//   them through an "empty" mempool data structure first.
// - We regularly re-process the entire mempool on block updates. This is fairly
//   inefficient, but it happens infrequently enough and the mempool is small enough
//   in general that it seems OK for now.
// The endgame is that we need to rigorously encode metadata dependencies, e.g.
// recording which MerchantID and merchant public key an order is relying on in a
// map and updating things accordingly. But this adds significant complexity to
// the point where the hacks above seem preferable, especially when volume is not
// a bottleneck.
//
// This function is safe for concurrent access.
func (mp *TxPool) RemoveTransaction(tx *MsgUltranetTxn, removeRedeemers bool) error {
	// Protect concurrent access.
	mp.mtx.Lock()
	defer mp.mtx.Unlock()
	return mp.removeTransaction(tx, removeRedeemers)
}

// RemoveDoubleSpends removes all transactions which spend outputs spent by the
// passed transaction from the memory pool. Removing those transactions then
// leads to removing all transactions which rely on them, recursively. This is
// necessary when a block is connected to the main chain because the block may
// contain transactions which were previously unknown to the memory pool.
//
// This function is safe for concurrent access.
func (mp *TxPool) RemoveDoubleSpends(tx *MsgUltranetTxn) {
	// Protect concurrent access.
	mp.mtx.Lock()
	for _, txIn := range tx.TxInputs {
		if txRedeemer, ok := mp.outpoints[UtxoKey(*txIn)]; ok {
			txRedeemerHash := txRedeemer.Hash()
			if txRedeemerHash == nil {
				glog.Error(fmt.Errorf("RemoveDoubleSpends: Problem hashing txRedeemer: "))
				return
			}
			txHash := tx.Hash()
			if txHash == nil {
				glog.Error(fmt.Errorf("RemoveDoubleSpends: Problem hashing tx: "))
				return
			}

			if !txRedeemerHash.IsEqual(txHash) {
				mp.removeTransaction(txRedeemer, true)
			}
		}
	}
	mp.mtx.Unlock()
}

// addTransaction adds the passed transaction to the memory pool. It should
// not be called directly as it doesn't perform any validation.
//
// This function MUST be called with the mempool lock held (for writes).
func (mp *TxPool) addTransaction(tx *MsgUltranetTxn, height uint32, fee uint64) (*TxDesc, error) {
	// Add the transaction to the pool and mark the referenced outpoints
	// as spent by the pool.
	txBytes, err := tx.ToBytes(false)
	if err != nil {
		return nil, errors.Wrapf(err, "addTransaction: Problem serializing txn: ")
	}
	serializedLen := uint64(len(txBytes))

	txHash := tx.Hash()
	if txHash == nil {
		return nil, errors.Wrapf(err, "addTransaction: Problem hashing tx: ")
	}

	txD := &TxDesc{
		Tx:          tx,
		Hash:        txHash,
		TxSizeBytes: uint64(serializedLen),
		Added:       time.Now(),
		Height:      height,
		Fee:         fee,
		FeePerKB:    fee * 1000 / serializedLen,
		// index will be set by the heap code.
	}
	// Get the txn metadata ID if applicable.
	metadataID, err := GetMetadataIDForTxn(tx, txHash)
	if err != nil {
		return nil, errors.Wrapf(err, "addTransaction: Problem looking up MetadataID for txn: ")
	}

	// Add the transaction to the main pool map.
	mp.poolMap[*txHash] = txD
	// Add the transaction to the outpoints map.
	for _, txIn := range tx.TxInputs {
		mp.outpoints[UtxoKey(*txIn)] = tx
	}
	// Add the transaction to the metadata map.
	if metadataID != nil {
		txMap, txMapExists := mp.txnsByMetadataID[*metadataID]
		if !txMapExists {
			txMap = make(map[BlockHash]*TxDesc)
		}
		txMap[*txHash] = txD
		mp.txnsByMetadataID[*metadataID] = txMap
	}
	// Add the transaction to the min heap.
	heap.Push(&mp.txFeeMinheap, txD)
	// Update the size of the mempool to reflect the added transaction.
	mp.totalTxSizeBytes += txD.TxSizeBytes

	atomic.StoreInt64(&mp.lastUpdated, time.Now().Unix())

	return txD, nil
}

// checkPoolDoubleSpend checks whether or not the passed transaction is
// attempting to spend coins already spent by other transactions in the pool.
// Note it does not check for double spends against transactions already in the
// main chain.
//
// This function MUST be called with the mempool lock held (for reads).
func (mp *TxPool) checkPoolDoubleSpend(tx *MsgUltranetTxn) error {
	for _, txIn := range tx.TxInputs {
		if _, exists := mp.outpoints[UtxoKey(*txIn)]; exists {
			return TxErrorDoubleSpend
		}
	}

	return nil
}

// CheckSpend checks whether the passed outpoint is already spent by a
// transaction in the mempool. If that's the case the spending transaction will
// be returned, if not nil will be returned.
func (mp *TxPool) CheckSpend(op UtxoKey) *MsgUltranetTxn {
	mp.mtx.RLock()
	txR := mp.outpoints[op]
	mp.mtx.RUnlock()

	return txR
}

func _dedupAndSortTxDescList(txList []*TxDesc) []*TxDesc {
	// Remove duplicates.
	txIDMap := make(map[BlockHash]bool)
	dedupedList := []*TxDesc{}
	for _, depTx := range txList {
		txHash := depTx.Hash

		if _, exists := txIDMap[*txHash]; !exists {
			txIDMap[*txHash] = true
			dedupedList = append(dedupedList, depTx)
		}
	}

	// Sort the list based on when the transactions were added.
	sort.Slice(dedupedList, func(ii, jj int) bool {
		return dedupedList[ii].Added.Before(dedupedList[jj].Added)
	})

	return dedupedList
}

// _findMempoolDependencies finds all transactions in the mempool that may be
// dependencies of the passed transaction and returns them all sorted by when they
// were added to the mempool. This method considers two types of dependencies:
// 1) UTXO dependencies, which is where a transaction is using outputs created by
//    another transaction in the mempool.
// 2) Metadata dependencies, which is where a transaction is updating an order or a
//    merchant that may also be updated by another transaction in the mempool.
//
// Once all of these potential dependencies are found, sorting them by when they were
// added to the mempool makes it so that all of these transactions can be connected to
// a UtxoView in order without causing a validation error.
func (mp *TxPool) _findMempoolDependencies(txn *MsgUltranetTxn, timeAdded time.Time) ([]*TxDesc, error) {
	// Start by finding all the direct dependencies of the passed transaction. These are
	// transactions that are directly referenced by the passed transaction's inputs and
	// by the transaction's metadata.
	directDependencies := []*TxDesc{}

	// Look up all potential metadata dependencies for this transaction.
	metadataDepIDs, err := mp._getDependentMetadataIDs(txn)
	if err != nil {
		return nil, errors.Wrapf(err, "_findMempoolDependencies: Error getting dependent MetadataIDs")
	}
	// For each MetadataID that this transaction could be dependent on, lookup the
	// transactions in the mempool corresponding to that ID and add them to our
	// dependency list only if they occur before the timeAdded. The timeAdded constraint
	// makes it so that we avoid re-adding transactions in an infinite loop on recursive
	// calls to this function.
	for _, metadataID := range metadataDepIDs {
		txList := mp.txnsByMetadataID[*metadataID]
		for _, metadataTxDesc := range txList {
			if !metadataTxDesc.Added.Before(timeAdded) {
				continue
			}

			directDependencies = append(directDependencies, metadataTxDesc)
		}
	}

	// Now go through the inputs and fetch transactions that are dependencies from a UTXO
	// standpoint. Note that these may overlap with the metadata dependencies and that's
	// OK because we dedup.
	for _, txIn := range txn.TxInputs {
		if mempoolTx, exists := mp.poolMap[txIn.TxID]; exists {
			directDependencies = append(directDependencies, mempoolTx)
		}
	}

	// If we've already hit our maximum transaction limit with just direct dependencies
	// then return early.
	directDependencies = _dedupAndSortTxDescList(directDependencies)
	if len(directDependencies) > MaxTransactionDependenciesToProcess {
		return directDependencies[:MaxTransactionDependenciesToProcess], nil
	}

	// Iterate over the direct dependencies and recursively fetch their dependencies.
	fullDependencyList := []*TxDesc{}
	for _, directDepTx := range directDependencies {
		newTxDescs, err := mp._findMempoolDependencies(directDepTx.Tx, directDepTx.Added)
		if err != nil {
			return nil, err
		}
		fullDependencyList = append(fullDependencyList, newTxDescs...)
		fullDependencyList = append(fullDependencyList, directDepTx)

		// If we've already hit our maximum transaction limit, then return early.
		fullDependencyList = _dedupAndSortTxDescList(fullDependencyList)
		if len(fullDependencyList) >= MaxTransactionDependenciesToProcess {
			return fullDependencyList[:MaxTransactionDependenciesToProcess], nil
		}
	}

	if len(fullDependencyList) >= MaxTransactionDependenciesToProcess {
		fullDependencyList = fullDependencyList[:MaxTransactionDependenciesToProcess]
	}
	return fullDependencyList, nil
}

// GetAugmentedUtxoViewForPublicKey creates a UtxoView that has connected all of
// the transactions that could result in utxos for the passed-in public key
// plus all of the dependencies of those transactions. This is useful for
// when we want to validate a transaction that builds on a transaction that has
// not yet been mined into a block. It is also useful for when we want to fetch all
// the unspent UtxoEntrys factoring in what's been spent by transactions in
// the mempool.
//
// TODO: Making this function accept multiple public keys, e.g. a merchant and buyer
// public key, or making it accept metadataIDs would make it fool-proof and fix some
// edge cases where dependencies might be missed. For example, when a buyer looks up
// all dependencies for a review transaction she may miss a merchant's confirmation
// transaction as it stands right now.
func (mp *TxPool) GetAugmentedUtxoViewForPublicKey(pkBytes []byte) (*UtxoView, error) {
	mp.mtx.RLock()
	defer mp.mtx.RUnlock()

	// Find all of the transactions in the mempool that result in an output
	// destined for this public key.
	pkMapKey := PkMapKey{}
	copy(pkMapKey[:], pkBytes)
	txDescsForPublicKey, exists := mp.outputPubKeyToTxnMap[pkMapKey]
	if !exists {
		txDescsForPublicKey = make(map[BlockHash]*TxDesc)
	}

	// For each transaction we found for this public key, find its dependencies
	// and add them to a new map. We use a map instead of a list to avoid
	// duplicates.
	fullDepTxDescsMap := make(map[BlockHash]*TxDesc)
	for _, txD := range txDescsForPublicKey {
		deps, err := mp._findMempoolDependencies(txD.Tx, txD.Added)
		if err != nil {
			return nil, fmt.Errorf("TxPool.getAugmentedUtxoViewForPublicKey: Problem finding "+
				"dependencies for TxDesc %v: %v", txD, err)
		}
		// Add the dependencies of this transaction.
		for _, txDescDep := range deps {
			fullDepTxDescsMap[*txDescDep.Hash] = txDescDep
		}
		// Add the transaction itself.
		fullDepTxDescsMap[*txD.Hash] = txD
	}

	// Now that we have all the unique transactions that could possibly result
	// in utxos for our public key, convert them into a list.
	fullDepTxDescsList := []*TxDesc{}
	for _, txD := range fullDepTxDescsMap {
		fullDepTxDescsList = append(fullDepTxDescsList, txD)
	}

	// Sort the transactions based on when they were added to the mempool.
	// This ensures they can be connected in this order.
	sort.Slice(fullDepTxDescsList, func(ii, jj int) bool {
		return fullDepTxDescsList[ii].Added.Before(fullDepTxDescsList[jj].Added)
	})

	// fullDepTxDescsList should now contain every transaction related to this
	// public key and all of its dependencies. It should be the case that any
	// utxo that is spendable by this public key will be covered by the union
	// of what's in the db and these transactions.

	// Create a view and connect all of these transactions to it.
	utxoView, err := NewUtxoView(mp.bc.db, mp.bc.params, mp.bc.bitcoinManager)
	if err != nil {
		return nil, errors.Wrapf(err, "TxPool.getAugmentedUtxoViewForPublicKey: Problem initializing UtxoView")
	}
	for _, txD := range fullDepTxDescsList {
		// Don't verify signatures since this transaction is already in the mempool.
		//
		// Note that mempool verification does not require that BitcoinExchange
		// transactions meet the MinBurnWork requirement. Note that a BitcoinExchange
		// transaction will only get this far once we are positive the BitcoinManager
		// has the block corresponding to the transaction.
		//
		// Use the block tip's height plus one since these transactions will presumably
		// be added in the next block at the earliest.
		bestHeight := uint32(mp.bc.blockTip().Height + 1)
		_, _, _, _, err := utxoView._connectTransaction(
			txD.Tx, txD.Hash, bestHeight, false, /*verifySignatures*/
			true, /*verifyMerchantMerkleRoot*/
			false /*enforceMinBitcoinBurnWork*/)
		if err != nil {
			// Note this can happen in odd cases where a transaction's dependency was removed
			// but the transaction depending on it was not. See the comment on
			// _findMempoolDependencies for more info on this case.
			return nil, errors.Wrapf(err, "TxPool.getAugmentedUtxoViewForPublicKey: Problem connecting transaction dependency: ")
		}
	}

	// At this point the utxoView should contain all of the potential dependencies
	// for the passed-in public key.

	// This view can now be used to validate transactions factoring in the latest
	// information available from the mempool.
	return utxoView, nil
}

// FetchTransaction returns the requested transaction from the transaction pool.
// This only fetches from the main transaction pool and does not include
// orphans.
//
// This function is safe for concurrent access.
func (mp *TxPool) FetchTransaction(txHash *BlockHash) *TxDesc {
	mp.mtx.RLock()
	defer mp.mtx.RUnlock()

	if txDesc, exists := mp.poolMap[*txHash]; exists {
		return txDesc
	}

	return nil
}

// maybeAcceptTransaction is the internal function which implements the public
// MaybeAcceptTransaction. See the comment for MaybeAcceptTransaction for
// more details.
//
// This function MUST be called with the mempool lock held (for writes) and the
// blockchain lock held for reads.
//
// TODO: Allow replacing a transaction with a higher fee.
func (mp *TxPool) maybeAcceptTransaction(tx *MsgUltranetTxn, rateLimit bool, rejectDupOrphans bool, verifySignatures bool) (_missingParents []*BlockHash, _txDesc *TxDesc, _err error) {
	// Compute the hash of the transaction.
	txHash := tx.Hash()
	if txHash == nil {
		return nil, nil, fmt.Errorf("maybeAcceptTransaction: Problem computing tx hash: ")
	}

	// Don't accept the transaction if it already exists in the pool. This
	// applies to orphan transactions as well when the reject duplicate
	// orphans flag is set. This check is intended to be a quick check to
	// weed out duplicates.
	if mp.isTransactionInPool(txHash) || (rejectDupOrphans &&
		mp.isOrphanInPool(txHash)) {

		return nil, nil, TxErrorDuplicate
	}

	// Block reward transactions shouldn't appear individually
	if tx.TxnMeta != nil && tx.TxnMeta.GetTxnType() == TxnTypeBlockReward {
		return nil, nil, TxErrorIndividualBlockReward
	}

	// Check the transaction's sanity.
	if err := CheckTransactionSanity(tx); err != nil {
		return nil, nil, err
	}

	// The transaction may not use any of the same outputs as other
	// transactions already in the pool as that would ultimately result in a
	// double spend. This check is intended to be quick and therefore only
	// detects double spends within the transaction pool itself. The
	// transaction could still be double spending coins from the main chain
	// at this point. There is a more in-depth check that happens later
	// after fetching the referenced transaction inputs from the main chain
	// which examines the actual spend data and prevents double spends.
	//
	// TODO: Implement being able to replace a transaction with a higher fee
	// when the transaction has the exact same inputs similar to RBF in
	// Bitcoin.
	err := mp.checkPoolDoubleSpend(tx)
	if err != nil {
		return nil, nil, err
	}

	// Find all of the dependencies of this transaction in the mempool.
	mempoolDependencies, err := mp._findMempoolDependencies(tx, time.Now())
	if err != nil {
		return nil, nil, errors.Wrapf(err, "maybeAcceptTransaction: Problem fetching mempool dependencies")
	}

	// Create a new UTXO view that represents the current tip. Note that it is safe
	// to use this because we expect that the blockchain lock is held for the duration
	// of this function call so there shouldn't be any shifting of the db happening
	// beneath our feet.
	utxoView, err := NewUtxoView(mp.bc.db, mp.bc.params, mp.bc.bitcoinManager)
	if err != nil {
		return nil, nil, errors.Wrapf(err, "maybeAcceptTransaction: Problem initializing UtxoView")
	}

	// Connnect all of this transaction's dependencies to the UtxoView in order. Note
	// that we can do this because _findMempoolDependencies returns the transactions in
	// sorted order based on when transactions were added.
	bestHeight := uint32(mp.bc.blockTip().Height + 1)
	for _, depTx := range mempoolDependencies {
		// Don't verify signatures since this transaction is already in the mempool.
		//
		// Additionally mempool verification does not require that BitcoinExchange
		// transactions meet the MinBurnWork requirement. Note that a BitcoinExchange
		// transaction will only get this far once we are positive the BitcoinManager
		// has the block corresponding to the transaction.
		_, _, _, _, err := utxoView._connectTransaction(
			depTx.Tx, depTx.Hash, bestHeight, false,
			false, /*verifyMerchantMerkleRoot*/
			false /*enforceMinBitcoinBurnWork*/)
		if err != nil {
			// Note this can happen in odd cases where a transaction's dependency was removed
			// but the transaction depending on it was not. See the comment on
			// _findMempoolDependencies for more info on this case.
			return nil, nil, errors.Wrapf(err, "maybeAcceptTransaction: Problem connecting transaction dependency: ")
		}
	}

	// Iterate over the transaction's inputs. If any of them don't have utxos in the
	// UtxoView that are unspent at this point then the transaction is an orphan. Use
	// a map to ensure there are no duplicates.
	missingParentsMap := make(map[BlockHash]bool)
	for _, txIn := range tx.TxInputs {
		utxoKey := UtxoKey(*txIn)
		utxoEntry := utxoView.GetUtxoEntryForUtxoKey(&utxoKey)
		if utxoEntry == nil || utxoEntry.isSpent {
			missingParentsMap[utxoKey.TxID] = true
		}
	}
	if len(missingParentsMap) > 0 {
		var missingParents []*BlockHash
		for txID := range missingParentsMap {
			// Must make a copy of the hash here since the iterator
			// is replaced and taking its address directly would
			// result in all of the entries pointing to the same
			// memory location and thus all be the final hash.
			hashCopy := txID
			missingParents = append(missingParents, &hashCopy)
		}
		return missingParents, nil, nil
	}

	// At this point, we have connected all of the transaction's dependencies and we
	// are certain the transaction is not an orphan in terms of its UTXO's.

	// Now that we have added all of the transaction's dependencies and connected
	// them, we can connect this transaction to verify that it obeys all of the
	// consensus rules. This step is responsible for doing all of the heavy
	// validation required before a transaction is added to the blockchain, including
	// checking signatures.
	//
	// Note that mempool verification does not require that BitcoinExchange
	// transactions meet the MinBurnWork requirement. Note that a BitcoinExchange
	// transaction will only get this far once we are positive the BitcoinManager
	// has the block corresponding to the transaction.
	_, totalInput, totalOutput, txFee, err := utxoView._connectTransaction(
		tx, txHash, bestHeight, verifySignatures,
		true, /*verifyMerchantMerkleRoot*/
		false /*enforceMinBitcoinBurnWork*/)
	if err != nil {
		return nil, nil, errors.Wrapf(err, "maybeAcceptTransaction: Problem "+
			"connecting transaction after connecting dependencies: ")
	}

	// Compute the feerate for this transaction for use below.
	txBytes, err := tx.ToBytes(false)
	if err != nil {
		return nil, nil, errors.Wrapf(err, "maybeAcceptTransaction: Problem serializing txn: ")
	}
	serializedLen := uint64(len(txBytes))
	txFeePerKB := txFee * 1000 / serializedLen

	// Transactions with a feerate below the minimum threshold will be outright
	// rejected. This is the first line of defense against attacks against the
	// mempool.
	minFeeAllowed := mp.minFeeRateNanosPerKB * serializedLen / 1000
	if rateLimit && txFeePerKB < minFeeAllowed {
		glog.Debugf("maybeAcceptTransaction: Fee rate per KB found was %d, which his below the "+
			"minimum required which is %d (= %d * %d / 1000). Total input: %d, total output: %d, txn: %v",
			txFeePerKB, minFeeAllowed, mp.minFeeRateNanosPerKB, serializedLen,
			totalInput, totalOutput, spew.Sdump(tx))
		return nil, nil, TxErrorInsufficientFeeMinFee
	}

	// If the feerate is below the minimum we've configured for the node, then apply
	// some rate-limiting logic to avoid stalling in situations in which someone is trying
	// to flood the network with low-value transacitons. This avoids a form of amplification
	// DDOS attack brought on by the fact that a single broadcast results in all nodes
	// communicating with each other.
	if rateLimit && txFeePerKB < mp.rateLimitFeeRateNanosPerKB {
		nowUnix := time.Now().Unix()

		// Exponentially decay the accumulator by a factor of 2 every 10m.
		mp.lowFeeTxSizeAccumulator /= math.Pow(2.0,
			float64(nowUnix-mp.lastLowFeeTxUnixTime)/(10*60))
		mp.lastLowFeeTxUnixTime = nowUnix

		// Check to see if the accumulator is over the limit.
		if mp.lowFeeTxSizeAccumulator >= float64(LowFeeTxLimitBytesPerTenMinutes) {
			return nil, nil, TxErrorInsufficientFeeRateLimit
		}

		// Update the accumulator and potentially log the state.
		oldTotal := mp.lowFeeTxSizeAccumulator
		mp.lowFeeTxSizeAccumulator += float64(serializedLen)
		glog.Tracef("maybeAcceptTransaction: Rate limit current total ~(%v) bytes/10m, nextTotal: ~(%v) bytes/10m, "+
			"limit ~(%v) bytes/10m", oldTotal, mp.lowFeeTxSizeAccumulator, LowFeeTxLimitBytesPerTenMinutes)
	}

	// If adding this transaction would put the pool over its limit of
	// MaxTotalTransactionSizeBytes then potentially remove some transactions to make
	// room for it.
	//
	// This check only applies when we have other transactions in the pool.
	if len(mp.txFeeMinheap) > 0 {
		// Remove transactions with a lower fee than this one until we have room for this
		// transaction. Note that if the totalTxSizeBytes is >0 then the heap should be
		// non-empty so there is no need for a bounds check on txFeeMinheap.
		for serializedLen+mp.totalTxSizeBytes > MaxTotalTransactionSizeBytes &&
			txFeePerKB >= mp.txFeeMinheap[0].FeePerKB {
			mp.removeTransaction(mp.txFeeMinheap[0].Tx, true)
		}

		// If the mempool is still full after removing as many transactions from the pool
		// as we can then reject this transaction.
		//
		// TODO: It seems like it could be problematic that we change the state of the
		// mempool by removing transactions in response to a transaction that we ultimately
		// reject. That being said, it seems anything that would try to exploit this
		// would only affect the lower-fee transactions. Also we won't relay
		// this transaction so any havoc that is wreaked will be somewhat localized.
		if serializedLen+mp.totalTxSizeBytes > MaxTotalTransactionSizeBytes {
			return nil, nil, TxErrorInsufficientFeePriorityQueue
		}
	}

	// At this point we are certain that the mempool has enough room to accomodate
	// this transaction and that the transaction is valid.

	// Add to transaction pool.
	txD, err := mp.addTransaction(tx, bestHeight, txFee)
	if err != nil {
		return nil, nil, errors.Wrapf(err, "maybeAcceptTransaction: ")
	}

	glog.Tracef("maybeAcceptTransaction: Accepted transaction %v (pool size: %v)", txHash,
		len(mp.poolMap))

	return nil, txD, nil
}

// MaybeAcceptTransaction is the main workhorse for handling insertion of new
// free-standing transactions into a memory pool. It includes functionality
// such as rejecting duplicate transactions, ensuring transactions follow all
// rules, detecting orphan transactions, and insertion into the memory pool.
//
// If the transaction is an orphan (missing parent transactions), the
// transaction is NOT added to the orphan pool, but each unknown referenced
// parent is returned. Use ProcessTransaction instead if new orphans should
// be added to the orphan pool.
//
// This function is safe for concurrent access. It is assumed the ChainLock is
// held before this function is a accessed.
func (mp *TxPool) MaybeAcceptTransaction(tx *MsgUltranetTxn, rateLimit bool, verifySignatures bool) ([]*BlockHash, *TxDesc, error) {
	// Protect concurrent access.
	mp.mtx.Lock()
	defer mp.mtx.Unlock()

	hashes, txD, err := mp.maybeAcceptTransaction(tx, rateLimit, true, verifySignatures)

	return hashes, txD, err
}

// processOrphans is the internal function which implements the public
// ProcessOrphans. See the comment for ProcessOrphans for more details.
//
// This function MUST be called with the mempool lock held (for writes).
func (mp *TxPool) processOrphans(acceptedTx *MsgUltranetTxn, rateLimit bool, verifySignatures bool) []*TxDesc {
	var acceptedTxns []*TxDesc

	// Start with processing at least the passed transaction.
	processList := list.New()
	processList.PushBack(acceptedTx)
	for processList.Len() > 0 {
		// Pop the transaction to process from the front of the list.
		firstElement := processList.Remove(processList.Front())
		processItem := firstElement.(*MsgUltranetTxn)

		processHash := processItem.Hash()
		if processHash == nil {
			glog.Error(fmt.Errorf("processOrphans: Problem hashing tx: "))
			return nil
		}
		prevOut := UltranetInput{TxID: *processHash}
		for txOutIdx := range processItem.TxOutputs {
			// Look up all orphans that redeem the output that is
			// now available. This will typically only be one, but
			// it could be multiple if the orphan pool contains
			// double spends. While it may seem odd that the orphan
			// pool would allow this since there can only possibly
			// ultimately be a single redeemer, it's important to
			// track it this way to prevent malicious actors from
			// being able to purposefully construct orphans that
			// would otherwise make outputs unspendable.
			//
			// Skip to the next available output if there are none.
			prevOut.Index = uint32(txOutIdx)
			orphans, exists := mp.orphansByPrev[UtxoKey(prevOut)]
			if !exists {
				continue
			}

			// Potentially accept an orphan into the tx pool.
			for _, tx := range orphans {
				missing, txD, err := mp.maybeAcceptTransaction(
					tx, rateLimit, false, verifySignatures)
				if err != nil {
					// The orphan is now invalid, so there
					// is no way any other orphans which
					// redeem any of its outputs can be
					// accepted. Remove them.
					mp.removeOrphan(tx, true)
					break
				}

				// Transaction is still an orphan. Try the next
				// orphan which redeems this output.
				if len(missing) > 0 {
					continue
				}

				// Transaction was accepted into the main pool.
				//
				// Add it to the list of accepted transactions
				// that are no longer orphans, remove it from
				// the orphan pool, and add it to the list of
				// transactions to process so any orphans that
				// depend on it are handled too.
				acceptedTxns = append(acceptedTxns, txD)
				mp.removeOrphan(tx, false)
				processList.PushBack(tx)

				// Only one transaction for this outpoint can be
				// accepted, so the rest are now double spends
				// and are removed later.
				break
			}
		}
	}

	// Recursively remove any orphans that also redeem any outputs redeemed
	// by the accepted transactions since those are now definitive double
	// spends.
	mp.removeOrphanDoubleSpends(acceptedTx)
	for _, txD := range acceptedTxns {
		mp.removeOrphanDoubleSpends(txD.Tx)
	}

	return acceptedTxns
}

// ProcessOrphans determines if there are any orphans which depend on the passed
// transaction hash (it is possible that they are no longer orphans) and
// potentially accepts them to the memory pool. It repeats the process for the
// newly accepted transactions (to detect further orphans which may no longer be
// orphans) until there are no more.
//
// It returns a slice of transactions added to the mempool. A nil slice means
// no transactions were moved from the orphan pool to the mempool.
//
// This function is safe for concurrent access.
func (mp *TxPool) ProcessOrphans(acceptedTx *MsgUltranetTxn, rateLimit bool, verifySignatures bool) []*TxDesc {
	mp.mtx.Lock()
	acceptedTxns := mp.processOrphans(acceptedTx, rateLimit, verifySignatures)
	mp.mtx.Unlock()

	return acceptedTxns
}

func (mp *TxPool) _addTxDescToPubKeyOutputMap(txD *TxDesc) {
	for _, ultranetOutput := range txD.Tx.TxOutputs {
		pkMapKey := PkMapKey{}
		copy(pkMapKey[:], ultranetOutput.PublicKey)
		mapForPk, exists := mp.outputPubKeyToTxnMap[pkMapKey]
		if !exists {
			mapForPk = make(map[BlockHash]*TxDesc)
			mp.outputPubKeyToTxnMap[pkMapKey] = mapForPk
		}
		mapForPk[*txD.Hash] = txD
	}
	// In addition to adding a mapping for each output public key, add a mapping
	// for the transaction's overall public key.
	if len(txD.Tx.PublicKey) == btcec.PubKeyBytesLenCompressed {
		pkMapKey := PkMapKey{}
		copy(pkMapKey[:], txD.Tx.PublicKey)
		mapForPk, exists := mp.outputPubKeyToTxnMap[pkMapKey]
		if !exists {
			mapForPk = make(map[BlockHash]*TxDesc)
			mp.outputPubKeyToTxnMap[pkMapKey] = mapForPk
		}
		mapForPk[*txD.Hash] = txD
	}

	// If the transaction is a PrivateMessage then add a mapping from the
	// recipient to this message so that it comes up when the recipient
	// creates an augmented view. Note the sender is already covered since
	// their public key is the one at the top-level transaction, which we
	// index just above.
	if txD.Tx.TxnMeta.GetTxnType() == TxnTypePrivateMessage {
		txnMeta := txD.Tx.TxnMeta.(*PrivateMessageMetadata)

		pkMapKey := MakePkMapKey(txnMeta.RecipientPublicKey)
		mapForPk, exists := mp.outputPubKeyToTxnMap[pkMapKey]
		if !exists {
			mapForPk = make(map[BlockHash]*TxDesc)
			mp.outputPubKeyToTxnMap[pkMapKey] = mapForPk
		}
		mapForPk[*txD.Hash] = txD
	}

	// If the transaction is a BitcoinExchange transaction, add a mapping
	// for the implicit output created by it.
	if txD.Tx.TxnMeta.GetTxnType() == TxnTypeBitcoinExchange {
		txnMeta := txD.Tx.TxnMeta.(*BitcoinExchangeMetadata)
		publicKey, err := _extractBitcoinPublicKeyFromBitcoinTransactionInputs(
			txnMeta.BitcoinTransaction, mp.bc.params.BitcoinBtcdParams)
		if err != nil {
			glog.Errorf("_addTxDescToPubKeyOutputMap: Problem extracting public key "+
				"from Bitcoin transaction for txnMeta %v", txnMeta)
			return
		}

		pkMapKey := PkMapKey{}
		copy(pkMapKey[:], publicKey.SerializeCompressed()[:])
		mapForPk, exists := mp.outputPubKeyToTxnMap[pkMapKey]
		if !exists {
			mapForPk = make(map[BlockHash]*TxDesc)
			mp.outputPubKeyToTxnMap[pkMapKey] = mapForPk
		}
		mapForPk[*txD.Hash] = txD
	}
}

// UpdateAfterBitcoinManagerNotification should be called whenever the Server gets a
// notification from the BitcoinManager that something has been updated. This gives
// the mempool an opportunity to reprocess any BitcoinExchange transactions that it
// considered unprocessable in the past due to the BitcoinManager not having the
// necessary information.
func (mp *TxPool) UpdateAfterBitcoinManagerNotification(
	allowOrphan, rateLimit bool, verifySignatures bool) (_txnsAddedToMempool []*TxDesc) {

	mp.mtx.Lock()
	defer mp.mtx.Unlock()

	// If the BitcoinManager is unset or isn't current then don't do anything.
	if mp.bc.bitcoinManager == nil ||
		!mp.bc.bitcoinManager.IsCurrent(false /*considerCumWork*/) {
		return nil
	}

	// Go through all the immature Bitcoin transactions and see if we can process
	// them now. If we can then do so and remove them from the immatureBitcoinTxns
	// map.
	newlyAddedTxns := []*TxDesc{}
	for _, ibt := range mp.immatureBitcoinTxns {
		txMeta := ibt.tx.TxnMeta.(*BitcoinExchangeMetadata)
		if mp.bc.bitcoinManager.HeaderForHash(txMeta.BitcoinBlockHash) == nil {
			continue
		}

		// Remove the immature Bitcoin transaction from the map and attempt to reprocess it.
		delete(mp.immatureBitcoinTxns, *ibt.tx.Hash())
		acceptedTxns, err := mp.processTransaction(
			ibt.tx, allowOrphan, rateLimit, ibt.peerID, verifySignatures)
		if err != nil {
			glog.Errorf("TxPool.UpdateAfterBitcoinManagerNotification: Problem adding "+
				"BitcoinExchange txn to mempool %v: %v", ibt.tx, err)
			continue
		}
		newlyAddedTxns = append(newlyAddedTxns, acceptedTxns...)
	}

	return newlyAddedTxns
}

func (mp *TxPool) _addImmatureBitcoinTransaction(txn *MsgUltranetTxn, peerID uint64) {
	// Nothing to do if no immature Bitcoin txns are allowed.
	if MaxImmatureBitcoinTxns <= 0 {
		return
	}

	// Limit the number immature Bitcoin transactions to prevent memory exhaustion.
	for len(mp.immatureBitcoinTxns)+1 >= MaxImmatureBitcoinTxns {
		// Remove a random entry from the map. The iteration order
		// is not important here because an adversary would have to be
		// able to pull off preimage attacks on the hashing function in
		// order to target eviction of specific entries anyways.
		for _, otx := range mp.immatureBitcoinTxns {
			delete(mp.immatureBitcoinTxns, *otx.tx.Hash())
			break
		}
	}
	mp.immatureBitcoinTxns[*txn.Hash()] = &OrphanTx{
		tx:     txn,
		peerID: peerID,
		// No expiration for immature Bitcoin transactions.
	}

	return
}

func (mp *TxPool) processTransaction(tx *MsgUltranetTxn, allowOrphan, rateLimit bool,
	peerID uint64, verifySignatures bool) ([]*TxDesc, error) {

	txHash := tx.Hash()
	if txHash == nil {
		return nil, fmt.Errorf("ProcessTransaction: Problem hashing tx")
	}
	glog.Tracef("Processing transaction %v", txHash)

	// If the transaction is a BitcoinExchange transaction whose BitcoinBlockHash
	// is not yet known to the BitcoinManager, add it to the immatureBitcoinTxns
	// map rather than processing it normally.
	if tx.TxnMeta.GetTxnType() == TxnTypeBitcoinExchange {
		if mp.bc.bitcoinManager == nil ||
			!mp.bc.bitcoinManager.IsCurrent(false /*considerCumWork*/) {

			glog.Tracef("TxPool.processTransaction: Rejecting txn with error: %v, "+
				"bitcoinManager: %v",
				TxErrorCannotProcessBitcoinExchangeUntilBitcoinManagerIsCurrent, mp.bc.bitcoinManager)
			return nil, TxErrorCannotProcessBitcoinExchangeUntilBitcoinManagerIsCurrent
		}

		txnMeta := tx.TxnMeta.(*BitcoinExchangeMetadata)
		if mp.bc.bitcoinManager.HeaderForHash(txnMeta.BitcoinBlockHash) == nil {
			mp._addImmatureBitcoinTransaction(tx, peerID)
			glog.Tracef("TxPool.processTransaction: Adding immature Bitcoin txn: %v", tx)
			return nil, nil
		}
	}

	// Potentially accept the transaction to the memory pool.
	missingParents, txD, err := mp.maybeAcceptTransaction(tx, rateLimit, true, verifySignatures)
	if err != nil {
		return nil, err
	}

	if len(missingParents) == 0 {
		// Accept any orphan transactions that depend on this
		// transaction (they may no longer be orphans if all inputs
		// are now available) and repeat for those accepted
		// transactions until there are no more.
		newTxs := mp.processOrphans(tx, rateLimit, verifySignatures)
		acceptedTxs := make([]*TxDesc, len(newTxs)+1)

		// Add the parent transaction first so remote nodes
		// do not add orphans.
		acceptedTxs[0] = txD
		copy(acceptedTxs[1:], newTxs)

		// Whenever transactions are accepted into the mempool, add a mapping
		// for each public key that they send an output to. This is useful so
		// we can find all of these outputs if, for example, the user wants
		// to know her balance while factoring in mempool transactions.
		for _, txnAccepted := range acceptedTxs {
			mp._addTxDescToPubKeyOutputMap(txnAccepted)
		}

		return acceptedTxs, nil
	}

	// The transaction is an orphan (has inputs missing). Reject
	// it if the flag to allow orphans is not set.
	if !allowOrphan {
		return nil, TxErrorOrphanNotAllowed
	}

	// Potentially add the orphan transaction to the orphan pool.
	err = mp.maybeAddOrphan(tx, peerID)
	return nil, err
}

// ProcessTransaction is the main workhorse for handling insertion of new
// free-standing transactions into the memory pool. It includes functionality
// such as rejecting duplicate transactions, ensuring transactions follow all
// rules, orphan transaction handling, and insertion into the memory pool.
//
// It returns a slice of transactions added to the mempool. When the
// error is nil, the list will include the passed transaction itself along
// with any additional orphan transaactions that were added as a result of
// the passed one being accepted.
//
// This function is safe for concurrent access.
func (mp *TxPool) ProcessTransaction(tx *MsgUltranetTxn, allowOrphan bool, rateLimit bool, peerID uint64, verifySignatures bool) ([]*TxDesc, error) {
	// Protect concurrent access.
	mp.mtx.Lock()
	defer mp.mtx.Unlock()

	return mp.processTransaction(tx, allowOrphan, rateLimit, peerID, verifySignatures)
}

// Count returns the number of transactions in the main pool. It does not
// include the orphan pool.
//
// This function is safe for concurrent access.
func (mp *TxPool) Count() int {
	mp.mtx.RLock()
	count := len(mp.poolMap)
	mp.mtx.RUnlock()

	return count
}

// TxHashes returns a slice of hashes for all of the transactions in the memory
// pool.
//
// This function is safe for concurrent access.
func (mp *TxPool) TxHashes() []*BlockHash {
	mp.mtx.RLock()
	hashes := make([]*BlockHash, len(mp.poolMap))
	ii := 0
	for hash := range mp.poolMap {
		hashCopy := hash
		hashes[ii] = &hashCopy
		ii++
	}
	mp.mtx.RUnlock()

	return hashes
}

// TxDescs returns a slice of descriptors for all the transactions in the pool.
// The descriptors are to be treated as read only.
//
// This function is safe for concurrent access.
func (mp *TxPool) TxDescs() []*TxDesc {
	mp.mtx.RLock()
	descs := make([]*TxDesc, len(mp.poolMap))
	i := 0
	for _, desc := range mp.poolMap {
		descs[i] = desc
		i++
	}
	mp.mtx.RUnlock()

	return descs
}

// LastUpdated returns the last time a transaction was added to or removed from
// the main pool. It does not include the orphan pool.
//
// This function is safe for concurrent access.
func (mp *TxPool) LastUpdated() time.Time {
	return time.Unix(atomic.LoadInt64(&mp.lastUpdated), 0)
}

// NewTxPool returns a new memory pool for validating and storing standalone
// transactions until they are mined into a block.
func NewTxPool(_bc *Blockchain, _rateLimitFeerateNanosPerKB uint64, _minFeerateNanosPerKB uint64) *TxPool {
	newPool := &TxPool{
		bc:                         _bc,
		rateLimitFeeRateNanosPerKB: _rateLimitFeerateNanosPerKB,
		minFeeRateNanosPerKB:       _minFeerateNanosPerKB,
		poolMap:                    make(map[BlockHash]*TxDesc),
		orphans:                    make(map[BlockHash]*OrphanTx),
		orphansByPrev:              make(map[UtxoKey]map[BlockHash]*MsgUltranetTxn),
		nextExpireScan:             time.Now().Add(orphanExpireScanInterval),
		outpoints:                  make(map[UtxoKey]*MsgUltranetTxn),
		outputPubKeyToTxnMap:       make(map[PkMapKey]map[BlockHash]*TxDesc),
		txnsByMetadataID:           make(map[BlockHash]map[BlockHash]*TxDesc),
		immatureBitcoinTxns:        make(map[BlockHash]*OrphanTx),
	}

	return newPool
}
