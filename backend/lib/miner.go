package lib

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"math/big"
	"math/rand"
	"reflect"
	"sort"
	"sync/atomic"
	"time"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/wire"
	"github.com/davecgh/go-spew/spew"
	"github.com/golang/glog"
	merkletree "github.com/laser/go-merkle-tree"
	"github.com/pkg/errors"
	"golang.org/x/crypto/scrypt"
	"golang.org/x/crypto/sha3"
)

// miner.go contains all of the logic for mining blocks with a CPU.

// UltranetMiner ...
type UltranetMiner struct {
	publicKeys     []*btcec.PublicKey
	numThreads     uint32
	mempool        *TxPool
	chain          *Blockchain
	bitcoinManager *BitcoinManager
	params         *UltranetParams

	stopping int32
}

// NewUltranetMiner ...
func NewUltranetMiner(_minerPublicKeys []string, _numThreads uint32, _mempool *TxPool,
	_chain *Blockchain, _bitcoinManager *BitcoinManager, _params *UltranetParams) (*UltranetMiner, error) {

	// Convert the public keys from Base58Check encoding to bytes.
	_pubKeys := []*btcec.PublicKey{}
	for _, publicKeyBase58 := range _minerPublicKeys {
		pkBytes, _, err := Base58CheckDecode(publicKeyBase58)
		if err != nil {
			return nil, errors.Wrapf(err, "NewUltranetMiner: ")
		}
		pkObj, err := btcec.ParsePubKey(pkBytes, btcec.S256())
		if err != nil {
			return nil, errors.Wrapf(err, "NewUltranetMiner: ")
		}
		_pubKeys = append(_pubKeys, pkObj)
	}

	return &UltranetMiner{
		publicKeys:     _pubKeys,
		numThreads:     _numThreads,
		mempool:        _mempool,
		chain:          _chain,
		bitcoinManager: _bitcoinManager,
		params:         _params,
	}, nil
}

type txBundle struct {
	txns     []*TxDesc
	feePerKB uint64
}

// Stop ...
func (ultranetMiner *UltranetMiner) Stop() {
	atomic.AddInt32(&ultranetMiner.stopping, 1)
}

func (ultranetMiner *UltranetMiner) _updateBlockTimestamp(blk *MsgUltranetBlock, lastNode *BlockNode) {
	// Set the block's timestamp. If the timesource's time happens to be before
	// the timestamp set in the last block then set the time based on the last
	// block's timestamp instead. We do this because consensus rules require a
	// monotonically increasing timestamp.
	blockTstamp := uint32(ultranetMiner.chain.timeSource.AdjustedTime().Unix())
	if blockTstamp <= lastNode.Header.TstampSecs {
		blockTstamp = lastNode.Header.TstampSecs + 1
	}
	blk.Header.TstampSecs = blockTstamp
}

func (ultranetMiner *UltranetMiner) _getBlockToMine(threadIndex uint32) (_blk *MsgUltranetBlock, _diffTarget *BlockHash, _lastNode *BlockNode, _err error) {
	// Lock the blockchain and the mempool for the duration of this function so
	// things don't shift under our feet while we do things. Note the locks must
	// always be acquired in this order.
	ultranetMiner.chain.ChainLock.RLock()
	defer ultranetMiner.chain.ChainLock.RUnlock()
	ultranetMiner.mempool.mtx.RLock()
	defer ultranetMiner.mempool.mtx.RUnlock()

	// Get the current tip of the best block chain. Note that using the tip of the
	// best block chain as opposed to the best header chain means we'll be mining
	// stale blocks until we're fully synced. This isn't ideal, but is currently
	// preferred to mining atop the best header chain because the latter currently results
	// in the blocks being rejected as orphans before the block tip is in-sync.
	lastNode := ultranetMiner.chain.blockTip()

	// Compute an extraNonce to set in the block reward in order to make each
	// thread mine a different part of the hash space.
	extraNonce, err := wire.RandomUint64()
	if err != nil {
		glog.Warningf("UltranetMiner._getBlockToMine: Error generating random extraNonce using "+
			"wire.RandomUint64; falling back to rand.Uint64: (%v)", err)
		rand.Seed(time.Now().UnixNano())
		extraNonce = rand.Uint64()
		// Reset the seed to its default value in case anything down the line wants
		// deterministic behavior by default.
		rand.Seed(1)
	}

	// Choose a random address to contribute the coins to. Use the extraNonce to
	// choose the random address since it's random.
	var rewardPk *btcec.PublicKey
	if len(ultranetMiner.publicKeys) == 0 {
		// This is to account for a really weird edge case where somebody stops the miner
		// in the middle of us getting a block.
		rewardPk = nil
	} else {
		pkIndex := int(extraNonce % uint64(len(ultranetMiner.publicKeys)))
		rewardPk = ultranetMiner.publicKeys[pkIndex]
	}

	// Compute the merchant merkle root at the point in time just before this
	// new block we're about to mine.
	var merchantMerkleRoot *BlockHash
	{
		utxoView, err := NewUtxoView(
			ultranetMiner.chain.db, ultranetMiner.params, ultranetMiner.bitcoinManager)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("UltranetMiner._getBlockToMine: Problem " +
				"initializing new UtxoView")
		}
		merchantMerkleRoot, err = utxoView._computeMerchantMerkleRoot()
		if err != nil {
			return nil, nil, nil, fmt.Errorf("UltranetMiner._getBlockToMine: Problem " +
				"computing merchant merkle root")
		}
	}

	// Construct the next block.
	blockRewardOutput := &UltranetOutput{}
	if rewardPk != nil {
		// This is to account for a really weird edge case where somebody stops the miner
		// in the middle of us getting a block.
		blockRewardOutput.PublicKey = rewardPk.SerializeCompressed()
	}
	// Set the block reward output initially to the maximum value for a uint64.
	// This ensures it will take the maximum amount of space in the block so our
	// size estimates won't get messed up.
	blockRewardOutput.AmountNanos = math.MaxUint64

	// Block reward txn only needs a single output. No need to specify spending
	// pk or sigs.
	blockRewardTxn := NewMessage(MsgTypeTxn).(*MsgUltranetTxn)
	blockRewardTxn.TxOutputs = append(blockRewardTxn.TxOutputs, blockRewardOutput)
	// Set the ExtraData to a random 64-bit extra nonce just so that multiple
	// threads on this machine (and clients running all over the world) don't
	// compute over the same 32-bit nonce-space (note the public key would
	// probably provide sufficient randomness if the nonce were longer, but at
	// 32 bits it can easily exhausted by one machine).
	blockRewardTxn.TxnMeta = &BlockRewardMetadataa{
		MerchantMerkleRoot: merchantMerkleRoot,
		ExtraData:          UintToBuf(extraNonce),
	}

	// Create the block and add the BlockReward txn to it.
	blockRet := NewMessage(MsgTypeBlock).(*MsgUltranetBlock)
	blockRet.Txns = append(blockRet.Txns, blockRewardTxn)
	blockRet.Header.Height = lastNode.Height + 1
	blockRet.Header.PrevBlockHash = lastNode.Hash
	ultranetMiner._updateBlockTimestamp(blockRet, lastNode)
	// Start the nonce at zero. This is fine since each thread will have a block
	// with extraNonce set to a random value.
	blockRet.Header.Nonce = 0

	// Only add transactions to the block if our chain is done syncing.
	totalFeeNanos := uint64(0)
	if ultranetMiner.chain.chainState() != SyncStateSyncingHeaders &&
		ultranetMiner.chain.chainState() != SyncStateNeedBlocksss {

		// Fetch a bunch of mempool transactions to add. Lock the mempool for the rest of
		// this function so things don't shift under our feet as we get these.
		txnsOrderedByTimeAdded, _, err := ultranetMiner.mempool._getTransactionsOrderedByTimeAdded()
		if err != nil {
			return nil, nil, nil, errors.Wrapf(err, "UltranetMiner._getBlockToMine: Problem getting mempool transactions: ")
		}
		// Iterate through the transactions fetched and bundle each one with its
		// dependencies. Also compute the average fee rate for the bundle as a
		// whole.
		txnsWithDependencies := []*txBundle{}
		for _, txD := range txnsOrderedByTimeAdded {
			mempoolDependencies, err := ultranetMiner.mempool._findMempoolDependencies(txD.Tx, txD.Added)
			if err != nil {
				return nil, nil, nil, errors.Wrapf(err, "UltranetMiner._getBlockToMine: Problem getting dependencies for txn: ")
			}

			totalFeeNanos := txD.Fee
			totalSizeBytes := txD.TxSizeBytes
			for _, depTxD := range mempoolDependencies {
				totalFeeNanos += depTxD.Fee
				totalSizeBytes += depTxD.TxSizeBytes
			}

			txnsWithDependencies = append(txnsWithDependencies, &txBundle{
				// Put the transaction at the end so that it will be applied after the
				// dependencies..
				txns:     append(mempoolDependencies, txD),
				feePerKB: totalFeeNanos * 1000 / totalSizeBytes,
			})
		}

		// Sort the bundles by their feerate such that the highest-fee bundle is at
		// the beginning of the list.
		sort.Slice(txnsWithDependencies, func(ii, jj int) bool {
			return txnsWithDependencies[ii].feePerKB > txnsWithDependencies[jj].feePerKB
		})

		// Now that the transaction bundles are sorted according to their feerate, keep
		// adding transactions to the block until the block is full.
		//
		// Compute the size of the header and then add the number of bytes used to encode
		// the number of transactions in the block. Note that headers have a fixed size.
		//
		// TODO: The code below is lazily-written and could be optimized to squeeze a few
		// more bytes into each block.
		//
		// Track the total size of the block as we go. Since the number of transactions
		// encoded in the block can become larger as we add transactions to it, add the
		// maximum size for this field to the current size to ensure we don't overfill
		// the block.
		blockBytes, err := blockRet.ToBytes(false)
		if err != nil {
			return nil, nil, nil, errors.Wrapf(err, "UltranetMiner._getBlockToMine: Problem serializing block: ")
		}
		currentBlockSize := uint64(len(blockBytes) + MaxVarintLen64)
		// Add transactions to a temporary pool to double-check their validity. No
		// need to set the min fees since this is just being used for validation.
		temporaryMempool := NewTxPool(ultranetMiner.mempool.bc, 0 /* rateLimitFeeRateNanosPerKB */, 0 /* minFeeRateNanosPerKB */)
		// Iterate until we either run out of transactions to add or we hit the block size
		// limit.
		for _, bundleOfTxns := range txnsWithDependencies {
			for _, txnInBundle := range bundleOfTxns.txns {
				// If this transaction would put us over the maximum block size,
				// then don't consider it.
				if txnInBundle.TxSizeBytes+currentBlockSize > ultranetMiner.params.MinerMaxBlockSizeBytes {
					continue
				}

				// If this transaction is a BitcoinExchange transaction without enough work
				// behind it, don't add it to the block as it will cause the block to be
				// rejected. Note that we buffer the BitcoinMinBurnWorkBlocks a bit because
				// doing so makes it so that even Peers with timestamps that are significantly
				// behind ours will accept this transaction and its corresponding block.
				if txnInBundle.Tx.TxnMeta.GetTxnType() == TxnTypeBitcoinExchange {
					// If our BitcoinManager is nil or if it's not time-current, don't process
					// BitcoinExchange transactions.
					if ultranetMiner.bitcoinManager == nil ||
						!ultranetMiner.bitcoinManager.IsCurrent(false /*considerCumWork*/) {

						//glog.Tracef("UltranetMiner._getBlockToMine: Not accepting txn yet because "+
						//"BitcoinManager is not time-current:  %v %v", txnInBundle.Tx, ultranetMiner.bitcoinManager)
						continue
					}

					txnMeta := txnInBundle.Tx.TxnMeta.(*BitcoinExchangeMetadata)
					bitcoinHeaderNode := ultranetMiner.bitcoinManager.HeaderForHash(txnMeta.BitcoinBlockHash)
					bitcoinBurnWorkBlocks :=
						ultranetMiner.bitcoinManager.GetBitcoinBurnWorkBlocks(bitcoinHeaderNode.Height)
					if bitcoinBurnWorkBlocks < int64(ultranetMiner.params.BitcoinMinBurnWorkBlocks+3) {
						//glog.Tracef("UltranetMiner._getBlockToMine: Not accepting txn yet because "+
						//"txn does not have enough work: %d but needs %d: %v",
						//bitcoinBurnWorkBlocks, ultranetMiner.params.BitcoinMinBurnWorkBlocks+3,
						//txnInBundle.Tx)
						continue
					}
				}

				// See if this transaction can be added to our mempool. If not, just
				// continue. Note this should implicitly weed out duplicates and double-spends
				// if there are any. Note there is no need to verify signatures since this transaction
				// came from the mempool, which should have already verified them.
				allowOrphan := false
				rateLimit := false
				peerID := uint64(0)
				verifySignatures := false
				_, err := temporaryMempool.processTransaction(txnInBundle.Tx, allowOrphan, rateLimit, peerID, verifySignatures)
				if err != nil {
					// If we had a problem adding this transaction, just continue since we
					// should have plenty of transactions to substitute for it.
					//
					// Note: We should see a lot of duplicate transaction errors since we
					// bundle transactions with their dependencies and these bundles could
					// include duplicates.

					//glog.Tracef("UltranetMiner._getBlockToMine: Error processing transaction: %v: %v", err, txnInBundle.Tx)
					continue
				}

				// If we get here, it means the block has room for the transaction and we
				// were able to add the transaction to the temporary mempool. So add the
				// transaction to the block and increase the block size accordingly.
				//
				// We add MaxVarintLen64 because the number of bytes in the transaction has
				// to be encoded on the wire when we serialize the block.
				currentBlockSize += txnInBundle.TxSizeBytes + MaxVarintLen64
				blockRet.Txns = append(blockRet.Txns, txnInBundle.Tx)
				// Add the fee to the block reward output as we go. Note this has some risk of
				// increasing the size of the block by one byte, but it seems like this is an
				// extreme edge case that goes away as soon as the function is called again.
				totalFeeNanos += txnInBundle.Fee
			}
		}

		// Double-check that the final block size is below the limit.
		blockBytes, err = blockRet.ToBytes(false)
		if err != nil {
			return nil, nil, nil, errors.Wrapf(err, "UltranetMiner._getBlockToMine: Problem serializing block after txns added: ")
		}
		if uint64(len(blockBytes)) > ultranetMiner.params.MinerMaxBlockSizeBytes {
			return nil, nil, nil, fmt.Errorf("UltranetMiner._getBlockToMine: Block created with size "+
				"(%d) exceeds MinerMaxBlockSizeBytes (%d): ", len(blockBytes), ultranetMiner.params.MinerMaxBlockSizeBytes)
		}
	}

	// Now that the total fees have been computed, set the value of the block reward
	// output.
	blockRewardOutput.AmountNanos = CalcBlockRewardNanos(blockRet.Header.Height) + totalFeeNanos

	// Compute the merkle root for the block now that all of the transactions have
	// been added.
	merkleRoot, _, err := ComputeMerkleRoot(blockRet.Txns)
	if err != nil {
		return nil, nil, nil, errors.Wrapf(err, "UltranetMiner._getBlockToMine: Problem computing merkle root: ")
	}
	blockRet.Header.TransactionMerkleRoot = merkleRoot

	// Compute the next difficulty target given the current tip.
	diffTarget, err := CalcNextDifficultyTarget(lastNode, ultranetMiner.params)
	if err != nil {
		return nil, nil, nil, errors.Wrapf(err, "UltranetMiner._getBlockToMine: Problem computing next difficulty: ")
	}

	return blockRet, diffTarget, lastNode, nil
}

func (ultranetMiner *UltranetMiner) _mineSingleBlock(threadIndex uint32) (_lastNode *BlockNode, _diffTarget *BlockHash, minedBlock *MsgUltranetBlock) {
	for {
		// This provides a way for outside processes to pause the miner.
		if len(ultranetMiner.publicKeys) == 0 {
			if atomic.LoadInt32(&ultranetMiner.stopping) == 1 {
				glog.Debugf("UltranetMiner._startThread: Stopping thread %d", threadIndex)
				break
			}
			time.Sleep(1 * time.Second)
			continue
		}

		blockToMine, diffTarget, lastNode, err := ultranetMiner._getBlockToMine(threadIndex)
		if err != nil {
			glog.Error(err)
			sleepSeconds := 60
			glog.Errorf("UltranetMiner._startThread: Sleeping for %d seconds because of error in _getBlockToMine", sleepSeconds)
			// If we can't assemble the block, sleep a bit and try again to see if the
			// problem goes away.j
			time.Sleep(time.Duration(sleepSeconds) * time.Second)
			continue
		}

		// See comment in _getBlockToMine for why we use the block tip here rather
		// than the header tip.
		if lastNode != ultranetMiner.chain.blockTip() {
			glog.Tracef("UltranetMiner._startThread: Not mining block because lastNode != blockTip")
			continue
		}

		ultranetMiner._updateBlockTimestamp(blockToMine, lastNode)
		// Compute a few hashes before checking if we've solved the block.
		timeBefore := time.Now()
		bestHash, bestNonce, err := FindLowestHash(blockToMine.Header,
			ultranetMiner.params.MiningIterationsPerCycle)
		glog.Tracef("UltranetMiner._startThread: Time per iteration: %v", time.Now().Sub(timeBefore))
		if err != nil {
			// If there's an error just log it and break out.
			glog.Error(errors.Wrapf(err, "UltranetMiner._startThread: Problem while mining: "))
			break
		}

		if atomic.LoadInt32(&ultranetMiner.stopping) == 1 {
			glog.Debugf("UltranetMiner._startThread: Stopping thread %d", threadIndex)
			break
		}

		if LessThan(diffTarget, bestHash) {
			//glog.Tracef("UltranetMiner._startThread: Best hash found %v does not beat target %v",
			//hex.EncodeToString(bestHash[:]), hex.EncodeToString(diffTarget[:]))
			continue
		}

		// If we get here then it means our bestHash has beaten the target and
		// that bestNonce is the nonce that generates the solution hash.

		// Set the winning nonce on the block's header.
		blockToMine.Header.Nonce = bestNonce

		return lastNode, diffTarget, blockToMine
	}

	return nil, nil, nil
}

func (ultranetMiner *UltranetMiner) _mineAndProcessSingleBlock(threadIndex uint32) (_block *MsgUltranetBlock, _err error) {
	lastNode, diffTarget, blockToMine := ultranetMiner._mineSingleBlock(threadIndex)
	if blockToMine == nil {
		return nil, fmt.Errorf("UltranetMiner._startThread: _mineSingleBlock returned nil; should only happen if we're stopping")
	}

	// Log information on the block we just mined.
	secsElapsed := blockToMine.Header.TstampSecs - lastNode.Header.TstampSecs
	bestHash, _ := blockToMine.Hash()
	glog.Infof("================== YOU MINED A NEW BLOCK! ================== Height: %d, Hash: %s", blockToMine.Header.Height, hex.EncodeToString(bestHash[:]))
	glog.Debugf("Height: (%d), Secs elapsed: (%d), Diff target: (%s), "+
		"New hash: (%s), , Header Tip: %v, Block Tip: %v", blockToMine.Header.Height,
		secsElapsed,
		hex.EncodeToString(diffTarget[:])[:10], hex.EncodeToString(bestHash[:]),
		ultranetMiner.chain.headerTip().Header,
		ultranetMiner.chain.blockTip().Header)
	scs := spew.ConfigState{DisableMethods: true, Indent: "  ", DisablePointerAddresses: true}
	glog.Debugf(scs.Sdump(blockToMine))
	// Sanitize the block for the comparison we're about to do. We need to do
	// this because the comparison function below will think they're different
	// if one has nil and one has an empty list. Annoying, but this solves the
	// issue.
	for _, tx := range blockToMine.Txns {
		if len(tx.TxInputs) == 0 {
			tx.TxInputs = nil
		}
	}
	blockBytes, err := blockToMine.ToBytes(false)
	if err != nil {
		glog.Error(err)
		return nil, err
	}
	glog.Debugf("Block bytes hex %d: %s", blockToMine.Header.Height, hex.EncodeToString(blockBytes))
	blockFromBytes := &MsgUltranetBlock{}
	err = blockFromBytes.FromBytes(blockBytes)
	if err != nil || !reflect.DeepEqual(*blockToMine, *blockFromBytes) {
		glog.Error(err)
		fmt.Println("Block as it was mined: ", *blockToMine)
		scs.Dump(blockToMine)
		fmt.Println("Block as it was de-serialized:", *blockFromBytes)
		scs.Dump(blockFromBytes)
		glog.Debugf("In case you missed the hex %d: %s", blockToMine.Header.Height, hex.EncodeToString(blockBytes))
		glog.Errorf("UltranetMiner._mineAndProcessSingleBlock: ERROR: Problem with block "+
			"serialization (see above for dumps of blocks): Diff: %v, err?: %v", Diff(blockToMine, blockFromBytes), err)
	}
	glog.Tracef("Mined block height:num_txns: %d:%d\n", blockToMine.Header.Height, len(blockToMine.Txns))

	// Process the block. If the block is connected and/or accepted, the Server
	// will be informed about it. This will cause it to be relayed appropriately.
	verifySignatures := true
	isMainChain, isOrphan, err := ultranetMiner.chain.ProcessBlock(blockToMine, verifySignatures)
	glog.Tracef("Called ProcessBlock: isMainChain=(%v), isOrphan=(%v), err=(%v)",
		isMainChain, isOrphan, err)
	if err != nil {
		glog.Errorf("ERROR calling ProcessBlock: isMainChain=(%v), isOrphan=(%v), err=(%v)",
			isMainChain, isOrphan, err)
		// We return the block even when we have an error in case the caller wants to do
		// something with it.
		return blockToMine, fmt.Errorf("ERROR calling ProcessBlock: isMainChain=(%v), isOrphan=(%v), err=(%v)",
			isMainChain, isOrphan, err)
	}

	decimalPlaces := int64(1000)
	diffTargetBaseline, _ := hex.DecodeString(ultranetMiner.params.MinDifficultyTargetHex)
	diffTargetBaselineBlockHash := BlockHash{}
	copy(diffTargetBaselineBlockHash[:], diffTargetBaseline)
	diffTargetBaselineBigint := big.NewInt(0).Mul(HashToBigint(&diffTargetBaselineBlockHash), big.NewInt(decimalPlaces))
	diffTargetBigint := HashToBigint(diffTarget)
	glog.Debugf("Difficulty factor (1 = 1 core running): %v", float32(big.NewInt(0).Div(diffTargetBaselineBigint, diffTargetBigint).Int64())/float32(decimalPlaces))

	if atomic.LoadInt32(&ultranetMiner.stopping) == 1 {
		return nil, fmt.Errorf("UltranetMiner._startThread: Stopping thread %d", threadIndex)
	}

	return blockToMine, nil
}

func (ultranetMiner *UltranetMiner) _startThread(threadIndex uint32) {
	for {
		// If we have a bitcoinManager set, wait for it to become time-current before
		// producing blocks. We don't wait for it to become work-current because worst-case
		// the BitcoinManager will reset its underlying chain, causing us to produce
		// stale blocks for a bit.
		if ultranetMiner.bitcoinManager != nil && !ultranetMiner.bitcoinManager.IsCurrent(false /*considerCumWork*/) {
			time.Sleep(1 * time.Second)
			continue
		}
		newBlock, err := ultranetMiner._mineAndProcessSingleBlock(threadIndex)
		if err != nil {
			glog.Errorf(err.Error())
		}
		isFinished := (newBlock == nil)
		if isFinished {
			return
		}
	}
}

// Start ...
func (ultranetMiner *UltranetMiner) Start() {
	glog.Infof("UltranetMiner.Start: Starting miner with difficulty target %s", ultranetMiner.params.MinDifficultyTargetHex)
	blockTip := ultranetMiner.chain.BlockTip()
	glog.Infof("UltranetMiner.Start: Block tip height %d and cum work %v",
		blockTip.Header.Height, BigintToHash(blockTip.CumWork))
	// Start a bunch of threads to mine for blocks.
	for threadIndex := uint32(0); threadIndex < ultranetMiner.numThreads; threadIndex++ {
		go func(threadIndex uint32) {
			glog.Debugf("UltranetMiner.Start: Starting thread %d", threadIndex)
			ultranetMiner._startThread(threadIndex)
		}(threadIndex)
	}
}

// CopyBytesIntoBlockHash ...
func CopyBytesIntoBlockHash(data []byte) *BlockHash {
	if len(data) != HashSizeBytes {
		errorStr := fmt.Sprintf("CopyBytesIntoBlockHash: Got data of size %d for BlockHash of size %d", len(data), HashSizeBytes)
		glog.Error(errorStr)
		return nil
	}
	var blockHash BlockHash
	copy(blockHash[:], data)
	return &blockHash
}

// ProofOfWorkHash is a hash function designed for computing Ultranet block hashes. My
// initial bias with this was to keep things simple and just use sha256x2. But I worried
// doing something like that would open us up to the risk that someone who has a large
// pre-existing investment Bitcoin mining hardware could spike the difficulty and disrupt
// the network (similar to what has happened occasionally to merge mined coins like
// namecoin). So I decided to make it a little more unique to mitigate this risk. Note
// that this is not the same thing as being concerned about a 51% attack, which I don't
// think is a big deal because miners are generally aligned to keep the network healthy.
// Rather, it is more like avoiding a 100x attack, where someone with vastly more resources
// mines on the network temporarily to cause trouble.
func ProofOfWorkHash(inputBytes []byte) *BlockHash {
	// The hash function below uses scrypt, sha256, and sha3 in combination. The goal is
	// to spend an equal amount of time in each of these functions so that if one of them
	// is compromised by an ASIC miner, the minimal amount of asymmetry occurs between the
	// ASIC and the remaining CPU miners. After doing some tests, I found that my CPU runs
	// the three hash functions in the following ratios:
	// - 1 scrypt iteration = 27 sha3 iterations = 160 sha256 iterations
	// As such, we start with a single scrypt iteration and then run sha256 160 times,
	// interleaving a sha3 iteration right before every sixth sha256 iteration, which
	// means we wind up running sha3 27 times.
	scryptHash1, _ := scrypt.Key(
		inputBytes, []byte("sarahc0nn0r"), 2, 8, 1, 32)

	output := BlockHash{}
	copy(output[:], scryptHash1[:])
	for ii := 0; ii < 160; ii++ {
		if ii%6 == 0 {
			output = sha3.Sum256(output[:])
		}
		output = sha256.Sum256(output[:])
	}
	return &output
}

// Sha256DoubleHash ...
func Sha256DoubleHash(input []byte) *BlockHash {
	hashBytes := merkletree.Sha256DoubleHash(input)
	ret := &BlockHash{}
	copy(ret[:], hashBytes[:])
	return ret
}

// HashToBigint ...
func HashToBigint(hash *BlockHash) *big.Int {
	// No need to check errors since the string is necessarily a valid hex
	// string.
	val, itWorked := new(big.Int).SetString(hex.EncodeToString(hash[:]), 16)
	if !itWorked {
		glog.Errorf("Failed in converting []byte (%#v) to bigint.", hash)
	}
	return val
}

// BigintToHash ...
func BigintToHash(bigint *big.Int) *BlockHash {
	hexStr := bigint.Text(16)
	if len(hexStr)%2 != 0 {
		// If we have an odd number of bytes add one to the beginning (remember
		// the bigints are big-endian.
		hexStr = "0" + hexStr
	}
	hexBytes, err := hex.DecodeString(hexStr)
	if err != nil {
		glog.Errorf("Failed in converting bigint (%#v) with hex "+
			"string (%s) to hash.", bigint, hexStr)
	}
	if len(hexBytes) > HashSizeBytes {
		glog.Errorf("BigintToHash: Bigint %v overflows the hash size %d", bigint, HashSizeBytes)
		return nil
	}

	var retBytes BlockHash
	copy(retBytes[HashSizeBytes-len(hexBytes):], hexBytes)
	return &retBytes
}

// BytesToBigint ...
func BytesToBigint(bb []byte) *big.Int {
	val, itWorked := new(big.Int).SetString(hex.EncodeToString(bb), 16)
	if !itWorked {
		glog.Errorf("Failed in converting []byte (%#v) to bigint.", bb)
	}
	return val
}

// BigintToBytes ...
func BigintToBytes(bigint *big.Int) []byte {
	hexStr := bigint.Text(16)
	if len(hexStr)%2 != 0 {
		// If we have an odd number of bytes add one to the beginning (remember
		// the bigints are big-endian.
		hexStr = "0" + hexStr
	}
	hexBytes, err := hex.DecodeString(hexStr)
	if err != nil {
		glog.Errorf("Failed in converting bigint (%#v) with hex "+
			"string (%s) to []byte.", bigint, hexStr)
	}
	return hexBytes
}

// LessThan ...
func LessThan(aa *BlockHash, bb *BlockHash) bool {
	aaBigint := new(big.Int)
	aaBigint.SetBytes(aa[:])
	bbBigint := new(big.Int)
	bbBigint.SetBytes(bb[:])

	return aaBigint.Cmp(bbBigint) < 0
}

// FindLowestHash ...
// Mine for a given number of iterations and return the lowest hash value
// found and its associated nonce. Hashing starts at the value of the Nonce
// set on the blockHeader field when it is passed and increments the value
// of the passed blockHeader field as it iterates. This makes it easy to
// continue a subsequent batch of iterations after we return.
func FindLowestHash(
	blockHeaderr *MsgUltranetHeader, iterations uint32) (
	lowestHash *BlockHash, lowestNonce uint32, ee error) {
	//// Compute a hash of the header with the current nonce value.
	bestNonce := blockHeaderr.Nonce
	bestHash, err := blockHeaderr.Hash()
	if err != nil {
		return nil, 0, err
	}

	for iterations > 0 {
		// Increment the nonce.
		blockHeaderr.Nonce++

		// Compute a new hash.
		currentHash, err := blockHeaderr.Hash()
		if err != nil {
			return nil, 0, err
		}

		// See if it's better than what we currently have
		if LessThan(currentHash, bestHash) {
			bestHash = currentHash
			bestNonce = blockHeaderr.Nonce
		}

		iterations--
	}

	// Increment the nonce one last time since we checked this hash.
	blockHeaderr.Nonce++

	return bestHash, bestNonce, nil
}
