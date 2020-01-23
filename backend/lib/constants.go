package lib

import (
	"encoding/hex"
	"fmt"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/shibukawa/configdir"
)

const (
	// ConfigDirVendorName is the enclosing folder for user data.
	// It's required to created a ConfigDir.
	ConfigDirVendorName = "ultranet"
	// ConfigDirAppName is the folder where we keep user data.
	ConfigDirAppName = "ultranet"
	// UseridLengthBytes is the number of bytes of entropy to use for
	// a userid.
	UseridLengthBytes = 32

	// These constants are used by the DNS seed code to pick a random last
	// seen time.
	SecondsIn3Days int32 = 24 * 60 * 60 * 3
	SecondsIn4Days int32 = 24 * 60 * 60 * 4
)

type NetworkType uint64

const (
	// The different network types. For now we have a mainnet and a testnet.
	// Also create an UNSET value to catch errors.
	NetworkType_UNSET   NetworkType = 0
	NetworkType_MAINNET NetworkType = 1
	NetworkType_TESTNET NetworkType = 2
)

func (nt NetworkType) String() string {
	switch nt {
	case NetworkType_UNSET:
		return "UNSET"
	case NetworkType_MAINNET:
		return "MAINNET"
	case NetworkType_TESTNET:
		return "TESTNET"
	default:
		return fmt.Sprintf("UNRECOGNIZED(%d) - make sure String() is up to date", nt)
	}
}

// UltranetParams defines the full list of possible parameters for the
// Ultranet network.
type UltranetParams struct {
	// The network type (mainnet, testnet, etc).
	NetworkType NetworkType
	// The current protocol version we're running.
	ProtocolVersion uint64
	// The minimum protocol version we'll allow a peer we connect to
	// to have.
	MinProtocolVersion uint64
	// Used as a "vanity plate" to identify different Ultranet
	// clients. Mainly useful in analyzing the network at
	// a meta level, not in the protocol itself.
	UserAgent string
	// The list of DNS seed hosts to use during bootstrapping.
	DNSSeeds []string

	// A list of DNS seed prefixes and suffixes to use during bootstrapping.
	// These prefixes and suffixes will be scanned and all IPs found will be
	// incorporated into the address manager.
	DNSSeedGenerators [][]string

	// BitcoinDNSSeeds is a list of seed hosts to use to bootstrap connections
	// to Bitcoin nodes. We connect to Bitcoin nodes to support the exchange
	// functionality that allows people to buy Ultra with Bitcoin.
	BitcoinDNSSeeds []string

	// The minimum amount of work a Bitcoin chain can have before we consider
	// it valid.
	BitcoinMinChainWorkHex string

	// The default port to connect to bitcoin nodes on.
	BitcoinDefaultPort string

	// The network parameter for Bitcoin messages as defined by the btcd library.
	// Useful for certain function calls we make to this library.
	BitcoinBtcdParams *chaincfg.Params

	// The version of the Bitcoin protocol we use.
	BitcoinProtocolVersion uint32

	BitcoinBlocksPerRetarget uint32

	BitcoinPowLimitBits uint32

	// Testnet only. Ignored if set to zero.
	BitcoinMinDiffReductionTime time.Duration

	BitcoinTargetTimespanSecs      uint32
	BitcoinMinRetargetTimespanSecs uint32
	BitcoinMaxRetargetTimespanSecs uint32

	// The maximum number of seconds in a future a Bitcoin block timestamp is allowed
	// to be before it is rejected.
	BitcoinMaxTstampOffsetSeconds uint64

	// This value is used to determine whether or not the Bitcoin tip is up-to-date.
	// If the Bitcoin tip's timestamp is greater than this value then a node should
	// assume that it needs to download more Bitcoin headers from its peers before it
	// is current.
	BitcoinMaxTipAge time.Duration

	// The time between Bitcoin blocks (=10m normally)
	BitcoinTimeBetweenBlocks time.Duration

	// When someone wants to convert Ultra to Bitcoin, they send Bitcoin to the burn address
	// and then create a transaction on the Ultranet chain referencing the burn from the
	// Bitcoin chain. This variable is the number of blocks that must be mined on top
	// of the initial Bitcoin burn before the corresponding Ultranet transaction can be
	// validated on the Ultranet chain.
	//
	// Note that, in order to make validation consistent across all nodes, even nodes
	// whose Bitcoin tip may be slightly behind, we define a very specific way of
	// computing how much work has been done for a given Bitcoin block. We define this
	// as follows:
	// - Compute the first Bitcoin block that has a timestamp less than MaxTipAge.
	//   Call this block the StalestBitcoinBlock.
	//   * Note that any node that believes itself to be up-to-date will be able to
	//     define a StalestBitcoinBlock that should be consistent with all other nodes
	//     that have a roughly similar timestamp (+/- one block in edge cases due to
	//     the timestamp being off).
	// - Suppose we have a Bitcoin burn transaction that was mined into a block. Define
	//   the work that has been done on this block as:
	//   * BitcoinWork = (StalestBitcoinBlock.Height - BitcoinBurnTransactionBlockHeight)
	//
	// Defining the BitcoinWork in this way ensures that the following holds:
	// - For a given Bitcoin transaction, if a particular node believes its Bitcoin tip
	//   to be up-to-date, then the BitcoinWork it computes for that transaction will be
	//   consistent with all other nodes that believe their Bitcoin tip to be up-to-date
	//   (+/- one block due to the timestamps being slightly off).
	// - Note that if a particular node does *not* believe its
	//   Bitcoin tip to be up-to-date, it will not process any Bitcoin burn transactions
	//   and so it does not matter that it cannot compute a value for BitcoinWork.
	//
	// Note that if we did not define BitcoinWork the way we do above and instead
	// defined it relative to a particular node's Bitcoin tip, for example, then
	// nodes could have vastly different values for BitcoinWork for the same transaction,
	// which would cause them to disagree about which Bitcoin burn transactions
	// are valid and which aren't.
	//
	// Given the above definition for BitcoinWork, miners can assure with near-certainty
	// that a block containing a Bitcoin burn transaction will be accepted by 100% of nodes
	// that are up-to-date as long as they ensure that all of the Bitcoin burn transactions
	// that they mine into their block have (BitcoinWork >= BitcoinMinBurnWorkBlocks + 1). Note that
	// nodes whose Bitcoin tip is not up-to-date will not process blocks until their tip
	// is up-to-date, which means they will also eventually accept this block as well (and
	// will not reject the block before they are up-to-date). Note also that using
	// BitcoinMinBurnWorkBlocks+1 rather than BitcoinMinBurnWorkBlocks is a good idea because it protects
	// against situations where nodes have slightly out-of-sync timestamps. In particular,
	// any node whose timestamp is between:
	// - (minerTstamp - minTimeBetweenBlocks) <= nodeTimestamp <= infinity
	// - where:
	//   * minTimeBetweenBlocks = (
	//       StalestBitcoinBlock.TImestamp - BlockRightBeforeStalestBitcoinBlock.Timestamp)
	//   * Note minTimeBetweenBlocks will be ~10m on average.
	// Will believe an Ultranet block containing a Bitcoin burn transaction to be valid if the
	// Miner computes that
	// - BitcoinWork >= BitcoinMinBurnWorkBlocks+1
	//
	// If the miner wants to ride the edge, she can mine transactions when
	// BitcoinWork >= BitcoinMinBurnWorkBlocks (without hte +1 buffer). However, in this case
	// nodes who have timesatamps within:
	// - nodeTstamp <= minerTstamp - minTimeBetweenBlocks
	// - where minTImeBetweenBlocks is defined as above
	// will initially reject any Ultranet blocks that contain such Bitcoin burn transactions,
	// which puts the block at risk of not being the main chain, particularly if other
	// miners prefer not to build on such blocks due to the risk of rejection.
	BitcoinMinBurnWorkBlocks uint32

	// Because we use the Bitcoin header chain only to process exchanges from
	// BTC to Ultra, we don't need to worry about Bitcoin blocks before a certain
	// point, which is specified by this node. This is basically used to make
	// header download more efficient but it's important to note that if for
	// some reason there becomes a different main chain that is stronger than
	// this one, then we will still switch to that one even with this parameter
	// set such as it is.
	BitcoinStartBlockNode *BlockNode

	// The base58Check-encoded Bitcoin address that users must send Bitcoin to in order
	// to purchase Ultra. Note that, unfortunately, simply using an all-zeros or
	// mostly-all-zeros address or public key doesn't work and, in fact, I found that
	// using almost any address other than this one also doesn't work.
	BitcoinBurnAddress string

	// This is a fee in basis points charged on BitcoinExchange transactions that gets
	// paid to the miners. Basically, if a user burned enough Satoshi to create 100 Ultra,
	// and if the BitcoinExchangeFeeBasisPoints was 1%, then 99 Ultra would be allocated to
	// the user's public key while 1 Ultra would be left as a transaction fee to the miner.
	BitcoinExchangeFeeBasisPoints uint64

	// Port used for network communications among full nodes.
	DefaultSocketPort uint16
	// Port used for the limited JSON API that supports light clients.
	DefaultJSONPort uint16
	// Port used by the web client to browse the Ultranet listings.
	DefaultWebClientPort uint16

	// The amount of time we wait when connecting to a peer.
	DialTimeout time.Duration
	// The amount of time we wait to receive a version message from a peer.
	VersionNegotiationTimeout time.Duration

	// The genesis block to use as the base of our chain.
	GenesisBlock *MsgUltranetBlock
	// The expected hash of the genesis block. Should align with what one
	// would get from actually hashing the provided genesis block.
	GenesisBlockHashHex string
	// How often we target a single block to be generated.
	TimeBetweenBlocks time.Duration
	// How many blocks between difficulty retargets.
	TimeBetweenDifficultyRetargets time.Duration
	// Block hashes, when interpreted as big-endian big integers, must be
	// values less than or equal to the difficulty
	// target. The difficulty target is expressed below as a big-endian
	// big integer and is adjusted every TargetTimePerBlock
	// order to keep blocks generating at consistent intervals.
	MinDifficultyTargetHex string
	// We will reject chains that have less than this amount of total work,
	// expressed as a hexadecimal big-endian bigint. Useful for preventing
	// disk-fill attacks, among other things.
	MinChainWorkHex string

	// This is used for determining whether we are still in initial block download.
	// If our tip is older than this, we continue with IBD.
	MaxTipAge time.Duration

	// Do not allow the difficulty to change by more than a factor of this
	// variable during each adjustment period.
	MaxDifficultyRetargetFactor int64
	// Amount of time one must wait before a block reward can be spent.
	BlockRewardMaturity time.Duration

	// The maximum number of seconds in a future a block timestamp is allowed
	// to be before it is rejected.
	MaxTstampOffsetSeconds uint64

	// The maximum number of bytes that can be allocated to transactions in
	// a block.
	MaxBlockSizeBytes uint64

	// It's useful to set the miner maximum block size to a little lower than the
	// maximum block size in certain cases. For example, on initial launch, setting
	// it significantly lower is a good way to avoid getting hit by spam blocks.
	MinerMaxBlockSizeBytes uint64

	// The number of basis points collected by the Ultranet platform on each
	// order. A basis point is 1/100th of a percent (e.g. 400bps = 4%).
	CommissionBasisPoints uint64
	// This is the number of basis points sent to the person who referred a
	// particular user to the platform whenever that user places an order.
	ReferrerCommissionBasisPoints uint64

	// In order to prevent merchants from conducting exit scams, an order that
	// is in the "confirmed" state will count against a merchant's reputation
	// for some period of time, after which it can be marked as "fulfilled" by
	// the merchant so that it stops hurting her reputation.
	TimeBeforeOrderFulfilled   time.Duration
	BlocksBeforeOrderFulfilled uint32

	// The maximums number of merchants to track and index listings for.
	MaxMerchantsToIndex uint64

	MaxListingsPerMerchant uint32

	MaxMerchantStorageBytes uint64

	MaxListingSizeBytes           uint64
	MaxListingTitleLengthBytes    uint64
	MaxListingBodyLengthBytes     uint64
	MaxListingCategoryLengthBytes uint64

	// Amount of time before the effective value of a merchant's score has
	// halved.
	MerchantScoreHalfLife time.Duration

	// In order to make public keys more human-readable, we convert
	// them to base58. When we do that, we use a prefix that makes
	// the public keys to become more identifiable. For example, all
	// mainnet public keys start with "X" because we do this.
	Base58PrefixPublicKey  [3]byte
	Base58PrefixPrivateKey [3]byte

	// MaxFetchBlocks is the maximum number of blocks that can be fetched from
	// a peer at one time.
	MaxFetchBlocks uint32

	// DefaultPbkdf2Iterations is the default number of pbkdf2 iterations performed when
	// using a password as an encryption key (for example, when encrypting a seed with a
	// user's password).
	DefaultPbkdf2Iterations uint32

	MiningIterationsPerCycle uint32
}

func mustDecodeBase58Check(input string) []byte {
	res, _, err := Base58CheckDecode(input)
	if err != nil {
		log.Fatal(err)
	}
	return res
}

// GenesisBlock defines the genesis block used for the Ultranet maainnet and testnet
var (
	GenesisBlock = MsgUltranetBlock{
		Header: &MsgUltranetHeader{
			Version:               0,
			PrevBlockHash:         &BlockHash{},
			TransactionMerkleRoot: mustDecodeHexBlockHash("9f64cd0f6ccc8ed6ff94308311b539b44a41c53c1b94f1008080b74f5a49fb96"),
			TstampSecs:            uint32(1578837445),
			Height:                uint32(0),
			Nonce:                 uint32(0),
		},
		Txns: []*MsgUltranetTxn{
			&MsgUltranetTxn{
				TxInputs: []*UltranetInput{},
				TxOutputs: []*UltranetOutput{
					&UltranetOutput{
						// The burn address is used within the genesis block as the recipient
						// of the BLOCK_REWARD transaction.
						PublicKey:   mustDecodeBase58Check("UNG4b4NGhrPV1Yz7jpb4i9MJshpXwsdYpFJwDw8U57qyoa52464yio"),
						AmountNanos: 0,
					},
				},
				TxnMeta: &BlockRewardMetadataa{
					MerchantMerkleRoot: &BlockHash{},
					ExtraData:          []byte("They came here, to the new world. World 2.0, version 1776."),
				},
				// A signature is not required for BLOCK_REWARD transactions since they
				// don't spend anything.
			},
		},
	}
	GenesisBlockHashHex = "d6df79e8c52c2e2993bf77f102435260d71d9377f5af963a768131d5b403ccfc"
)

// UltranetMainnetParams defines the Ultranet parameters for the mainnet.
var UltranetMainnetParams = UltranetParams{
	NetworkType:        NetworkType_MAINNET,
	ProtocolVersion:    0,
	MinProtocolVersion: 0,
	UserAgent:          "sarahc0nn0r",
	DNSSeeds: []string{
		"ultranet.coinbase.com",
		"ultranet.gemini.com",
		"ultranet.kraken.com",
		"ultranet.bitstamp.com",
		"ultranet.bitfinex.com",
		"ultranet.binance.com",
		"ultranet.hbg.com",
		"ultranet.okex.com",
		"ultranet.bithumb.com",
		"ultranet.upbit.com",
	},
	DNSSeedGenerators: [][]string{
		[]string{
			"ultranet-seed-",
			".io",
		},
	},

	GenesisBlock:        &GenesisBlock,
	GenesisBlockHashHex: GenesisBlockHashHex,
	// This is used as the starting difficulty for the chain.
	MinDifficultyTargetHex: "000002FFFF000000000000000000000000000000000000000000000000000000",

	// FIXME: Set a reasonable value for min chain work.
	MinChainWorkHex: "00000000000000000000000000000000000000000000000000000001d4bcfb37",

	MaxTipAge: 24 * time.Hour,

	// ===================================================================================
	// Mainnet Bitcoin config
	// ===================================================================================
	BitcoinDNSSeeds: []string{
		"seed.bitcoin.sipa.be",       // Pieter Wuille, only supports x1, x5, x9, and xd
		"dnsseed.bluematt.me",        // Matt Corallo, only supports x9
		"dnsseed.bitcoin.dashjr.org", // Luke Dashjr
		"seed.bitcoinstats.com",      // Christian Decker, supports x1 - xf
		"seed.bitnodes.io",
		"seed.bitcoin.jonasschnelli.ch", // Jonas Schnelli, only supports x1, x5, x9, and xd
		"seed.btc.petertodd.org",        // Peter Todd, only supports x1, x5, x9, and xd
		"seed.bitcoin.sprovoost.nl",     // Sjors Provoost
		"dnsseed.emzy.de",               // Stephan Oeste
	},
	// The MinChainWork value we set below has been adjusted for the BitcoinStartBlockNode we
	// chose. Basically it's the work to get from the start block node we set up to the
	// current tip.
	BitcoinMinChainWorkHex:      "000000000000000000000000000000000000000000198a9bc691ef86f7576e71",
	BitcoinDefaultPort:          "8333",
	BitcoinBtcdParams:           &chaincfg.MainNetParams,
	BitcoinProtocolVersion:      70013,
	BitcoinBlocksPerRetarget:    2016,
	BitcoinPowLimitBits:         0x1d00ffff,
	BitcoinMinDiffReductionTime: 0,

	BitcoinTargetTimespanSecs:      1209600,
	BitcoinMinRetargetTimespanSecs: 1209600 / 4,
	BitcoinMaxRetargetTimespanSecs: 1209600 * 4,
	// Normal Bitcoin clients set this to be 24 hours usually. The reason we diverge here
	// is because we want to decrease the amount of time a user has to wait before Ultranet
	// nodes will be willing to process a BitcoinExchange transaction. Put another way, making
	// this longer would require users to wait longer before their BitcoinExchange transactions
	// are accepted, which is
	// something we want to avoid. On the other hand, if we make this time too short
	// (e.g. <10m as an extreme example), then we might think we're not current when in
	// practice the problem is just that the Bitcoin blockchain took a little longer than
	// usual to generate a block.
	//
	// As such, considering all of the above, the time we use here should be the shortest
	// time that virtually guarantees that a Bitcoin block has been generated during this
	// interval. The longest Bitcoin inter-block arrival time since 2011 was less than two
	// hours but just to be on the safe side, we pad this value a bit and call it a day. In
	// the worst-case if the Bitcoin chain stalls for longer than this, the Ultranet chain will
	// just pause for the same amount of time and jolt back into life once the Bitcoin chain
	// comes back online, which is not the end of the world. In practice, we could also sever
	// the dependence of the Ultranet chain on the Bitcoin chain at some point ahead of time if we
	// expect this will be an issue (remember BitcoinExchange transactions are really only
	// needed to bootstrap the initial supply of Ultra).
	//
	// See this answer for a discussion on Bitcoin block arrival times:
	// - https://www.reddit.com/r/Bitcoin/comments/1vkp1x/what_is_the_longest_time_between_blocks_in_the/
	BitcoinMaxTipAge:         3 * time.Hour,
	BitcoinTimeBetweenBlocks: 10 * time.Minute,
	// As discussed in the original comment for this field, this is actually the minimum
	// number of blocks a burn transaction must have between the block where it was mined
	// and the *StalestBitcoinBlock*, not the tip (where StalestBitcoinBlock is defined
	// in the original comment). As such, if we can presume that the StalestBitcoinBlock is
	// is generally already defined as a block with a fair amount of work built on top of it
	// then the value of BitcoinMinBurnWorkBlocks doesn't need to be very high (in fact we could
	// theoretically make it zero). However, there is a good reason to make it a substantive
	// value and that is that in situations in which the Bitcoin blockchain is producing
	// blocks with a very high time between blocks (for example due to a bad difficulty
	// mismatch), then the StalestBitcoinBlock could actually be pretty close to the Bitcoin
	// tip (it could theoretically actually *be* the tip). As such, to protect ourselves in
	// this case, we demand a solid number of blocks having been mined between the
	// StalestBitcoinTip, which we assume isn't super reliable, and any Bitcoin burn transaction
	// that we are mining into the Ultranet chain.
	BitcoinMinBurnWorkBlocks: uint32(60 * int64(time.Minute) / (10 * int64(time.Minute))),
	BitcoinBurnAddress:       "18TiAVVS51z738NgdueKMXNA9jAdKwbmdF",

	// Reject Bitcoin blocks that are more than two hours in the future.
	BitcoinMaxTstampOffsetSeconds: 2 * 60 * 60,

	// We use a start node that is near the tip of the Bitcoin header chain. Doing
	// this allows us to bootstrap Bitcoin transactions much more quickly without
	// comrpomising on security because, if this node ends up not being on the best
	// chain one day (which would be completely ridiculous anyhow because it would mean that
	// days or months of bitcoin transactions got reverted), our code will still be
	// able to robustly switch to an alternative chain that has more work. It's just
	// much faster if the best chain is the one that has this start node in it (similar
	// to the --assumevalid Bitcoin flag).
	//
	// Process for generating this config:
	// - Find a node config from the test_nodes folder (we used fe0)
	// - Make sure the logging for bitcoin_manager is set to 2. --vmodule="bitcoin_manager=2"
	// - Run the node config (./fe0)
	// - A line should print every time there's a difficulty adjustment with the parameters
	//   required below (including "DiffBits"). Just copy those into the below and
	//   everything should work.
	// - Oh and you might have to set BitcoinMinChainWorkHex to something lower/higher. The
	//   value should equal the amount of work it takes to get from whatever start node you
	//   choose and the tip. This is done by running once, letting it fail, and then rerunning
	//   with the value it outputs.
	BitcoinStartBlockNode: NewBlockNode(
		nil,
		mustDecodeHexBlockHashBitcoin("0000000000000000000657ec7477dece018c07b534be94edfff9aed1068a7613"),
		// Note the height is always one greater than the parent node.
		610848,
		_difficultyBitsToHash(387212786),
		// CumWork shouldn't matter.
		big.NewInt(0),
		// We are bastardizing the Ultranet header to store Bitcoin information here.
		&MsgUltranetHeader{
			TstampSecs: 1577915667,
			Height:     0,
		},
		StatusBitcoinHeaderValidated,
	),
	/*
		BitcoinStartBlockNode: NewBlockNode(
			nil,
			mustDecodeHexBlockHashBitcoin("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"),
			// Note the height is always one greater than the parent node.
			0,
			_difficultyBitsToHash(0x1d00ffff),
			// CumWork shouldn't matter.
			big.NewInt(0),
			// We are bastardizing the Ultranet header to store Bitcoin information here.
			&MsgUltranetHeader{
				Version:        1,
				PrevBlockHash:  &BlockHash{},
				TransactionMerkleRoot: mustDecodeHexBlockHashBitcoin("4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"),
				TstampSecs:     0x495fab29,
				Height:         0,
				Nonce:          0x7c2bac1d,
			},
			StatusBitcoinHeaderValidated,
		),
	*/
	BitcoinExchangeFeeBasisPoints: 10,

	DefaultSocketPort:    uint16(17000),
	DefaultJSONPort:      uint16(17001),
	DefaultWebClientPort: uint16(17002),

	DialTimeout:               5 * time.Second,
	VersionNegotiationTimeout: 5 * time.Second,

	BlockRewardMaturity: time.Hour * 3,

	// Use a ten-minute block time. Although a shorter block time seems like
	// it would improve the user experience, the reality is that zero-confirmation
	// transactions can usually be relied upon to give the user the illusion of
	// instant gratification (particularly since we implement a limited form of
	// RBF that makes it difficult to reverse transactions once they're in the
	// mempool of nodes). Moreover, longer block times mean we require fewer
	// headers to be downloaded by light clients in the long run, which is a
	// big win in terms of performance.
	TimeBetweenBlocks: 10 * time.Minute,
	// We retarget the difficulty every three days. Note this value must
	// ideally be evenly divisible by TimeBetweenBlocks.
	TimeBetweenDifficultyRetargets: 3 * 24 * time.Hour,
	// Difficulty can't decrease to below 50% of its previous value or increase
	// to above 200% of its previous value.
	MaxDifficultyRetargetFactor: 2,
	Base58PrefixPublicKey:       [3]byte{0x9, 0x7f, 0x0},
	Base58PrefixPrivateKey:      [3]byte{0x50, 0xd5, 0x0},

	DefaultPbkdf2Iterations: 100000,

	// 6 months roughly
	MerchantScoreHalfLife: time.Duration(6 * 30 * 24 * time.Hour),

	// Reject blocks that are more than two hours in the future.
	MaxTstampOffsetSeconds: 2 * 60 * 60,

	// We use a max block size of 1MB. This seems to work well for BTC and
	// most of our data doesn't need to be stored on the blockchain anyway.
	MaxBlockSizeBytes: 1000000,

	// We set this to be lower initially to avoid winding up with really big
	// spam blocks in the event someone tries to abuse the initially low min
	// fee rates.
	MinerMaxBlockSizeBytes: 200000,

	// 4% commissions.
	CommissionBasisPoints: 400,
	// 1% goes to the referrer.
	ReferrerCommissionBasisPoints: 100,

	// After two weeks a merchant can mark an order as fulfilled even if the user
	// hasn't reviewed it yet.
	TimeBeforeOrderFulfilled: time.Hour * 24 * 14,

	MaxMerchantsToIndex: 5000,

	// Each merchant gets up to 5MB of storage.
	MaxMerchantStorageBytes: 5 * 1e6,

	// Each listing can be no larger than 500KB.
	MaxListingSizeBytes: 500 * 1e3,

	// Each merchant gets 20 listing slots.
	MaxListingsPerMerchant: 20,

	// Some sanity-checks on lengths of various fields.
	MaxListingTitleLengthBytes:    240,
	MaxListingBodyLengthBytes:     1000,
	MaxListingCategoryLengthBytes: 30,

	// This takes about ten seconds on a reasonable CPU, which makes sense given
	// a 10 minute block time.
	MiningIterationsPerCycle: 95000,
}

func mustDecodeHexBlockHashBitcoin(ss string) *BlockHash {
	hash, err := chainhash.NewHashFromStr(ss)
	if err != nil {
		panic(err)
	}
	return (*BlockHash)(hash)
}

func mustDecodeHexBlockHash(ss string) *BlockHash {
	bb, err := hex.DecodeString(ss)
	if err != nil {
		log.Fatalf("Problem decoding hex string to bytes: (%s): %v", ss, err)
	}
	if len(bb) != 32 {
		log.Fatalf("mustDecodeHexBlockHash: Block hash has length (%d) but should be (%d)", len(bb), 32)
	}
	ret := BlockHash{}
	copy(ret[:], bb)
	return &ret
}

// UltranetTestnetParams defines the Ultranet parameters for the testnet.
var UltranetTestnetParams = UltranetParams{
	NetworkType:        NetworkType_TESTNET,
	ProtocolVersion:    0,
	MinProtocolVersion: 0,
	UserAgent:          "sarahc0nn0r",
	DNSSeeds:           []string{},
	DNSSeedGenerators:  [][]string{},

	// ===================================================================================
	// Testnet Bitcoin config
	// ===================================================================================
	//
	// We use the Bitcoin testnet when we use the Ultranet testnet. Note there's no
	// reason we couldn't use the Bitcoin mainnet with the Ultranet testnet instead,
	// but it seems reasonable to assume someone using the Ultranet testnet would prefer
	// the Bitcoin side be testnet as well.
	BitcoinDNSSeeds: []string{
		"testnet-seed.bitcoin.jonasschnelli.ch",
		"testnet-seed.bitcoin.schildbach.de",
		"seed.tbtc.petertodd.org",
		"testnet-seed.bluematt.me",
		"seed.testnet.bitcoin.sprovoost.nl",
	},
	// See comment in mainnet config.
	// Below we have a ChainWork value that is much lower to accommodate testing situations.
	//
	//BitcoinMinChainWorkHex:      "000000000000000000000000000000000000000000000000000007d007d007d0",
	BitcoinMinChainWorkHex:      "000000000000000000000000000000000000000000000002795d13e8d9f051d2",
	BitcoinDefaultPort:          "18333",
	BitcoinBtcdParams:           &chaincfg.TestNet3Params,
	BitcoinProtocolVersion:      70013,
	BitcoinBlocksPerRetarget:    2016,
	BitcoinPowLimitBits:         0x1d00ffff,
	BitcoinMinDiffReductionTime: time.Minute * 20,

	BitcoinTargetTimespanSecs:      1209600,
	BitcoinMinRetargetTimespanSecs: 1209600 / 4,
	BitcoinMaxRetargetTimespanSecs: 1209600 * 4,

	// See commentary on these values in the Mainnet config above and in the struct
	// definition (also above).
	//
	// Below are some alternative settings for BitcoinMaxTipAge that are useful
	// for testing. They make it so that the chain becomes current really fast,
	// meaning things that block until the Bitcoin chain is current can be tested
	// more easily.
	//
	// Super quick age (does one header download before becoming current)
	//BitcoinMaxTipAge: 65388 * time.Hour,
	// Medium quick age (does a few header downloads before becoming current)
	//BitcoinMaxTipAge: 64888 * time.Hour,
	// TODO: Change back to 3 hours when we launch the testnet. In the meantime this value
	// is more useful for local testing.
	//BitcoinMaxTipAge:              3 * time.Hour,
	BitcoinMaxTipAge:         20 * time.Minute,
	BitcoinTimeBetweenBlocks: 10 * time.Minute,
	// TODO: Change back to 6 blocks when we launch the testnet. In the meantime this value
	// is more useful for local testing.
	//BitcoinMinBurnWorkBlocks:      6, // = 60min / 10min per block
	BitcoinMinBurnWorkBlocks:      1,
	BitcoinBurnAddress:            "mvHnjq11sWjTpMinUeoiyNaLjjtrnPM8ZY",
	BitcoinExchangeFeeBasisPoints: 10,

	// Reject Bitcoin blocks that are more than two hours in the future.
	BitcoinMaxTstampOffsetSeconds: 2 * 60 * 60,

	// See comment in mainnet config.
	BitcoinStartBlockNode: NewBlockNode(
		nil,
		mustDecodeHexBlockHashBitcoin("0000000000000123dfcf9ba40bef0f9db55c4872a11f144fb625ad59df37806a"),
		1636992,
		_difficultyBitsToHash(436349167),

		// CumWork: We set the work of the start node such that, when added to all of the
		// blocks that follow it, it hurdles the min chain work.
		big.NewInt(0),
		// We are bastardizing the Ultranet header to store Bitcoin information here.
		&MsgUltranetHeader{
			TstampSecs: 1577808009,
			Height:     0,
		},
		StatusBitcoinHeaderValidated,
	),
	/*
		// Testnet genesis block node:
		BitcoinStartBlockNode: NewBlockNode(
			nil,
			mustDecodeHexBlockHashBitcoin("000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943"),
			// Note the height is always one greater than the parent node.
			0,
			_difficultyBitsToHash(486604799),
			// CumWork shouldn't matter.
			big.NewInt(0),
			// We are bastardizing the Ultranet header to store Bitcoin information here.
			&MsgUltranetHeader{
				TstampSecs: 0x495fab29,
				Height:     0,
			},
			StatusBitcoinHeaderValidated,
		),
	*/

	// ===================================================================================
	// Testnet socket config
	// ===================================================================================
	DefaultSocketPort:    uint16(18000),
	DefaultJSONPort:      uint16(18001),
	DefaultWebClientPort: uint16(18002),

	DialTimeout:               5 * time.Second,
	VersionNegotiationTimeout: 5 * time.Second,

	GenesisBlock:        &GenesisBlock,
	GenesisBlockHashHex: GenesisBlockHashHex,

	// Use a very fast block time in the testnet.
	TimeBetweenBlocks: 2 * time.Second,
	// Use a very short difficulty retarget period in the testnet.
	TimeBetweenDifficultyRetargets: 6 * time.Second,
	// This is used as the starting difficulty for the chain.
	MinDifficultyTargetHex: "0090000000000000000000000000000000000000000000000000000000000000",
	// Minimum amount of work a valid chain needs to have. Useful for preventing
	// disk-fill attacks, among other things.
	//MinChainWorkHex: "000000000000000000000000000000000000000000000000000000011883b96c",
	// FIXME: Set a reasonable value for min chain work.
	MinChainWorkHex: "0000000000000000000000000000000000000000000000000000000000000000",

	// TODO: Set to one day when we launch the testnet. In the meantime this value
	// is more useful for local testing.
	MaxTipAge: time.Minute * 100,

	// Difficulty can't decrease to below 50% of its previous value or increase
	// to above 200% of its previous value.
	MaxDifficultyRetargetFactor: 2,
	// Miners need to wait a day before spending their block reward.
	// TODO: Make this 24 hours when we launch the testnet. In the meantime this value
	// is more useful for local testing.
	BlockRewardMaturity: time.Second * 4,

	// Reject blocks that are more than two hours in the future.
	MaxTstampOffsetSeconds: 2 * 60 * 60,

	// We use a max block size of 1MB. This seems to work well for BTC and
	// most of our data doesn't need to be stored on the blockchain anyway.
	MaxBlockSizeBytes: 1000000,

	// We set this to be lower initially to avoid winding up with really big
	// spam blocks in the event someone tries to abuse the initially low min
	// fee rates.
	MinerMaxBlockSizeBytes: 200000,

	// 4% commissions.
	CommissionBasisPoints: 400,
	// 1% goes to the referrer.
	ReferrerCommissionBasisPoints: 100,

	// Set to two weeks.
	//TimeBeforeOrderFulfilled: time.Hour * 24 * 14,
	TimeBeforeOrderFulfilled: 1 * time.Minute,

	MaxMerchantsToIndex: 1100,

	// Set this to 5 megabytes.
	MaxMerchantStorageBytes: 5 * 1e6,

	// 500 Kilobyte max for listings.
	MaxListingSizeBytes: 500 * 1e3,
	// Number of listings allowed for a amerchant.
	MaxListingsPerMerchant: 3,
	// 240 characters.
	MaxListingTitleLengthBytes:    240,
	MaxListingBodyLengthBytes:     1000,
	MaxListingCategoryLengthBytes: 30,

	MerchantScoreHalfLife: time.Duration(6 * 30 * 24 * time.Hour),

	Base58PrefixPublicKey:  [3]byte{0x11, 0xdc, 0x4b},
	Base58PrefixPrivateKey: [3]byte{0x4f, 0x81, 0x0},

	// Set pbkdf2 iterations very low in order to make bulk user creation faster.
	DefaultPbkdf2Iterations: 10,

	MiningIterationsPerCycle: 9500,
}

// GetDataDir gets the user data directory where we store files
// in a cross-platform way.
func GetDataDir(params *UltranetParams) string {
	configDirs := configdir.New(
		ConfigDirVendorName, ConfigDirAppName)
	dirString := configDirs.QueryFolders(configdir.Global)[0].Path
	dataDir := filepath.Join(dirString, params.NetworkType.String())
	if err := os.MkdirAll(dataDir, os.ModePerm); err != nil {
		log.Fatalf("GetDataDir: Could not create data directories (%s): %v", dataDir, err)
	}
	return dataDir
}
