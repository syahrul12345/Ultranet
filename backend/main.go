package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"math"
	"math/rand"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"
	"ultranet/backend/lib"

	"github.com/btcsuite/btcd/addrmgr"
	"github.com/btcsuite/btcd/btcd_lib"
	"github.com/btcsuite/btcd/wire"
	"github.com/davecgh/go-spew/spew"
	"github.com/dgraph-io/badger"
	"github.com/gobuffalo/packr"
	"github.com/golang/glog"
	"github.com/pkg/browser"
	"github.com/pkg/errors"
	deadlock "github.com/sasha-s/go-deadlock"
)

var (
	flagUseUltraTestnet = flag.Bool(
		"ultra_testnet", false,
		"Whether or not to use the Ultra testnet. Mainnet is used by default.")
	flagExternalIps = flag.String(
		"externalips", "",
		"A comma-separated list of ip:port addresses that we should listen on. "+
			"These will take priority over addresses discovered by network "+
			"interfaces.")
	flagConnectIps = flag.String(
		"connectips", "",
		"A comma-separated list of ip:port addresses that we should connect to on startup. "+
			"If this argument is specified, we don't connect to any other peers.")
	flagMinerPublicKeys = flag.String(
		"miner_public_keys", "",
		"A miner is started if and only if this field is set. Indicates where to send "+
			"block rewards from mining blocks. Public keys must be "+
			"comma-separated compressed ECDSA public keys formatted as base58 strings.")
	flagNumMiningThreads = flag.Int(
		"num_mining_threads", 0,
		"How many threads to run for mining. Only has an effect when --miner_public_keys "+
			"is set. If set to zero, which is the default, then the number of "+
			"threads available to the system will be used.")
	flagAddIps = flag.String(
		"addips", "",
		"A comma-separated list of ip:port addresses that we should connect to on startup. "+
			"If this argument is specified, we will still fetch addresses from DNS seeds and "+
			"potentially connect to them.")
	flagAddSeeds = flag.String(
		"addseeds", "",
		"A comma-separated list of DNS seeds to be used in addition to the "+
			"pre-configured seeds.")
	flagSharedSecret = flag.String(
		"shared_secret", "",
		"Because some API calls are private, we need a mechanism to ensure that the "+
			"person calling them is authorized to do so. Otherwise, for example, any process running "+
			"locally could theoretically drain a user's account balance by calling a "+
			"spend API call on a full node that is running on the same machine. As such, API "+
			"calls that need to be private require the user calling them to have a shared "+
			"secret with this program that is set by this flag.")
	flagProtocolListenPort = flag.Uint64(
		"protocol_listen_port", 0,
		"When set, determines the port on which this node will listen for protocol-related "+
			"messages. If unset, the port will default to what is present in the UltraParams set. "+
			"Note also that even though the node will listen on this port, its outbount "+
			"connections will not be determined by this flag.")
	flagJSONPort = flag.Int64(
		"json_api_port", 0,
		"When set, determines the port on which this node will listen for json "+
			"requests. If unset, the port will default to what is present in the UltraParams set.")
	flagWebClientPort = flag.Int64(
		"web_client_port", 0,
		"When set, determines the port on which this node will listen for connections "+
			"from the user's web client. If unset, the port will default to what is present "+
			"in the UltraParams set.")
	flagRateLimitFeerateNanosPerKB = flag.Uint64(
		"rate_limit_feerate", 0,
		"Transactions below this feerate will be rate-limited rather than flat-out "+
			"rejected. This is in contrast to min_feerate, which will flat-out reject "+
			"transactions with feerates below what is specified. As such, this value will have no "+
			"effect if it is set below min_feerate. This, along with min_feerate, should "+
			"be the first line of defense against attacks that involve flooding the "+
			"network with low-fee transactions in an attempt to overflow the mempool")
	flagMinFeeRateNanosPerKB = flag.Uint64(
		"min_feerate", 5,
		"The minimum feerate this node will accept when processing transactions "+
			"relayed by peers. Increasing this number, along with increasing "+
			"rate_limit_feerate, should be the first line of "+
			"defense against attacks that involve flooding the network with low-fee "+
			"transactions in an attempt to overflow the mempool")
	flagTargetOutboundPeers = flag.Uint64(
		"target_outbound_peers", 8,
		"The target number of outbound peers. The node will continue attempting to connect to "+
			"random addresses until it has this many outbound connections. During testing it's "+
			"useful to turn this number down and test a small number of nodes in a controlled "+
			"environment.")
	flagMaxInboundPeers = flag.Uint64(
		"max_peers", 125,
		"The maximum number of inbound peers a node can have.")
	flagDataDirPath = flag.String(
		"data_dir_path", "",
		"The location where all of the protocol-related data like blocks is stored. "+
			"Useful for testing situations where multiple clients need to run on the "+
			"same machine without trampling over each other. "+
			"When unset, defaults to the system's configuration directory.")
	flagLimitOneInboundConnectionPerIP = flag.Bool(
		"limit_one_inbound_connection_per_ip", true,
		"When set, the node will not allow more than one connection to/from a particular "+
			"IP. This prevents forms of attack whereby one node tries to monopolize all of "+
			"our connections and potentially make onerous requests as well. Useful to "+
			"disable this flag when testing locally to allow multiple inbound connections "+
			"from test servers")
	flagStallTimeoutSeconds = flag.Uint64(
		"stall_timeout_seconds", 120,
		"How long the node will wait for a peer to reply to certain types of requests.")
	flagPrivateMode = flag.Bool(
		"private_mode", false,
		"When set to true, the node does not look up addresses from DNS seeds.")
)

func _getAddrsToListenOn(protocolPort uint16) ([]net.TCPAddr, []net.Listener) {
	listeningAddrs := []net.TCPAddr{}
	listeners := []net.Listener{}
	ifaceAddrs, err := net.InterfaceAddrs()
	if err != nil {
		glog.Warningf("Failed to get local interface addrs so can't listen to incoming connections: %v", err)
	} else {
		for _, iAddr := range ifaceAddrs {
			ifaceIP, _, err := net.ParseCIDR(iAddr.String())
			if err != nil {
				glog.Warningf("Problem with parsing local addr: %s", iAddr.String())
				continue
			}

			if ifaceIP.IsLinkLocalUnicast() {
				glog.Debugf("Skipping link-local ipv6 addr: %s", iAddr.String())
				continue
			}

			netAddr := net.TCPAddr{
				IP:   ifaceIP,
				Port: int(protocolPort),
			}

			listener, err := net.Listen(netAddr.Network(), netAddr.String())
			if err != nil {
				glog.Warningf("Can't listen on (net, addr, err): (%s, %s, %v)", netAddr.Network(), netAddr.String(), err)
				continue
			}
			glog.Infof("Listening on local interface: %s", netAddr.String())
			listeners = append(listeners, listener)
			listeningAddrs = append(listeningAddrs, netAddr)
		}
	}
	return listeningAddrs, listeners
}

func _checkParams(params *lib.UltranetParams) {
	if params.BitcoinBurnAddress == "" {
		log.Fatalf("The UltraParams being used are missing the BitcoinBurnAddress field.")
	}

	// Check that TimeBetweenDifficultyRetargets is evenly divisible
	// by TimeBetweenBlocks.
	if params.TimeBetweenBlocks == 0 {
		log.Fatalf("The UltraParams being used have TimeBetweenBlocks=0")
	}
	numBlocks := params.TimeBetweenDifficultyRetargets / params.TimeBetweenBlocks
	truncatedTime := params.TimeBetweenBlocks * numBlocks
	if truncatedTime != params.TimeBetweenDifficultyRetargets {
		log.Fatalf("TimeBetweenDifficultyRetargets (%v) should be evenly divisible by "+
			"TimeBetweenBlocks (%v)", params.TimeBetweenDifficultyRetargets,
			params.TimeBetweenBlocks)
	}

	if params.GenesisBlock == nil || params.GenesisBlockHashHex == "" {
		log.Fatalf("The UltraParams are missing genesis block info.")
	}

	sarahsPublicKey := []byte{0x3, 0xf9, 0x38, 0x14, 0xd8, 0x41, 0x34, 0x7b, 0x91, 0x2a, 0x8b, 0xa9, 0x14, 0xe, 0x85, 0x69, 0x63, 0x5c, 0x52, 0xeb, 0xc5, 0x4f, 0x3a, 0x46, 0x22, 0x45, 0xee, 0xf6, 0xca, 0x30, 0xcd, 0xc6, 0xfe}
	if !reflect.DeepEqual(params.GenesisBlock.Txns[0].TxOutputs[0].PublicKey, sarahsPublicKey) {
		log.Fatalf("Sarah's public key in the genesis block was %#v but should "+
			"have been %#v", params.GenesisBlock.Txns[0].TxOutputs[0].PublicKey, sarahsPublicKey)
	}

	// Compute the merkle root for the genesis block and make sure it matches.
	merkle, _, err := lib.ComputeMerkleRoot(params.GenesisBlock.Txns)
	if err != nil {
		log.Fatalf("Could not compute a merkle root for the genesis block: %v", err)
	}
	if *merkle != *params.GenesisBlock.Header.TransactionMerkleRoot {
		log.Fatalf("Genesis block merkle root (%s) not equal to computed merkle root (%s)",
			hex.EncodeToString(params.GenesisBlock.Header.TransactionMerkleRoot[:]),
			hex.EncodeToString(merkle[:]))
	}

	genesisHash, err := params.GenesisBlock.Header.Hash()
	if err != nil {
		log.Fatalf("Problem hashing header for the GenesisBlock in "+
			"the UltraParams (%+v): %v", params.GenesisBlock.Header, err)
	}
	genesisHashHex := hex.EncodeToString(genesisHash[:])
	if genesisHashHex != params.GenesisBlockHashHex {
		log.Fatalf("GenesisBlockHash in UltraParams (%s) does not match the block "+
			"hash computed (%s) %d %d", params.GenesisBlockHashHex, genesisHashHex, len(params.GenesisBlockHashHex), len(genesisHashHex))
	}

	if params.MinDifficultyTargetHex == "" {
		log.Fatalf("The UltraParams MinDifficultyTargetHex (%s) should be non-empty",
			params.MinDifficultyTargetHex)
	}

	// Check to ensure the genesis block hash meets the initial
	// difficulty target.
	{
		hexBytes, err := hex.DecodeString(params.MinDifficultyTargetHex)
		if err != nil || len(hexBytes) != 32 {
			log.Fatalf("The UltraParams MinDifficultyTargetHex (%s) with length (%d) is "+
				"invalid: %v", params.MinDifficultyTargetHex, len(params.MinDifficultyTargetHex), err)
		}
		//initialDiffHash := lib.BytesToBlockHash(hexBytes)

		//if lib.LessThan(initialDiffHash, genesisHash) {
		//log.Fatalf("The UltraParams MinDifficultyTarget (%#v) should be "+
		//"greater than the GenesisHash (%#v)", initialDiffHash, genesisHash)
		//}
	}

	if params.MaxDifficultyRetargetFactor == 0 {
		log.Fatalf("The UltraParams MaxDifficultyRetargetFactor is unset")
	}

	if params.BlockRewardMaturity == 0 {
		log.Fatalf("The UltraParams BlockRewardMaturity is unset")
	}
}

func _processFlagsMain() (_params *lib.UltranetParams, _externalIPs []string, _connectIPs []string, _connectIPNetAddrs []*wire.NetAddress, _addIPs []string, _addSeeds []string, _sharedSecret string, _jsonPort uint16, _protocolPort uint16, _webClientPort uint16, _dataDir string, _minerPublicKeys []string) {
	params := &lib.UltranetMainnetParams
	if *flagUseUltraTestnet {
		params = &lib.UltranetTestnetParams
	}
	_checkParams(params)

	// Set the shared secret to something random if it isn't provided. This will at
	// least ensure that no unauthorized access to private APIs will occur.
	sharedSecret := lib.RandomBytesHex(lib.HashSizeBytes)
	if *flagSharedSecret != "" {
		sharedSecret = *flagSharedSecret
	}

	jsonPort := params.DefaultJSONPort
	if *flagJSONPort != 0 {
		if *flagJSONPort > math.MaxUint16 {
			glog.Fatalf("JSON port %d exceeds maximum port value %d", *flagJSONPort, math.MaxUint16)
		}
		jsonPort = uint16(*flagJSONPort)
	}
	protocolPort := params.DefaultSocketPort
	if *flagProtocolListenPort != 0 {
		if *flagProtocolListenPort > math.MaxUint16 {
			glog.Fatalf("Protocol port %d exceeds maximum port value %d", *flagProtocolListenPort, math.MaxUint16)
		}
		protocolPort = uint16(*flagProtocolListenPort)
	}

	webClientPort := params.DefaultWebClientPort
	if *flagWebClientPort != 0 {
		if *flagWebClientPort > math.MaxUint16 {
			glog.Fatalf("WebClient port %d exceeds maximum port value %d", *flagWebClientPort, math.MaxUint16)
		}
		webClientPort = uint16(*flagWebClientPort)
	}

	var externalIps []string
	if *flagExternalIps != "" {
		externalIps = strings.Split(*flagExternalIps, ",")
		glog.Infof("Using external ip list: %v", externalIps)
	}

	var addIps []string
	if *flagAddIps != "" {
		addIps = strings.Split(*flagAddIps, ",")
		glog.Infof("Using add ip list: %v", addIps)
	}

	var addSeeds []string
	if *flagAddSeeds != "" {
		addSeeds = strings.Split(*flagAddSeeds, ",")
		glog.Infof("Using add seeds list: %v", addSeeds)
	}

	var connectIps []string
	if *flagConnectIps != "" {
		connectIps = strings.Split(*flagConnectIps, ",")
		glog.Infof("Using connect ip list (and not connecting to anything else): %v", connectIps)
	}
	connectIPNetaddrs := []*wire.NetAddress{}
	// Add the --connectips to the addrmgr. Die if we fail to add any.
	for _, ipStr := range connectIps {
		netAddr, err := lib.IPToNetAddr(ipStr, params)
		if err != nil {
			glog.Fatalf("Cannot add %s as connect IP: %v", ipStr, err)
		}

		// Normally the second argument is the source who told us about the
		// addresses we're adding. In this case since the source is a commandline
		// flag, set the address itself as the source.
		connectIPNetaddrs = append(connectIPNetaddrs, netAddr)
	}

	var minerPublicKeys []string
	if *flagMinerPublicKeys != "" {
		minerPublicKeys = strings.Split(*flagMinerPublicKeys, ",")
		glog.Infof("Using miner public key list: %v", minerPublicKeys)
	}

	dataDir := *flagDataDirPath
	if dataDir == "" {
		dataDir = lib.GetDataDir(params)
	}
	if err := os.MkdirAll(dataDir, os.ModePerm); err != nil {
		log.Fatalf("_processFlagsMain: Could not create data directories (%s): %v", dataDir, err)
	}

	return params, externalIps, connectIps, connectIPNetaddrs, addIps, addSeeds, sharedSecret, jsonPort, protocolPort, webClientPort, dataDir, minerPublicKeys
}

func _addIPsForHost(ultranetAddrMgr *addrmgr.AddrManager, host string, params *lib.UltranetParams) {
	ipAddrs, err := net.LookupIP(host)
	if err != nil {
		glog.Tracef("_addSeedAddrs: DNS discovery failed on seed host (continuing on): %s %v\n", host, err)
		return
	}
	if len(ipAddrs) == 0 {
		glog.Tracef("_addSeedAddrs: No IPs found for host: %s\n", host)
		return
	}

	// Don't take more than 5 IPs per host.
	ipsPerHost := 5
	if len(ipAddrs) > ipsPerHost {
		glog.Debugf("_addSeedAddrs: Truncating IPs found from %d to %d\n", len(ipAddrs), ipsPerHost)
		ipAddrs = ipAddrs[:ipsPerHost]
	}

	glog.Debugf("_addSeedAddrs: Adding seed IPs from seed %s: %v\n", host, ipAddrs)

	// Convert addresses to NetAddress'es.
	netAddrs := make([]*wire.NetAddress, len(ipAddrs))
	for ii, ip := range ipAddrs {
		netAddrs[ii] = wire.NewNetAddressTimestamp(
			// We initialize addresses with a
			// randomly selected "last seen time" between 3
			// and 7 days ago similar to what bitcoind does.
			time.Now().Add(-1*time.Second*time.Duration(lib.SecondsIn3Days+
				lib.RandInt32(lib.SecondsIn4Days))),
			0,
			ip,
			params.DefaultSocketPort)
	}
	glog.Debugf("_addSeedAddrs: Computed the following wire.NetAddress'es: %s", spew.Sdump(netAddrs))

	// Normally the second argument is the source who told us about the
	// addresses we're adding. In this case since the source is a DNS seed
	// just use the first address in the fetch as the source.
	ultranetAddrMgr.AddAddresses(netAddrs, netAddrs[0])
}

func _addSeedAddrs(ultranetAddrMgr *addrmgr.AddrManager, params *lib.UltranetParams, connectIps []string, addIps []string, addSeeds []string, queryDNSSeeds bool) {
	// We only fetch seed addresses if --connectips is not specified.
	connectIPNetaddrs := []*wire.NetAddress{}
	if len(connectIps) > 0 {
		if len(addIps) > 0 || len(addSeeds) > 0 {
			glog.Fatalf("_addSeedAddrs: Cannot specify addips or addseeds if connectips is set.")
		}

		// Add the --connectips. Die if we fail to add any.
		for _, ipStr := range connectIps {
			netAddr, err := lib.IPToNetAddr(ipStr, params)
			if err != nil {
				glog.Fatalf("_addSeedAddrs: Cannot add %s as connect IP: %v", ipStr, err)
			}

			connectIPNetaddrs = append(connectIPNetaddrs, netAddr)
		}
	} else {
		// Get some addrs from the seeds if --connectips is unset.
		if queryDNSSeeds {
			glog.Info("_addSeedAddrs: Looking for addresses from DNS seeds")
			allSeeds := append(append([]string{}, params.DNSSeeds...), addSeeds...)
			for _, host := range allSeeds {
				_addIPsForHost(ultranetAddrMgr, host, params)
			}
		}

		// Add the --addips to the addrmgr. Die if we fail to add any.
		var addIPNetAddrs []*wire.NetAddress
		for _, ipStr := range addIps {
			netAddr, err := lib.IPToNetAddr(ipStr, params)
			if err != nil {
				glog.Fatalf("_addSeedAddrs: Cannot add %s as addip: %v", ipStr, err)
			}
			addIPNetAddrs = append(addIPNetAddrs, netAddr)
		}
		if len(addIPNetAddrs) > 0 {
			// Normally the second argument is the source who told us about the
			// addresses we're adding. In this case since the source is a DNS seed
			// just use the first address in the fetch as the source.
			ultranetAddrMgr.AddAddressesRelaxed(addIPNetAddrs, addIPNetAddrs[0])
		}
	}
}

// Must be run in a goroutine. This function continuously adds IPs from a DNS seed
// prefix+suffix by iterating up through all of the possible numeric values, which are typically
// [0, 99999]
func _addSeedAddrsFromPrefixes(ultranetAddrMgr *addrmgr.AddrManager, params *lib.UltranetParams) {
	MaxIterations := 99999

	// This one iterates sequentially.
	go func() {
		for dnsNumber := 0; dnsNumber < MaxIterations; dnsNumber++ {
			var wg deadlock.WaitGroup
			for _, dnsGeneratorOuter := range params.DNSSeedGenerators {
				wg.Add(1)
				go func(dnsGenerator []string) {
					dnsString := fmt.Sprintf("%s%d%s", dnsGenerator[0], dnsNumber, dnsGenerator[1])
					glog.Tracef("_addSeedAddrsFromPrefixes: Querying DNS seed: %s", dnsString)
					_addIPsForHost(ultranetAddrMgr, dnsString, params)
					wg.Done()
				}(dnsGeneratorOuter)
			}
			wg.Wait()
		}
	}()

	// This one iterates randomly.
	go func() {
		for index := 0; index < MaxIterations; index++ {
			dnsNumber := int(rand.Int63() % int64(MaxIterations))
			var wg deadlock.WaitGroup
			for _, dnsGeneratorOuter := range params.DNSSeedGenerators {
				wg.Add(1)
				go func(dnsGenerator []string) {
					dnsString := fmt.Sprintf("%s%d%s", dnsGenerator[0], dnsNumber, dnsGenerator[1])
					glog.Tracef("_addSeedAddrsFromPrefixes: Querying DNS seed: %s", dnsString)
					_addIPsForHost(ultranetAddrMgr, dnsString, params)
					wg.Done()
				}(dnsGeneratorOuter)
			}
			wg.Wait()
		}
	}()
}

func _addLocalAddrs(ultranetAddrMgr *addrmgr.AddrManager, params *lib.UltranetParams, listeningAddrs []net.TCPAddr, externalIps []string) {
	// Add local addresses as candidates for what we broadcast
	// to peers. Right now we use the --externalips from the commandline
	// and any routable interface IPs that we are able to listen on.
	//
	// TODO: Implement upnp discovery.
	//
	// Check and add the --externalips as candidates for broadcast addrs.
	for _, ipStr := range externalIps {
		netAddr, err := lib.IPToNetAddr(ipStr, params)
		if err != nil {
			glog.Fatalf("Cannot add %s as externalip: %v", ipStr, err)
			continue
		}

		err = ultranetAddrMgr.AddLocalAddress(netAddr, addrmgr.ManualPrio)
		if err != nil {
			glog.Warningf("Skipping specified external IP: %v", err)
		}
	}
	// Check and add the network interface addresses as candidates for
	// broadcast addrs.
	for _, addr := range listeningAddrs {
		netAddr := wire.NewNetAddress(&addr, 0)
		ultranetAddrMgr.AddLocalAddress(netAddr, addrmgr.BoundPrio)
	}
}

func main() {
	flag.Parse()

	// Set up logging.
	glog.Init()
	log.Printf("Logging to folder: %s", glog.GlogFlags.LogDir)
	log.Printf("Symlink to latest: %s", glog.GlogFlags.Symlink)
	log.Println("To log output on commandline, run with -alsologtostderr")
	glog.CopyStandardLogTo("INFO")

	// Process some of the flags.
	params, externalIps, connectIPs, connectIPNetAddrs, addIPs, addSeeds, sharedSecret, jsonPort, protocolPort, webClientPort, dataDir, minerPublicKeys := _processFlagsMain()

	// Figure out all the interfaces we're capable of listening on and listen on them.
	listeningAddrs, listeners := _getAddrsToListenOn(protocolPort)

	// Start the address manager, add some seed addresses, and add the local
	// addresses we're listening on.
	ultranetAddrMgr := addrmgr.New(dataDir, net.LookupIP)
	ultranetAddrMgr.Start()
	_addLocalAddrs(ultranetAddrMgr, params, listeningAddrs, externalIps)
	go func() {
		// We don't query DNS seeds when private mode is true.
		shouldQueryDNSSeeds := !*flagPrivateMode
		_addSeedAddrs(ultranetAddrMgr, params, connectIPs, addIPs, addSeeds, shouldQueryDNSSeeds)
		if shouldQueryDNSSeeds {
			_addSeedAddrsFromPrefixes(ultranetAddrMgr, params)
		}
	}()

	opts := badger.DefaultOptions
	opts.Dir = lib.GetBadgerDbPath(dataDir)
	opts.Truncate = true
	opts.ValueDir = lib.GetBadgerDbPath(dataDir)
	glog.Infof("BadgerDB Dir: %v", opts.Dir)
	glog.Infof("BadgerDB ValueDir: %v", opts.ValueDir)
	db, err := badger.Open(opts)
	if err != nil {
		glog.Fatal(err)
	}

	bitcoinDataDir := filepath.Join(dataDir, "bitcoin_manager")
	if err := os.MkdirAll(bitcoinDataDir, os.ModePerm); err != nil {
		log.Fatalf("Could not create Bitcoin datadir (%s): %v", dataDir, err)
	}
	backendServer, err := lib.NewServer(params, listeners, ultranetAddrMgr,
		connectIPNetAddrs, db, uint32(*flagTargetOutboundPeers), uint32(*flagMaxInboundPeers),
		minerPublicKeys, *flagNumMiningThreads, *flagLimitOneInboundConnectionPerIP,
		*flagRateLimitFeerateNanosPerKB, *flagMinFeeRateNanosPerKB,
		*flagStallTimeoutSeconds, bitcoinDataDir, jsonPort)
	if err != nil {
		glog.Fatal(err)
	}
	backendServer.Start()

	frontendServer, err := lib.NewFrontendServer(
		backendServer, backendServer.GetListingManager(),
		backendServer.GetBlockchain(), params, sharedSecret, jsonPort,
		*flagMinFeeRateNanosPerKB)
	if err != nil {
		glog.Fatal(err)
	}
	go frontendServer.Start()

	interrupt := btcd_lib.InterruptListener()
	defer glog.Info("Shutdown complete")
	defer func() {
		frontendServer.Stop()
		ultranetAddrMgr.Stop()
		backendServer.Stop()
		db.Close()
	}()

	// Use packr to serve web clients a UI they can use to interact with the Ultranet.
	// Note we serve a static angular single-page app from the frontend directory.
	// packr is smart enough to bundle this with our app as long as we build with the
	// following commands from within the backend/ directory:
	// $ packr && go build
	box := packr.NewBox("../frontend/dist")
	glog.Debugf("Found the following files with packr.NewBox(): %v", box.List())

	http.Handle("/", http.FileServer(box))
	glog.Infof("Listening to web client connections on port %d", webClientPort)
	go http.ListenAndServe(fmt.Sprintf(":%d", webClientPort), nil)

	// Open a web browser and point it to our server, which will run as a daemon.
	browserURL := fmt.Sprintf(
		"http://localhost:%d/?shared_secret=%s&local_node=localhost:%d",
		webClientPort, sharedSecret, jsonPort)
	// It's useful to the user if we print the URL, but we don't want it to wind up in
	// a log file since that could allow malware on the user's system to get privileged
	// access by scanning the logs. As such, we use fmt.Printf rather than glog.Infof.
	fmt.Printf("Opening brower URL: %s\n", browserURL)
	if err := browser.OpenURL(browserURL); err != nil {
		glog.Error(errors.Wrapf(err, "Problem opening browser: "))
	}

	// Comment this in to profile things.
	// After profiling is complete and program exits, run:
	// $ go tool pprof main /tmp/pprof_cpu
	// > web FuncName
	/*
		var cpuFile *os.File
		cpuFile, err = os.Create("/tmp/pprof_cpu")
		heapFile, err := os.Create("/tmp/pprof_heap")
		if err != nil {
			log.Fatal(err)
		}
		pprof.StartCPUProfile(cpuFile)
		go func() {
			time.Sleep(120 * time.Second)
			fmt.Println("DONE WITH PPROF!")
			pprof.StopCPUProfile()
			pprof.WriteHeapProfile(heapFile)
			os.Exit(0)
		}()
	*/

	// Wait until the interrupt signal is received from an OS signal or
	// shutdown is requested through one of the subsystems such as the RPC
	// server.
	<-interrupt
	return
}
