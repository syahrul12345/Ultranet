package lib

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math"
	"net/http"

	"github.com/golang/glog"
	"github.com/pkg/errors"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
)

// bitcoin_burner.go finds the Bitcoin UTXOs associated with a Bitcoin
// address and constructs a burn transaction on behalf of the user. Note that the
// use of an API here is strictly cosmetic, and that none of this
// logic is used for actually validating anything (that is all done by bitcoin_manager.go,
// which relies on Bitcoin peers and is fully decentralized). The user can
// also simply use an existing Bitcoin wallet to send Bitcoin to the burn address
// rather than this utility, but that is slightly less convenient than just
// baking this functionality in, which is why we do it.
//
// TODO: If this API doesn't work in the long run, I think the ElectrumX network would
// be a pretty good alternative.

type BitcoinUtxo struct {
	TxID           *chainhash.Hash
	Index          int64
	AmountSatoshis int64
}

func _estimateBitcoinTxSize(numInputs int, numOutputs int) int {
	return numInputs*180 + numOutputs*34
}

func _estimateBitcoinTxFee(
	numInputs int, numOutputs int, feeRateSatoshisPerKB uint64) uint64 {

	return uint64(_estimateBitcoinTxSize(numInputs, numOutputs)) * feeRateSatoshisPerKB / 1000
}

func CreateUnsignedBitcoinSpendTransaction(
	spendAmountSatoshis uint64,
	feeRateSatoshisPerKB uint64,
	spendAddrString string,
	recipientAddrString string,
	params *UltranetParams,
	utxoSource func(addr string, params *UltranetParams) ([]*BitcoinUtxo, error)) (
	_txn *wire.MsgTx, _totalInput uint64, _fee uint64, _err error) {

	// Get the utxos for the spend key.
	bitcoinUtxos, err := utxoSource(spendAddrString, params)
	if err != nil {
		return nil, 0, 0, errors.Wrapf(err, "CreateUnsignedBitcoinSpendTransaction: Problem getting "+
			"Bitcoin utxos for Bitcoin address %s",
			spendAddrString)
	}

	glog.Tracef("CreateUnsignedBitcoinSpendTransaction: Found %d BitcoinUtxos", len(bitcoinUtxos))

	// Create the transaction we'll be returning.
	retTxn := &wire.MsgTx{}
	// Set locktime to 0 since we're not using it.
	retTxn.LockTime = 0
	// The version seems to be 2 these days.
	retTxn.Version = 2

	// Add an output sending spendAmountSatoshis to the recipientAddress.
	//
	// We decode it twice in order to guarantee that we're sending to an *address*
	// rather than to a public key.
	recipientOutput := &wire.TxOut{}
	recipientAddrTmp, err := btcutil.DecodeAddress(
		recipientAddrString, params.BitcoinBtcdParams)
	if err != nil {
		return nil, 0, 0, errors.Wrapf(err, "CreateUnsignedBitcoinSpendTransaction: Problem decoding "+
			"recipient address %s", recipientAddrString)
	}
	recipientAddr, err := btcutil.DecodeAddress(
		recipientAddrTmp.EncodeAddress(), params.BitcoinBtcdParams)
	if err != nil {
		return nil, 0, 0, errors.Wrapf(err, "CreateUnsignedBitcoinSpendTransaction: Problem decoding "+
			"recipient address pubkeyhash %s %s", recipientAddrString, recipientAddrTmp.EncodeAddress())
	}
	recipientOutput.PkScript, err = txscript.PayToAddrScript(recipientAddr)
	recipientOutput.Value = int64(spendAmountSatoshis)
	retTxn.TxOut = append(retTxn.TxOut, recipientOutput)

	// Decode the spendAddrString.
	//
	// We decode it twice in order to guarantee that we're sending to an *address*
	// rather than to a public key.
	spendAddrTmp, err := btcutil.DecodeAddress(
		spendAddrString, params.BitcoinBtcdParams)
	if err != nil {
		return nil, 0, 0, errors.Wrapf(err, "CreateUnsignedBitcoinSpendTransaction: Problem decoding "+
			"spend address %s", spendAddrString)
	}
	spendAddr, err := btcutil.DecodeAddress(
		spendAddrTmp.EncodeAddress(), params.BitcoinBtcdParams)
	if err != nil {
		return nil, 0, 0, errors.Wrapf(err, "CreateUnsignedBitcoinSpendTransaction: Problem decoding "+
			"spend address pubkeyhash %s %s", spendAddrString, spendAddrTmp.EncodeAddress())
	}

	// Rack up the number of utxos you need to pay the spend amount. Add each
	// one to our transaction until we have enough to cover the spendAmount
	// plus the fee.
	totalInputSatoshis := uint64(0)
	for _, bUtxo := range bitcoinUtxos {
		totalInputSatoshis += uint64(bUtxo.AmountSatoshis)

		// Construct an input corresponding to this utxo.
		txInput := &wire.TxIn{}
		txInput.PreviousOutPoint = *wire.NewOutPoint(bUtxo.TxID, uint32(bUtxo.Index))
		// Set Sequence to the max value to disable locktime.
		txInput.Sequence = math.MaxUint32
		// Don't set the SignatureScript yet.

		// Set the input on the transaction.
		retTxn.TxIn = append(retTxn.TxIn, txInput)

		// If the total input we've accrued thus far covers the spend amount and the
		// fee precisely, then we're done.
		txFee := _estimateBitcoinTxFee(
			len(retTxn.TxIn), len(retTxn.TxOut), feeRateSatoshisPerKB)
		if totalInputSatoshis == spendAmountSatoshis+txFee {
			break
		}

		// Since our input did not precisely equal the spend amount plus the fee,
		// see if if the input exceeds the spend amount plus the fee after we add
		// a change output. If it does, then we're done. Note the +1 in the function
		// call below.
		txFeeWithChange := _estimateBitcoinTxFee(
			len(retTxn.TxIn), len(retTxn.TxOut)+1, feeRateSatoshisPerKB)
		if totalInputSatoshis >= spendAmountSatoshis+txFeeWithChange {
			// In this case we add a change output to the transaction that sends the
			// excess Bitcoin back to the spend address.
			changeOutput := &wire.TxOut{}
			changeOutput.PkScript, err = txscript.PayToAddrScript(spendAddr)
			totalOutputSatoshis := spendAmountSatoshis + txFeeWithChange
			changeOutput.Value = int64(totalInputSatoshis - totalOutputSatoshis)
			retTxn.TxOut = append(retTxn.TxOut, changeOutput)

			break
		}
	}

	// At this point, if the totalInputSatoshis is not greater than or equal to
	// the spend amount plus the estimated fee then we didn't have enough input
	// to successfully form the transaction.
	finalFee := _estimateBitcoinTxFee(
		len(retTxn.TxIn), len(retTxn.TxOut), feeRateSatoshisPerKB)
	if totalInputSatoshis < spendAmountSatoshis+finalFee {
		return nil, 0, 0, fmt.Errorf("CreateUnsignedBitcoinSpendTransaction: Total input satoshis %d is "+
			"not sufficient to cover the spend amount %d plus the fee %d",
			totalInputSatoshis, spendAmountSatoshis, finalFee)
	}

	return retTxn, totalInputSatoshis, finalFee, nil
}

func CreateBitcoinSpendTransaction(
	spendAmountSatoshis uint64, feeRateSatoshisPerKB uint64,
	spendPrivateKey *btcec.PrivateKey,
	recipientAddrString string, params *UltranetParams,
	utxoSource func(addr string, params *UltranetParams) ([]*BitcoinUtxo, error)) (_txn *wire.MsgTx, _totalInput uint64, _fee uint64, _err error) {

	// Get the public key from the private key.
	pubKey := spendPrivateKey.PubKey()

	// Convert the public key into a Bitcoin address.
	spendAddrTmp, err := btcutil.NewAddressPubKey(
		pubKey.SerializeCompressed(), params.BitcoinBtcdParams)
	spendAddrr := spendAddrTmp.AddressPubKeyHash()
	if err != nil {
		return nil, 0, 0, errors.Wrapf(err, "CreateBitcoinSpendTransaction: Problem converting "+
			"pubkey to address: ")
	}
	spendAddrString := spendAddrr.EncodeAddress()

	glog.Tracef("CreateBitcoinSpendTransaction: Creating spend for "+
		"<from: %s, to: %s> for amount %d, feeRateSatoshisPerKB %d",
		spendAddrString,
		recipientAddrString, spendAmountSatoshis, feeRateSatoshisPerKB)

	retTxn, totalInputSatoshis, finalFee, err := CreateUnsignedBitcoinSpendTransaction(
		spendAmountSatoshis, feeRateSatoshisPerKB, spendAddrString,
		recipientAddrString, params, utxoSource)
	if err != nil {
		return nil, 0, 0, errors.Wrapf(err, "CreateBitcoinSpendTransaction: Problem "+
			"creating unsigned Bitcoin spend: ")
	}

	// At this point we are confident the transaction has enough input to cover its
	// outputs. Now go through and set the input scripts.
	//
	// All the inputs are signing an identical output script corresponding to the
	// spend address.
	outputScriptToSign, err := txscript.PayToAddrScript(spendAddrr)
	if err != nil {
		return nil, 0, 0, errors.Wrapf(err, "CreateBitcoinSpendTransaction: Problem computing "+
			"output script for spendAddr %v", spendAddrr)
	}
	for ii, txInput := range retTxn.TxIn {
		scriptSig, err := txscript.SignatureScript(
			retTxn, ii, outputScriptToSign, txscript.SigHashAll, spendPrivateKey,
			true /*compress*/)
		if err != nil {
			return nil, 0, 0, errors.Wrapf(err, "CreateBitcoinSpendTransaction: Problem "+
				"creating scriptsig for input %d", ii)
		}

		txInput.SignatureScript = scriptSig
	}

	// At this point all the inputs should be signed and the total input should cover
	// the spend amount plus the fee with any change going back to the spend address.
	glog.Tracef("CreateBitcoinSpendTransaction: Created transaction with "+
		"(%d inputs, %d outputs, %d total input, %d spend amount, %d change, %d fee)",
		len(retTxn.TxIn), len(retTxn.TxOut), totalInputSatoshis,
		spendAmountSatoshis, totalInputSatoshis-spendAmountSatoshis-finalFee, finalFee)

	return retTxn, totalInputSatoshis, finalFee, nil
}

func IsBitcoinTestnet(params *UltranetParams) bool {
	return params.BitcoinBtcdParams.Name == "testnet3"
}

// ======================================================================================
// BlockCypher API code
//
// This is bascially a user experience hack. We use BlockCypher to fetch
// BitcoinUtxos to determine what the user is capable of spending from their address
// and to craft burn transactions for the user using their address and available utxos. Note
// that we could do this in the BitcoinManager and cut reliance on BlockCypher to make
// decentralized, but it would increase complexity significantly. Moreover, this
// piece is not critical to the protocol or to consensus, and it breaking doesn't even
// stop people from being able to purchase Ultra since they can always do that by sending
// Bitcoin to the burn address from any standard Bitcoin client after entering their
// seed phrase.
// ======================================================================================

type BlockCypherAPIInputResponse struct {
	PrevTxIDHex    string   `json:"prev_hash"`
	Index          int64    `json:"output_index"`
	ScriptHex      string   `json:"script"`
	AmountSatoshis int64    `json:"output_value"`
	Sequence       int64    `json:"sequence"`
	Addresses      []string `json:"addresses"`
	ScriptType     string   `json:"script_type"`
	Age            int64    `json:"age"`
}

type BlockCypherAPIOutputResponse struct {
	AmountSatoshis int64    `json:"value"`
	ScriptHex      string   `json:"script"`
	Addresses      []string `json:"addresses"`
	ScriptType     string   `json:"script_type"`
	SpentBy        string   `json:"spent_by"`
}

type BlockCypherAPITxnResponse struct {
	BlockHashHex  string                          `json:"block_hash"`
	BlockHeight   int64                           `json:"block_height"`
	LockTime      int64                           `json:"lock_time"`
	TxIDHex       string                          `json:"hash"`
	Inputs        []*BlockCypherAPIInputResponse  `json:"inputs"`
	Outputs       []*BlockCypherAPIOutputResponse `json:"outputs"`
	Confirmations int64                           `json:"confirmations"`
}

type BlockCypherAPIFullAddressResponse struct {
	Address string `json:"address"`
	// Balance data
	ConfirmedBalance   int64 `json:"balance"`
	UnconfirmedBalance int64 `json:"unconfirmed_balance"`
	FinalBalance       int64 `json:"final_balance"`

	// Transaction data
	Txns []*BlockCypherAPITxnResponse `json:"txs"`

	HasMore bool `json:"hasMore"`

	Error string `json:"error"`
}

func BlockCypherExtractBitcoinUtxosFromResponse(
	apiData *BlockCypherAPIFullAddressResponse, addrString string, params *UltranetParams) (
	[]*BitcoinUtxo, error) {

	glog.Tracef("BlockCypherExtractBitcoinUtxosFromResponse: Extracting BitcoinUtxos "+
		"from %d txns", len(apiData.Txns))
	addr, err := btcutil.DecodeAddress(addrString, params.BitcoinBtcdParams)
	if err != nil {
		return nil, err
	}
	outputScriptForAddr, err := txscript.PayToAddrScript(addr)
	if err != nil {
		return nil, err
	}

	// Go through and index all of the outputs that appear as inputs. The reason
	// we must do this is because the API only sets to SpentBy field if a transaction
	// has at least one confirmation. So, in order to mark outputs as spent when they
	// appear in transactions that aren't confirmed, we need to make this adjustment.
	//
	// We overload the BitcoinUtxo here because it's easier than defining a new struct.
	type utxoKey struct {
		TxIDHex string
		Index   int64
	}
	outputsSpentInResponseInputs := make(map[utxoKey]bool)
	for _, txn := range apiData.Txns {
		for _, input := range txn.Inputs {
			currentUtxo := utxoKey{
				TxIDHex: input.PrevTxIDHex,
				Index:   input.Index,
			}
			outputsSpentInResponseInputs[currentUtxo] = true
		}

	}

	bitcoinUtxos := []*BitcoinUtxo{}
	for _, txn := range apiData.Txns {
		for outputIndex, output := range txn.Outputs {
			if output.SpentBy != "" {
				// This is how we determine if an output is spent or not.
				continue
			}
			if output.ScriptHex != hex.EncodeToString(outputScriptForAddr) {
				// Only outputs that are destined for the passed-in address are considered.
				continue
			}
			// If the output is spent in one of the inputs of the API response then
			// consider it spent here. We do this to count confirmed transactions in
			// the utxo set.
			currentUtxo := utxoKey{
				TxIDHex: txn.TxIDHex,
				Index:   int64(outputIndex),
			}
			if _, exists := outputsSpentInResponseInputs[currentUtxo]; exists {
				continue
			}

			// If we get here we know we are dealing with an unspent output destined
			// for the address passed in.

			bUtxo := &BitcoinUtxo{}
			bUtxo.AmountSatoshis = output.AmountSatoshis
			bUtxo.Index = int64(outputIndex)
			txid := (chainhash.Hash)(*mustDecodeHexBlockHashBitcoin(txn.TxIDHex))
			bUtxo.TxID = &txid

			bitcoinUtxos = append(bitcoinUtxos, bUtxo)
		}
	}

	glog.Tracef("BlockCypherExtractBitcoinUtxosFromResponse: Extracted %d BitcoinUtxos",
		len(bitcoinUtxos))

	return bitcoinUtxos, nil
}

func GetBlockCypherAPIFullAddressResponse(addrString string, params *UltranetParams) (
	_apiData *BlockCypherAPIFullAddressResponse, _err error) {

	URL := fmt.Sprintf("http://api.blockcypher.com/v1/btc/main/addrs/%s/full", addrString)
	if IsBitcoinTestnet(params) {
		URL = fmt.Sprintf("http://api.blockcypher.com/v1/btc/test3/addrs/%s/full", addrString)
	}
	glog.Tracef("GetBlockCypherAPIFullAddressResponse: Querying URL: %s", URL)

	// jsonValue, err := json.Marshal(postData)
	req, err := http.NewRequest("GET", URL, nil)
	req.Header.Set("Content-Type", "application/json")

	// To add a ?a=b query string, use the below.
	q := req.URL.Query()
	// TODO: Right now we'll only fetch a maximum of 50 transactions from the API.
	// This means if the user has done more than 50 transactions with their address
	// we'll start missing some of the older utxos. This is easy to fix, though, and
	// just amounts to cycling through the API's pages. Note also that this does not
	// prevent a user from buying Ultra in this case nor does it prevent her from being
	// able to recover her Bitcoin. Both of these can be accomplished by loading the
	// address in a standard Bitcoin wallet like Electrum.
	q.Add("limit", "50")
	req.URL.RawQuery = q.Encode()
	glog.Tracef("GetBlockCypherAPIFullAddressResponse: URL with params: %s", req.URL)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GetBlockCypherAPIFullAddressResponse: Problem with HTTP request %s: %v", URL, err)
	}
	defer resp.Body.Close()

	// Decode the response into the appropriate struct.
	body, _ := ioutil.ReadAll(resp.Body)
	responseData := &BlockCypherAPIFullAddressResponse{}
	decoder := json.NewDecoder(bytes.NewReader(body))
	if err := decoder.Decode(responseData); err != nil {
		return nil, fmt.Errorf("GetBlockCypherAPIFullAddressResponse: Problem decoding response JSON into "+
			"interface %v, response: %v, error: %v", responseData, resp, err)
	}
	//glog.Tracef("BlockCypherUtxoSource: Received response: %v", responseData)

	if responseData.Error != "" {
		return nil, fmt.Errorf("GetBlockCypherAPIFullAddressResponse: Had an "+
			"error in the response: %s", responseData.Error)
	}

	return responseData, nil
}

func BlockCypherUtxoSource(addrString string, params *UltranetParams) (
	[]*BitcoinUtxo, error) {

	apiData, err := GetBlockCypherAPIFullAddressResponse(addrString, params)
	if err != nil {
		return nil, errors.Wrapf(err, "BlockCypherUtxoSource: Problem getting API data "+
			"for address %s: ", addrString)
	}

	return BlockCypherExtractBitcoinUtxosFromResponse(apiData, addrString, params)
}
