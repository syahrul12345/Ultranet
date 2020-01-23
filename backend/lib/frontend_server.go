package lib

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"image"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/tyler-smith/go-bip39"

	"github.com/btcsuite/btcd/addrmgr"
	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/golang/glog"
	"github.com/gorilla/mux"
	"github.com/nfnt/resize"
	"github.com/pkg/errors"

	// We import this so that we can decode gifs.
	_ "image/gif"
	"image/jpeg"
	// We import this so that we can decode pngs.
	_ "image/png"
)

// TODO: frontend_utils and frontend_server were actually supposed to be one big file.
// The only reason I broke them up is because vim-go refused to give me error-checks
// once the file exceeded a certain size. I chopped it kindof randomly in the middle,
// so if we want to keep it as two files going forward, we should clean up
// what goes where. A good place to start is probably InitRoutes() in frontend_server.go
// to see what all the functions that are exposed are.

const (
	// MaxRequestBodySizeBytes is the maximum size of a request body we will
	// generally be willing to process.
	MaxRequestBodySizeBytes = 10 * 1e6 // 10M
	// TopCategoriesPrefixParam ...
	TopCategoriesPrefixParam = "top_categories_prefix"
	// SharedSecretParam ...
	SharedSecretParam = "shared_secret"
	// DraftImageIDParam ...
	DraftImageIDParam = "draft_image_id"
	// ListingImageIDParam ...
	ListingImageIDParam = "listing_image_id"
	// StartBlockHeightParam ...
	StartBlockHeightParam = "start_block_height"
	// EndBlockHeightParam ...
	EndBlockHeightParam = "end_block_height"
	// MaxListingDimension ...
	MaxListingDimension = 500
	// MaxThumbnailDimension ...
	MaxThumbnailDimension = 200
	// MinTitleCharacters ...
	MinTitleCharacters = 3
	// MaxTopCategoriesToReturn ...
	MaxTopCategoriesToReturn = 1000

	// Two floats are equal if they differ by less than this value. We choose
	// this value because we generally expose around this much precision to
	// the user when we show them numbers on the screen.
	FloatEpsilon = float64(.00001)
)

func _getSarahsPublicKey(params *UltranetParams) []byte {
	return params.GenesisBlock.Txns[0].TxOutputs[0].PublicKey
}

func (fes *FrontendServer) updateUserFields(user *User, topMerchantMap map[string]*MerchantEntryResponse) error {
	// If there's no public key, then return an error. We need a public key on
	// the user object in order to be able to update the fields.
	if user.PublicKeyBase58Check == "" {
		return fmt.Errorf("updateUserFields: Missing PublicKeyBase58Check")
	}

	// Decode the public key into bytes.
	publicKeyBytes, _, err := Base58CheckDecode(user.PublicKeyBase58Check)
	if err != nil {
		return errors.Wrapf(err, "updateUserFields: Problem decoding user public key: ")
	}

	// Find the MerchantEntry for the user if one exists. If one doesn't exist
	// it will be set to nil, which is expected. Use an augmented UtxoView to
	// factor in mempool transactions. This will return a MerchantEntry if the
	// merchant either exists in the view due to applying mempool transactions OR
	// if the user exists in the db itself.
	var merchantEntryRes *MerchantEntryResponse
	utxoView, err := fes.backendServer.mempool.GetAugmentedUtxoViewForPublicKey(publicKeyBytes)
	if err != nil {
		return errors.Wrapf(err, "updateUserFields: Problem getting augmented UtxoView from mempool for merchant: ")
	}
	var merchantID *BlockHash
	merchantEntry := utxoView._getMerchantEntryForPublicKey(publicKeyBytes)
	if merchantEntry != nil {
		// If we have the merchantEntry in the topMerchantMap, use set its rank accordingly.
		// Otherwise, set the rank to be the highest possible. Doing it this way avoids an
		// extra topMerchants fetch in MerchantEntryToResponse.
		merchantRank := int64(fes.Params.MaxMerchantsToIndex)
		if mapEntry, mapEntryExists := topMerchantMap[PkToString(merchantEntry.merchantID[:], fes.Params)]; mapEntryExists {
			merchantRank = mapEntry.MerchantRank
		}

		merchantEntryRes = fes.MerchantEntryToResponse(merchantEntry, merchantRank)
		merchantID = merchantEntry.merchantID
	}
	user.MerchantEntry = merchantEntryRes

	// If the MerchantEntry is non-nil, update the username to what's in the entry.
	if user.MerchantEntry != nil {
		user.Username = user.MerchantEntry.Username
	}

	// If the MerchantEntry is set, get all the listings.
	if user.MerchantEntry != nil {
		listingsRet, err := fes._getListingResponsesForCriteria(
			user.MerchantEntry.MerchantIDBase58Check, -1, "", false, false, /*fetchMerchantEntries*/
			false /*adjustPriceForCommissions*/)
		if err != nil {
			return errors.Wrapf(err, "updateUserFields: Problem fetching listings: ")
		}

		// Manually attach the MerchantEntryResponses to the listings since they all
		// should correspond to this user.
		for _, listing := range listingsRet {
			listing.MerchantEntry = user.MerchantEntry
		}

		user.Listings = listingsRet
	}
	// Always set to an empty list for listings rather than nil.
	if user.Listings == nil {
		user.Listings = []*SingleListingResponse{}
	}

	// Fetch and set the orders for the user.
	orderEntries, err := utxoView.GetOrdersForUser(publicKeyBytes, merchantID)
	if err != nil {
		return errors.Wrapf(err, "updateUserFields: Problem fetching OrderEntries from augmented UtxoView: ")
	}

	// Go through all the OrderEntries and create OrderEntryResponses for each one.
	orderEntryResponses := []*OrderEntryResponse{}
	for _, orderEntry := range orderEntries {
		orderEntryRes, err := fes.OrderEntryToResponse(orderEntry, user, fes.Params)
		if err != nil {
			return errors.Wrapf(err, "updateUserFields: Problem converting "+
				"OrderEntry %v to OrderEntryResponse: ", orderEntry)
		}
		orderEntryResponses = append(orderEntryResponses, orderEntryRes)
	}
	// Sort the responses by their last modified time.
	sort.Slice(orderEntryResponses, func(ii, jj int) bool {
		// The LastModifiedAt for an order entry should always be set. At minimum it should
		// be the time when the order was created.
		if orderEntryResponses[ii].LastModifiedAtTstampSecs == orderEntryResponses[jj].LastModifiedAtTstampSecs {
			return orderEntryResponses[ii].OrderIDBase58Check > orderEntryResponses[jj].OrderIDBase58Check
		}

		return orderEntryResponses[ii].LastModifiedAtTstampSecs > orderEntryResponses[jj].LastModifiedAtTstampSecs
	})
	user.Orders = orderEntryResponses

	// Go through all the MessageEntries and create a MessageEntryResponse for each one.
	// Sort the MessageEntries by their timestamp.
	//
	// TODO: The timestamp is spoofable, but it's not a big deal. See comment on MessageEntry
	// for more insight on this.
	messageEntries, err := utxoView.GetMessagesForUser(publicKeyBytes)
	if err != nil {
		return errors.Wrapf(err, "updateUserFields: Problem fetching MessageEntries from augmented UtxoView: ")
	}

	// Add a help message from Sarah so they know they can reach out if they need anything.
	sarahPkBytes := _getSarahsPublicKey(fes.Params)
	sarahPkBase58Check := PkToString(sarahPkBytes, fes.Params)
	if !reflect.DeepEqual(publicKeyBytes, sarahPkBytes) {
		publicKeyObj, err := btcec.ParsePubKey(publicKeyBytes, btcec.S256())
		if err != nil {
			return errors.Wrapf(err, "updateUserFields: Problem parsing "+
				"user public key to encrypt message.")
		}
		encryptedText, err := EncryptBytesWithPublicKey(
			[]byte("Welcome to the Ultranet. My name is sarah and I'm the "+
				"Ultranet's original designer. If you run into trouble or have any "+
				"questions, please don't hesitate to message me here. And remember "+
				"that all messages are end-to-end encrypted and decentralized."),
			publicKeyObj.ToECDSA())
		messageEntries = append(messageEntries, &MessageEntry{
			SenderPublicKey:    sarahPkBytes,
			RecipientPublicKey: publicKeyBytes,
			EncryptedText:      encryptedText,
			TstampNanos:        1578461283 * 1000000000,
		})
		user.LocalState.PublicKeyToNickname[sarahPkBase58Check] = "sarah c0nn0r"
	}

	// Sort the messages by their timestamp.
	sort.Slice(messageEntries, func(ii, jj int) bool {
		return messageEntries[ii].TstampNanos < messageEntries[jj].TstampNanos
	})
	// Contacts organized by their public key.
	contactMap := make(map[string]*MessageContactResponse)
	newContactEntries := []*MessageContactResponse{}
	messageEntryResponses := []*MessageEntryResponse{}
	for _, messageEntry := range messageEntries {
		// If we hit an error while decrypting the message text, log an error but don't
		// stop the show.
		decryptedText, err := fes._tryDecryptMessageText(
			publicKeyBytes, messageEntry, user.LocalState.MessageKeyToDecryptedText)
		if err != nil {
			// Only log an error if this happens to the logged-in user otherwise ignore.
			if fes.UserData != nil && fes.UserData.LoggedInUser != nil &&
				fes.UserData.LoggedInUser.PublicKeyBase58Check == user.PublicKeyBase58Check {

				glog.Errorf(fmt.Sprintf("MessageEntryResponse: Problem decrypting message "+
					"text for LoggedInUser: %v; this should never happen", err))
			}
			// In this case we attach this text to the user but don't set it in the map.
			// This makes it so that if we eventually maange to decrypt it we can show the
			// user the real message.
			decryptedText = "UNKNOWN PROBLEM ENCOUNTERED WHEN DECRYPTING MESSAGE"
		}

		senderPublicKeyBase58Check := PkToString(messageEntry.SenderPublicKey, fes.Params)
		messageEntryRes := &MessageEntryResponse{
			SenderPublicKeyBase58Check:    senderPublicKeyBase58Check,
			RecipientPublicKeyBase58Check: PkToString(messageEntry.RecipientPublicKey, fes.Params),
			DecryptedText:                 decryptedText,
			TstampNanos:                   messageEntry.TstampNanos,
			IsSender:                      senderPublicKeyBase58Check == user.PublicKeyBase58Check,
		}
		messageEntryResponses = append(messageEntryResponses, messageEntryRes)

		// Update the nickname for the contact corresponding to this message if needed.
		contactPublicKeyBase58Check := messageEntryRes.SenderPublicKeyBase58Check
		if messageEntryRes.SenderPublicKeyBase58Check == user.PublicKeyBase58Check {
			contactPublicKeyBase58Check = messageEntryRes.RecipientPublicKeyBase58Check
		}

		contactNickname, contactExists := user.LocalState.PublicKeyToNickname[contactPublicKeyBase58Check]
		if !contactExists {
			// If this is a brand new contact, try and set the nickname to the merchant
			// username.
			contactPubKeyBytes, _, err := Base58CheckDecode(contactPublicKeyBase58Check)
			if err != nil {
				return errors.Wrapf(err, "updateUserFields: Problem decoding contact public "+
					"key: %s", contactPublicKeyBase58Check)
			}
			merchantEntry := utxoView._getMerchantEntryForPublicKey(contactPubKeyBytes)
			if merchantEntry != nil && !merchantEntry.isDeleted {
				contactNickname = string(merchantEntry.Username)
			} else {
				// If the user is not a merchant and if we don't have them stored in
				// our mapping then set their nickname to the empty string. This makes
				// it so we won't need to do this lookup again.
				contactNickname = ""
			}

			// Set the nickname according to what we found above.
			user.LocalState.PublicKeyToNickname[contactPublicKeyBase58Check] = contactNickname
		}

		// Update the contact entry for this message.
		contactEntry, contactExists := contactMap[contactPublicKeyBase58Check]
		if !contactExists {
			contactEntry = &MessageContactResponse{
				PublicKeyBase58Check: contactPublicKeyBase58Check,
				Nickname:             contactNickname,
				Messages:             []*MessageEntryResponse{},
			}
			contactMap[contactPublicKeyBase58Check] = contactEntry
			// Add the contact to the user's list of contacts.
			newContactEntries = append(newContactEntries, contactEntry)
		}
		contactEntry.Messages = append(contactEntry.Messages, messageEntryRes)
	}
	// At this point, we have a bunch of new contact entries. In order to avoid losing
	// the fields we want to persist from the old contact entries, go through and
	// preserve them.
	// TODO: This isn't a good way to do this but it works for now...
	oldContactMap := make(map[string]*MessageContactResponse)
	for _, contactEntry := range user.LocalState.OrderedContactsWithMessages {
		oldContactMap[contactEntry.PublicKeyBase58Check] = contactEntry
	}
	// Now go through and update the contacts. If the contact existed before then
	// just copy over the new messages. Otherwise, set the contact data afresh.
	user.LocalState.OrderedContactsWithMessages = []*MessageContactResponse{}
	for _, contactEntry := range newContactEntries {
		oldContactEntry, oldContactExists := oldContactMap[contactEntry.PublicKeyBase58Check]
		if oldContactExists {
			// Messages is the only thing we need to update.
			oldContactEntry.Messages = contactEntry.Messages
			contactEntry = oldContactEntry
		}

		// Always set the nickname according to the contact map.
		nickname, nicknameExists := user.LocalState.PublicKeyToNickname[contactEntry.PublicKeyBase58Check]
		if nicknameExists {
			contactEntry.Nickname = nickname
		}

		user.LocalState.OrderedContactsWithMessages = append(
			user.LocalState.OrderedContactsWithMessages, contactEntry)
	}

	// Get the UtxoEntries from the augmented view
	utxoEntries, err := fes.blockchain.GetSpendableUtxosForPublicKey(publicKeyBytes, fes.backendServer.mempool)
	if err != nil {
		return errors.Wrapf(err, "updateUserFields: Problem getting utxos from view: ")
	}
	totalBalanceNanos := uint64(0)
	utxoResponses := []*UtxoResponse{}
	for _, utxoEntry := range utxoEntries {
		utxoResponses = append(utxoResponses, UtxoEntryToResponse(utxoEntry, fes.Params))
		totalBalanceNanos += utxoEntry.AmountNanos
	}
	// Sort the UtxoResponses so that we return a consistent ordering.
	sort.Slice(utxoResponses, func(ii, jj int) bool {
		// Sort by BlockHeight and break ties with TxID:Index, which should be unique
		// for each UTXO.
		if utxoResponses[ii].BlockHeight == utxoResponses[jj].BlockHeight {
			if utxoResponses[ii].TxIDBase58Check == utxoResponses[jj].TxIDBase58Check {
				return utxoResponses[ii].Index < utxoResponses[jj].Index
			}
			return utxoResponses[ii].TxIDBase58Check < utxoResponses[jj].TxIDBase58Check
		}

		return utxoResponses[ii].BlockHeight < utxoResponses[jj].BlockHeight
	})
	user.Utxos = utxoResponses

	// Set the user's balance.
	user.BalanceNanos = totalBalanceNanos

	// We expect SeedInfo and LocalState are set and don't mess with them in this
	// function.

	return nil
}

func (fes *FrontendServer) updateUsers() error {
	topMerchantsRes, err := fes._getTopMerchantResponse()
	if err != nil {
		return fmt.Errorf("updateUsers: Problem getting top merchants: %v", err)
	}
	topMerchantMap := make(map[string]*MerchantEntryResponse)
	for _, topM := range topMerchantsRes.TopMerchants {
		topMerchantMap[topM.MerchantIDBase58Check] = topM
	}

	// Prevent duplicate users from cropping up.
	newUserList := []*User{}
	userMap := make(map[string]bool)
	for _, user := range fes.UserData.UserList {
		if _, exists := userMap[user.PublicKeyBase58Check]; exists {
			continue
		}
		userMap[user.PublicKeyBase58Check] = true
		newUserList = append(newUserList, user)
	}
	fes.UserData.UserList = newUserList

	for _, user := range fes.UserData.UserList {
		// If we get an error updating the user, log it but don't stop the show.
		if err := fes.updateUserFields(user, topMerchantMap); err != nil {
			glog.Errorf(fmt.Sprintf("updateUsers: Problem updating user with pk %s: %v", user.PublicKeyBase58Check, err))
		}
		// Make sure the LoggedInUser gets set to the proper reference.
		if fes.UserData.LoggedInUser != nil &&
			user.PublicKeyBase58Check == fes.UserData.LoggedInUser.PublicKeyBase58Check {
			fes.UserData.LoggedInUser = user
		}
	}

	if err := DbPutLocalUserData(fes.UserData, fes.blockchain.db); err != nil {
		return fmt.Errorf("UpdateUsers: Problem storing user data: %v", err)
	}

	return nil
}

func (fes *FrontendServer) UpdateUsers() error {
	fes.DataLock.Lock()
	defer fes.DataLock.Unlock()

	return fes.updateUsers()
}

// CreateUser ...
func (fes *FrontendServer) CreateUser(ww http.ResponseWriter, req *http.Request) {
	// Grab the DataLock for writing.
	fes.DataLock.Lock()
	defer fes.DataLock.Unlock()

	// Decode the request data.
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	createUserData := CreateUserRequest{}
	if err := decoder.Decode(&createUserData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CreateUser: Problem parsing request body: %v", err))
		return
	}

	// Verify that username is not the same as a pre-existing user.
	for _, existingUser := range fes.UserData.UserList {
		if createUserData.Username == existingUser.Username {
			_AddBadRequestError(ww, fmt.Sprintf("CreateUser: Username %v is not unique", createUserData.Username))
			return
		}
	}

	// Don't allow the username to be too long. Normally the blockchain will catch
	// this when the user actually goes to register but it helps to prevent
	// the error earlier.
	if len([]byte(createUserData.Username)) > MaxUsernameLengthBytes {
		_AddBadRequestError(ww, fmt.Sprintf("CreateUser: Username %v with length "+
			"(in bytes) of %d exceeds max username length (in bytes): %d",
			createUserData.Username, len([]byte(createUserData.Username)),
			MaxUsernameLengthBytes))
		return
	}

	// Convert the entropy into a mnemonic and make sure it matches the mnemonic
	// passed in.
	entropyBytes, err := hex.DecodeString(createUserData.EntropyHex)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CreateUser: Problem converting entropyHex to bytes: %+v", err))
		return
	}
	entropyMnemonic, err := bip39.NewMnemonic(entropyBytes)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CreateUser: Problem converting entropy to mnemonic: %+v", err))
		return
	}
	if entropyMnemonic != createUserData.Mnemonic {
		_AddBadRequestError(ww, fmt.Sprintf("CreateUser: Mnemonic computed from entropy (%s) doesn't match entropy passed (%s)", entropyMnemonic, createUserData.Mnemonic))
		return
	}

	// Compute a seed from the mnemonic and the extra text and verify that it matches
	// the seed passed in.
	seedBytes, err := hex.DecodeString(createUserData.SeedHex)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CreateUser: Error decoding SeedHex to bytes: %+v", err))
		return
	}
	computedSeedBytes, err := bip39.NewSeedWithErrorChecking(createUserData.Mnemonic, createUserData.ExtraText)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CreateUser: Error converting mnemonic and extra text to seed: %+v", err))
		return
	}
	if !reflect.DeepEqual(seedBytes, computedSeedBytes) {
		_AddBadRequestError(ww, fmt.Sprintf("CreateUser: Seed computed from mnemonic and extra text (%+v) does not match seed passed in (%+v)", computedSeedBytes, seedBytes))
		return
	}

	// Encrypt the seed using the password.
	encryptedSeed, pwSalt, pbkdf2Iters, err := EncryptSeed(seedBytes, createUserData.Password, fes.Params.DefaultPbkdf2Iterations)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CreateUser: Problem encrypting seed with password: %+v", err))
		return
	}

	// Decrypt the seed and make sure the result is equal as a sanity check.
	decryptedSeed, err := DecryptSeed(encryptedSeed, createUserData.Password, pwSalt, pbkdf2Iters)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CreateUser: Problem decrypting seed with password as a sanity check: %+v", err))
		return
	}
	if !reflect.DeepEqual(seedBytes, decryptedSeed) {
		_AddBadRequestError(ww, fmt.Sprintf("CreateUser: Seed decryption sanity check failed. Decrypted seed (%+v) is not equal to original seed (%+v)", decryptedSeed, seedBytes))
		return
	}

	// At this point, we have an encrypted seed and we are confident that
	// it is decryptable given the user's password.

	// Use the unencrypted seed to produce a public key for the user.
	pubKey, _, btcAddress, err := ComputeKeysFromSeed(seedBytes, IsBitcoinTestnet(fes.Params))
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CreateUser: Seed decryption sanity check failed. Decrypted seed (%+v) is not equal to original seed (%+v)", decryptedSeed, seedBytes))
		return
	}

	// Only set a referrer public key if it parses correctly. When left unset the
	// merchant gets the referral amount as a tip.
	referrerPublicKey := createUserData.ReferrerPublicKeyBase58Check
	referrerPkBytes, _, err := Base58CheckDecode(createUserData.ReferrerPublicKeyBase58Check)
	if err != nil || len(referrerPkBytes) != btcec.PubKeyBytesLenCompressed {
		referrerPublicKey = ""
	}

	// Convert the public key to base58.
	isPrivate := false
	pubKeyBase58Check := Base58CheckEncode(pubKey.SerializeCompressed(), isPrivate, fes.Params)

	newUser := &User{
		Username:                     createUserData.Username,
		PublicKeyBase58Check:         pubKeyBase58Check,
		ReferrerPublicKeyBase58Check: referrerPublicKey,
		SeedInfo: &SeedInfo{
			HasPassword:       (createUserData.Password != ""),
			EncryptedSeedHex:  hex.EncodeToString(encryptedSeed),
			PwSaltHex:         hex.EncodeToString(pwSalt),
			Pbkdf2Iterations:  pbkdf2Iters,
			BtcDepositAddress: btcAddress,
			IsTestnet:         IsBitcoinTestnet(fes.Params),
		},
		LocalState: &LocalState{
			OrderIDToBuyerMessage:     make(map[string]*BuyerMessage),
			OrderIDToRejectReason:     make(map[string]string),
			BitcoinTxnsToBroadcast:    make(map[string]*BitcoinBroadcastInfo),
			OutgoingTransactions:      make(map[string]*TransactionInfo),
			MessageKeyToDecryptedText: make(map[string]string),
			PublicKeyToNickname:       make(map[string]string),
		},
		BitcoinAPIResponse: &BlockCypherAPIFullAddressResponse{
			FinalBalance: 0,
		},

		// All the other fields will be set in the call to UpdateUsers below.
	}

	// Add the password to the in-memory password map for this user.
	fes.PublicKeyToPasswordMap[pubKeyBase58Check] = createUserData.Password

	// Add the new user to the UserList and call UpdateUsers to set all of
	// its fields.
	fes.UserData.UserList = append(fes.UserData.UserList, newUser)
	fes.UserData.LoggedInUser = newUser

	// The call to updateUsers will augment the newUser object from above and
	// store the updated state to the db.
	fes.updateUsers()

	res := CreateUserResponse{
		UserData: fes.UserData,
	}
	if err := json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("CreateUser: Problem encoding response as JSON: %v", err))
		return
	}
	return
}

type UpdateUserRequest struct {
	// What operation to perform. See supportedOperationTypes in UpdateUser().
	OperationType string

	// The below fields are required by some operations
	PublicKeyBase58Check string
	// Used to update the username of the LoggedInUser.
	NewUsername string
	// For the login operation, a password is required if the user being logged in
	// has a password set.
	Password string
}

type UpdateUserResponse struct {
	UserData *LocalUserData `json:"userData"`
}

func (fes *FrontendServer) UpdateUser(ww http.ResponseWriter, req *http.Request) {
	// Grab the DataLock for writing.
	fes.DataLock.Lock()
	defer fes.DataLock.Unlock()

	// Decode the request data.
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	request := UpdateUserRequest{}
	if err := decoder.Decode(&request); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("UpdateUser: Problem parsing request body: %v", err))
		return
	}

	supportedOperationTypes := map[string]bool{
		"logout": true,
		"login":  true,
		"update": true,
		"delete": true,
	}
	if _, operationTypeSupported := supportedOperationTypes[request.OperationType]; !operationTypeSupported {
		_AddBadRequestError(ww, fmt.Sprintf("UpdateUser: Unrecognized "+
			"OperationType: %s. Supported types: {%v}", request.OperationType, supportedOperationTypes))
	}

	if request.OperationType == "logout" {
		fes.UserData.LoggedInUser = nil

	} else if request.OperationType == "login" {
		// Public key is required for this operation.
		if request.PublicKeyBase58Check == "" {
			_AddBadRequestError(ww, fmt.Sprintf("UpdateUser: PublicKeyBase58Check is "+
				"required for login operation"))
			return
		}

		// Find the user in our UserList that matches the public key.
		var userToLogin *User
		for _, user := range fes.UserData.UserList {
			if user.PublicKeyBase58Check == request.PublicKeyBase58Check {
				userToLogin = user
				break
			}
		}
		if userToLogin == nil {
			_AddBadRequestError(ww, fmt.Sprintf("UpdateUser: Could not find user data "+
				"for public key %s", request.PublicKeyBase58Check))
			return
		}

		// Verify that the password for the user is correct. If the user has no password
		// set we're automatically OK here.
		password := ""
		if userToLogin.SeedInfo.HasPassword {
			password = request.Password
		}
		// If we can get the private key without an issue then the password is valid.
		_, _, err := fes._getPrivateKeyForPublicKey(request.PublicKeyBase58Check, password)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf(
				"UpdateUser: Invalid password with login operation: %v", err))
			return
		}
		// If we get here, we are sure password can be used to decrypt the seed so set it
		// in our password map for future reference.
		fes.PublicKeyToPasswordMap[request.PublicKeyBase58Check] = password

		fes.UserData.LoggedInUser = userToLogin

	} else if request.OperationType == "update" {
		if fes.UserData.LoggedInUser == nil {
			_AddBadRequestError(ww, fmt.Sprintf("UpdateUser: Cannot do update operation while LoggedInUser is null"))
			return
		}
		if request.NewUsername == "" {
			_AddBadRequestError(ww, fmt.Sprintf("UpdateUser: NewUsername is required with update operation"))
			return
		}

		fes.UserData.LoggedInUser.Username = request.NewUsername

	} else if request.OperationType == "delete" {
		// Public key is required for this operation.
		if request.PublicKeyBase58Check == "" {
			_AddBadRequestError(ww, fmt.Sprintf("UpdateUser: PublicKeyBase58Check is "+
				"required with delete operation"))
			return
		}
		// Find the user in our UserList who matches the public key.
		newUserList := []*User{}
		for _, user := range fes.UserData.UserList {
			if user.PublicKeyBase58Check == request.PublicKeyBase58Check {
				continue
			}
			newUserList = append(newUserList, user)
		}
		fes.UserData.UserList = newUserList

		if fes.UserData.LoggedInUser != nil &&
			fes.UserData.LoggedInUser.PublicKeyBase58Check == request.PublicKeyBase58Check {

			fes.UserData.LoggedInUser = nil
		}

	} else {
		_AddBadRequestError(ww, fmt.Sprintf("UpdateUser: Unrecognized "+
			"OperationType: %s. Supported types: {%v}", request.OperationType, supportedOperationTypes))
		return
	}

	// The call to updateUsers will store the updated state to the db.
	fes.updateUsers()

	res := UpdateUserResponse{
		UserData: fes.UserData,
	}
	if err := json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("UpdateUser: Problem encoding response as JSON: %v", err))
		return
	}
}

func (fes *FrontendServer) BroadcastListing(listingMessage *MsgUltranetListing) {
	// Use the backendServer to relay the listing to Peers. This shoud do
	// all of its heavy-lifting in a goroutine and so won't slow us down.
	fes.backendServer._relayListings([]*MsgUltranetListing{listingMessage})
	return
}

func (fes *FrontendServer) BroadcastTransaction(txn *MsgUltranetTxn) ([]*TxDesc, error) {
	// Use the backendServer to add the transaction to the mempool and
	// relay it to peers. When a transaction is created by the user there
	// is no need to consider a rateLimit and also no need to verifySignatures
	// because we generally will have done that already.
	txDescs, err := fes.backendServer._addNewTxnAndRelay(nil /*peer*/, txn, false /*rateLimit*/, false /*verifySignatures*/)
	if err != nil {
		return nil, errors.Wrapf(err, "FrontendServer.BroadcastTransaction: ")
	}
	return txDescs, nil
}

func (fes *FrontendServer) AugmentAndProcessTransactionWithSubsidy(
	txn *MsgUltranetTxn, pubKeyBase58 string, optionalPassword string,
	minFeeRateNanosPerKB uint64, inputSubsidy uint64, wantsSignature bool, wantsValidation bool,
	wantsBroadcast bool) (
	_totalInput uint64, _spendAmount uint64, _changeAmount uint64,
	_fees uint64, _err error) {

	// Note that the inner function here will lock the ChainLock for reading. This is
	// OK because the order of acquiring the DataLock before the ChainLock is the accepted
	// ordering.
	fes.DataLock.RLock()
	defer fes.DataLock.RUnlock()

	return fes._augmentAndProcessTransactionWithSubsidy(
		txn, pubKeyBase58, optionalPassword,
		minFeeRateNanosPerKB, inputSubsidy, wantsSignature, wantsValidation,
		wantsBroadcast)
}

func (fes *FrontendServer) AugmentAndProcessTransaction(
	txn *MsgUltranetTxn, pubKeyBase58 string, optionalPassword string,
	minFeeRateNanosPerKB uint64, wantsSignature bool, wantsValidation bool,
	wantsBroadcast bool) (
	_totalInput uint64, _spendAmount uint64, _changeAmount uint64,
	_fees uint64, _err error) {

	// Note that the inner function here will lock the ChainLock for reading. This is
	// OK because the order of acquiring the DataLock before the ChainLock is the accepted
	// ordering.
	fes.DataLock.RLock()
	defer fes.DataLock.RUnlock()

	return fes._augmentAndProcessTransactionWithSubsidy(
		txn, pubKeyBase58, optionalPassword,
		minFeeRateNanosPerKB, 0 /*inputSubsidy*/, wantsSignature, wantsValidation,
		wantsBroadcast)
}

func (fes *FrontendServer) _augmentAndProcessTransaction(
	txn *MsgUltranetTxn, pubKeyBase58 string, optionalPassword string,
	minFeeRateNanosPerKB uint64, wantsSignature bool, wantsValidation bool,
	wantsBroadcast bool) (
	_totalInput uint64, _spendAmount uint64, _changeAmount uint64,
	_fees uint64, _err error) {

	return fes._augmentAndProcessTransactionWithSubsidy(
		txn, pubKeyBase58, optionalPassword,
		minFeeRateNanosPerKB, 0 /*inputSubsidy*/, wantsSignature, wantsValidation,
		wantsBroadcast)
}

func (fes *FrontendServer) _processTransaction(
	txn *MsgUltranetTxn, pubKeyBase58 string, optionalPassword string,
	wantsSignature bool, wantsValidation bool, wantsBroadcast bool) error {

	// Sign the transaction with the sender's private key if the password is provided.
	// If the password is not provided, leave the transaction unsigned. Giving the
	// frontend the option to provide this allows it to do quick pings to get the fees
	// required for the transaction so it can show them to the user.
	if wantsSignature {
		// Get the private key corresponding to the from public key and find the
		// user corresponding to this as well. If a user doesn't exist with this
		// public key, we'll have an error.
		privKey, _, err := fes._getPrivateKeyForPublicKey(pubKeyBase58, optionalPassword)
		if err != nil {
			return fmt.Errorf("_augmentAndProcessTransaction: Problem getting private key "+
				"for public key %s: %v", pubKeyBase58, err)
		}
		txnSignature, err := txn.Sign(privKey)
		if err != nil {
			return fmt.Errorf("_augmentAndProcessTransaction: Error computing "+
				"transaction signature: %v", err)
		}
		txn.Signature = txnSignature
	} else {
		if wantsValidation || wantsBroadcast {
			return fmt.Errorf("_augmentAndProcessTransaction: Request has Sign=false but "+
				"has (Validate=%v, Broadcast=%v), which is not allowed because validation "+
				"requires a signature and broadcast requires validation (and therefore "+
				"a signature as well)", wantsValidation, wantsValidation)
		}
	}

	// At this point the transaction is fully formed. Validate it if the
	// caller asked us to.
	if wantsValidation {
		// Grab the block tip and use it as the height for validation.
		blockHeight := fes.blockchain.BlockTip().Height
		err := fes.blockchain.ValidateTransaction(
			txn,
			// blockHeight is set to the next block since that's where this
			// transaction will be mined at the earliest.
			blockHeight+1,
			true,  /*verifySignatures*/
			true,  /*verifyMerchantMerkleRoot*/
			false, /*enforceMinBitcoinBurnWork*/
			fes.backendServer.mempool)
		if err != nil {
			return fmt.Errorf("_augmentAndProcessTransaction: Problem validating txn: %v", err)
		}
	} else {
		if wantsBroadcast {
			return fmt.Errorf("_augmentAndProcessTransaction: Request has Broadcast=true but " +
				"Validate=false, which is not allowed because " +
				"broadcast requires validation")
		}
	}

	// Broadcast the transaction if the caller asked us to. Note that if we
	// get here and Broadcast is true then we've already validated the transaction
	// so all we need is to broadcast it.
	if wantsBroadcast {
		if _, err := fes.BroadcastTransaction(txn); err != nil {
			return fmt.Errorf("_augmentAndProcessTransaction: Problem broadcasting txn: %v", err)
		}
	}

	return nil
}

func (fes *FrontendServer) _augmentAndProcessTransactionWithSubsidy(
	txn *MsgUltranetTxn, pubKeyBase58 string, optionalPassword string,
	minFeeRateNanosPerKB uint64, inputSubsidy uint64, wantsSignature bool, wantsValidation bool,
	wantsBroadcast bool) (
	_totalInput uint64, _spendAmount uint64, _changeAmount uint64,
	_fees uint64, _err error) {

	// Add inputs to the transaction to satisfy the amount the user wants to burn,
	// if any. If we don't have enough total input to satisfy the constraints,
	// return an error.
	totalInput, spendAmount, changeAmount, fees, err :=
		fes.blockchain.AddInputsAndChangeToTransactionWithSubsidy(txn, minFeeRateNanosPerKB,
			inputSubsidy, fes.backendServer.mempool)
	if err != nil {
		return 0, 0, 0, 0, fmt.Errorf("_augmentAndProcessTransaction: Problem adding inputs and "+
			"change to transaction %v: %v", txn, err)
	}

	// Sanity check that the input is equal to:
	//   (spend amount + change amount + fees)
	if totalInput != (spendAmount + changeAmount + fees) {
		return 0, 0, 0, 0, fmt.Errorf("_augmentAndProcessTransaction: totalInput=%d is not equal "+
			"to the sum of the (spend amount=%d, change=%d, and fees=%d) which sums "+
			"to %d. This means there was likely a problem with AddInputsAndChangeToTransaction",
			totalInput, spendAmount, changeAmount, fees, (spendAmount + changeAmount + fees))
	}

	// At this point we know the transaction has enough input to cover the output
	// we want to send to the recipient plus the fees required to meet the feerate
	// specified (even if the signature has its maximum size). It also gives excess
	// change back to the sender public key.

	err = fes._processTransaction(
		txn, pubKeyBase58, optionalPassword, wantsSignature,
		wantsValidation, wantsBroadcast)
	if err != nil {
		return 0, 0, 0, 0, errors.Wrapf(
			err, "_augmentAndProcessTransaction: Problem processing transaction: ")
	}

	return totalInput, spendAmount, changeAmount, fees, nil
}

// UpdateMerchantRequest ...
type UpdateMerchantRequest struct {
	// A merchant is updated by passing their public key. From their public key,
	// we look up the private key and merchantID so we can complete the update.
	PublicKeyBase58Check string `json:"publicKeyBase58Check"`

	// The fields the user wants to update on the merchant.
	NewPublicKeyBase58Check string `json:"newPublicKeyBase58Check"`
	NewUsername             string `json:"newUsername"`
	NewDescription          string `json:"newDescription"`
	BurnAmountNanos         uint64 `json:"burnAmountNanos"`
	MinFeeRateNanosPerKB    uint64 `json:"minFeeRateNanosPerKB"`

	// Can be left unset when Signature is false or if the user legitimately
	// doesn't have a password. Additionally if the user already has their password
	// stored in memory, for example if they logged in earlier, then this field is
	// not required.
	Password string `json:"password"`
	// Whether or not we should sign the transaction after constructing it.
	// Setting this flag to false is useful in
	// cases where the caller just wants to construct the transaction
	// to see what the fees will be, for example.
	Sign bool `json:"sign"`
	// Whether or not we should fully validate the transaction.
	Validate bool `json:"validate"`
	// Whether or not we should broadcast the transaction after constructing
	// it. This will also validate the transaction if it's set.
	Broadcast bool `json:"broadcast"`
}

// UpdateMerchantResponse ...
type UpdateMerchantResponse struct {
	TotalInputNanos   uint64          `json:"totalInputNanos"`
	SpendAmountNanos  uint64          `json:"spendAmountNanos"`
	ChangeAmountNanos uint64          `json:"changeAmountNanos"`
	FeeNanos          uint64          `json:"feeNanos"`
	Transaction       *MsgUltranetTxn `json:"transaction"`
}

// UpdateMerchant ...
func (fes *FrontendServer) UpdateMerchant(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := &UpdateMerchantRequest{}
	if err := decoder.Decode(requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("UpdateMerchant: Problem parsing request body: %v", err))
		return
	}

	// TODO: Changing the merchant's public key is currently not supported in the frontend
	// because we don't have a good flow for allowing the user to enter the private
	// key material and password for the new public key they choose.
	if len(requestData.NewPublicKeyBase58Check) != 0 {
		_AddBadRequestError(ww, fmt.Sprintf("UpdateMerchant: Updating public key is "+
			"currently not supported in the frontend because we don't have a good "+
			"flow for getting the user to give us their private key material"))
		return
	}

	// Decode the user's public key. A merchant is updated by passing their public
	// key. From their public key, we look up the private key and merchantID so we
	// can complete the update.
	pubKeyBytes, _, err := Base58CheckDecode(requestData.PublicKeyBase58Check)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("UpdateMerchant: Problem decoding base58 "+
			"public key %s: %v", requestData.PublicKeyBase58Check, err))
		return
	}

	// Try to look up the user for the corresponding public key.
	user := fes.GetUserForPublicKey(requestData.PublicKeyBase58Check)
	if user == nil {
		_AddBadRequestError(ww, fmt.Sprintf("UpdateMerchant: Could not find user with "+
			"public key %v to update merchant info for", requestData.PublicKeyBase58Check))
		return
	}

	// If the user isn't a merchant or if the MerchantID isn't set then reject the
	// transaction.
	if user.MerchantEntry == nil || len(user.MerchantEntry.MerchantIDBase58Check) == 0 {
		_AddBadRequestError(ww, fmt.Sprintf("UpdateMerchant: User found %v is "+
			"not a merchant or MerchantID is not present", user))
		return
	}
	merchantIDBytes, _, err := Base58CheckDecode(user.MerchantEntry.MerchantIDBase58Check)
	if err != nil || len(merchantIDBytes) != HashSizeBytes {
		_AddBadRequestError(ww, fmt.Sprintf("UpdateMerchant: Problem decoding "+
			"MerchantID %s for user %v: %v", user.MerchantEntry.MerchantIDBase58Check, user, err))
		return
	}
	merchantID := &BlockHash{}
	copy(merchantID[:], merchantIDBytes)

	// As a slight hack, if the request has the username or the description
	// set to the same value as what the user had before, set them to the empty
	// string so that they don't get updated unnecessarily.
	if requestData.NewUsername == user.Username {
		requestData.NewUsername = ""
	}
	if requestData.NewDescription == user.MerchantEntry.Description {
		requestData.NewDescription = ""
	}

	// At this point we have the user object and we are confident the user
	// is a merchant with a valid MerchantID.

	// Assemble the transaction so that inputs can be found and fees can
	// be computed. Note we assume there will be no outputs for this type of
	// transaction.
	txn := &MsgUltranetTxn{
		// The inputs will be set below.
		TxInputs:  []*UltranetInput{},
		TxOutputs: []*UltranetOutput{},
		PublicKey: pubKeyBytes,
		TxnMeta: &UpdateMerchantMetadata{
			MerchantID: merchantID,
			// For the rest of the arguments, we just forward what we got passed-in.
			NewPublicKey:    nil, // Updating pubilc key not currently supported. See TODO above.
			NewUsername:     []byte(requestData.NewUsername),
			NewDescription:  []byte(requestData.NewDescription),
			BurnAmountNanos: requestData.BurnAmountNanos,
		},

		// We wait to compute the signature until we've added all the
		// inputs and change.
	}

	// Add inputs to the transaction and do signing, validation, and broadcast
	// depending on what the user requested.
	totalInput, spendAmount, changeAmount, fees, err := fes.AugmentAndProcessTransaction(
		txn, requestData.PublicKeyBase58Check,
		fes.GetPassword(requestData.PublicKeyBase58Check, requestData.Password),
		requestData.MinFeeRateNanosPerKB,
		requestData.Sign,
		requestData.Validate,
		requestData.Broadcast)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("UpdateMerchant: Error processing transaction: %v", err))
		return
	}

	// If we got here and if broadcast was requested then it means the
	// transaction passed validation and it's therefore reasonable to
	// update the user objects to reflect that. Note the function above
	// will have already broadcasted the transaction in this case so no
	// need to do it here.
	if requestData.Broadcast {
		fes.UpdateUsers()
	}

	// Return the transaction in the response along with some metadata. If we
	// get to this point and if the user requested that the transaction be
	// validated or broadcast, the user can assume that those operations
	// occurred successfully.
	res := UpdateMerchantResponse{
		TotalInputNanos:   totalInput,
		SpendAmountNanos:  spendAmount,
		ChangeAmountNanos: changeAmount,
		FeeNanos:          fees,
		Transaction:       txn,
	}
	if err := json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("UpdateMerchant: Problem encoding response as JSON: %v", err))
		return
	}
	return
}

func (fes *FrontendServer) GetPassword(publicKeyBase58Check string, overridePassword string) string {
	fes.DataLock.RLock()
	defer fes.DataLock.RUnlock()

	return fes._getPassword(publicKeyBase58Check, overridePassword)
}

func (fes *FrontendServer) _getPassword(publicKeyBase58Check string, overridePassword string) string {
	// Get the password for the user. If an override is set then it will override
	// anything we have stored for the user.
	if overridePassword != "" {
		return overridePassword
	}
	password := ""
	storedPassword, storedPasswordExists := fes.PublicKeyToPasswordMap[publicKeyBase58Check]
	if storedPasswordExists {
		password = storedPassword
	}
	return password
}

type RegisterMerchantRequest struct {
	Username             string
	MerchantDescription  string
	PublicKeyBase58Check string
	BurnAmountNanos      uint64
	MinFeeRateNanosPerKB uint64
	// Can be left unset when Signature is false or if the user legitimately
	// doesn't have a password. Can also be left unset if the user has logged
	// in recently as the password will be stored in memory.
	Password string
	// Whether or not we should sign the transaction after constructing it.
	// Setting this flag to false is useful in
	// cases where the caller just wants to construct the transaction
	// to see what the fees will be, for example.
	Sign bool
	// Whether or not we should fully validate the transaction.
	Validate bool
	// Whether or not we should broadcast the transaction after constructing
	// it. This will also validate the transaction if it's set.
	Broadcast bool
}

type RegisterMerchantResponse struct {
	TotalInputNanos   uint64          `json:"totalInputNanos"`
	SpendAmountNanos  uint64          `json:"spendAmountNanos"`
	ChangeAmountNanos uint64          `json:"changeAmountNanos"`
	FeeNanos          uint64          `json:"feeNanos"`
	Transaction       *MsgUltranetTxn `json:"transaction"`
}

// RegisterMerchant ...
func (fes *FrontendServer) RegisterMerchant(ww http.ResponseWriter, req *http.Request) {
	// Grab the DataLock for writing.
	fes.DataLock.Lock()
	defer fes.DataLock.Unlock()

	// Decode the request data.
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := &RegisterMerchantRequest{}
	if err := decoder.Decode(requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("RegisterMerchant: Problem parsing request body: %v", err))
		return
	}

	// Decode the user's public key.
	pubKeyBytes, _, err := Base58CheckDecode(requestData.PublicKeyBase58Check)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("RegisterMerchant: Problem decoding base58 public key %s: %v", requestData.PublicKeyBase58Check, err))
		return
	}

	// Assemble the transaction so that inputs can be found and fees can
	// be computed. Note we assume there will be no outputs for this type of
	// transaction.
	txn := &MsgUltranetTxn{
		// The inputs will be set below.
		TxInputs:  []*UltranetInput{},
		TxOutputs: []*UltranetOutput{},
		PublicKey: pubKeyBytes,
		TxnMeta: &RegisterMerchantMetadata{
			Username:        []byte(requestData.Username),
			Description:     []byte(requestData.MerchantDescription),
			BurnAmountNanos: requestData.BurnAmountNanos,
		},

		// We wait to compute the signature until we've added all the
		// inputs and change.
	}

	// Add inputs to the transaction and do signing, validation, and broadcast
	// depending on what the user requested.
	totalInput, spendAmount, changeAmount, fees, err := fes._augmentAndProcessTransaction(
		txn, requestData.PublicKeyBase58Check,
		fes._getPassword(requestData.PublicKeyBase58Check, requestData.Password),
		requestData.MinFeeRateNanosPerKB,
		requestData.Sign,
		requestData.Validate,
		requestData.Broadcast)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("RegisterMerchant: processing transaction: %v", err))
		return
	}

	// If we got here and if broadcast was requested then it means the
	// transaction passed validation and it's therefore reasonable to
	// update the user objects to reflect that.
	if requestData.Broadcast {
		fes.updateUsers()
	}

	// Return the transaction in the response along with some metadata. If we
	// get to this point and if the user requested that the transaction be
	// validated or broadcast, the user can assume that those operations
	// occurred successfully.
	res := RegisterMerchantResponse{
		TotalInputNanos:   totalInput,
		SpendAmountNanos:  spendAmount,
		ChangeAmountNanos: changeAmount,
		FeeNanos:          fees,
		Transaction:       txn,
	}
	if err := json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("RegisterMerchant: Problem encoding response as JSON: %v", err))
		return
	}
	return
}

func _resizeImage(imageObj image.Image, maxDim uint) image.Image {
	// Get the width and height.
	imgWidth := imageObj.Bounds().Max.X
	imgHeight := imageObj.Bounds().Max.Y

	// Resize the image based on which side is longer. Doing it this way preserves the
	// image's aspect ratio while making sure it isn't too large.
	var resizedImage image.Image
	if imgWidth > imgHeight {
		newWidth := uint(imgWidth)
		if newWidth >= maxDim {
			newWidth = maxDim
		}
		resizedImage = resize.Resize(newWidth, 0, imageObj, resize.Lanczos3)
	} else {
		newHeight := uint(imgHeight)
		if newHeight >= maxDim {
			newHeight = maxDim
		}
		resizedImage = resize.Resize(0, newHeight, imageObj, resize.Lanczos3)
	}

	return resizedImage
}

func (fes *FrontendServer) _addDraftImageBase64(base64String string) {
}

// AddDraftImageRequest ...
type AddDraftImageRequest struct {
	ImageBase64 string `json:"image_base64"`
}

type AddDraftImageResponse struct{}

// AddDraftImage ...
func (fes *FrontendServer) AddDraftImage(ww http.ResponseWriter, req *http.Request) {
	// Acquire the DataLock for writing first.
	fes.DataLock.Lock()
	defer fes.DataLock.Unlock()

	// Decode the request data.
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	reqData := AddDraftImageRequest{}
	if err := decoder.Decode(&reqData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AddDraftImage: Problem parsing request body: %v", err))
		return
	}

	// If the image uploaded is nil or empty return an error.
	if len(reqData.ImageBase64) == 0 {
		_AddBadRequestError(ww, fmt.Sprintf("AddDraftImage: Empty image uploaded"))
		return
	}

	// Convert the base64 input image to a byte slice so we can process it.
	imageBytes, err := base64.StdEncoding.DecodeString(reqData.ImageBase64)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AddDraftImage: Problem decoding base64 input image: %v", err))
		return
	}

	// Decode the image into an object.
	imageObj, _, err := image.Decode(bytes.NewReader(imageBytes))
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AddDraftImage: Problem processing image: %v", err))
		return
	}

	// Resize the image to conform to listing dimensions.
	listingImage := _resizeImage(imageObj, MaxListingDimension)
	// Convert the listing image to jpeg.
	jpegListing := bytes.Buffer{}
	if err := jpeg.Encode(bufio.NewWriter(&jpegListing), listingImage, nil); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AddDraftImage: Problem converting image to JPEG format: %v", err))
		return
	}
	fes.DraftImages = append(fes.DraftImages, &DraftImage{
		// The ID is just a counter. Kindof annoying we can't do ++ here but whatever
		ID:    fes.NextDraftImageID,
		Image: jpegListing.Bytes(),
	})
	fes.NextDraftImageID++

	// If there are no other images in the list, use the image added to produce and
	// add a thumbnail image.
	if len(fes.DraftImages) == 1 {
		if err := fes._makeThumbnail(fes.DraftImages[0].ID); err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("AddDraftImage: Problem creating thumbnail: %v", err))
			return
		}
	}

	res := AddDraftImageResponse{}
	if err := json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AddDraftImage: Problem encoding response as JSON: %v", err))
		return
	}
}

type LoadListingDraftImagesRequest struct {
	MerchantIDBase58Check string
	ListingIndex          int64
}
type LoadListingDraftImagesResponse struct {
	ImageIDs []uint64
}

func (fes *FrontendServer) LoadListingDraftImages(ww http.ResponseWriter, req *http.Request) {
	// Acquire the DataLock for writing first.
	fes.DataLock.Lock()
	defer fes.DataLock.Unlock()

	// Decode the request data.
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	reqData := LoadListingDraftImagesRequest{}
	if err := decoder.Decode(&reqData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf(
			"LoadListingDraftImages: Problem parsing request body: %v", err))
		return
	}

	// Ensure the ListingIndex is in range. If it's not return an error.
	if reqData.ListingIndex < 0 ||
		reqData.ListingIndex > int64(fes.Params.MaxListingsPerMerchant) {

		_AddBadRequestError(ww, fmt.Sprintf(
			"LoadListingDraftImages: Invalid ListingIndex value: %d", reqData.ListingIndex))
		return
	}

	// Decode the MerchantID
	merchantIDBytes, _, err := Base58CheckDecode(reqData.MerchantIDBase58Check)
	if err != nil || len(merchantIDBytes) != HashSizeBytes {
		_AddBadRequestError(ww, fmt.Sprintf(
			"LoadListingDraftImages: Problem decoding MerchantID base58 %s: %v",
			reqData.MerchantIDBase58Check, err))
		return
	}
	merchantID := &BlockHash{}
	copy(merchantID[:], merchantIDBytes[:])

	// Look up listing message using the MerchantID and ListingIndex.
	listingMessage := DbGetListingMessage(
		fes.blockchain.db, merchantID, uint32(reqData.ListingIndex))
	if listingMessage == nil {
		_AddBadRequestError(ww, fmt.Sprintf("LoadListingDraftImages: Could not find listing "+
			"message for MerchantID %v and listingIndex %d",
			merchantID, reqData.ListingIndex))
		return
	}

	// Convert all of the Base64 images into DraftImage objects starting with the thumbnail,
	// which always has ID=0.
	draftImages := []*DraftImage{&DraftImage{
		ID:    0,
		Image: listingMessage.ThumbnailImage,
	}}
	for _, imageBytes := range listingMessage.ListingImages {
		draftImages = append(draftImages, &DraftImage{
			ID:    fes.NextDraftImageID,
			Image: imageBytes,
		})
		fes.NextDraftImageID++
	}

	// Set the draft images equal to the images we found above.
	fes.DraftImages = draftImages

	// At this point we have set the DraftImages to be equal to the listing's images.
	// Grab the IDs so we can return them.
	res := &LoadListingDraftImagesResponse{}
	res.ImageIDs = []uint64{}
	for _, draftImage := range fes.DraftImages {
		// The thumbnail doesn't get included in this.
		if draftImage.ID == 0 {
			continue
		}
		res.ImageIDs = append(res.ImageIDs, draftImage.ID)
	}

	// Encode the response.
	if err := json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf(
			"LoadListingDraftImages: Problem encoding response as JSON: %v", err))
		return
	}
}

// GetDraftImageIDsResponse ...
type GetDraftImageIDsResponse struct {
	ImageIDs []uint64 `json:"imageIDs"`
}

// GetDraftImageIDs ...
func (fes *FrontendServer) GetDraftImageIDs(ww http.ResponseWriter, req *http.Request) {
	// Acquire the DataLock for reading first.
	fes.DataLock.RLock()
	defer fes.DataLock.RUnlock()

	idsToReturn := &GetDraftImageIDsResponse{}

	// Gather the IDs (skip the thumbnail).
	for _, draftImage := range fes.DraftImages {
		if draftImage.ID == 0 {
			continue
		}
		idsToReturn.ImageIDs = append(idsToReturn.ImageIDs, draftImage.ID)
	}

	if err := json.NewEncoder(ww).Encode(idsToReturn); err != nil {
		errorString := fmt.Sprintf("GetDraftImageIDs: Problem serializing "+
			"object to JSON: %v\n Request: %v", idsToReturn, req)
		glog.Error(errors.Wrapf(err, errorString))
		ww.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(ww).Encode(JSONError{Code: http.StatusInternalServerError, Text: errorString})
		return
	}
}

// GetListingImage ...
func (fes *FrontendServer) GetListingImage(ww http.ResponseWriter, req *http.Request) {
	// Acquire the DataLock for reading first.
	fes.DataLock.RLock()
	defer fes.DataLock.RUnlock()

	// Parse all the vars from the URL
	vars := mux.Vars(req)
	mainIDStr, mainIDExists := vars["publicKeyOrMerchantIDBase58Check"]
	if !mainIDExists {
		_AddBadRequestError(ww, fmt.Sprintf("GetListingImage: Missing public key or "+
			"merchantID. Usage: /<publickeybase58check|merchantIDBase58Check>/<listingIndex>/<imageIndex>"))
		return
	}
	listingIndexStr, listingIndexExists := vars["listingIndex"]
	if !listingIndexExists {
		_AddBadRequestError(ww, fmt.Sprintf("GetListingImage: Missing listingIndex. "+
			"Usage: /<publickeybase58check|merchantIDBase58Check>/<listingIndex>/<imageIndex>"))
		return
	}
	listingIndex, err := strconv.Atoi(listingIndexStr)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetListingImage: listingIndex value %s did "+
			"not parse into an int: %v",
			listingIndexStr, err))
		return
	}
	imageIndexStr, imageIndexExists := vars["imageIndex"]
	if !imageIndexExists {
		_AddBadRequestError(ww, fmt.Sprintf("GetListingImage: Missing imageIndex. "+
			"Usage: /<publickeybase58check|merchantIDBase58Check>/<listingIndex>/<imageIndex>"))
		return
	}
	imageIndex, err := strconv.Atoi(imageIndexStr)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetListingImage: imageIndex value %s did "+
			"not parse into an int: %v",
			imageIndexStr, err))
		return
	}

	// A mainIDStr is either a MerchantID or a public key (both base58 encoded).
	// In the latter case we look up a MerchantID using the public key.
	decodedBytes, _, err := Base58CheckDecode(mainIDStr)
	var merchantID *BlockHash
	if len(decodedBytes) == btcec.PubKeyBytesLenCompressed {
		// If we're given a public key then use it to look up the MerchantID.
		merchantID = DbGetMerchantIDForPubKey(fes.blockchain.db, decodedBytes)
	} else if len(decodedBytes) == HashSizeBytes {
		merchantID = &BlockHash{}
		copy(merchantID[:], decodedBytes[:])
	} else {
		_AddBadRequestError(ww, fmt.Sprintf("GetListingImage: First param after slash "+
			"must consist of either publickeybase58check OR merchantidbase58check but"+
			"value was %s with byte length was %d, which is incompatible with both",
			mainIDStr, len(decodedBytes)))
		return
	}

	// If we were unable to find a MerchantID for this value then return an error.
	if merchantID == nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetListingImage: Param "+
			"value %s did not correspond to a valid MerchantID",
			mainIDStr))
		return
	}

	// Actually fetch the listing.
	listingMessageFound := DbGetListingMessage(fes.blockchain.db, merchantID, uint32(listingIndex))
	if listingMessageFound == nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetListingImage: Could not find listing "+
			"message for MerchantID %v and listingIndex %d",
			merchantID, listingIndex))
		return
	}

	// Verify the image index is not out of bounds.
	if imageIndex >= len(listingMessageFound.ListingImages) {
		_AddBadRequestError(ww, fmt.Sprintf("GetListingImage: ImageIndex for listing %d "+
			"is greater than or equal to the number of images in the listing %d",
			imageIndex, len(listingMessageFound.ListingImages)))
		return
	}

	// Normally the header will have been set at this point to application/json but
	// this should adjust it to image instead.
	ww.Header().Set("Content-Type", "image/jpeg")
	ww.Write(listingMessageFound.ListingImages[imageIndex])
}

// GetDraftImage ...
func (fes *FrontendServer) GetDraftImage(ww http.ResponseWriter, req *http.Request) {
	// Acquire the DataLock for reading first.
	fes.DataLock.RLock()
	defer fes.DataLock.RUnlock()

	draftImageIDParams, imageIDExists := req.URL.Query()[DraftImageIDParam]

	// If the request doesn't have a image id then error.
	if !imageIDExists || len(draftImageIDParams) == 0 {
		_AddBadRequestError(ww, fmt.Sprintf("GetDraftImage: Missing %s parameter", DraftImageIDParam))
		return
	}
	// Try to parse the image ID into an int.
	imageID, err := strconv.Atoi(draftImageIDParams[0])
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetDraftImage: Problem parsing %s value: %s",
			DraftImageIDParam, draftImageIDParams[0]))
		return
	}

	// Because there are so few images, iterating over all the images to find the one
	// with the matching ID is fine.
	var imageFound *DraftImage
	for _, draftImage := range fes.DraftImages {
		if int(draftImage.ID) == imageID {
			imageFound = draftImage
		}
	}

	if imageFound == nil {
		_AddBadRequestError(ww, fmt.Sprintf(
			"GetDraftImage: Draft image with ID %s does not exist",
			draftImageIDParams[0]))
		return
	}

	// Normally the header will have been set at this point to application/json but
	// this should adjust it to image instead.
	ww.Header().Set("Content-Type", "image/jpeg")
	ww.Write(imageFound.Image)
}

// UpdateDraftImages ...
func (fes *FrontendServer) UpdateDraftImages(ww http.ResponseWriter, req *http.Request) {
	// Acquire the DataLock for writing first.
	fes.DataLock.Lock()
	defer fes.DataLock.Unlock()

	// Decode the request data.
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	var reqData struct {
		ImageIDs []uint64 `json:"imageIDs"`
	}
	if err := decoder.Decode(&reqData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("UpdateDraftImages: Problem parsing request body: %v", err))
		return
	}

	// Go through the IDs in the request and make sure they exist as images currently.
	// While doing that, construct the new DraftImages slice.
	validIDs := make(map[uint64]*DraftImage)
	for _, draftImage := range fes.DraftImages {
		validIDs[draftImage.ID] = draftImage
	}
	newDraftImages := []*DraftImage{}
	for _, imageID := range reqData.ImageIDs {
		if _, idExists := validIDs[imageID]; !idExists {
			_AddBadRequestError(ww, fmt.Sprintf("UpdateDraftImages: ID %d does not exist", imageID))
			return
		}

		// If the imageID is valid, grab its DraftImage and add it to the list.
		newDraftImages = append(newDraftImages, validIDs[imageID])
	}
	// Manually add back the thumbnail if there are any images in left in the array.
	// Otherwise don't add it. This makes the frontend experience smoother.
	if len(newDraftImages) != 0 {
		newDraftImages = append(newDraftImages, validIDs[0])
	}

	// Finally, assign the new slice.
	fes.DraftImages = newDraftImages
}

// Note: It's assumed the DataLock is held for writing when this is called.
func (fes *FrontendServer) _makeThumbnail(imageID uint64) error {
	// Find the image with the matching ID. Because there are very few images brute
	// force iteration is fine.
	var imageFound *DraftImage
	for _, draftImage := range fes.DraftImages {
		if draftImage.ID == imageID {
			imageFound = draftImage
			break
		}
	}
	if imageFound == nil {
		return fmt.Errorf("_makeThumbnail: Could not find image with ID %d", imageID)
	}

	// We have to convert the image bytes into an image object to resize.
	imageObj, _, err := image.Decode(bytes.NewReader(imageFound.Image))
	if err != nil {
		return fmt.Errorf("_makeThumbnail: Problem converting image bytes into image object: %v", err)
	}

	// Resize the image to thumbnail dimensions.
	thumbnail := _resizeImage(imageObj, MaxThumbnailDimension)
	// Convert to Jpeg format.
	jpegThumbnail := bytes.Buffer{}
	if err := jpeg.Encode(bufio.NewWriter(&jpegThumbnail), thumbnail, nil); err != nil {
		return fmt.Errorf("_makeThumbnail: Problem converting image to JPEG format: %v", err)
	}

	// If a thumbnail exists, just oerwrite it. Otherwise, append it.
	var previousThumbnail *DraftImage
	for _, draftImage := range fes.DraftImages {
		if draftImage.ID == 0 {
			previousThumbnail = draftImage
			draftImage.Image = jpegThumbnail.Bytes()
			break
		}
	}
	// If it doesn't exist, add the thumbnail to our list.
	if previousThumbnail == nil {
		fes.DraftImages = append(fes.DraftImages, &DraftImage{
			// ID of 0 is always reserved for the thumbnail.
			ID:    0,
			Image: jpegThumbnail.Bytes(),
		})
	}

	return nil
}

// UpdateThumbnail ...
func (fes *FrontendServer) UpdateThumbnail(ww http.ResponseWriter, req *http.Request) {
	// Acquire the DataLock for writing first.
	fes.DataLock.Lock()
	defer fes.DataLock.Unlock()

	// Decode the request data.
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	var reqData struct {
		ImageID uint64 `json:"imageID"`
	}
	if err := decoder.Decode(&reqData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("UpdateThumbnail: Problem parsing request body: %v", err))
		return
	}

	// The helper does the leg-work.
	if err := fes._makeThumbnail(reqData.ImageID); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("UpdateThumbnail: Problem creating thumbnail: %v", err))
		return
	}
}

func (fes *FrontendServer) GetUserForPublicKey(publicKeyBase58Check string) *User {
	fes.DataLock.RLock()
	defer fes.DataLock.RUnlock()

	return fes._getUserForPublicKey(publicKeyBase58Check)
}

func (fes *FrontendServer) _getUserForPublicKey(publicKeyBase58Check string) *User {
	var userFound *User
	for _, currentUser := range fes.UserData.UserList {
		if currentUser.PublicKeyBase58Check == publicKeyBase58Check {
			userFound = currentUser
			break
		}
	}
	return userFound
}

func (fes *FrontendServer) GetPrivateKeyForPublicKey(publicKeyBase58Check string, password string) (*btcec.PrivateKey, *User, error) {
	fes.DataLock.RLock()
	defer fes.DataLock.RUnlock()

	return fes._getPrivateKeyForPublicKey(publicKeyBase58Check, password)
}

func (fes *FrontendServer) _getPrivateKeyForPublicKey(publicKeyBase58Check string, password string) (*btcec.PrivateKey, *User, error) {
	userFound := fes._getUserForPublicKey(publicKeyBase58Check)
	if userFound == nil {
		return nil, nil, fmt.Errorf("_getPrivateKeyForPublicKey: User with public key %s does not exist", publicKeyBase58Check)
	}
	seedInfo := userFound.SeedInfo
	encryptedSeedBytes, err := hex.DecodeString(seedInfo.EncryptedSeedHex)
	pwSaltBytes, _ := hex.DecodeString(seedInfo.PwSaltHex)
	unencryptedSeedBytes, err := DecryptSeed(encryptedSeedBytes, password, pwSaltBytes, seedInfo.Pbkdf2Iterations)
	if err != nil {
		return nil, nil, errors.Wrapf(err, "_getPrivateKeyForPublicKey: Problem decoding seed")
	}
	_, privKey, _, err := ComputeKeysFromSeed(unencryptedSeedBytes, seedInfo.IsTestnet)
	if err != nil {
		return nil, nil, errors.Wrapf(err, "_getPrivateKeyForPublicKey: Problem generating keys from seed")
	}

	return privKey, userFound, nil
}

func _computeFeesForTxSize(txnCopy *MsgUltranetTxn, spendAmount uint64, totalInput uint64, feeRateNanosPerKB uint64) uint64 {
	// Compute what fees the transaction needs given its current inputs
	// and its current fee rate.
	txnBytes, _ := txnCopy.ToBytes(false /*preSignature*/)
	fees := uint64(len(txnBytes)) * feeRateNanosPerKB / 1000

	// Determine whether the transaction in its current state needs
	// a change output. If it does, then increment the fees to account
	// for the extra output.
	//
	// TODO: This isn't perfect and will result in an output occasionally being
	// paid for but that we won't actually wind up adding.
	totalNeededBeforeChangeOutput := (spendAmount + fees)
	if totalInput-totalNeededBeforeChangeOutput > 0 {
		fees = uint64(len(txnBytes)+OutputSizeBytes) * feeRateNanosPerKB / 1000
	}

	return fees
}

// SendUltraRequest ...
type SendUltraRequest struct {
	SenderPublicKeyBase58Check    string
	RecipientPublicKeyBase58Check string
	AmountNanos                   int64
	MinFeeRateNanosPerKB          uint64
	// Can be left unset when Signature is false or if the user legitimately
	// doesn't have a password. Can also be left unset if the user has logged
	// in recently as the password will be stored in memory.
	Password string
	// Whether or not we should sign the transaction after constructing it.
	// Setting this flag to false is useful in
	// cases where the caller just wants to construct the transaction
	// to see what the fees will be, for example.
	Sign bool
	// Whether or not we should fully validate the transaction.
	Validate bool
	// Whether or not we should broadcast the transaction after constructing
	// it. This will also validate the transaction if it's set.
	Broadcast bool

	// TODO: Perhaps it could be useful to allow sending of Ultra by using
	// a private key directly rather than using a password to decrypt the
	// private key of an already-registered user. Could make testing slightly
	// easier as well. When private key is set, we could just ignore the
	// password param.
}

// SendUltraResponse ...
type SendUltraResponse struct {
	TotalInputNanos   uint64
	SpendAmountNanos  uint64
	ChangeAmountNanos uint64
	FeeNanos          uint64
	TxIDBase58Check   string
	Transaction       *MsgUltranetTxn
}

// SendUltra ...
func (fes *FrontendServer) SendUltra(ww http.ResponseWriter, req *http.Request) {
	fes.DataLock.Lock()
	defer fes.DataLock.Unlock()

	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := SendUltraRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SendUltra: Problem parsing request body: %v", err))
		return
	}

	// Decode the sender public key.
	senderPkBytes, _, err := Base58CheckDecode(requestData.SenderPublicKeyBase58Check)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SendUltra: Problem decoding sender base58 public key %s: %v", requestData.SenderPublicKeyBase58Check, err))
		return
	}

	// Decode the recipient's public key.
	recipientPkBytes, _, err := Base58CheckDecode(requestData.RecipientPublicKeyBase58Check)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SendUltra: Problem decoding recipient base58 public key %s: %v", requestData.RecipientPublicKeyBase58Check, err))
		return
	}

	// If the AmountNanos is less than zero then we have a special case where we create
	// a transaction with the maximum spend.
	var txnn *MsgUltranetTxn
	var totalInputt uint64
	var spendAmountt uint64
	var changeAmountt uint64
	var feeNanoss uint64
	if requestData.AmountNanos < 0 {
		// Create a MAX transaction
		txnn, totalInputt, spendAmountt, feeNanoss, err = fes.blockchain.CreateMaxSpend(
			senderPkBytes, recipientPkBytes, requestData.MinFeeRateNanosPerKB,
			fes.backendServer.mempool)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("SendUltra: Error processing MAX transaction: %v", err))
			return
		}

		// Sanity check that the input is equal to:
		//   (spend amount + change amount + fees)
		if totalInputt != (spendAmountt + changeAmountt + feeNanoss) {
			_AddBadRequestError(ww, fmt.Sprintf("SendUltra: totalInput=%d is not equal "+
				"to the sum of the (spend amount=%d, change=%d, and fees=%d) which sums "+
				"to %d. This means there was likely a problem with CreateMaxSpend",
				totalInputt, spendAmountt, changeAmountt, feeNanoss, (spendAmountt+changeAmountt+feeNanoss)))
			return
		}

		// Process the transaction according to whether the user wants us to
		// sign/validate/broadcast it.
		err = fes._processTransaction(
			txnn, requestData.SenderPublicKeyBase58Check,
			fes._getPassword(requestData.SenderPublicKeyBase58Check, requestData.Password),
			requestData.Sign,
			requestData.Validate,
			requestData.Broadcast)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("SendUltra: Problem processing transaction: %v", err))
			return
		}

	} else {
		// In this case, we are spending what the user asked us to spend as opposed to
		// spending the maximum amount posssible.

		// Create the transaction outputs and add the recipient's public key and the
		// amount we want to pay them
		txnOutputs := []*UltranetOutput{}
		txnOutputs = append(txnOutputs, &UltranetOutput{
			PublicKey: recipientPkBytes,
			// If we get here we know the amount is non-negative.
			AmountNanos: uint64(requestData.AmountNanos),
		})

		// Assemble the transaction so that inputs can be found and fees can
		// be computed.
		txnn = &MsgUltranetTxn{
			// The inputs will be set below.
			TxInputs:  []*UltranetInput{},
			TxOutputs: txnOutputs,
			PublicKey: senderPkBytes,
			TxnMeta:   &BasicTransferMetadata{},
			// We wait to compute the signature until we've added all the
			// inputs and change.
		}

		// Add inputs to the transaction and do signing, validation, and broadcast
		// depending on what the user requested.
		totalInputt, spendAmountt, changeAmountt, feeNanoss, err = fes._augmentAndProcessTransaction(
			txnn, requestData.SenderPublicKeyBase58Check,
			fes._getPassword(requestData.SenderPublicKeyBase58Check, requestData.Password),
			requestData.MinFeeRateNanosPerKB,
			requestData.Sign,
			requestData.Validate,
			requestData.Broadcast)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("SendUltra: Error processing regular transaction: %v", err))
			return
		}
	}

	// If we got here and if broadcast was requested then it means the
	// transaction passed validation and it's therefore reasonable to
	// update the user objects to reflect that.
	txID := PkToString(txnn.Hash()[:], fes.Params)
	if requestData.Broadcast {
		// If we're broadcasting the transaction then add it to our list of
		// transactions.
		recipientPks := []string{}
		recipientAmounts := []uint64{}
		txnBytes, _ := txnn.ToBytes(false)
		for _, output := range txnn.TxOutputs {
			recipientPks = append(recipientPks, PkToString(output.PublicKey, fes.Params))
			recipientAmounts = append(recipientAmounts, output.AmountNanos)
		}
		txnInfo := &TransactionInfo{
			TotalInputNanos:   totalInputt,
			SpendAmountNanos:  spendAmountt,
			ChangeAmountNanos: changeAmountt,
			FeeNanos:          feeNanoss,
			TxIDBase58Check:   txID,

			// These are Base58Check encoded
			RecipientPublicKeys:   recipientPks,
			RecipientAmountsNanos: recipientAmounts,

			TransactionHex: hex.EncodeToString(txnBytes),

			//Transaction:    txnn,

			TimeAdded: time.Now().Unix(),
		}
		userFound := fes._getUserForPublicKey(requestData.SenderPublicKeyBase58Check)
		if userFound != nil {
			userFound.LocalState.OutgoingTransactions[txnInfo.TxIDBase58Check] = txnInfo
		}

		// Update all the user objects.
		fes.updateUsers()
	}

	// Return the transaction in the response along with some metadata. If we
	// get to this point and if the user requested that the transaction be
	// validated or broadcast, the user can assume that those operations
	// occurred successfully.
	res := SendUltraResponse{
		TotalInputNanos:   totalInputt,
		SpendAmountNanos:  spendAmountt,
		ChangeAmountNanos: changeAmountt,
		FeeNanos:          feeNanoss,
		TxIDBase58Check:   txID,
		Transaction:       txnn,
	}
	if err := json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SendUltra: Problem encoding response as JSON: %v", err))
		return
	}
	return
}

// LoadTestRequest ...
type LoadTestRequest struct {
}

// LoadTestResponse ...
type LoadTestResponse struct {
}

func (fes *FrontendServer) _processLoadTestTxn(txn *MsgUltranetTxn, privBytes []byte, validate bool) error {
	privKey, _ := btcec.PrivKeyFromBytes(btcec.S256(), privBytes)
	txnSignature, err := txn.Sign(privKey)
	if err != nil {
		return errors.Wrapf(err, "_processLoadTestTxn: Signature issue: ")
	}
	txn.Signature = txnSignature

	if validate {
		// Validate the transaction before broadcasting it as a sanity check.
		err = fes.blockchain.ValidateTransaction(
			txn,
			// blockHeight is set to the next block since that's where this
			// transaction will be mined at the earliest.
			fes.blockchain.BlockTip().Height+1,
			true,  /*verifySignatures*/
			true,  /*verifyMerchantMerkleRoot*/
			false, /*enforceMinBitcoinBurnWork*/
			fes.backendServer.mempool)
		if err != nil {
			return errors.Wrapf(err, "_processLoadTestTxn: Validation issue: ")
		}
	}

	// Now broadcast the transaction.
	if _, err := fes.BroadcastTransaction(txn); err != nil {
		return errors.Wrapf(err, "_processLoadTestTxn: Broadcast issue: ")
	}

	return nil
}

// LoadTest ...
func (fes *FrontendServer) LoadTest(ww http.ResponseWriter, req *http.Request) {
	// A key pair we assume has some Ultra to start with.
	// Run transaction_util with manual_entropy_hex=0x00 to get this key.
	masterPrivBytes := []byte{0xcb, 0x47, 0x93, 0xfa, 0x23, 0xe9, 0x84, 0x37, 0xe2, 0xd3, 0x76, 0x55, 0xea, 0xaa, 0x59, 0xcf, 0x3, 0xa0, 0x63, 0x7e, 0xa8, 0x90, 0xf8, 0x5a, 0x85, 0xd9, 0x19, 0x46, 0xe9, 0x21, 0x4c, 0x64}
	masterPubBytes := []byte{0x3, 0x42, 0xd9, 0x43, 0xb8, 0xdb, 0xa9, 0x3a, 0x4c, 0xe2, 0x9b, 0x85, 0x84, 0x79, 0xc6, 0x7f, 0x1e, 0x4f, 0x11, 0x10, 0xee, 0xcb, 0xe1, 0xf8, 0x3d, 0xc0, 0x1b, 0x45, 0x5e, 0xb8, 0xb1, 0x23, 0xb3}
	fmt.Printf("Master public key: %s\n", PkToString(masterPubBytes, fes.Params))

	for counter := 0; ; counter++ {
		fmt.Printf("Running iteration %d\n", counter)

		// Create 1000 new private keys and 1000 corresponding outputs that
		// pay them from the master pub key. Note a single block reward should
		// be enough to cover this.
		privKeys := []*btcec.PrivateKey{}
		txnOutputs := []*UltranetOutput{}
		amountPerKey := uint64(1000)
		keysPerIter := 4000
		for ii := 0; ii < keysPerIter; ii++ {
			currentPriv, err := btcec.NewPrivateKey(btcec.S256())
			if err != nil {
				panic(err)
			}
			privKeys = append(privKeys, currentPriv)

			txnOutputs = append(txnOutputs, &UltranetOutput{
				PublicKey:   currentPriv.PubKey().SerializeCompressed(),
				AmountNanos: amountPerKey,
			})
		}

		fmt.Printf("Generated keys %d\n", counter)

		// Create a transaction that pays all of the random keys above. Note a single
		// block reward should be enough to cover all this.
		{
			txn := &MsgUltranetTxn{
				// The inputs will be set below.
				TxInputs:  []*UltranetInput{},
				TxOutputs: txnOutputs,
				PublicKey: masterPubBytes,
				TxnMeta:   &BasicTransferMetadata{},
				// We wait to compute the signature until we've added all the
				// inputs and change.
			}
			_, _, _, _, err :=
				fes.blockchain.AddInputsAndChangeToTransactionWithSubsidy(txn, 10, /*minFeeRate*/
					0 /*inputSubsidy*/, fes.backendServer.mempool)
			if err != nil {
				panic(err)
			}

			err = fes._processLoadTestTxn(txn, masterPrivBytes, true /*validate*/)
			if err != nil {
				panic(err)
			}
		}

		fmt.Printf("Processed initial txn %d\n", counter)

		// At this point all 5,000 of the random keys from above should have some
		// Ultra to throw around.

		// Generate keysPerIter transactions, one from each of the keys.
		for ii, privKey := range privKeys {
			// Send the maximum amount back to the key itself.
			txn, _, _, _, err := fes.blockchain.CreateMaxSpend(
				privKey.PubKey().SerializeCompressed(), privKey.PubKey().SerializeCompressed(), 10,
				fes.backendServer.mempool)
			if err != nil {
				glog.Error(err)
				continue
			}

			err = fes._processLoadTestTxn(txn, privKey.Serialize(), false /*validate*/)
			if err != nil {
				glog.Error(err)
				continue
			}

			if ii%100 == 0 {
				fmt.Printf("LoadTest: Processing txn %d out of %d with counter %d\n", ii, keysPerIter, counter)
			}
		}

		fmt.Printf("Done with iteration %d\n", counter)
	}
}

// SignatureRequest ...
type SignatureRequest struct {
	// The public key of the user that is signing the message. Only needed for
	// Action=sign.
	PublicKeyBase58Check string
	// The text that is being signed or verified depending on the value of Action.
	MessageText string

	// Whether to compute the signature of the MessageText or to verify that it has
	// a valid signature.
	Action string

	// Can be left unset if the user has logged
	// in recently as the password will be stored in memory.
	Password string

	// TODO: Perhaps it could be useful to allow signatures of using
	// a private key directly rather than using a password to decrypt the
	// private key of an already-registered user. Could make testing slightly
	// easier as well. When private key is set, we could just ignore the
	// password param.
}

// SignatureResponse ...
type SignatureResponse struct {
	// Only set when Action="sign"
	SignedMessage string
	// Only set when Action="verify"
	IsValidSignature bool
}

// Signature ...
func (fes *FrontendServer) Signature(ww http.ResponseWriter, req *http.Request) {
	fes.DataLock.Lock()
	defer fes.DataLock.Unlock()

	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := SignatureRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("Signature: Problem parsing request body: %v", err))
		return
	}

	allowedActions := make(map[string]bool)
	allowedActions["sign"] = true
	allowedActions["verify"] = true
	if _, actionAllowed := allowedActions[requestData.Action]; !actionAllowed {
		_AddBadRequestError(ww, fmt.Sprintf("Signature: Action %s not allowed. "+
			"Actions allowed are: %v", requestData.Action, allowedActions))
		return
	}

	var res *SignatureResponse
	switch requestData.Action {
	case "sign":
		// Compute a signature of the MessageText and return it in the response.

		// Fetch the the private key for the corresponding public key.
		password := fes._getPassword(requestData.PublicKeyBase58Check, requestData.Password)
		privKey, _, err := fes._getPrivateKeyForPublicKey(
			requestData.PublicKeyBase58Check, password)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("Signature: Problem decoding private "+
				"key with password for public key %s", requestData.PublicKeyBase58Check))
			return
		}

		// Compute a hash of the message bytes.
		messageHash := Sha256DoubleHash([]byte(requestData.MessageText))
		messageSignature, err := privKey.Sign(messageHash[:])
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("Signature: Problem signing message: %v", err))
			return
		}

		// Add the public key and the signature to the end of the message. The exact
		// formatting is:
		// 	 MessageText\n<signature_hex>\nPublicKeyBase58Check
		signedMessage := requestData.MessageText + "\n" + hex.EncodeToString(messageSignature.Serialize()) + "\n" + requestData.PublicKeyBase58Check

		res = &SignatureResponse{
			SignedMessage: signedMessage,
		}

	case "verify":
		// The format for a signed message is:
		//   MessageText\n<signature_hex>\nPublicKeyBase58Check.
		stringPieces := strings.Split(requestData.MessageText, "\n")
		// We need to have at least three pieces, possibly more if MessageText contains
		// newlines itself.
		if len(stringPieces) < 3 {
			_AddBadRequestError(ww, fmt.Sprintf("Signature: Invalid signature; format "+
				"must be <message text><newline><signature_hex><newline><public_key_base58check>"))
			return
		}

		// Extract the signature hex and the public key and re-assemble the message without
		// those last two pieces.
		signatureHex := stringPieces[len(stringPieces)-2]
		signatureBytes, err := hex.DecodeString(signatureHex)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("Signature: Problem decoding "+
				"signature hex: %s: %v", signatureHex, err))
			return
		}
		signature, err := btcec.ParseDERSignature(signatureBytes, btcec.S256())
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("Signature: Problem parsing serialized "+
				"signature: %s: %v", signatureHex, err))
			return
		}
		publicKeyBase58Check := stringPieces[len(stringPieces)-1]
		pkBytes, _, err := Base58CheckDecode(publicKeyBase58Check)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("Signature: Problem decoding base58 "+
				"public key %s: %v", publicKeyBase58Check, err))
			return
		}
		publicKey, err := btcec.ParsePubKey(pkBytes, btcec.S256())
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("Signature: Problem parsing "+
				"public key %s: %v", publicKeyBase58Check, err))
			return
		}
		messageText := strings.Join(stringPieces[:len(stringPieces)-2], "\n")
		messageHash := Sha256DoubleHash([]byte(messageText))

		validSignature := false
		if signature.Verify(messageHash[:], publicKey) {
			validSignature = true
		}
		res = &SignatureResponse{
			IsValidSignature: validSignature,
		}

	default:
		_AddBadRequestError(ww, fmt.Sprintf("Signature: Action %s is allowed but "+
			"unhandled; this should never happen", requestData.Action))
		return
	}

	if err := json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("Signature: Problem encoding response as "+
			"JSON: %v", err))
		return
	}
	return
}

// UpdateMessagesRequest ...
type UpdateMessagesRequest struct {
	// This is required with all requests. Specifies the user we are updating
	// information for.
	PublicKeyBase58Check string

	// This is required with all requests. It specifies which contact we should update.
	ContactPublicKeyBase58Check string
	// Optional. When set, we update the contact's nickname.
	UpdateNickname string
}

// UpdateMessagesResponse ...
type UpdateMessagesResponse struct {
}

// UpdateMessages ...
func (fes *FrontendServer) UpdateMessages(ww http.ResponseWriter, req *http.Request) {
	fes.DataLock.Lock()
	defer fes.DataLock.Unlock()

	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := UpdateMessagesRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("UpdateMessages: Problem parsing request body: %v", err))
		return
	}

	// Find the user assocated with the passed-in public key.
	userFound := fes._getUserForPublicKey(requestData.PublicKeyBase58Check)
	if userFound == nil {
		_AddBadRequestError(ww, fmt.Sprintf("UpdateMessages: Could not find user for "+
			"public key %s:", requestData.PublicKeyBase58Check))
		return
	}

	// Update the current users so we have the latest messages set.
	fes.updateUsers()

	// Find the contact in the user's list. If we don't have them then error.
	var contactFound *MessageContactResponse
	for _, contactEntry := range userFound.LocalState.OrderedContactsWithMessages {
		if contactEntry.PublicKeyBase58Check == requestData.ContactPublicKeyBase58Check {
			contactFound = contactEntry
			break
		}
	}
	if contactFound == nil {
		_AddBadRequestError(ww, fmt.Sprintf("UpdateMessages: Could not find contact for "+
			"public key %s:", requestData.ContactPublicKeyBase58Check))
		return
	}

	// Set the contact's number of messages read equal to the number of messages. This
	// removes any notifications.
	contactFound.NumMessagesRead = int64(len(contactFound.Messages))

	// If a public key is set for a recipient, update the nickname as well.
	if requestData.UpdateNickname != "" {
		userFound.LocalState.PublicKeyToNickname[requestData.ContactPublicKeyBase58Check] = requestData.UpdateNickname
	}

	// Return all the data associated with the transaction in the response
	res := UpdateMessagesResponse{}
	if err := json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("UpdateMessages: Problem encoding response as "+
			"JSON: %v", err))
		return
	}
	return
}

// SendMessageRequest ...
type SendMessageRequest struct {
	SenderPublicKeyBase58Check    string
	RecipientPublicKeyBase58Check string
	MessageText                   string
	MinFeeRateNanosPerKB          uint64

	// Can be left unset when Signature is false or if the user legitimately
	// doesn't have a password. Can also be left unset if the user has logged
	// in recently as the password will be stored in memory.
	Password string
	// Whether or not we should sign the transaction after constructing it.
	// Setting this flag to false is useful in
	// cases where the caller just wants to construct the transaction
	// to see what the fees will be, for example.
	Sign bool
	// Whether or not we should fully validate the transaction.
	Validate bool
	// Whether or not we should broadcast the transaction after constructing
	// it. This will also validate the transaction if it's set.
	Broadcast bool

	// TODO: Perhaps it could be useful to allow sending of Ultra by using
	// a private key directly rather than using a password to decrypt the
	// private key of an already-registered user. Could make testing slightly
	// easier as well. When private key is set, we could just ignore the
	// password param.
}

// SendMessageResponse ...
type SendMessageResponse struct {
	TstampNanos uint64

	TotalInputNanos   uint64
	ChangeAmountNanos uint64
	FeeNanos          uint64
	Transaction       *MsgUltranetTxn
}

// SendMessage ...
func (fes *FrontendServer) SendMessage(ww http.ResponseWriter, req *http.Request) {
	fes.DataLock.Lock()
	defer fes.DataLock.Unlock()

	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := SendMessageRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SendMessage: Problem parsing request body: %v", err))
		return
	}

	// Decode the sender public key.
	senderPkBytes, _, err := Base58CheckDecode(requestData.SenderPublicKeyBase58Check)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SendMessage: Problem decoding sender "+
			"base58 public key %s: %v", requestData.SenderPublicKeyBase58Check, err))
		return
	}

	// Decode the recipient's public key.
	recipientPkBytes, _, err := Base58CheckDecode(requestData.RecipientPublicKeyBase58Check)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SendMessage: Problem decoding recipient "+
			"base58 public key %s: %v", requestData.RecipientPublicKeyBase58Check, err))
		return
	}

	// Try and create the message for the user.
	tstamp := uint64(time.Now().UnixNano())
	txn, totalInput, changeAmount, fees, err := fes.blockchain.CreatePrivateMessageTxn(
		senderPkBytes, recipientPkBytes, requestData.MessageText,
		tstamp,
		requestData.MinFeeRateNanosPerKB, fes.backendServer.mempool)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SendMessage: Problem creating transaction: %v", err))
		return
	}

	// Process the transaction according to whether the user wants us to
	// sign/validate/broadcast it.
	err = fes._processTransaction(
		txn, requestData.SenderPublicKeyBase58Check,
		fes._getPassword(requestData.SenderPublicKeyBase58Check, requestData.Password),
		requestData.Sign,
		requestData.Validate,
		requestData.Broadcast)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SendMessage: Problem processing transaction: %v", err))
		return
	}

	// If we got here and if broadcast was requested then it means the
	// transaction passed validation and it's therefore reasonable to
	// update the user objects to reflect that. We store the unencrypted
	// message on the user object so that it can be shown to the user
	// as part of the history (otherwise we wouldn't be able to decrypt it).
	if requestData.Broadcast {
		messageKey := MakeMessageKey(senderPkBytes, tstamp)
		userFound := fes._getUserForPublicKey(requestData.SenderPublicKeyBase58Check)
		if userFound != nil {
			userFound.LocalState.MessageKeyToDecryptedText[messageKey.StringKey(fes.Params)] = requestData.MessageText
		}

		// Update all the user objects.
		fes.updateUsers()

		// When we send a message, make sure that the user corresponding to the recipient
		// public key has all of their messages read.
		for _, contactEntry := range userFound.LocalState.OrderedContactsWithMessages {
			if contactEntry.PublicKeyBase58Check == requestData.RecipientPublicKeyBase58Check {
				contactEntry.NumMessagesRead = int64(len(contactEntry.Messages))
				break
			}
		}
	}

	// Return all the data associated with the transaction in the response
	res := SendMessageResponse{
		TstampNanos: tstamp,

		TotalInputNanos:   totalInput,
		ChangeAmountNanos: changeAmount,
		FeeNanos:          fees,
		Transaction:       txn,
	}
	if err := json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("SendMessage: Problem encoding response as "+
			"JSON: %v", err))
		return
	}
	return
}

// BurnBitcoinRequest ...
type BurnBitcoinRequest struct {
	// The public key of the user who we're creating the burn for.
	PublicKeyBase58Check string
	// Note: When BurnAmountSatoshis is negative, we assume that the user wants
	// to burn the maximum amount of satoshi she has available.
	BurnAmountSatoshis   int64
	FeeRateSatoshisPerKB int64

	// Can be left unset when Signature is false or if the user legitimately
	// doesn't have a password. Can also be left unset if the user has logged
	// in recently as the password will be stored in memory.
	Password string
	// Whether or not we should sign the transaction after constructing it.
	// Setting this flag to false is useful in
	// cases where the caller just wants to construct the transaction
	// to see what the fees will be, for example.
	Sign bool
	// Whether or not we should broadcast the transaction after constructing
	// it. This will also validate the transaction if it's set.
	Broadcast bool
}

// BurnBitcoinResponse ...
type BurnBitcoinResponse struct {
	TotalInputSatoshis   uint64
	BurnAmountSatoshis   uint64
	ChangeAmountSatoshis uint64
	FeeSatoshis          uint64
	BitcoinTransaction   *wire.MsgTx
}

// BurnBitcoin ...
func (fes *FrontendServer) BurnBitcoin(ww http.ResponseWriter, req *http.Request) {
	fes.DataLock.Lock()
	defer fes.DataLock.Unlock()

	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := BurnBitcoinRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("BurnBitcoin: Problem parsing request body: %v", err))
		return
	}

	// Make sure the fee rate isn't negative.
	if requestData.FeeRateSatoshisPerKB < 0 {
		_AddBadRequestError(ww, fmt.Sprintf("BurnBitcoin: BurnAmount %d or "+
			"FeeRateSatoshisPerKB %d cannot be negative",
			requestData.BurnAmountSatoshis, requestData.FeeRateSatoshisPerKB))
		return
	}

	// Find the user associated with the public key.
	userFound := fes._getUserForPublicKey(requestData.PublicKeyBase58Check)
	if userFound == nil {
		_AddBadRequestError(ww, fmt.Sprintf("BurnBitcoin: Couldn't find user for "+
			"public key %s", requestData.PublicKeyBase58Check))
		return
	}

	// If BurnAmountSatoshis is negative, set it to the maximum amount of satoshi
	// that can be burned while accounting for the fee.
	burnAmountSatoshis := requestData.BurnAmountSatoshis
	if burnAmountSatoshis < 0 {
		bitcoinUtxos, err := BlockCypherExtractBitcoinUtxosFromResponse(
			userFound.BitcoinAPIResponse, userFound.SeedInfo.BtcDepositAddress, fes.Params)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("BurnBitcoin: Problem getting "+
				"Bitcoin UTXOs: %v", err))
			return
		}
		totalInput := int64(0)
		for _, utxo := range bitcoinUtxos {
			totalInput += utxo.AmountSatoshis
		}
		// We have one output in this case because we're sending all of the Bitcoin to
		// the burn address with no change left over.
		txFee := _estimateBitcoinTxFee(
			len(bitcoinUtxos), 1, uint64(requestData.FeeRateSatoshisPerKB))
		if int64(txFee) > totalInput {
			_AddBadRequestError(ww, fmt.Sprintf("BurnBitcoin: Transaction fee %d is "+
				"so high that we can't spend the inputs total=%d", txFee, totalInput))
			return
		}

		burnAmountSatoshis = totalInput - int64(txFee)
		glog.Tracef("BurnBitcoin: Getting ready to burn %d Satoshis", burnAmountSatoshis)
	}

	// Prevent the user from creating a burn transaction with a dust output since
	// this will result in the transaction being rejected by Bitcoin nodes.
	if burnAmountSatoshis < 1000 {
		_AddBadRequestError(ww, "BurnBitcoin: You must burn at least .00001 Bitcoins "+
			"or else Bitcoin nodes will reject your transaction as \"dust.\"")
		return
	}

	// Get a UtxoSource from the user's BitcoinAPI data. Note we could change the API
	// around a bit to not have to do this but oh well.
	utxoSource := func(spendAddr string, params *UltranetParams) ([]*BitcoinUtxo, error) {
		if spendAddr != userFound.SeedInfo.BtcDepositAddress {
			return nil, fmt.Errorf("ButnBitcoin.UtxoSource: Expecting deposit address %s "+
				"but got unrecognized address %s", userFound.SeedInfo.BtcDepositAddress, spendAddr)
		}
		return BlockCypherExtractBitcoinUtxosFromResponse(
			userFound.BitcoinAPIResponse, userFound.SeedInfo.BtcDepositAddress, fes.Params)
	}

	var bitcoinTxn *wire.MsgTx
	var totalInputSatoshis uint64
	var fee uint64
	var err error
	if requestData.Sign {
		// Decode the user's private key with the password.
		password := fes._getPassword(requestData.PublicKeyBase58Check, requestData.Password)
		privKey, _, err := fes._getPrivateKeyForPublicKey(
			requestData.PublicKeyBase58Check, password)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("BurnBitcoin: Problem decoding private "+
				"key with password for public key %s", requestData.PublicKeyBase58Check))
			return
		}

		bitcoinTxn, totalInputSatoshis, fee, err = CreateBitcoinSpendTransaction(
			uint64(burnAmountSatoshis),
			uint64(requestData.FeeRateSatoshisPerKB),
			privKey,
			fes.Params.BitcoinBurnAddress,
			fes.Params,
			utxoSource)

	} else {
		bitcoinTxn, totalInputSatoshis, fee, err = CreateUnsignedBitcoinSpendTransaction(
			uint64(burnAmountSatoshis),
			uint64(requestData.FeeRateSatoshisPerKB),
			userFound.SeedInfo.BtcDepositAddress,
			fes.Params.BitcoinBurnAddress,
			fes.Params,
			utxoSource)
	}
	if err != nil {
		_AddBadRequestError(
			ww, fmt.Sprintf("BurnBitcoin: Problem creating Bitcoin spend "+
				"transaction given input: %v", err))
		return
	}

	if requestData.Broadcast {
		glog.Tracef("BurnBitcoin: Broadcasting Bitcoin txn: %v",
			bitcoinTxn)

		// It is not safe to broadcast transactions if any of the transactions have not
		// yet been registered by the API. Return an error when this is the case.
		for txid, broadcastInfo := range userFound.LocalState.BitcoinTxnsToBroadcast {
			hasEnoughTimeElapsed := broadcastInfo.TimeCreated.Add(60 * time.Second).Before(time.Now())
			if !broadcastInfo.ApiResponseReturned && !hasEnoughTimeElapsed {
				_AddBadRequestError(
					ww, fmt.Sprintf("BurnBitcoin: Transaction with TxID %s has not yet had "+
						"enough time to propagate through the network. Please give it up to "+
						"two minutes to do so before executing another transaction", txid))
				return
			}
		}

		// Note this is OK to modify because we're holding the lock at the top of the
		// function.
		userFound.LocalState.BitcoinTxnsToBroadcast[bitcoinTxn.TxHash().String()] = &BitcoinBroadcastInfo{
			BitcoinTxn: bitcoinTxn,
			// The transaction will not be in the API response when it is initially created.
			ApiResponseReturned: false,
			TimeCreated:         time.Now(),
		}
		// Note this runs a goroutine so no need to worry about it slowing us down.
		fes.blockchain.bitcoinManager.BroadcastTxn(bitcoinTxn)
		// Just update the users for good measure.
		fes.updateUsers()

		// In a situation where the user wants us to broadcast a burn transaction,
		// do a semi-immediate update of the BitcoinAPIResponse with the hope that it
		// will contain the data for this transaction.
		go func() {
			// This should be about the amount of time it takes the API to pick up
			// a new transaction.
			time.Sleep(5 * time.Second)
			// Note these will re-acquire the DataLock but that is OK because it's a
			// separate goroutine.
			fes.UpdateLoggedInUserBitcoinAPIResponse()
			fes.UpdateAndBroadcastBitcoinTxns()
		}()
	}

	res := &BurnBitcoinResponse{
		TotalInputSatoshis:   totalInputSatoshis,
		BurnAmountSatoshis:   uint64(burnAmountSatoshis),
		FeeSatoshis:          fee,
		ChangeAmountSatoshis: totalInputSatoshis - uint64(burnAmountSatoshis) - fee,
		BitcoinTransaction:   bitcoinTxn,
	}
	if err := json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("BurnBitcoin: Problem encoding response as JSON: %v", err))
		return
	}
}

type ReprocessBitcoinBlockResponse struct {
	Message string
}

// ReprocessBitcoinBlock ...
func (fes *FrontendServer) ReprocessBitcoinBlock(ww http.ResponseWriter, req *http.Request) {
	// Parse all the vars from the URL
	vars := mux.Vars(req)
	blockHashHexOrHeight, blockHashHexOrHeightExists := vars["blockHashHexOrblockHeight"]
	if !blockHashHexOrHeightExists {
		_AddBadRequestError(ww, fmt.Sprintf("ReprocessBitcoinBlock: Missing block hash hex or height parameter after the slash. "+
			"Usage: curl localhost:8080/reprocess-bitcoin-block/<block hash or block height>"))
		return
	}

	res := &ReprocessBitcoinBlockResponse{}
	// If the parameter has the length of a Bitcoin block hash then we interpret it as such.
	if len(blockHashHexOrHeight) == HashSizeBytes*2 {
		hash, err := chainhash.NewHashFromStr(blockHashHexOrHeight)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("ReprocessBitcoinBlock: Problem decoding "+
				"block hash hex: %v", err))
			return
		}

		glog.Tracef("ReprocessBitcoinBlock: Requesting Bitcoin block with hash: %v", hash)
		fes.blockchain.bitcoinManager.RequestBitcoinBlock(*hash)

		res.Message = fmt.Sprintf("Requested block %v for reprocessing", hash)
	} else {
		// If the parameter does not look like a block hash then we interpret it as a block
		// height.
		blockHeight, err := strconv.Atoi(blockHashHexOrHeight)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf(
				"ReprocessBitcoinBlock: Problem decoding block height: %v", err))
			return
		}

		if blockHeight < 0 || int64(blockHeight) > int64(fes.blockchain.bitcoinManager.HeaderTip().Height) {
			_AddBadRequestError(ww, fmt.Sprintf(
				"ReprocessBitcoinBlock: Height provided is less than zero or exceeds "+
					"maximum height known, which is %d", blockHeight))
			return
		}

		blockNode := fes.blockchain.bitcoinManager.HeaderAtHeight(uint32(blockHeight))
		if blockNode == nil {
			_AddBadRequestError(ww, fmt.Sprintf(
				"ReprocessBitcoinBlock: Did not find Bitcoin block with height: %d", blockHeight))
			return
		}

		res.Message = fmt.Sprintf("Requested block %v with height %d for reprocessing", (chainhash.Hash)(*blockNode.Hash), blockHeight)
	}

	// Return the response.
	if err := json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("ReprocessBitcoinBlock: Problem encoding response as JSON: %v", err))
		return
	}
}

// PlaceOrderRequest ...
type PlaceOrderRequest struct {
	SenderPublicKeyBase58Check string

	Listing *SingleListingResponse

	RequiredFields    []string
	OptionalFields    []string
	ItemQuantity      float64
	FeeRateNanosPerKB float64

	// These should sum up to what the user is expecting to pay.
	//
	// = ItemQuantity * Listing.PricePerUnitNanos
	ItemTotalNanos float64
	TipAmountNanos float64
	// = FeeRateNanosPerKB * txnSizeBytes / 1000
	ExpectedTotalFeeNanos float64

	// Can be left unset when Signature is false or if the user legitimately
	// doesn't have a password.
	Password string
	// Whether or not we should sign the transaction after constructing it.
	// Setting this flag to false is useful in
	// cases where the caller just wants to construct the transaction
	// to see what the fees will be, for example.
	Sign bool
	// Whether or not we should fully validate the transaction.
	Validate bool
	// Whether or not we should broadcast the transaction after constructing
	// it. This will also validate the transaction if it's set.
	Broadcast bool
}

// PlaceOrderResponse ...
type PlaceOrderResponse struct {
	TotalInputNanos         uint64
	SpendAmountNanos        uint64
	ChangeAmountNanos       uint64
	FeeNanos                uint64
	TransactionSizeBytes    uint64
	ActualFeeRateNanosPerKB uint64
	Transaction             *MsgUltranetTxn
	OrderIDBase58Check      string
}

// PlaceOrder ...
func (fes *FrontendServer) PlaceOrder(ww http.ResponseWriter, req *http.Request) {
	fes.DataLock.Lock()
	defer fes.DataLock.Unlock()

	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := PlaceOrderRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("PlaceOrder: Problem parsing request body: %v", err))
		return
	}

	// Decode the public key and check that it's valid.
	senderPkBytes, _, err := Base58CheckDecode(requestData.SenderPublicKeyBase58Check)
	if err != nil || len(senderPkBytes) != btcec.PubKeyBytesLenCompressed {
		_AddBadRequestError(ww, fmt.Sprintf(
			"PlaceOrder: Problem decoding sender base58 public key %s: %v",
			requestData.SenderPublicKeyBase58Check, err))
		return
	}

	// Verify that the listing and the MerchantEntry are provided.
	if requestData.Listing == nil {
		_AddBadRequestError(ww, fmt.Sprintf(
			"PlaceOrder: Listing field must be set on requrest"))
		return
	}
	if requestData.Listing.MerchantEntry == nil {
		_AddBadRequestError(ww, fmt.Sprintf(
			"PlaceOrder: Listing.MerchantEntry field must be set on requrest"))
		return
	}

	// Decode the MerchantID and check that it belongs to a real merchant. Pull
	// up the MerchantEntry for that merchant.
	merchantIDBase58Check := requestData.Listing.MerchantEntry.MerchantIDBase58Check
	merchantIDBytes, _, err := Base58CheckDecode(merchantIDBase58Check)
	if err != nil || len(merchantIDBytes) != HashSizeBytes {
		_AddBadRequestError(ww, fmt.Sprintf(
			"PlaceOrder: Problem decoding MerchantID base58 %s: %v",
			merchantIDBase58Check, err))
		return
	}
	merchantID := &BlockHash{}
	copy(merchantID[:], merchantIDBytes[:])

	// Pull up the listing for the merchant to ensure she has one. Verify that the
	// key fields haven't changed.
	// - PricePerUnitNanos
	// - RequiredFields
	listingIndex := requestData.Listing.ListingIndex
	listingMessageFound := DbGetListingMessage(
		fes.blockchain.db, merchantID, uint32(listingIndex))
	if listingMessageFound == nil {
		_AddBadRequestError(ww, fmt.Sprintf(
			"PlaceOrder: Listing does not exist in db for (merchantID: %s, "+
				"listingIndex: %d)", merchantIDBase58Check, listingIndex))
		return
	}
	// The commissions includes the amount that will be sent to the referrer.
	itemCommissionsWithReferrerAmount, err := _computeCommissionsFromPriceNanos(
		listingMessageFound.PricePerUnitNanos,
		fes.Params.CommissionBasisPoints+fes.Params.ReferrerCommissionBasisPoints)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf(
			"PlaceOrder: Error computing commissionsWithReferrerAmount from price per untit nanos: %d",
			itemCommissionsWithReferrerAmount))
		return
	}
	if (listingMessageFound.PricePerUnitNanos + itemCommissionsWithReferrerAmount) != requestData.Listing.PricePerUnitNanos {
		_AddBadRequestError(ww, fmt.Sprintf(
			"PlaceOrder: PricePerUnitNanos found on DB listing %d differs from "+
				"PricePerUnitNanos on passed-in listing %d",
			listingMessageFound.PricePerUnitNanos+itemCommissionsWithReferrerAmount, requestData.Listing.PricePerUnitNanos))
		return
	}
	// Now isolate the part that is actual commissions from the part that we're
	// sending to the referrer.
	itemCommissions, err := _computeCommissionsFromPriceNanos(
		listingMessageFound.PricePerUnitNanos,
		fes.Params.CommissionBasisPoints)

	tipCommissionsWithReferrerAmount, merchantTipRevenue, err := _computeCommissionsAndRevenueFromPayment(
		uint64(requestData.TipAmountNanos),
		fes.Params.CommissionBasisPoints+fes.Params.ReferrerCommissionBasisPoints)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf(
			"PlaceOrder: Error computing tipCommissionsWithReferrerAmount from tip: %d",
			uint64(requestData.TipAmountNanos)))
	}
	// Now isolate the actual commissions from the referrer amount.
	tipCommissions, err := _computeCommissionsFromPriceNanos(
		merchantTipRevenue,
		fes.Params.CommissionBasisPoints)
	// The referrer amount is what's left after subtracting commissions from the
	// amount paid for the item and the amount paid as a tip.
	referrerAmount := (itemCommissionsWithReferrerAmount - itemCommissions +
		tipCommissionsWithReferrerAmount - tipCommissions)

	// Get the user object to determine if a referrer is set. If there is no user or
	// if a valid referrer is not set then the referrerAmount goes back to the merchant
	// the user is buying from.
	user := fes._getUserForPublicKey(requestData.SenderPublicKeyBase58Check)
	referrerPublicKey := requestData.Listing.MerchantEntry.PublicKeyBase58Check
	if user != nil && user.ReferrerPublicKeyBase58Check != "" {
		referrerPublicKey = user.ReferrerPublicKeyBase58Check
	}

	if len(listingMessageFound.RequiredFields) !=
		len(requestData.Listing.RequiredFields)+len(requestData.Listing.OptionalFields) {
		_AddBadRequestError(ww, fmt.Sprintf(
			"PlaceOrder: RequiredFields found on DB listing %d differs from "+
				"RequiredFields on passed-in listing %d",
			len(listingMessageFound.RequiredFields),
			len(requestData.Listing.RequiredFields)+len(requestData.Listing.OptionalFields)))
		return
	}

	// Sanity-check that the correct numer of required fields are set.
	if (len(requestData.RequiredFields) + len(requestData.OptionalFields)) !=
		(len(requestData.Listing.RequiredFields) + len(requestData.Listing.OptionalFields)) {

		_AddBadRequestError(ww, fmt.Sprintf(
			"PlaceOrder: RequiredFields have length %d differs from "+
				"RequiredFields on passed-in listing %d",
			(len(requestData.RequiredFields)+len(requestData.OptionalFields)),
			(len(requestData.Listing.RequiredFields)+len(requestData.Listing.OptionalFields))))
		return
	}
	// Note that we don't verify that required fields are set to non-empty string because
	// this would complicate our ability to do fee estimation on a partial transaction.
	// As such, we just have the frontend do it.

	// Multiply the ItemQuantity by the PricePerUnitNanos and verify that it is
	// approximately equal to the ItemTotalNanos. We will use ItemTotalNanos as our
	// source of truth.
	computedTotalAmountNanos := math.Floor(requestData.ItemQuantity * float64(requestData.Listing.PricePerUnitNanos))
	if math.Abs(computedTotalAmountNanos-float64(requestData.ItemTotalNanos)) > FloatEpsilon {
		_AddBadRequestError(ww, fmt.Sprintf(
			"PlaceOrder: (ItemQuantity=%f * PricePerUnitNanos=%d) = %f differs "+
				"from ItemTotalNanos %f by more than the allowed epsilon value %f",
			requestData.ItemQuantity, requestData.Listing.PricePerUnitNanos, computedTotalAmountNanos,
			requestData.ItemTotalNanos, FloatEpsilon))
		return
	}

	// Encrypt the BuyerMessage with the merchant's public key.
	merchantPubKeyBase58Check := requestData.Listing.MerchantEntry.PublicKeyBase58Check
	merchantPubKeyBytes, _, err := Base58CheckDecode(merchantPubKeyBase58Check)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf(
			"PlaceOrder: Problem decoding merchant base58 public key %s: %v",
			merchantPubKeyBase58Check, err))
		return
	}
	merchantPubKey, err := btcec.ParsePubKey(merchantPubKeyBytes, btcec.S256())
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf(
			"PlaceOrder: Problem parsing merchant public key bytes %#v: %v",
			merchantPubKeyBytes, err))
		return
	}

	// A merchant isn't allowed to place an order with herself.
	if merchantPubKeyBase58Check == requestData.SenderPublicKeyBase58Check {
		_AddBadRequestError(ww, "PlaceOrder: You cannot place an order with yourself")
		return
	}

	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf(
			"PlaceOrder: Problem generating nonce for BuyerMessage: %v", err))
		return
	}
	buyerMessageObj := &BuyerMessage{
		RequiredFields: requestData.RequiredFields,
		OptionalFields: requestData.OptionalFields,
		ItemQuantity:   requestData.ItemQuantity,
		TipAmountNanos: uint64(requestData.TipAmountNanos),
		ListingIndex:   uint64(listingIndex),
	}
	encryptedBuyerMessageBytes, err := buyerMessageObj.EncryptWithPubKey(merchantPubKey)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf(
			"PlaceOrder: Problem encrypting BuyerMessage with merchant pub key: %v", err))
		return
	}

	// Assemble the transaction. Note that a PlaceOrder transaction does not typically
	// pay anyone. Rather, it usually locks up some amount of Ultra that the merchant
	// can collect later by confirming the order.
	txn := &MsgUltranetTxn{
		// The inputs will be set below.
		TxInputs:  []*UltranetInput{},
		TxOutputs: []*UltranetOutput{},
		PublicKey: senderPkBytes,
		TxnMeta: &PlaceOrderMetadata{
			MerchantID: merchantID,
			// We need to subtract off the referrerAmount since we're paying that as an
			// output to the ReferralPublicKeyBase58Check
			AmountLockedNanos: uint64(requestData.ItemTotalNanos) + uint64(requestData.TipAmountNanos) - uint64(referrerAmount),
			BuyerMessage:      encryptedBuyerMessageBytes,
		},
		// We wait to compute the signature until we've added all the
		// inputs and change.
	}

	// Add an output for the referrer. Note this could be the merchant in the event
	// a referrer isn't set.
	//
	// TODO: I added referral bonuses as a bit of an after-thought and a problem with
	// how it's done here is that it's not tied to the actual order (the merchant will
	// literally just see it as a random payment she got when the buyer has no referrer
	// set). The right way to do it is
	// to somehow account for it in the order, but given it should be rare for a buyer
	// to have no referrer set and given that this is a short-lived feature
	// anyway my bias is to remove this logic after we're through the bootstrapping phase rather
	// than to make it cleaner.
	referrerPkBytes, _, err := Base58CheckDecode(referrerPublicKey)
	if err != nil || len(referrerPkBytes) != btcec.PubKeyBytesLenCompressed {
		_AddBadRequestError(ww, fmt.Sprintf(
			"PlaceOrder: Problem parsing referrer public key %s: %v", referrerPublicKey, err))
		return
	}
	txn.TxOutputs = append(txn.TxOutputs, &UltranetOutput{
		PublicKey:   referrerPkBytes,
		AmountNanos: referrerAmount,
	})

	// Add inputs to the transaction and do signing, validation, and broadcast
	// depending on what the user requested.
	totalInput, spendAmount, changeAmount, fees, err := fes._augmentAndProcessTransaction(
		txn, requestData.SenderPublicKeyBase58Check,
		fes._getPassword(requestData.SenderPublicKeyBase58Check, requestData.Password),
		uint64(requestData.FeeRateNanosPerKB),
		requestData.Sign,
		requestData.Validate,
		requestData.Broadcast)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("PlaceOrder: Problem processing transaction: %v", err))
		return
	}
	txnBytes, err := txn.ToBytes(false /*preSignature*/)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("PlaceOrder: Problem computing txn bytes: %v", err))
		return
	}
	numTxnBytes := len(txnBytes)
	// The OrderID is the same as the transaction hash.
	orderID := txn.Hash()
	orderIDBase58Check := PkToString(orderID[:], fes.Params)

	// Add the BuyerMessage to the user's mapping of OrderIDs to BuyerMessages so that
	// it can be displayed to the user later even thoush she can't actually decrypt it.
	if user != nil {
		user.LocalState.OrderIDToBuyerMessage[orderIDBase58Check] = buyerMessageObj
	}

	// If we got here and if broadcast was requested then it means the
	// transaction passed validation and it's therefore reasonable to
	// update the user objects to reflect that. The transaction will have
	// been added to the mempool in AugmentAndProcessTransaction so the
	// update here should factor it in.
	if requestData.Broadcast {
		fes.updateUsers()
	}

	// Return the transaction in the response along with some metadata. If we
	// get to this point and if the user requested that the transaction be
	// validated or broadcast, the user can assume that those operations
	// occurred successfully.
	res := PlaceOrderResponse{
		TotalInputNanos:         totalInput,
		SpendAmountNanos:        spendAmount,
		ChangeAmountNanos:       changeAmount,
		FeeNanos:                fees,
		TransactionSizeBytes:    uint64(numTxnBytes),
		ActualFeeRateNanosPerKB: fees * 1000 / uint64(numTxnBytes),
		Transaction:             txn,
		OrderIDBase58Check:      orderIDBase58Check,
	}
	if err := json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("PlaceOrder: Problem encoding response as JSON: %v", err))
		return
	}
	return
}

// OrderActionRequest ...
type OrderActionRequest struct {
	// The public key of the user acting on the order.
	PublicKeyBase58Check string

	OrderIDBase58Check string
	FeeRateNanosPerKB  float64

	// The action the user wants to perform on the order.
	Action string

	// Only set for Action='reject'
	RejectReason string

	// Only set for Action='review'
	ReviewType string
	ReviewText string

	// Can be left unset when Signature is false or if the user legitimately
	// doesn't have a password. Can also be omitted when the user has logged
	// in and has specified their password at some point.
	Password string
	// Whether or not we should sign the transaction after constructing it.
	// Setting this flag to false is useful in
	// cases where the caller just wants to construct the transaction
	// to see what the fees will be, for example.
	Sign bool
	// Whether or not we should fully validate the transaction.
	Validate bool
	// Whether or not we should broadcast the transaction after constructing
	// it. This will also validate the transaction if it's set.
	Broadcast bool
}

// OrderActionResponse ...
type OrderActionResponse struct {
	TotalInputNanos         uint64
	SpendAmountNanos        uint64
	ChangeAmountNanos       uint64
	FeeNanos                uint64
	TransactionSizeBytes    uint64
	ActualFeeRateNanosPerKB uint64
	Transaction             *MsgUltranetTxn
	OrderIDBase58Check      string
}

// OrderAction ...
func (fes *FrontendServer) OrderAction(ww http.ResponseWriter, req *http.Request) {
	// Locking this because the OrderIDTo* maps are accessed directly in this function.
	fes.DataLock.Lock()
	defer fes.DataLock.Unlock()

	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := OrderActionRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("OrderAction: Problem parsing request body: %v", err))
		return
	}

	// A valid OrderID must be included.
	orderIDBytes, _, err := Base58CheckDecode(requestData.OrderIDBase58Check)
	if err != nil || len(orderIDBytes) != HashSizeBytes {
		_AddBadRequestError(ww, fmt.Sprintf(
			"OrderAction: Problem decoding OrderIDBase58Check %s: %v",
			requestData.OrderIDBase58Check, err))
		return
	}
	orderID := &BlockHash{}
	copy(orderID[:], orderIDBytes)

	// Decode the public key bytes.
	pkBytes, _, err := Base58CheckDecode(requestData.PublicKeyBase58Check)
	if err != nil || len(pkBytes) != btcec.PubKeyBytesLenCompressed {
		_AddBadRequestError(ww, fmt.Sprintf(
			"OrderAction: Problem decoding sender base58 public key %s: %v",
			requestData.PublicKeyBase58Check, err))
		return
	}

	// Get the user object for the public key.
	user := fes._getUserForPublicKey(requestData.PublicKeyBase58Check)
	if user == nil {
		_AddBadRequestError(ww, fmt.Sprintf("OrderAction: Could not find user with "+
			"public key %v", requestData.PublicKeyBase58Check))
		return
	}
	var merchantID *BlockHash
	if user.MerchantEntry != nil {
		// Decode the merchantID and set it if we have it on the user object.
		merchantIDBase58Check := user.MerchantEntry.MerchantIDBase58Check
		merchantIDBytes, _, err := Base58CheckDecode(merchantIDBase58Check)
		if err != nil || len(merchantIDBytes) != HashSizeBytes {
			_AddBadRequestError(ww, fmt.Sprintf(
				"OrderAction: Problem decoding user merchantID %s: %v",
				merchantIDBase58Check, err))
			return
		}
		merchantID = &BlockHash{}
		copy(merchantID[:], merchantIDBytes)
	}

	// Verify that the OrderEntry corresponding to the order exists either in the
	// db or in the mempool. Fetch it so we can use it afterward.
	//
	// Get an augmented UtxoView so we can include orders from transactions that may
	// be in our mempool.
	utxoViewForOrders, err := fes.backendServer.mempool.GetAugmentedUtxoViewForPublicKey(pkBytes)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf(
			"OrderAction: Problem getting augmented UtxoView from mempool for orders: %v", err))
		return
	}
	orderEntry := utxoViewForOrders._getOrderEntryForOrderID(orderID)
	if orderEntry == nil || orderEntry.isDeleted {
		_AddBadRequestError(ww, fmt.Sprintf(
			"OrderAction: No OrderEntry found for OrderID %s for user with public key %s: %v",
			requestData.OrderIDBase58Check, requestData.PublicKeyBase58Check, orderEntry))
		return
	}

	// Create a husk of a transaction that we can modify depending on the action type.
	txn := &MsgUltranetTxn{
		// The inputs will be set below.
		TxInputs:  []*UltranetInput{},
		TxOutputs: []*UltranetOutput{},
		PublicKey: pkBytes,

		// Set the txn meta depending on what action the user wants to execute.
		//
		// We wait to compute the signature until we've added all the
		// inputs and change.
	}

	// Compute the revenue to use below.
	_, revenueNanos, err := _computeCommissionsAndRevenueFromPayment(
		orderEntry.PaymentAmountNanos, fes.Params.CommissionBasisPoints)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf(
			"OrderAction: Problem computing revenue for orderEntry: %v", orderEntry))
		return
	}

	inputSubsidy := uint64(0)
	switch requestData.Action {
	case "cancel":
		txn.TxnMeta = &CancelOrderMetadata{
			OrderID: orderID,
		}
		// To cancel an order, we send the AmountLockedNanos back to the BuyerPk.
		txn.TxOutputs = append(txn.TxOutputs, &UltranetOutput{
			PublicKey:   orderEntry.BuyerPk,
			AmountNanos: orderEntry.AmountLockedNanos,
		})
		inputSubsidy = orderEntry.AmountLockedNanos

	case "reject":
		var encryptedRejectReason []byte
		if requestData.RejectReason != "" {
			buyerPk, err := btcec.ParsePubKey(orderEntry.BuyerPk, btcec.S256())
			if err != nil {
				_AddBadRequestError(ww, fmt.Sprintf(
					"OrderAction: Problem parsing buyer public key from orderEntry: %v, %v", orderEntry, err))
				return
			}
			encryptedRejectReasonBytes, err := EncryptBytesWithPublicKey([]byte(requestData.RejectReason), buyerPk.ToECDSA())
			if err != nil {
				_AddBadRequestError(ww, fmt.Sprintf(
					"OrderAction: Problem encrypting reject reason with buyer public key: %v", err))
				return
			}
			encryptedRejectReason = encryptedRejectReasonBytes
		}
		// Set the reject reason on the map so the merchant can know about it in the future.
		// Note that not doing this would result in the merchant not knowing the reject reason
		// they set because they don't know how to decrypt it.
		user.LocalState.OrderIDToRejectReason[requestData.OrderIDBase58Check] = requestData.RejectReason

		// Create the txn meta with the encrypted reject reason, which could be empty.
		txn.TxnMeta = &RejectOrderMetadata{
			OrderID:      orderID,
			RejectReason: encryptedRejectReason,
		}
		// To reject an order, we send the AmountLockedNanos back to the BuyerPk.
		txn.TxOutputs = append(txn.TxOutputs, &UltranetOutput{
			PublicKey:   orderEntry.BuyerPk,
			AmountNanos: orderEntry.AmountLockedNanos,
		})
		inputSubsidy = orderEntry.AmountLockedNanos

	case "confirm":
		txn.TxnMeta = &ConfirmOrderMetadata{
			OrderID: orderID,
		}
		// When we confirm an order we send the revenue to the merchant pk. Note
		// that if the user is the one making the confirm call then we can assume
		// they are the merchant.
		txn.TxOutputs = append(txn.TxOutputs, &UltranetOutput{
			PublicKey:   pkBytes,
			AmountNanos: revenueNanos,
		})
		inputSubsidy = revenueNanos

	case "fulfill_order":
		txn.TxnMeta = &FulfillOrderMetadata{
			OrderID: orderID,
		}
		// Fulfilling an order doesn't require any outputs or any input subsidy.

	case "review":
		var reviewType ReviewType
		switch requestData.ReviewType {
		case "negative":
			reviewType = ReviewTypeNegative
		case "neutral":
			reviewType = ReviewTypeNeutral
		case "positive":
			reviewType = ReviewTypePositive
		default:
			_AddBadRequestError(ww, fmt.Sprintf(
				"OrderAction: ReviewType '%s' must be one of {'negative', 'neutral', 'positive'}", requestData.ReviewType))
			return
		}
		txn.TxnMeta = &ReviewOrderMetadata{
			OrderID:    orderID,
			ReviewType: reviewType,
			ReviewText: []byte(requestData.ReviewText),
		}
		// In the case of a review add a single nano output to force the transaction
		// to have an input attached to it. The output pays the user back and so it
		// shouldn't matter.
		txn.TxOutputs = append(txn.TxOutputs, &UltranetOutput{
			PublicKey:   pkBytes,
			AmountNanos: 1,
		})

	case "request_refund":
		_AddBadRequestError(ww, fmt.Sprintf(
			"OrderAction: Unrecognized action '%s'", requestData.Action))

	case "refund_order":
		txn.TxnMeta = &RefundOrderMetadata{
			OrderID: orderID,
		}
		// To refund an order we need to include an output paying the buyer
		// back the amount they initially paid minus commissions.
		txn.TxOutputs = append(txn.TxOutputs, &UltranetOutput{
			PublicKey:   orderEntry.BuyerPk,
			AmountNanos: revenueNanos,
		})
		// Note there is no input subsidy for a refund because it comes from the
		// merchant's own pocket.

	default:
		_AddBadRequestError(ww, fmt.Sprintf(
			"OrderAction: Unrecognized action '%s'", requestData.Action))
		return
	}

	// Add inputs to the transaction and do signing, validation, and broadcast
	// depending on what the user requested.
	totalInput, spendAmount, changeAmount, fees, err := fes._augmentAndProcessTransactionWithSubsidy(
		txn, requestData.PublicKeyBase58Check,
		fes._getPassword(requestData.PublicKeyBase58Check, requestData.Password),
		uint64(requestData.FeeRateNanosPerKB),
		inputSubsidy,
		requestData.Sign,
		requestData.Validate,
		requestData.Broadcast)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("OrderAction: Problem processing transaction: %v", err))
		return
	}
	txnBytes, err := txn.ToBytes(false /*preSignature*/)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("OrderAction: Problem computing txn bytes: %v", err))
		return
	}
	numTxnBytes := len(txnBytes)

	// If we got here and if broadcast was requested then it means the
	// transaction passed validation and it's therefore reasonable to
	// update the user objects to reflect that. The transaction will have
	// been added to the mempool in _augmentAndProcessTransactionWithSubsidy so the
	// update here should factor it in.
	if requestData.Broadcast {
		fes.updateUsers()
	}

	// Return the transaction in the response along with some metadata. If we
	// get to this point and if the user requested that the transaction be
	// validated or broadcast, the user can assume that those operations
	// occurred successfully.
	res := OrderActionResponse{
		TotalInputNanos:         totalInput,
		SpendAmountNanos:        spendAmount,
		ChangeAmountNanos:       changeAmount,
		FeeNanos:                fees,
		TransactionSizeBytes:    uint64(numTxnBytes),
		ActualFeeRateNanosPerKB: fees * 1000 / uint64(numTxnBytes),
		Transaction:             txn,
	}
	if err := json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("OrderAction: Problem encoding response as JSON: %v", err))
		return
	}
	return
}

// NodeControlRequest ...
type NodeControlRequest struct {
	// An address in <IP>:<Port> format.
	Address string

	// A comma-separated list of miner public keys to use.
	MinerPublicKeys string

	// The type of operation to perform on the node.
	OperationType string
}

type NodeStatusResponse struct {
	// A summary of what the node is currently doing.
	State string

	// We generally track the latest header we have and the latest block we have
	// separately since headers-first synchronization can cause the latest header
	// to diverge slightly from the latest block.
	LatestHeaderHeight     uint32
	LatestHeaderHash       string
	LatestHeaderTstampSecs uint32

	LatestBlockHeight     uint32
	LatestBlockHash       string
	LatestBlockTstampSecs uint32

	// This is non-zero unless the main header chain is fully current. It can be
	// an estimate in cases where we don't know exactly what the tstamp of the
	// current main chain is.
	HeadersRemaining uint32
	// This is non-zero unless the main header chain is fully current and all
	// the corresponding blocks have been downloaded.
	BlocksRemaining uint32
}

type PeerResponse struct {
	IP           string
	ProtocolPort uint16
	JSONPort     uint16
	IsSyncPeer   bool
}

// NodeControlResponse ...
type NodeControlResponse struct {
	// The current status the Ultra node is at in terms of syncing the Ultra
	// chain.
	UltraStatus   *NodeStatusResponse
	BitcoinStatus *NodeStatusResponse

	UltraOutboundPeers    []*PeerResponse
	UltraInboundPeers     []*PeerResponse
	UltraUnconnectedPeers []*PeerResponse

	BitcoinSyncPeer         *PeerResponse
	BitcoinUnconnectedPeers []*PeerResponse

	MinerPublicKeys []string
}

func parseIPAndPort(address string) (string, uint16) {
	ipAndPort := strings.Split(address, ":")
	ip := address
	port := uint16(0)
	if len(ipAndPort) >= 2 {
		portStr := ipAndPort[len(ipAndPort)-1]
		parsedPort, err := strconv.Atoi(portStr)
		if err == nil && parsedPort <= math.MaxUint16 {
			// Only set the port if we didn't have an error during conversion.
			port = uint16(parsedPort)
			ip = strings.Join(ipAndPort[:len(ipAndPort)-1], ":")
		}
	}

	return ip, port
}

func (fes *FrontendServer) _handleNodeControlGetInfo(
	requestData *NodeControlRequest, ww http.ResponseWriter) {

	// Lock the blockchain and the BitcoinManager since we lookup a lot of their
	// fields below.
	fes.blockchain.ChainLock.RLock()
	defer fes.blockchain.ChainLock.RUnlock()
	fes.blockchain.bitcoinManager.BitcoinHeaderIndexLock.RLock()
	defer fes.blockchain.bitcoinManager.BitcoinHeaderIndexLock.RUnlock()

	// Set some fields we'll need to use down below.
	ultraChainState := fes.blockchain.chainState()
	ultraHeaderTip := fes.blockchain.headerTip()
	ultraBlockTip := fes.blockchain.blockTip()
	isBitcoinChainCurrent := fes.blockchain.bitcoinManager._isCurrent(
		false /*considerCumWork*/)
	bitcoinHeaderTip := fes.blockchain.bitcoinManager._headerTip()

	// Compute the fields for the Ultra NodeStatusResponse
	ultraNodeStatus := &NodeStatusResponse{}
	if !isBitcoinChainCurrent {
		ultraNodeStatus.State = "SYNCING_BITCOIN"
	} else {
		ultraNodeStatus.State = ultraChainState.String()
	}
	// Main header chain fields
	{
		ultraNodeStatus.LatestHeaderHeight = ultraHeaderTip.Height
		ultraNodeStatus.LatestHeaderHash = hex.EncodeToString(ultraHeaderTip.Hash[:])
		ultraNodeStatus.LatestHeaderTstampSecs = ultraHeaderTip.Header.TstampSecs
	}
	// Main block chain fields
	{
		ultraNodeStatus.LatestBlockHeight = ultraBlockTip.Height
		ultraNodeStatus.LatestBlockHash = hex.EncodeToString(ultraBlockTip.Hash[:])
		ultraNodeStatus.LatestBlockTstampSecs = ultraBlockTip.Header.TstampSecs
	}
	// We only have headers remaining if we're in this state.
	if ultraChainState == SyncStateSyncingHeaders {
		ultraNodeStatus.HeadersRemaining = uint32(
			(time.Now().Unix() - int64(ultraNodeStatus.LatestHeaderTstampSecs)) /
				int64(fes.Params.TimeBetweenBlocks.Seconds()))
	}
	// We only have blocks remaining if we're in one of the following states.
	if ultraChainState == SyncStateSyncingHeaders ||
		ultraChainState == SyncStateSyncingBlocks ||
		ultraChainState == SyncStateNeedBlocksss {

		ultraNodeStatus.BlocksRemaining = ultraHeaderTip.Height - ultraBlockTip.Height
	}

	// Get and sort the peers so we have a consistent ordering.
	allUltraPeers := fes.backendServer.cmgr.GetAllPeers()
	sort.Slice(allUltraPeers, func(ii, jj int) bool {
		// Use a hash to get a random but deterministic ordering.
		return allUltraPeers[ii].addrStr < allUltraPeers[jj].addrStr
	})

	// Rack up the inbound and outbound peers from the connection manager.
	ultraOutboundPeers := []*PeerResponse{}
	ultraInboundPeers := []*PeerResponse{}
	ultraUnconnectedPeers := []*PeerResponse{}
	existingUltraPeers := make(map[string]bool)
	syncPeer := fes.backendServer.syncPeer
	for _, ultraPeer := range allUltraPeers {
		isSyncPeer := false
		if syncPeer != nil && (ultraPeer.addrStr == syncPeer.addrStr) {
			isSyncPeer = true
		}
		currentPeerRes := &PeerResponse{
			IP:           ultraPeer.netAddr.IP.String(),
			ProtocolPort: ultraPeer.netAddr.Port,
			JSONPort:     ultraPeer.jsonAPIPort,
			IsSyncPeer:   isSyncPeer,
		}
		if ultraPeer.isOutbound {
			ultraOutboundPeers = append(ultraOutboundPeers, currentPeerRes)
		} else {
			ultraInboundPeers = append(ultraInboundPeers, currentPeerRes)
		}

		existingUltraPeers[currentPeerRes.IP+fmt.Sprintf(":%d", currentPeerRes.ProtocolPort)] = true
	}
	// Return some ultra addrs from the addr manager.
	ultraAddrs := fes.backendServer.cmgr.addrMgr.GetAllAddrs()
	sort.Slice(ultraAddrs, func(ii, jj int) bool {
		// Use a hash to get a random but deterministic ordering.
		hashI := string(Sha256DoubleHash([]byte(ultraAddrs[ii].IP.String() + fmt.Sprintf(":%d", ultraAddrs[ii].Port)))[:])
		hashJ := string(Sha256DoubleHash([]byte(ultraAddrs[jj].IP.String() + fmt.Sprintf(":%d", ultraAddrs[jj].Port)))[:])

		return hashI < hashJ
	})
	for _, netAddr := range ultraAddrs {
		if len(ultraUnconnectedPeers) >= 250 {
			break
		}
		addr := netAddr.IP.String() + fmt.Sprintf(":%d", netAddr.Port)
		if _, exists := existingUltraPeers[addr]; exists {
			continue
		}
		ultraUnconnectedPeers = append(ultraUnconnectedPeers, &PeerResponse{
			IP:           netAddr.IP.String(),
			ProtocolPort: netAddr.Port,
			// Unconnected peers have not told us their JSON port so set it to zero.
			JSONPort: 0,
			// Unconnected peers are not sync peers so leave it set to false.
		})
	}

	// Compute the fields for the Bitcoin NodeStatusResponse
	bitcoinNodeStatus := &NodeStatusResponse{}
	if fes.blockchain.bitcoinManager._isCurrent(true /*considerCumWork*/) {
		bitcoinNodeStatus.State = "FULLY_CURRENT"
	} else if fes.blockchain.bitcoinManager._isCurrent(false /*considerCumWork*/) {
		bitcoinNodeStatus.State = "TENTATIVELY_CURRENT"
	} else {
		bitcoinNodeStatus.State = "SYNCING"
	}
	// For the Bitcoin part of this we only set information on headers.
	{
		bitcoinNodeStatus.LatestHeaderHeight = bitcoinHeaderTip.Height
		bitcoinNodeStatus.LatestHeaderHash = (chainhash.Hash)(*bitcoinHeaderTip.Hash).String()
		bitcoinNodeStatus.LatestHeaderTstampSecs = bitcoinHeaderTip.Header.TstampSecs
	}
	if !isBitcoinChainCurrent {
		bitcoinNodeStatus.HeadersRemaining = uint32(
			(time.Now().Unix() - int64(bitcoinNodeStatus.LatestHeaderTstampSecs)) /
				int64(fes.Params.BitcoinTimeBetweenBlocks.Seconds()))
	}
	// Set the current Bitcoin sync peer.
	var bitcoinSyncPeer *PeerResponse
	bitcoinSyncConn := fes.blockchain.bitcoinManager.syncConn
	if bitcoinSyncConn != nil {
		// This is annoying but for the sync peer we need to split the IP from the port
		// because all we have is RemoteAddr which is a string. RemoteAddr is always
		// <IP>:<port> and so the last element after the colon when we Split() the
		// RemoteAddr is the port.
		ip, port := parseIPAndPort(bitcoinSyncConn.RemoteAddr().String())

		bitcoinSyncPeer = &PeerResponse{
			IP:           ip,
			ProtocolPort: port,
			// Bitcoin peers have no JSON API port
			JSONPort:   0,
			IsSyncPeer: true,
		}
	}
	// Get some alternative peers from the Bitcoin addrmgr
	bitcoinUnconnectedPeers := []*PeerResponse{}
	bitcoinAddrs := fes.blockchain.bitcoinManager.addrMgr.GetAllAddrs()
	sort.Slice(bitcoinAddrs, func(ii, jj int) bool {
		// Use a hash to get a deterministic but random order.
		hashI := string(Sha256DoubleHash([]byte(bitcoinAddrs[ii].IP.String() + fmt.Sprintf(":%d", bitcoinAddrs[ii].Port)))[:])
		hashJ := string(Sha256DoubleHash([]byte(bitcoinAddrs[jj].IP.String() + fmt.Sprintf(":%d", bitcoinAddrs[jj].Port)))[:])
		return hashI < hashJ
	})
	for _, netAddr := range bitcoinAddrs {
		// Only IPV4 addresses are currently supported for Bitcoin.
		if netAddr.IP.To4() == nil {
			continue
		}
		if len(bitcoinUnconnectedPeers) >= 250 {
			break
		}
		if bitcoinSyncPeer != nil && bitcoinSyncPeer.IP == netAddr.IP.String() {
			continue
		}
		bitcoinUnconnectedPeers = append(bitcoinUnconnectedPeers, &PeerResponse{
			IP:           netAddr.IP.String(),
			ProtocolPort: netAddr.Port,
			// Bitcoin peers have no JSON API port
			JSONPort: 0,
			// This is not a sync peer by definition.
		})
	}

	// Encode the miner public keys as strings.
	minerPublicKeyStrs := []string{}
	for _, publicKey := range fes.backendServer.miner.publicKeys {
		minerPublicKeyStrs = append(minerPublicKeyStrs, PkToString(
			publicKey.SerializeCompressed(), fes.Params))
	}

	res := NodeControlResponse{
		UltraStatus:   ultraNodeStatus,
		BitcoinStatus: bitcoinNodeStatus,

		UltraOutboundPeers:    ultraOutboundPeers,
		UltraInboundPeers:     ultraInboundPeers,
		UltraUnconnectedPeers: ultraUnconnectedPeers,

		BitcoinSyncPeer:         bitcoinSyncPeer,
		BitcoinUnconnectedPeers: bitcoinUnconnectedPeers,

		MinerPublicKeys: minerPublicKeyStrs,
	}
	if err := json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf(
			"NodeControl: Problem encoding response as JSON: %v", err))
		return
	}
}

func (fes *FrontendServer) _handleConnectUltraNode(
	ww http.ResponseWriter, ip string, protocolPort uint16) {

	// Grab the ChainLock since we might do a blockchain lookup below.
	fes.blockchain.ChainLock.RLock()
	defer fes.blockchain.ChainLock.RUnlock()

	// Don't connect to the peer if we're already aware of them.
	for _, ultraPeer := range fes.backendServer.cmgr.GetAllPeers() {
		if strings.Contains(ultraPeer.addrStr, ip+fmt.Sprintf(":%d", protocolPort)) {
			_AddBadRequestError(ww, fmt.Sprintf(
				"You are already connected to peer %s:%d", ip, protocolPort))
			return
		}
	}

	// Give the peer a dial just to make sure it's alive as a sanity-check.
	conn, err := net.DialTimeout("tcp", ip+fmt.Sprintf(":%d", protocolPort), fes.Params.DialTimeout)
	if err != nil {
		// Give a clean error we can display in this case.
		_AddBadRequestError(ww, fmt.Sprintf(
			"Cannot connect to node %s:%d: %v", ip, protocolPort, err))
		return
	}
	conn.Close()

	// connectPeer has an infinite loop in it so we want to avoid letting it run
	// forever.
	// TODO: Right now every time this gets messed up we kick off a spinning
	// goroutine. It's not so bad because connectPeer has an exponentially
	// increasing retry delay, but we should still clean it up at some point.
	connectPeerDone := make(chan bool)
	go func() {
		netAddr, err := addrmgr.HostToNetAddress(ip, protocolPort, 0)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf(
				"_handleConnectUltraNode: Cannot connect to node %s:%d: %v", ip, protocolPort, err))
			return
		}
		fes.backendServer.cmgr._connectPeer(nil, netAddr)

		// Spin until the peer shows up in the connection manager or until 100 iterations.
		// Note the pause between each iteration.
		for ii := 0; ii < 100; ii++ {
			for _, ultraPeer := range fes.backendServer.cmgr.GetAllPeers() {
				if !strings.Contains(ultraPeer.addrStr, ip+fmt.Sprintf(":%d", protocolPort)) {
					continue
				}
				// If we get here it means we're dealing with the peer we just connected to.

				// Send a GetHeaders message to the Peer to start the headers sync.
				// Note that we include an empty BlockHash as the stopHash to indicate we want as
				// many headers as the Peer can give us.
				// Note: We don't need to acquire the ChainLock because our parent does it.
				locator := latestLocator(
					fes.blockchain.headerTip(), fes.blockchain.bestHeaderChain, fes.blockchain.bestHeaderChainMap)
				go func() {
					ultraPeer.PushGetHeadersMsg(locator, &BlockHash{})
				}()

				// After sending GetHeaders above, make the peer the syncPeer.
				fes.backendServer.syncPeer = ultraPeer

				// At this point the peer shoud be connected. Add their address to the addrmgr
				// in case the user wants to connect again in the future. Set the source to be
				// the address itself since we don't have anything else.
				fes.backendServer.cmgr.addrMgr.AddAddress(netAddr, netAddr)

				connectPeerDone <- true
				return
			}

			time.Sleep(200 * time.Millisecond)
		}
	}()
	select {
	case <-connectPeerDone:
	case <-time.After(5 * time.Second):
		_AddBadRequestError(ww, fmt.Sprintf(
			"Cannot connect to node %s:%d: %v", ip, protocolPort, err))
		return
	}

	res := NodeControlResponse{
		// Return an empty response, which indicates we set the peer up to be connected.
	}
	if err := json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf(
			"NodeControl: Problem encoding response as JSON: %v", err))
		return
	}
}

func (fes *FrontendServer) _handleDisconnectUltraNode(
	ww http.ResponseWriter, ip string, port uint16) {

	// Get all the peers from the connection manager and try and find one
	// that has a matching IP.
	var peerFound *Peer
	for _, ultraPeer := range fes.backendServer.cmgr.GetAllPeers() {
		if strings.Contains(ultraPeer.addrStr, ip+fmt.Sprintf(":%d", port)) {
			peerFound = ultraPeer
			break
		}
	}
	if peerFound == nil {
		_AddBadRequestError(ww, fmt.Sprintf(
			"Peer with IP %s not found in connected peer list. Are you sure "+
				"you are connected to this peer?", ip))
		return
	}

	// Manually remove the peer from the connection manager and mark it as such
	// so that the connection manager won't reconnect to it or replace it.
	fes.backendServer.cmgr.removePeer(peerFound)
	peerFound.peerManuallyRemovedFromConnectionManager = true

	peerFound.Disconnect()

	res := NodeControlResponse{
		// Return an empty response, which indicates we set the peer up to be connected.
	}
	if err := json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf(
			"NodeControl: Problem encoding response as JSON: %v", err))
		return
	}
}

func (fes *FrontendServer) _handleChangeBitcoinSyncPeer(ww http.ResponseWriter, newPeerAddr string) {
	// Let it block. We want to wait for the response.
	replyChan := make(chan error)
	fes.blockchain.bitcoinManager.switchPeerChan <- &SwitchPeerMsg{
		NewAddr:   newPeerAddr,
		ReplyChan: replyChan,
	}
	err := <-replyChan
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf(
			"Problem connecting to new peer %s: %v", newPeerAddr, err))
		return
	}

	res := NodeControlResponse{
		// Return an empty response, which indicates we set the peer up to be connected.
	}
	if err := json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf(
			"NodeControl: Problem encoding response as JSON: %v", err))
		return
	}
}

// NodeControl ...
func (fes *FrontendServer) NodeControl(ww http.ResponseWriter, req *http.Request) {
	// This function doesn't change anything on the user object so no need to lock.
	//fes.DataLock.Lock()
	//defer fes.DataLock.Unlock()

	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := NodeControlRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf(
			"NodeControlRequest: Problem parsing request body: %v", err))
		return
	}

	allowedOperationTypes := make(map[string]bool)
	allowedOperationTypes["get_info"] = true
	allowedOperationTypes["connect_ultra_node"] = true
	allowedOperationTypes["disconnect_ultra_node"] = true
	allowedOperationTypes["connect_bitcoin_node"] = true
	allowedOperationTypes["update_miner"] = true

	if _, isOperationTypeAllowed := allowedOperationTypes[requestData.OperationType]; !isOperationTypeAllowed {
		_AddBadRequestError(ww, fmt.Sprintf(
			"NodeControlRequest: OperationType %s is not allowed. Allowed types are: %v",
			requestData.OperationType, allowedOperationTypes))
		return
	}

	if requestData.OperationType == "get_info" {
		fes._handleNodeControlGetInfo(&requestData, ww)
		return

	} else if requestData.OperationType == "connect_ultra_node" {
		ip, port := parseIPAndPort(requestData.Address)
		fes._handleConnectUltraNode(ww, ip, port)
		return

	} else if requestData.OperationType == "disconnect_ultra_node" {
		ip, port := parseIPAndPort(requestData.Address)
		fes._handleDisconnectUltraNode(ww, ip, port)
		return

	} else if requestData.OperationType == "connect_bitcoin_node" {
		fes._handleChangeBitcoinSyncPeer(ww, requestData.Address)
		return

	} else if requestData.OperationType == "update_miner" {
		// Parse the miner public keys into a list of *btcec.PublicKey
		minerPublicKeys := []*btcec.PublicKey{}
		if requestData.MinerPublicKeys != "" {
			pkStrings := strings.Split(requestData.MinerPublicKeys, ",")
			for _, pkStr := range pkStrings {
				publicKeyBytes, _, err := Base58CheckDecode(pkStr)
				if err != nil {
					_AddBadRequestError(ww, fmt.Sprintf(
						"NodeControlRequest: Problem decoding miner public key from base58 %s: %v", pkStr, err))
					return
				}
				pk, err := btcec.ParsePubKey(publicKeyBytes, btcec.S256())
				if err != nil {
					_AddBadRequestError(ww, fmt.Sprintf(
						"NodeControlRequest: Problem parsing miner public key %s: %v", pkStr, err))
					return
				}

				minerPublicKeys = append(minerPublicKeys, pk)
			}
		}
		fes.backendServer.miner.publicKeys = minerPublicKeys

	} else {
		_AddBadRequestError(ww, fmt.Sprintf(
			"NodeControlRequest: OperationType %s is allowed but not implemented; "+
				"this should never happen", requestData.OperationType))
		return
	}
}

func (fes *FrontendServer) UpdateAndBroadcastBitcoinTxns() {
	fes.DataLock.Lock()
	defer fes.DataLock.Unlock()

	// If there is no logged-in user just return.
	if fes.UserData == nil || fes.UserData.LoggedInUser == nil {
		return
	}
	loggedInUser := fes.UserData.LoggedInUser

	// Iterate through all of the transactions in the API response. If there
	// are any transactions in the API response that have more than zero
	// confirmations, then make sure they are removed from the
	// BitcoinTransactionsToBroadcast. If there are any transactions that have
	// zero confirmations, make sure they are marked as having been received.
	if loggedInUser.BitcoinAPIResponse != nil && loggedInUser.BitcoinAPIResponse.Txns != nil {
		for _, apiTxn := range loggedInUser.BitcoinAPIResponse.Txns {

			txnBroadcastInfo, txnExistsInBroadcastTxns := loggedInUser.LocalState.BitcoinTxnsToBroadcast[apiTxn.TxIDHex]
			if txnExistsInBroadcastTxns {
				// Mark the transaction as having been received no matter what.
				glog.Tracef("UpdateAndBroadcastBitcoinTxns: Marking txn with TxID %s as received", apiTxn.TxIDHex)
				txnBroadcastInfo.ApiResponseReturned = true

				// If the transaction has greater than zero confirmations then remove it
				// from the pending list. When we remove it from the pending list, create
				// and add an Ultra transaction crediting the Ultra being created to the user
				// to the OutgoingTransactions list.
				if apiTxn.Confirmations > 0 {
					glog.Tracef("UpdateAndBroadcastBitcoinTxns: Removing Bitcoin txn with "+
						"TxID %s from rebroadcast list since it now has %d confirmations",
						apiTxn.TxIDHex, apiTxn.Confirmations)

					delete(loggedInUser.LocalState.BitcoinTxnsToBroadcast, apiTxn.TxIDHex)
				}
			}
		}
	}

	// Rebroadcast any Bitcoin txns that are still in BroadcastTxns as we're confident
	// these have zero confirmations still.
	for txid, txnBroadcastInfo := range loggedInUser.LocalState.BitcoinTxnsToBroadcast {
		glog.Tracef("UpdateAndBroadcastBitcoinTxns: Rebroadcasting Bitcoin txn with TxID %s", txid)
		fes.blockchain.bitcoinManager.BroadcastTxn(txnBroadcastInfo.BitcoinTxn)
	}
}

func (fes *FrontendServer) UpdateLoggedInUserBitcoinAPIResponse() {
	// We don't lock here because the API request could take a while and we don't access
	// any maps.

	if fes.UserData == nil || fes.UserData.LoggedInUser == nil {
		return
	}

	btcDepositAddr := fes.UserData.LoggedInUser.SeedInfo.BtcDepositAddress
	apiData, err := GetBlockCypherAPIFullAddressResponse(btcDepositAddr, fes.Params)
	if err != nil {
		glog.Errorf("UpdateLoggedInUserBitcoinAPIResponse: Problem fetching BitcoinAPIResponse for LoggedInUser from BlockCypher API: %v", err)
		return
	}
	glog.Tracef("UpdateLoggedInUserBitcoinAPIResponse: Fetched balance for logged "+
		"in user with address %s = %d satoshis", btcDepositAddr, apiData.FinalBalance)
	fes.UserData.LoggedInUser.BitcoinAPIResponse = apiData
}

// Logger ...
func Logger(inner http.Handler, name string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		inner.ServeHTTP(w, r)

		glog.Tracef(
			"%s\t%s\t%s\t%s",
			r.Method,
			r.RequestURI,
			name,
			time.Since(start),
		)
	})
}

// AddHeaders ...
func AddHeaders(inner http.Handler, name string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET PUT POST DELETE OPTIONS")
		// If it's an options request stop at the CORS headers.
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		// For all normal requests, add the JSON header and run the business
		// logic handlers.
		w.Header().Set("Content-Type", "application/json")
		inner.ServeHTTP(w, r)
	})
}

// JSONError ...
type JSONError struct {
	Code int    `json:"code"`
	Text string `json:"text"`
}

// CheckSecret ...
func CheckSecret(inner http.Handler, name string, sharedSecret string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		reqSharedSecret, exists := req.URL.Query()[SharedSecretParam]

		// If the shared secret param isn't included, stop here.
		if !exists || len(reqSharedSecret) == 0 {
			_AddBadRequestError(w, fmt.Sprintf("CheckSecret: Missing %s parameter", SharedSecretParam))
			return
		}

		// If the shared secret param is incorrect, stop here.
		if sharedSecret != reqSharedSecret[0] {
			_AddBadRequestError(w, fmt.Sprintf("CheckSecret: Invalid shared secret: %s", reqSharedSecret[0]))
			return
		}

		// We only get here if we had a valid shared secret.
		inner.ServeHTTP(w, req)
	})
}

const (
	RoutePathGetTopCategories       = "/get-top-categories"
	RoutePathGetTopMerchants        = "/get-top-merchants"
	RoutePathGetExchangeRate        = "/get-exchange-rate"
	RoutePathSendUltra              = "/send-ultra"
	RoutePathSendMessage            = "/send-message"
	RoutePathSignature              = "/signature"
	RoutePathUpdateMessages         = "/update-messages"
	RoutePathGetBlocks              = "/get-blocks"
	RoutePathGetUsers               = "/get-users"
	RoutePathCreateUsers            = "/create-user"
	RoutePathUpdateUser             = "/update-user"
	RoutePathRegisterMerchant       = "/register-merchant"
	RoutePathUpdateMerchant         = "/update-merchant"
	RoutePathGetListings            = "/get-listings"
	RoutePathGetListingImage        = "/get-listing-image"
	RoutePathPublishListing         = "/draft-listing/publish"
	RoutePathUpdateDraftImages      = "/draft-images/update"
	RoutePathAddDraftImage          = "/draft-images/add"
	RoutePathGetDraftImageIDs       = "/draft-images/get/ids"
	RoutePathGetDraftImage          = "/draft-images/get"
	RoutePathUpdateThumbnail        = "/draft-images/thumbnail"
	RoutePathLoadListingDraftImages = "/draft-images/load-listing"
	RoutePathPlaceOrder             = "/order/place"
	RoutePathOrderAction            = "/order/action"
	RoutePathBurnBitcoin            = "/burn-bitcoin"
	RoutePathReprocessBitcoinBlock  = "/reprocess-bitcoin-block"
	RoutePathNodeControl            = "/node-control"
	RoutePathLoadTest               = "/load-test"
)

// InitRoutes ...
// Note: Be very careful when editing existing routes in this list.
// This *must* be kept in-sync with the backend-api.service.ts file in the
// frontend code. If not, then requests will fail.
func (fes *FrontendServer) InitRoutes() *mux.Router {
	var FrontendRoutes = []Route{
		Route{
			"Index",
			[]string{"GET"},
			"/",
			fes.Index,
			false, // CheckSecret
		},

		// Routes for populating various UI elements on the Market page.
		Route{
			"GetTopCategories",
			[]string{"GET"},
			RoutePathGetTopCategories,
			fes.GetTopCategories,
			false, // CheckSecret
		},
		Route{
			"GetTopMerchants",
			[]string{"GET"},
			RoutePathGetTopMerchants,
			fes.GetTopMerchants,
			false, // CheckSecret
		},
		Route{
			"GetExchangeRate",
			[]string{"GET"},
			RoutePathGetExchangeRate,
			fes.GetExchangeRate,
			false, // CheckSecret
		},

		// Route for sending Ultra
		Route{
			"SendUltra",
			[]string{"POST", "OPTIONS"},
			RoutePathSendUltra,
			fes.SendUltra,
			true, // CheckSecret
		},

		// Route for sending a message
		Route{
			"SendMessage",
			[]string{"POST", "OPTIONS"},
			RoutePathSendMessage,
			fes.SendMessage,
			true, // CheckSecret
		},

		// Route for signing messages
		Route{
			"Signature",
			[]string{"POST", "OPTIONS"},
			RoutePathSignature,
			fes.Signature,
			true, // CheckSecret
		},

		// Route for updating message information
		Route{
			"UpdateMessages",
			[]string{"POST", "OPTIONS"},
			RoutePathUpdateMessages,
			fes.UpdateMessages,
			true, // CheckSecret
		},

		// Route for burning Bitcoin for Ultra
		Route{
			"BurnBitcoin",
			[]string{"POST", "OPTIONS"},
			RoutePathBurnBitcoin,
			fes.BurnBitcoin,
			true, // CheckSecret
		},
		// Endpoint to trigger the reprocessing of a particular Bitcoin block.
		Route{
			"ReprocessBitcoinBlock",
			[]string{"GET"},
			RoutePathReprocessBitcoinBlock + "/{blockHashHexOrblockHeight:[0-9abcdefABCDEF]+}",
			fes.ReprocessBitcoinBlock,
			true, // CheckSecret
		},

		// Route for getting blocks from the main chain.
		Route{
			"GetBlocks",
			[]string{"GET"},
			RoutePathGetBlocks,
			fes.GetBlocks,
			true, // CheckSecret
		},

		// Route for getting the user data on startup.
		Route{
			"GetUsers",
			[]string{"GET"},
			RoutePathGetUsers,
			fes.GetUsers,
			true, // CheckSecret
		},
		Route{
			"CreateUser",
			[]string{"POST", "OPTIONS"},
			RoutePathCreateUsers,
			fes.CreateUser,
			true, // CheckSecret
		},
		Route{
			"UpdateUser",
			[]string{"POST", "OPTIONS"},
			RoutePathUpdateUser,
			fes.UpdateUser,
			true, // CheckSecret
		},

		// Routes for merchant-related actions.
		Route{
			"RegisterMerchant",
			[]string{"POST", "OPTIONS"},
			RoutePathRegisterMerchant,
			fes.RegisterMerchant,
			true, // CheckSecret
		},
		Route{
			"UpdateMerchant",
			[]string{"POST", "OPTIONS"},
			RoutePathUpdateMerchant,
			fes.UpdateMerchant,
			true, // CheckSecret
		},

		Route{
			"GetListings",
			[]string{"POST", "OPTIONS"},
			RoutePathGetListings,
			fes.GetListings,
			// Note having CheckSecret set to false is OK for this because it is just
			// returning publicly-visible listings.
			false, // CheckSecret
		},
		Route{
			"GetListingImage",
			[]string{"GET"},
			RoutePathGetListingImage + "/{publicKeyOrMerchantIDBase58Check}/{listingIndex:[0-9]+}/{imageIndex:[0-9]+}",
			fes.GetListingImage,
			false, // CheckSecret
		},

		// Routes for managing a draft listing.
		Route{
			"PublishListing",
			[]string{"POST", "OPTIONS"},
			RoutePathPublishListing,
			fes.PublishListing,
			true, // CheckSecret
		},
		Route{
			"UpdateDraftImages",
			[]string{"POST", "OPTIONS"},
			RoutePathUpdateDraftImages,
			fes.UpdateDraftImages,
			true, // CheckSecret
		},
		Route{
			"AddDraftImage",
			[]string{"POST", "OPTIONS"},
			RoutePathAddDraftImage,
			fes.AddDraftImage,
			true, // CheckSecret
		},
		Route{
			"GetDraftImageIDs",
			[]string{"GET"},
			RoutePathGetDraftImageIDs,
			fes.GetDraftImageIDs,
			true, // CheckSecret
		},
		Route{
			"GetDraftImage",
			[]string{"GET"},
			RoutePathGetDraftImage,
			fes.GetDraftImage,
			true, // CheckSecret
		},
		Route{
			"UpdateThumbnail",
			[]string{"POST", "OPTIONS"},
			RoutePathUpdateThumbnail,
			fes.UpdateThumbnail,
			true, // CheckSecret
		},
		Route{
			"LoadListingDraftImages",
			[]string{"POST", "OPTIONS"},
			RoutePathLoadListingDraftImages,
			fes.LoadListingDraftImages,
			true, // CheckSecret
		},

		// Route for placing an order
		Route{
			"PlaceOrder",
			[]string{"POST", "OPTIONS"},
			RoutePathPlaceOrder,
			fes.PlaceOrder,
			true, // CheckSecret
		},

		// Route for all other order operations
		Route{
			"OrderAction",
			[]string{"POST", "OPTIONS"},
			RoutePathOrderAction,
			fes.OrderAction,
			true, // CheckSecret
		},

		// Route for all low-level node operations.
		Route{
			"NodeControl",
			[]string{"POST", "OPTIONS"},
			RoutePathNodeControl,
			fes.NodeControl,
			true, // CheckSecret
		},

		// Only used for testing purposes. Generates a lot of transactions.
		Route{
			"LoadTest",
			[]string{"GET"},
			RoutePathLoadTest,
			fes.LoadTest,
			true, // CheckSecret
		},
	}

	router := mux.NewRouter().StrictSlash(true)
	for _, route := range FrontendRoutes {
		var handler http.Handler

		handler = route.HandlerFunc
		// Note that the wrapper that is applied last is actually called first. For
		// example if you have:
		// - handler = C(handler)
		// - handler = B(handler)
		// - handler = A(handler)
		// then A will be called first B will be called second, and C will be called
		// last.
		if route.CheckSecret {
			handler = CheckSecret(handler, route.Name, fes.SharedSecret)
		}
		handler = Logger(handler, route.Name)
		handler = AddHeaders(handler, route.Name)

		router.
			Methods(route.Method...).
			Path(route.Pattern).
			Name(route.Name).
			Handler(handler)
	}

	return router
}

func (fes *FrontendServer) Stop() {
	glog.Info("FrontendServer.Stop: Gracefully shutting down FrontendServer")
}

// Start ...
func (fes *FrontendServer) Start() {
	glog.Info("FrontendServer.Start: Starting FrontendServer")
	router := fes.InitRoutes()

	// Load the user data.
	fes.UserData = DbGetLocalUserData(fes.blockchain.db)
	if fes.UserData == nil {
		glog.Debugf("FrontendServer.Start: User data not found; initializing from scratch")
		// If we have no user data, intitialize an empty object.
		fes.UserData = &LocalUserData{
			// Initialize the UserList to an empty list.
			UserList: []*User{},
		}
		if err := DbPutLocalUserData(fes.UserData, fes.blockchain.db); err != nil {
			glog.Fatalf("FrontendServer.Start: Could not create user data: %v", err)
		}
	}
	glog.Debugf("FrontendServer.Start: Loaded user data: %v", fes.UserData)

	// If a LoggedInUser is set initially and if the user has a password set then
	// set the LoggedInUser to nil. Doing this forces the user to login and enter
	// her password again.
	if fes.UserData.LoggedInUser != nil {
		if fes.UserData.LoggedInUser.SeedInfo.HasPassword {
			// If the LoggedInUser has a password set then set it to nil so we can force
			// the user to login on startup.
			fes.UserData.LoggedInUser = nil
		} else {
			// If no password is set, leave the user as logged in and store an empty
			// string in the password map.
			fes.PublicKeyToPasswordMap[fes.UserData.LoggedInUser.PublicKeyBase58Check] = ""
		}
	}

	// Set up a goroutine to update the Bitcoin holdings of the LoggedInUser every
	// thirty seconds if we have one.
	go func() {
		for {
			glog.Tracef("FrontendServer.Start: Updating BalanceSatoshis")
			// The BlockCypher API limits us to 200 requests per second so to stay on
			// the safe side we poll this once every 30 seconds.
			fes.UpdateLoggedInUserBitcoinAPIResponse()
			fes.UpdateAndBroadcastBitcoinTxns()
			time.Sleep(45 * time.Second)
		}
	}()

	glog.Infof("Json API started on port :%d", fes.JSONPort)
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", fes.JSONPort), router))
}
