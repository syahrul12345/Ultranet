// FIXME: Delete this file.
// Encryption libraries.
var nodeCrypto = require('crypto');
var bip32 = require('bip32');
var bitcoinjs = require('bitcoinjs-lib');
var validator = require('validator');
var bigInt = require("big-integer");
var pbkdf2 = require('pbkdf2');
var ecies = require('standard-ecies');
var classTransformer = require('class-transformer');
var blockexplorer = require('blockchain.info/blockexplorer');
var bip39Custom = require('bip39')

var IsTestMode = true

// Generate the seed using the mnemonic and the extraText.
let unencryptedSeedBuf = bip39Custom.mnemonicToSeed(
    "salt august scan top indoor resource believe buyer craft defy among run ice notable service",
    "");

// Save the public key before encrypting the seed.
let xpubRoot = bip32.fromSeed(
    unencryptedSeedBuf, bitcoinjs.networks.testnet).derivePath(
        "m/44'/0'/0'").neutered().toBase58()

console.log(xpubRoot)

let userPublicKey = bip32.fromBase58(
    xpubRoot, bitcoinjs.networks.testnet).derive(0).derive(0).publicKey

console.log(userPublicKey.toString('hex'))

// Set BTC deposit address depending on whether we're in test mode
// or not.
let btcDepositAddress = bitcoinjs.payments.p2pkh({
  pubkey: userPublicKey,
  network: bitcoinjs.networks.bitcoin}).address
if (IsTestMode) {
  btcDepositAddress = bitcoinjs.payments.p2pkh({
    pubkey: userPublicKey,
    network: bitcoinjs.networks.testnet}).address
}

console.log(btcDepositAddress)
