import { Component, OnInit, Input, ChangeDetectorRef } from '@angular/core';
import { sprintf } from "sprintf-js";
import * as validator from 'validator';
import * as nodeCrypto from '../../../vendor/crypto.browserify.js'
import * as buf from '../../../vendor/buffer.browserify.js'
import bip39Custom from '../../../vendor/bip39.browserify.js'
import bigInt from '../../../vendor/big-integer.browserify.js'

class EntropyGeneratorConstants {
  static DEFAULT_ENTROPY_BYTES: number = 16;
  static ENTROPY_ALIGNMENT_BYTES: number = 4;
  static MIN_ENTROPY_BYTES = 16
  static MAX_ENTROPY_BYTES = 64
}

export class Messages {
  static INVALID_HEX_ENTROPY: string = `Your entropy is not a valid hexadecimal string.`;
  static NO_ENTROPY: string = `Enter some entropy in the format most convenient to you.`;
  static SHORT_ENTROPY: string = `You must have at least %d characters (= 32 bits) of hexadecimal entropy.`;
  static LONG_ENTROPY: string = `No more than %d characters (= 512 bits) of hexadecimal entropy allowed (if it makes you feel any better the US government allegedly uses 384 bits to protect its most sensitive information...).`;
  static ENTROPY_NOT_BYTE_ALIGNED: string = `You need a multiple of %s hex characters to create a well-formed mnemonic.`;
  static INVALID_DICE_ENTROPY: string = `Your dice entropy is not valid. Make sure you\'re only using numbers [1-6].`;
  static INVALID_DECIMAL_ENTROPY: string = `Your decimal entropy is not valid. Make sure you\'re only using numbers [0-9].`;
  static INVALID_MNEMONIC: string = `You've entered an invalid mnemonic.`;
}

// Entropy we generate for the user during the signup process.
// Some fields are redundant so we can display them in the
// template.
//
export type TemporaryEntropy = {
  entropy: buf.Buffer,
  isVerified: boolean,
  mnemonic: string,
  extraText: string,

  // Display fields.
  customEntropyHex: string,
  customEntropyHexMessage: string,

  customEntropyDice: string,
  customEntropyDiceMessage: string,

  customEntropyDecimal: string,
  customEntropyDecimalMessage: string,

  customMnemonicMessage: string
}

@Component({
  selector: 'app-entropy-generator',
  templateUrl: './entropy-generator.component.html',
  styleUrls: ['./entropy-generator.component.scss']
})
export class EntropyGeneratorComponent implements OnInit {
  // Keep a reference to the parent app data.
  @Input() temporaryEntropy: { value: TemporaryEntropy };

  constructor(private changeRef: ChangeDetectorRef) { }

  ngOnInit() {
    // Only generate entropy if we don't already have something set.
    if (this.temporaryEntropy.value == null) {
      // Temporary entropy we generate for the user.
      this.resetEntropy();
    }
  }

  isSimpleSelected: boolean = true;
  simplePressed() {
    this.isSimpleSelected = true;
  }
  advancedPressed() {
    this.isSimpleSelected = false;
  }

  resetEntropy() {
    this.temporaryEntropy.value = this.generateEntropy();
  }

  generateEntropy(): TemporaryEntropy {
    let entropy = nodeCrypto.randomBytes(
        EntropyGeneratorConstants.DEFAULT_ENTROPY_BYTES);
    //let entropy = new Uint8Array(EntropyGeneratorConstants.DEFAULT_ENTROPY_BYTES);
    //crypto.getRandomValues(entropy);

    // TODO: We should have the backend do all of the crypto stuff to make
    // everything consistent.
    let mnemonic =
        bip39Custom.entropyToMnemonic(entropy);

    // We try to always set the fields of temporaryEntropy like
    // this to make sure everything stays consistent.
    return {
      entropy: entropy,
      isVerified: false,
      mnemonic: mnemonic,
      extraText: '',

      customEntropyHex: entropy.toString('hex'),
      customEntropyHexMessage: '',

      customEntropyDice: this._entropyToDice(entropy),
      customEntropyDiceMessage: '',

      customEntropyDecimal: bigInt(
          entropy.toString('hex'), 16).toString(10),
      customEntropyDecimalMessage: '',

      customMnemonicMessage: ''
    }
  }

  customEntropyHexChanged(newValue) {
    // We want to avoid messing with extraText in this function.
    let extraText = this.temporaryEntropy.value.extraText;

    if (newValue.length === 0) {
      this.temporaryEntropy.value = {
        entropy: null,
        isVerified: false,
        mnemonic: '',
        extraText: extraText,

        customEntropyHex: newValue,
        customEntropyHexMessage: Messages.NO_ENTROPY,

        customEntropyDice: '',
        customEntropyDiceMessage: '',

        customEntropyDecimal: '',
        customEntropyDecimalMessage: '',

        customMnemonicMessage: '',
      }
      return;
    }
    if (!validator.isHexadecimal(newValue)) {
      this.temporaryEntropy.value = {
        entropy: null,
        isVerified: false,
        mnemonic: '',
        extraText: extraText,

        customEntropyHex: newValue,
        customEntropyHexMessage: Messages.INVALID_HEX_ENTROPY,

        customEntropyDice: '',
        customEntropyDiceMessage: '',

        customEntropyDecimal: '',
        customEntropyDecimalMessage: '',

        customMnemonicMessage: '',
      }
      return;
    }
    if (newValue.length < (
        EntropyGeneratorConstants.MIN_ENTROPY_BYTES * 2)) {
      this.temporaryEntropy.value = {
        entropy: null,
        isVerified: false,
        mnemonic: '',
        extraText: extraText,

        customEntropyHex: newValue,
        customEntropyHexMessage: sprintf(
            Messages.SHORT_ENTROPY,
            EntropyGeneratorConstants.MIN_ENTROPY_BYTES * 2),

        customEntropyDice: this._entropyToDice(buf.Buffer(newValue.length % 2 == 0 ? newValue : newValue+'0', 'hex')),
        customEntropyDiceMessage: '',

        customEntropyDecimal: bigInt(
            newValue, 16).toString(10),
        customEntropyDecimalMessage: '',

        customMnemonicMessage: ''
      }
      return;
    }
    if (newValue.length > (
        EntropyGeneratorConstants.MAX_ENTROPY_BYTES * 2)) {
      this.temporaryEntropy.value = {
        entropy: null,
        isVerified: false,
        mnemonic: '',
        extraText: extraText,

        customEntropyHex: newValue,
        customEntropyHexMessage: sprintf(
            Messages.LONG_ENTROPY,
            EntropyGeneratorConstants.MAX_ENTROPY_BYTES * 2),

        customEntropyDice: this._entropyToDice(buf.Buffer(newValue.length % 2 == 0 ? newValue : newValue+'0', 'hex')),
        customEntropyDiceMessage: '',

        customEntropyDecimal: bigInt(
            newValue, 16).toString(10),
        customEntropyDecimalMessage: '',

        customMnemonicMessage: ''
      }
      return;
    }
    if (newValue.length % (EntropyGeneratorConstants.ENTROPY_ALIGNMENT_BYTES * 2) !== 0) {
      this.temporaryEntropy.value = {
        entropy: null,
        isVerified: false,
        mnemonic: '',
        extraText: extraText,

        customEntropyHex: newValue,
        customEntropyHexMessage: sprintf(
          Messages.ENTROPY_NOT_BYTE_ALIGNED,
          EntropyGeneratorConstants.ENTROPY_ALIGNMENT_BYTES * 2),

        customEntropyDice: this._entropyToDice(buf.Buffer(newValue.length % 2 == 0 ? newValue : newValue+'0', 'hex')),
        customEntropyDiceMessage: '',

        customEntropyDecimal: bigInt(
            newValue, 16).toString(10),
        customEntropyDecimalMessage: '',

        customMnemonicMessage: ''
      }
      return;
    }

    // If the custom entropy isn't malformed, we'll take it.

    let entropy = buf.Buffer(newValue, 'hex');
    let mnemonic = bip39Custom.entropyToMnemonic(entropy);
    console.log(newValue);
    console.log(entropy);
    console.log(entropy.toString('hex'));
    console.log(mnemonic);

    this.temporaryEntropy.value = {
      entropy: entropy,
      isVerified: false,
      mnemonic: mnemonic,
      extraText: extraText,

      customEntropyHex: newValue,
      customEntropyHexMessage: '',

      customEntropyDice: this._entropyToDice(buf.Buffer(newValue.length % 2 == 0 ? newValue : newValue+'0', 'hex')),
      customEntropyDiceMessage: '',

      customEntropyDecimal: bigInt(newValue, 16).toString(10),
      customEntropyDecimalMessage: '',

      customMnemonicMessage: ''
    }
  }

  _entropyToDice(entropy: buf.Buffer) {
    return bigInt(entropy.toString('hex'), 16).toString(6).replace(/0/g, '6')
  }

  _diceToEntropy(dice: string) {
    // We want to avoid messing with extraText in this function.
    let extraText = this.temporaryEntropy.value.extraText;

    console.log(bigInt(dice.replace(/6/g, '0'), 6).toString(16));
    return buf.Buffer(bigInt(dice.replace(/6/g, '0'), 6).toString(16), 'hex')
  }

  customEntropyDiceChanged(newValue) {
    // We want to avoid messing with extraText in this function.
    let extraText = this.temporaryEntropy.value.extraText;

    if (newValue.replace(/[1-6]/g, '').length > 0) {
      this.temporaryEntropy.value = {
        entropy: null,
        isVerified: false,
        mnemonic: '',
        extraText: extraText,

        customEntropyHex: '',
        customEntropyHexMessage: '',

        customEntropyDice: newValue,
        customEntropyDiceMessage: Messages.INVALID_DICE_ENTROPY,

        customEntropyDecimal: '',
        customEntropyDecimalMessage: '',

        customMnemonicMessage: ''
      }
      return;
    }
    this.customEntropyHexChanged(this._diceToEntropy(newValue).toString('hex'))
    this.temporaryEntropy.value.customEntropyDice = newValue;
  }

  customEntropyDecimalChanged(newValue) {
    // We want to avoid messing with extraText in this function.
    let extraText = this.temporaryEntropy.value.extraText;

    if (newValue.replace(/[0-9]/g, '').length > 0) {
      this.temporaryEntropy.value = {
        entropy: null,
        isVerified: false,
        mnemonic: '',
        extraText: extraText,

        customEntropyHex: '',
        customEntropyHexMessage: '',

        customEntropyDice: '',
        customEntropyDiceMessage: '',

        customEntropyDecimal: newValue,
        customEntropyDecimalMessage: Messages.INVALID_DECIMAL_ENTROPY,

        customMnemonicMessage: ''
      }
      return;
    }
    this.customEntropyHexChanged(bigInt(newValue, 10).toString(16))
    this.temporaryEntropy.value.customEntropyDecimal = newValue;
  }

  mnemonicChanged(newValue) {
    // We want to avoid messing with extraText in this function.
    let extraText = this.temporaryEntropy.value.extraText;

    try {
      let entropy = bip39Custom.mnemonicToEntropy(newValue);
      let hexEntropy = entropy.toString('hex');
      this.customEntropyHexChanged(hexEntropy);
      this.temporaryEntropy.value.mnemonic = newValue;
    } catch {
      this.temporaryEntropy.value = {
        entropy: null,
        isVerified: false,
        mnemonic: newValue,
        extraText: extraText,

        customEntropyHex: '',
        customEntropyHexMessage: '',

        customEntropyDice: '',
        customEntropyDiceMessage: '',

        customEntropyDecimal: '',
        customEntropyDecimalMessage: '',

        customMnemonicMessage: Messages.INVALID_MNEMONIC
      }
      return;
    }
  }

  extraTextChanged(newValue: string) {
    // Ensure the extra words are normalized.
    newValue = newValue.normalize('NFKD');
    this.temporaryEntropy.value.extraText = newValue;
  }

}
