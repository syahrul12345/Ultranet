import { AppData, PageType } from '../../app.component';
import { ApplicationRef, ChangeDetectorRef, Component, OnInit, Input } from '@angular/core';
import { TemporaryEntropy } from './../entropy-generator/entropy-generator.component';
import { first } from 'rxjs/operators'
import { isHexadecimal } from 'validator';
import * as _ from "lodash";
import { sprintf } from "sprintf-js";
import { WindowRefService } from '../../window-ref.service';
import { grpc } from "@improbable-eng/grpc-web";
import { AdjectiveList } from '../../../vendor/random-words/adjectives'
import { NounList } from '../../../vendor/random-words/nouns'
import { BackendApiService, User, TopMerchant } from '../../backend-api.service';
import bip39Custom from '../../../vendor/bip39.browserify.js'

class Messages {
  static INTERNAL_ENTROPY_ERROR: string = `We had a problem verifying your mnemonic. Could you try another one?`
  static INTERNAL_EXTRA_TEXT_ERROR: string = `We had a problem verifying your extra text. Could you try some different text?`
  static VERIFICATION_FAILED_MNEMONIC: string = `The string you entered doesn't match the seed generated in the previous step.\nExpected seed: %s\nWhat you entered: %s`
  static VERIFICATION_FAILED_EXTRA_WORDS: string = `The extra words you entered don't match what you entered in the previous step. Don't forget that spaces matter.\nExpected: %s\nWhat you entered: %s`
  static CONFIRM_SKIP_VERIFICATION: string = `Are you sure you want to skip verification?`
  static CONFIRM_SKIP_PASSWORD: string = `Are you sure you want to skip creating a password? Your password is used to encrypt your seed and not entering one is bad because it means your seed will be stored on disk unencrypted.`
  static CONFIRM_DELETE_USER = `Are you sure you want to delete this account? You can always restore it later using your seed.`
  static MISSING_MNEMONIC = `Please go back and generate a mnemonic first.`
  static PASSWORDS_DONT_MATCH = `Your passwords don't match.`

  static USERNAME_TOO_SHORT = `Your username is too short.`
  static MERCHANT_DESCRIPTION_TOO_SHORT = `Your description is too short.`
  static MISSING_LOGGED_IN_USER = `Missing logged-in user data. Try logging out and logging back in again or restarting the app.`
  static PROBLEM_CREATING_USER = `There was a problem creating your user. Are you connected to your node? Debug output: %s.`
  static PROBLEM_LOGGING_OUT_USER = `There was a problem logging out your user. Are you connected to your node? Debug output: %s.`
  static PROBLEM_LOGGING_IN_USER  = `There was a problem logging in your user. Are you connected to your node? Debug output: %s.`
  static PROBLEM_UPDATING_USER = `There was a problem updating your user. Are you connected to your node? Debug output: %s.`
  static PROBLEM_DELETING_USER  = `There was a problem deleting your user. Are you connected to your node? Debug output: %s.`

  static INCORRECT_PASSWORD = `The password you entered was incorrect.`
  static INSUFFICIENT_BALANCE = `Your balance is insufficient to process the transaction. Decreasing the fee rate may fix this.`
  static CONNECTION_PROBLEM = `There is currently a connection problem. Is your connection to your node healthy?`
  static UNKOWN_PROBLEM = `There was a weird problem with the transaction. Debug output: %s`

  static CONFIRM_UPDATE_STRING = `Ready to update your merchant data for %s Ultra?`
  static UPDATE_MERCHANT_SUCCESS = `Merchant data updated successfully. It may take a few minutes for the change to be reflected in the top merchants page (technically, it won't be visible to everyone on the network until your update transaction has been mined into a block).`

  static USERNAME_EXISTS = `The username you selected is already taken. Merchant usernames must be globally unique so please choose another one.`
  static CONFIRM_REGISTER_MERCHANT_STRING = `Ready to register as a merchant for %s Ultra?`
  static REGISTER_MERCHANT_SUCCESS = `You successfully registered as a merchant. It may take a few minutes for the change to be reflected in the top merchants page (technically, it won't be visible to everyone on the network until your transaction has been mined into a block).`
}

enum ViewShowing {
 None,

 // Views for the create user flow
 EnterNewAccountInfo,
 CopySeed,
 VerifySeed,
 EnterPassword,

 // View for logging in from seed
 LoadAccountFromSeed,

 // Views for the create merchant flow
 EnterNewMerchantInfo,
}

@Component({
  selector: 'app-setup-user',
  templateUrl: './setup-user.component.html',
  styleUrls: ['./setup-user.component.scss']
})
export class SetupUserComponent implements OnInit {
  // Keep a reference to the global app data.
  @Input() appData: AppData;

  intervalsSet: number[] = [];
  _repeat(funcToRepeat: () => void, timeoutMillis) {
    funcToRepeat()
    let interval: number = <any>setInterval(() => {
      funcToRepeat()
    }, timeoutMillis)
    this.intervalsSet.push(interval)
  }

  // All the local variables.
  parseFloat = parseFloat;
  ViewShowing = ViewShowing;
  viewShowing: ViewShowing = ViewShowing.None;

  temporaryEntropy: {
    value: TemporaryEntropy
  } = {
    value: null,
  }
  mnemonicVerificationText: string = '';
  mnemonicExtraTextVerification: string = '';

  tempPassword: string = '';
  tempPasswordVerification: string = '';

  _randomUsername(): string {
    let adjectiveIndex = Math.floor((Math.random() * AdjectiveList.adjectives.length))
    let nounIndex = Math.floor((Math.random() * NounList.nouns.length))
    return AdjectiveList.adjectives[adjectiveIndex] + '-' + NounList.nouns[nounIndex];
  }

  _clickLogoutUser() {
    // Transition back to the main view.
    this.appData.loggedInUser = null
    this._transitionToNone()
    this.changeRef.detectChanges();

    this.backendApi.Logout(this.appData.localNode, this.appData.localNodeSecret).subscribe(
      (res: any) => {
        if (res.userData == null) {
          alert(sprintf(Messages.PROBLEM_LOGGING_OUT_USER, JSON.stringify(res)))
          return
        }
      },
      (error) => {
          alert(sprintf(Messages.PROBLEM_LOGGING_OUT_USER, JSON.stringify(error)))
          return
       }
    )
  }

  createUserUsername: string = '';
  createUserReferralPublicKey: string = '';
  _clickCreateUser(){
    if (this.appData.localNodeSecret == null || this.appData.localNodeSecret === '') {
      alert('You are currently using an untrusted node to preview the Ultranet. '+
        'The Ultranet is totally decentralized and, as a result, creating accounts '+
        'on untrusted nodes is currently not secure. '+
        'If you would like to see the Ultranet in its full glory please download '+
        'the desktop client from ultranet.one.')
      return;
    }

    // Launch the user into the account creation flow.
    this.viewShowing = ViewShowing.EnterNewAccountInfo;
    this.createUserUsername =  this._randomUsername();
  }

  _clickLoadUserFromSeed() {
    if (this.appData.localNodeSecret == null || this.appData.localNodeSecret === '') {
      alert('You are currently using an untrusted node to preview the Ultranet. '+
        'The Ultranet is totally decentralized and, as a result, loading accounts '+
        'on untrusted nodes is currently not secure. '+
        'If you would like to see the Ultranet in its full glory please download '+
        'the desktop client from ultranet.one.')
      return;
    }
    this.viewShowing = ViewShowing.LoadAccountFromSeed
    this.changeRef.detectChanges()
  }

  _clickBecomeMerchant() {
    this.viewShowing = ViewShowing.EnterNewMerchantInfo;
    this._resetFormFields();
    this.changeRef.detectChanges();
  }

  updateUsername: string = '';
  _clickUpdateUsername() {
    if (this.updateUsername == null || this.updateUsername === '') {
      alert("You need to choose a username to change to.")
      return
    }

    // Transition back to the main view.
    this.appData.loggedInUser.Username = this.updateUsername
    this.changeRef.detectChanges();

    this.backendApi.Update(
      this.appData.localNode, this.appData.localNodeSecret, this.updateUsername).subscribe(
      (res: any) => {
        if (res.userData == null) {
          alert(sprintf(Messages.PROBLEM_UPDATING_USER, JSON.stringify(res)))
          return
        }

      },
      (error) => {
          alert(sprintf(Messages.PROBLEM_UPDATING_USER, JSON.stringify(error)))
          return
       }
    )
  }

  _clickBuyUltra() {
    this.appData.selectedPage = PageType.BuyUltra;
    this.changeRef.detectChanges();
    window.scrollTo(0, 0);
    return
  }

  loginPasswords = {}
  _clickLoginAsUser(user: any, userIndex: number) {
    let passwordForUser = this.loginPasswords[userIndex];
    if (passwordForUser == null) {
      passwordForUser = '';
    }

    this.backendApi.Login(
      this.appData.localNode, this.appData.localNodeSecret,
      user.PublicKeyBase58Check, passwordForUser).subscribe(

      (res: any) => {
        this.loginPasswords = {}
        if (res.userData == null) {
          alert(sprintf(Messages.PROBLEM_LOGGING_IN_USER, JSON.stringify(res)))
          return
        }

        alert(sprintf('Successfully logged in as user: %s', user.Username))
        this.appData.loggedInUser = user
        this._resetFormFields();
        this._transitionToNone()
        this.changeRef.detectChanges();
        window.scrollTo(0, 0);
      },
      (error) => {
          alert(this._extractMerchantOperationError(error))
          return
       }
    )
  }

  _clickDeleteAccount(user: any) {
    if (this.appData.loggedInUser != null &&
      user.PublicKeyBase58Check === this.appData.loggedInUser.PublicKeyBase58Check) {

      this.appData.loggedInUser = null
    }
    let newUserList = [];
    for (var ii = 0; ii < this.appData.userList.length; ii++) {
      if (this.appData.userList[ii].PublicKeyBase58Check === user.PublicKeyBase58Check) {
        continue;
      }
      newUserList.push(this.appData.userList[ii])
    }
    this.appData.userList = newUserList;
    this._transitionToNone()
    this.changeRef.detectChanges();

    this.backendApi.DeleteUser(
      this.appData.localNode, this.appData.localNodeSecret,
      user.PublicKeyBase58Check).subscribe(
      (res: any) => {
        if (res.userData == null) {
          alert(sprintf(Messages.PROBLEM_DELETING_USER, JSON.stringify(res)))
          return
        }
      },
      (error) => {
          alert(sprintf(Messages.PROBLEM_DELETING_USER, JSON.stringify(error)))
          return
       }
    )
  }

  // Merchant account info stuff.
  newMerchantUsername = '';
  newMerchantDescription = '';
  merchantBurnUltra = 0;
  merchantFeeRateUltraPerKB = '0';
  merchantTotalFeeNanos = 0;
  merchantPassword = '';
  merchantError = '';
  _resetFormFields() {
    if (this.appData.loggedInUser == null) {
      return;
    }

    this.updateUsername = this.appData.loggedInUser.Username;
    this.newMerchantUsername = this.appData.loggedInUser.Username
    this.merchantFeeRateUltraPerKB = (this.appData.defaultFeeRateNanosPerKB / 1e9).toFixed(9)
    this.changeRef.detectChanges()
      
    if (this.appData.loggedInUser.MerchantEntry == null) {
      return;
    }
    this.newMerchantDescription = this.appData.loggedInUser.MerchantEntry.Description
  }
  _clickResetUpdateMerchantFeeRate() {
    this.merchantFeeRateUltraPerKB = (this.appData.defaultFeeRateNanosPerKB / 1e9).toFixed(9)
  }

  // This function calls UpdateMerchant on the backend. Note that we throttle
  // UpdateMerchant so that we don't make multiple calls at the same time.
  callingUpdateMerchant = false
  _updateMerchant(
    password: string, sign: boolean, validate: boolean, broadcast: boolean, force: boolean): Promise<any> {

    if (this.callingUpdateMerchant && !force) {
      return;
    }

    if (this.appData.loggedInUser == null) {
      return;
    }

    this.callingUpdateMerchant = true;
    return this.backendApi.UpdateMerchant(
      this.appData.localNode, this.appData.localNodeSecret,
      this.appData.loggedInUser.PublicKeyBase58Check,
      this.newMerchantUsername,
      this.newMerchantDescription,
      this.merchantBurnUltra * 1e9,
      parseFloat(this.merchantFeeRateUltraPerKB) * 1e9,
      password,
      sign,
      validate,
      broadcast,
    ).toPromise().then((res)=>{
      this.callingUpdateMerchant = false;
      return this.appData._wrapWithPromise(res)
    }, (err) =>{
      this.callingUpdateMerchant = false;
      return this.appData._wrapWithPromise(err)
    })
  }

  // This function calls RegisterMerchant on the backend. Note that we throttle
  // RegisterMerchant so that we don't make multiple calls at the same time.
  callingRegisterMerchant = false
  _registerMerchant(
    password: string, sign: boolean, validate: boolean, broadcast: boolean): Promise<any> {

    if (this.callingRegisterMerchant) {
      return;
    }

    if (this.appData.loggedInUser == null) {
      return;
    }

    return this.backendApi.RegisterMerchant(
      this.appData.localNode, this.appData.localNodeSecret,
      this.newMerchantUsername,
      this.newMerchantDescription,
      this.appData.loggedInUser.PublicKeyBase58Check,
      this.merchantBurnUltra * 1e9,
      parseFloat(this.merchantFeeRateUltraPerKB) * 1e9,
      password,
      sign,
      validate,
      broadcast,
    ).toPromise().then((res)=>{
      this.callingRegisterMerchant = false;
      return this.appData._wrapWithPromise(res)
    }, (err) =>{
      this.callingRegisterMerchant = false;
      return this.appData._wrapWithPromise(err)
    })
  }

  _extractMerchantOperationError(err: any): string {
    if (err.error != null && err.error.error != null) {
      // Is it obvious yet that I'm not a frontend gal?
      // TODO: Error handling between BE and FE needs a major redesign.
      let rawError = err.error.error;
      if (rawError.includes("password")) {
        return Messages.INCORRECT_PASSWORD
      } else if (rawError.includes("not sufficient")) {
        if (rawError.includes("UpdateMerchant")) {
          return Messages.INSUFFICIENT_BALANCE + " Note that merchant updates require a non-zero burn amount."
        }
        return Messages.INSUFFICIENT_BALANCE
      } else if (rawError.includes("RuleErrorMerchantUsernameExists")) {
        return Messages.USERNAME_EXISTS
      } else {
        return rawError
      }
    }
    if (err.status != null && err.status != 200) {
      return Messages.CONNECTION_PROBLEM;
    }
    // If we get here we have no idea what went wrong so just return the
    // errorString.
    return sprintf(Messages.UNKOWN_PROBLEM, JSON.stringify(err))
  }
  _updateMerchantOperationTxnFee(force: boolean): Promise<any> {
    // Don't bother computing fees if the user is not logged in or the
    // user is not a merchant.
    if (this.appData.loggedInUser == null) {
      return;
    }

    let updateOrRegisterPromise: Promise<any> = null;
    if (this.viewShowing === ViewShowing.EnterNewMerchantInfo) {
      updateOrRegisterPromise = this._registerMerchant(
        '' /*password*/, false /*sign*/, false /*validate*/, false /*broadcast*/)

    } else if (this.viewShowing === ViewShowing.None &&
      this.appData.loggedInUser.MerchantEntry != null) {

      updateOrRegisterPromise = this._updateMerchant(
        '' /*password*/, false /*sign*/, false /*validate*/, false /*broadcast*/, force)

    } else {
      return
    }

    if(updateOrRegisterPromise == null) {
      return
    }

    return updateOrRegisterPromise.then((res)=>{
      if (res.feeNanos == null) {
        return
      }
      this.merchantTotalFeeNanos = res.feeNanos
      this.merchantError = ''
      this.changeRef.detectChanges()
      return res
    }, (err)=>{
      this.merchantTotalFeeNanos = 0
      this.merchantError = this._extractMerchantOperationError(err)
      this.changeRef.detectChanges()
      return err
    })
  }
  _confirmAndUpdateMerchant(res: any): Promise<any> {
    if (this.merchantError != null && this.merchantError !== '') {
      alert(this.merchantError);
      return;
    }

    let totalNanos = this.merchantBurnUltra*1e9 + this.merchantTotalFeeNanos

    if (totalNanos === 0) {
      this.merchantBurnUltra = 1e-9
      totalNanos = 1
    }
    let totalUltra = this.appData.nanosToUltra(totalNanos)

    let confirmandUpdateMerchantString = sprintf(
      Messages.CONFIRM_UPDATE_STRING, totalUltra)

    if (confirm(confirmandUpdateMerchantString)) {
      return this._updateMerchant(
        this.merchantPassword, true /*sign*/, true /*validate*/,
        true /*broadcast*/, true /*force*/)
    } else {
      return null;
    }
  }
  _confirmAndRegisterMerchant(res: any): Promise<any> {
    let totalNanos = this.merchantBurnUltra*1e9 + this.merchantTotalFeeNanos

    let confirmandUpdateMerchantString = sprintf(
      Messages.CONFIRM_REGISTER_MERCHANT_STRING, this.appData.nanosToUltra(totalNanos))

    if (confirm(confirmandUpdateMerchantString)) {
      return this._registerMerchant(
        this.merchantPassword, true /*sign*/, true /*validate*/,
        true /*broadcast*/)
    } else {
      return null;
    }
  }
  _clickRegisterMerchant() {
    let registerMerchantPromise = this._updateMerchantOperationTxnFee(true /*force*/)

    if (registerMerchantPromise == null) {
      console.log('Not calling RegisterMerchant because waiting for previous call to complete.')
      return
    }

    registerMerchantPromise.then(
      (res: any) => {
        let confirmMerchantRegisterPromise = this._confirmAndRegisterMerchant(res)
        if (confirmMerchantRegisterPromise == null) {
          this.merchantPassword = '';
          return
        }
        confirmMerchantRegisterPromise.then(
          (res) => {
            alert(sprintf(Messages.REGISTER_MERCHANT_SUCCESS));
            // Don't reset the form fields because they're currently what we want them
            // to be and the next fetch of the user data should fixe them up.
            //this._resetFormFields()
            //
            // Do reset the password though.
            this.merchantPassword = '';
            this.merchantBurnUltra = 0;
            this._transitionToNone();
          }, (err) => {
            // Reset the password .
            this.merchantPassword = '';
            // Alert the error that was returned.
            alert(this._extractMerchantOperationError(err))
          }
        )
      }, (err: any) => {
        alert("There was a problem updating the listing fee prior to placing the order: "+ JSON.stringify(err))
      }
    )
  }
  _clickUpdateMerchantData() {
    // Force the update to happen when the button is pressed.
    let updateMerchantPromise = this._updateMerchantOperationTxnFee(true /*force*/)

    if (updateMerchantPromise == null) {
      console.log('Not calling UpdateMerchant because waiting for previous call to complete.')
      return
    }

    updateMerchantPromise.then(
      (res: any) => {
        let confirmMerchantUpdatePromise = this._confirmAndUpdateMerchant(res)
        if (confirmMerchantUpdatePromise == null) {
          this.merchantPassword = '';
          return
        }
        confirmMerchantUpdatePromise.then(
          (res) => {
            alert(sprintf(Messages.UPDATE_MERCHANT_SUCCESS));
            // Don't reset the form fields because they're currently what we want them
            // to be and the next fetch of the user data should fixe them up.
            //this._resetFormFields()
            //
            // Do reset the password though.
            this.merchantPassword = '';
          }, (err) => {
            // Reset the password .
            this.merchantPassword = '';
            // Alert the error that was returned.
            alert(this._extractMerchantOperationError(err))
          }
        )
      }, (err: any) => {
        alert("There was a problem updating the listing fee prior to placing the order: "+ JSON.stringify(err))
      }
    )
  }

  _transitionToNone() {
    this._resetFormFields();
    this.viewShowing = ViewShowing.None;
  }

  // This function captures the back functionality for all the
  // states. We aggregate all similar back button functions into
  // one so you can get a better sense of what the state machine
  // looks like.
  backPressed() {
    switch(this.viewShowing) {
    case ViewShowing.EnterNewAccountInfo: {
      // Go back to deciding between login and creating an account.
      this._transitionToNone();
      break;

    // These are the create merchant back button cases.
    } case ViewShowing.EnterNewMerchantInfo: {
      // Transition back to the info entry page.
      this._transitionToNone();
      break;

    // These are the create user back button cases.
    } case ViewShowing.CopySeed: {
      // Transition back to the info entry page.
      this.viewShowing = ViewShowing.EnterNewAccountInfo;
      break;
    } case ViewShowing.VerifySeed: {
      // Transition back to the copy seed view.
      this.viewShowing = ViewShowing.CopySeed;
      break;
    } case ViewShowing.EnterPassword: {
      // Go back to verifying your seed.
      this.viewShowing = ViewShowing.VerifySeed;
      break;
    } case ViewShowing.LoadAccountFromSeed: {
      this._transitionToNone();
      break;
    } default: {
      throw 'Unrecognized transition from: ' + this.viewShowing;
    }
    }
  }

  _handleNextEnterAccountInfo()  {
    // Validate the input. 
    if (this.createUserUsername.length === 0) {
      alert('You must enter a username before proceeding.');
      return;
    }
    if (this.createUserReferralPublicKey.length === 0) {
      if (confirm('You didn\'t enter a referrer public key. Are you sure you want to continue?')) {
        alert('For a limited time, you will enjoy 20% off all orders even though you didn\'t enter a referrer public key. Happy decentralized shopping.')
        this.viewShowing = ViewShowing.CopySeed;
        return;
      } else {
        return;
      }
    }
    this.viewShowing = ViewShowing.CopySeed;
  }

  _handleNextCopySeed(event: string) {
    // Before we move forward, as a sanity check, ensure that the
    // entropy we have is in-line with the mnemonic.
    if (this.temporaryEntropy.value == null ||
        this.temporaryEntropy.value.entropy == null ||
        this.temporaryEntropy.value.mnemonic === '' ||
        bip39Custom.entropyToMnemonic(
            this.temporaryEntropy.value.entropy) !==
            this.temporaryEntropy.value.mnemonic) {
      alert(Messages.INTERNAL_ENTROPY_ERROR);
      return;
    }
    if (this.temporaryEntropy.value.extraText == null) {
      alert(Messages.INTERNAL_EXTRA_TEXT_ERROR);
      return;
    }

    // Empty out the extra words form on the verification page if the
    // user has cleared it from the seed generation page.
    if (this.temporaryEntropy.value.extraText === '') {
      this.mnemonicExtraTextVerification = '';
    }
    
    // Transition to the seed verification step.
    this.viewShowing = ViewShowing.VerifySeed;
    return;
  }

  _handleNextVerifySeed(event: string) {
    if (this.temporaryEntropy.value == null ||
        this.temporaryEntropy.value.entropy == null ||
        this.temporaryEntropy.value.mnemonic === '') {
      alert(Messages.MISSING_MNEMONIC);
      return;
    }
    if (event === 'skip') {
      if (confirm(Messages.CONFIRM_SKIP_VERIFICATION)) {
        // Explain registration to them.
        this.viewShowing = ViewShowing.EnterPassword;
        return;
      } else {
        return;
      }
    }
    let actualWords = this.temporaryEntropy.value.mnemonic.split(/\s+/g);
    let verificationWords = this.mnemonicVerificationText.split(/\s+/g);
    if (!_.isEqual(actualWords, verificationWords)) {
      let errorString = sprintf(
          Messages.VERIFICATION_FAILED_MNEMONIC,
          this.temporaryEntropy.value.mnemonic.replace(/ /g, '_ '),
          this.mnemonicVerificationText.replace(/ /g, '_ '));
      alert(errorString);
      return;
    }

    let extraText = this.temporaryEntropy.value.extraText;
    let verificationExtraText = this.mnemonicExtraTextVerification;
    if (extraText !== verificationExtraText) {
      let errorString = sprintf(
          Messages.VERIFICATION_FAILED_EXTRA_WORDS,
          this.temporaryEntropy.value.extraText.replace(/ /g, '_ '),
          this.mnemonicExtraTextVerification.replace(/ /g, '_ '));
      alert(errorString);
      return;
    }

    // After they've verified their seed it's time to get them to
    // register.

    // Explain registration to them.
    this.viewShowing = ViewShowing.EnterPassword;
  }

  _handleNextEnterPassword(event: string) {
    if (this.temporaryEntropy.value == null ||
        this.temporaryEntropy.value.entropy == null ||
        this.temporaryEntropy.value.mnemonic === '') {
      alert(Messages.MISSING_MNEMONIC);
      return;
    }
    if ((bip39Custom.entropyToMnemonic(
        this.temporaryEntropy.value.entropy) !==
        this.temporaryEntropy.value.mnemonic)) {
      alert(Messages.INTERNAL_ENTROPY_ERROR);
      return;
    }
    if (this.temporaryEntropy.value.extraText == null) {
      alert(Messages.INTERNAL_EXTRA_TEXT_ERROR);
      return;
    }
    if (event === 'skip' ||
        (this.tempPassword === '' && this.tempPasswordVerification === '')) {
      if (confirm(Messages.CONFIRM_SKIP_PASSWORD)) {
        this.tempPassword = '';
        this.tempPasswordVerification = '';
      } else {
        return;
      }
    }
    if (this.tempPassword !== this.tempPasswordVerification) {
      alert(Messages.PASSWORDS_DONT_MATCH);
      return;
    }

    let seedHex = bip39Custom.mnemonicToSeedHex(this.temporaryEntropy.value.mnemonic, this.temporaryEntropy.value.extraText)
    this.backendApi.CreateUser(
      this.appData.localNode, this.appData.localNodeSecret,
      this.createUserUsername, // username
      this.createUserReferralPublicKey, // referral public key. can be empty.
      this.temporaryEntropy.value.entropy.toString('hex'), // entropyHex
      this.temporaryEntropy.value.mnemonic, // mnemonic
      this.temporaryEntropy.value.extraText, // extraText
      this.tempPassword, // password
      seedHex // seedHex
    ).subscribe(
      (res: any) => {
        if (res.userData == null || res.userData.loggedInUser == null) {
          alert(sprintf(Messages.PROBLEM_CREATING_USER, JSON.stringify(res)))
          return
        }

        // Purge the unencrypted data on success.
        seedHex = null;
        this.tempPassword = null;
        this.tempPasswordVerification = null;
        this.temporaryEntropy.value = null;

        this.appData.loggedInUser = res.userData.loggedInUser;
        this.appData.userList = res.userData.userList;
    
        // Transition back to the main view.
        this._transitionToNone()
        this.changeRef.detectChanges();
      },
      (error) => {
        alert(sprintf('There was a problem creating your user account. Is your connection healthy? Debug output: %s', JSON.stringify(error)))
        console.error(error)
        return;
      }
    )
  }

  // All the state for the LoadAccountFromSeed page.
  loginUsername: string = '';
  loginPassword: string = '';
  loginPasswordConfirm: string = '';
  loginSeedText: string = '';
  loginExtraText: string = '';
  _handleNextLoadAccountFromSeed() {
    if (this.loginPassword !== this.loginPasswordConfirm) {
      alert(Messages.PASSWORDS_DONT_MATCH);
      return;
    }

    let entropyHex = '';
    try {
      entropyHex = bip39Custom.mnemonicToEntropy(this.loginSeedText);
    } catch(e) {
      alert(e)
      return
    }

    let seedHex = bip39Custom.mnemonicToSeedHex(this.loginSeedText, this.loginExtraText)
    this.backendApi.CreateUser(
      this.appData.localNode, this.appData.localNodeSecret,
      this.loginUsername, // username
      // TODO: We shoud get rid of this whole referral code nonsense after we're
      // through the bootstrapping phase.
      '', // We don't set a referral public key for a login.
      entropyHex, // entropyHex
      this.loginSeedText, // mnemonic
      this.loginExtraText, // extraText
      this.loginPassword, // password
      seedHex // seedHex
    ).subscribe(
      (res: any) => {
        if (res.userData == null || res.userData.loggedInUser == null) {
          alert(sprintf(Messages.PROBLEM_CREATING_USER, JSON.stringify(res)))
          return
        }
        this.appData.loggedInUser = res.userData.loggedInUser;
        this.appData.userList = res.userData.userList;
    
        // Transition back to the main view.
        this._transitionToNone()
        this.changeRef.detectChanges();
      },
      (error) => { console.error(error) }
    )
    

    // Purge the unencrypted data.
    seedHex = null;
    this.tempPassword = null;
    this.tempPasswordVerification = null;
    this.temporaryEntropy.value = null;
  }

  // Next is generically something that advances the user's state
  // through the signup flow. We put all th enext functions for all
  // the views in one place to make it easier to internalize the
  // state machine.
  nextPressed(event='') {
    switch(this.viewShowing) {
    // These are the cases for the create merchant flow.
    case ViewShowing.EnterNewMerchantInfo: {
      alert('not implemented')
      break;

    // These are the cases for the create user flow.
    } case ViewShowing.EnterNewAccountInfo: {
      this._handleNextEnterAccountInfo()
      break;
    } case ViewShowing.CopySeed: {
      this._handleNextCopySeed(event);
      break;
    }  case ViewShowing.VerifySeed: {
      this._handleNextVerifySeed(event);
      break;
    } case ViewShowing.EnterPassword: {
      this._handleNextEnterPassword(event);
      break;
    } case ViewShowing.LoadAccountFromSeed: {
      this._handleNextLoadAccountFromSeed();
      break;
    }
    }
  }

  constructor(private changeRef: ChangeDetectorRef,
              private appRef: ApplicationRef,
              private windowRef: WindowRefService,
              private backendApi: BackendApiService) { }

  destroyCalled = false
  ngOnInit() {
    this._resetFormFields();
    setTimeout(()=>{
      // Avoid resetting the fields after the view is destroyed.
      if (this.destroyCalled) {
        return;
      }
      this._resetFormFields();
    }, 1000)

    // TODO: Doing an update of the fee every second is super inefficient. The right
    // way to achieve this is to do somthing like the following:
    // - <div (change)="_updateMerchantOperationTxnFee()">
    // on each of the fields that could impact the fee. The only reason we don't do
    // this is because Angular is broken and doesn't update when a number field changes,
    // only when it loses focus. Until this is fixed the UX seems slightly better doing
    // this update once per second hack.
    this._repeat(() => {this._updateMerchantOperationTxnFee(false /*force*/)}, 1000)
  }

  ngOnDestroy() {
    this.destroyCalled = true
    for (let ii = 0; ii < this.intervalsSet.length; ii++) {
      clearInterval(this.intervalsSet[ii]);
    }
  }
}
