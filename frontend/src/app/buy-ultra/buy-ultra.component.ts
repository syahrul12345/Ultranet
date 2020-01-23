import { ApplicationRef, ChangeDetectorRef, Component, OnInit, Input } from '@angular/core';
import { AppData, DashboardPage, PageType } from '../app.component';
import { BackendApiService, AddDraftImageResponse, GetDraftImageIDsResponse, BackendRoutes } from '../backend-api.service';
import { sprintf } from "sprintf-js";


class Messages {
  static INCORRECT_PASSWORD = `The password you entered was incorrect.`
  static INSUFFICIENT_BALANCE = `Your balance is insufficient to process the transaction.`
  static CONNECTION_PROBLEM = `There is currently a connection problem. Is your connection to your node healthy?`
  static UNKOWN_PROBLEM = `There was a weird problem with the transaction. Debug output: %s`

  static CONFIRM_BUY_ULTRA = `Are you ready to exchange %s Bitcoin with a fee of %s Bitcoin for %s Ultra`
  static ZERO_ULTRA_ERROR = `You must purchase a non-zero amount Ultra`
  static NEGATIVE_ULTRA_ERROR = `You must purchase a non-negative amount Ultra`

  //static CONFIRM_UPDATE_STRING = `Ready to update your merchant data for %s Ultra?`
  //static UPDATE_MERCHANT_SUCCESS = `Merchant data updated successfully. It may take a few minutes for the change to be reflected in the top merchants page (technically, it won't be visible to everyone on the network until your update transaction has been mined into a block).`
}

class Constants {
  static UPDATE_CYCLE_TIME = 60
}

@Component({
  selector: 'app-buy-ultra',
  templateUrl: './buy-ultra.component.html',
  styleUrls: ['./buy-ultra.component.scss']
})
export class BuyUltraComponent implements OnInit {
  @Input() appData: AppData;

  showHowItWorks = false;
  showAreYouReady = false;
  showPendingTransactions = true;

  constructor(
    private ref: ChangeDetectorRef,
    private backendApi: BackendApiService) { }

  _extractBurnError(err: any): string {
    if (err.error != null && err.error.error != null) {
      // Is it obvious yet that I'm not a frontend gal?
      // TODO: Error handling between BE and FE needs a major redesign.
      let rawError = err.error.error;
      if (rawError.includes("password")) {
        return Messages.INCORRECT_PASSWORD
      } else if (rawError.includes("not sufficient")) {
        return Messages.INSUFFICIENT_BALANCE
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

  buyUltraFields = {
    ultraToBuy: '0',
    bitcoinToExchange: '0',
    bitcoinTransactionFeeRateSatoshisPerKB: 14,
    bitcoinTotalTransactionFeeSatoshis: '0',
    password: '',
    error: '',
    timeBeforeNextUpdate: Constants.UPDATE_CYCLE_TIME,
  }
  _clickCreateAccountOrLogin()  {
    this.appData.selectedPage = PageType.Account;
    this.ref.detectChanges();
    return
  }
  _updateBitcoinFee(bitcoinToExchange: number): Promise<any> {
    if (this.appData == null || this.appData.loggedInUser == null) {
      return
    }

    // Update the total fee to account for the extra Bitcoin.
    return this.backendApi.BurnBitcoin(
      this.appData.localNode, this.appData.localNodeSecret,
      this.appData.loggedInUser.PublicKeyBase58Check,
      Math.floor(bitcoinToExchange*1e8),
      Math.floor(this.buyUltraFields.bitcoinTransactionFeeRateSatoshisPerKB),
      "" /*Password*/,
      false /*Sign*/,
      false /*Broadcast*/).toPromise().then(
        (res) => {
          console.log(res)
          if (res == null || res.FeeSatoshis == null) {
            this.buyUltraFields.bitcoinTotalTransactionFeeSatoshis = '0'
            this.buyUltraFields.error = Messages.UNKOWN_PROBLEM
            return null
          }
          this.buyUltraFields.error = ''
          this.buyUltraFields.bitcoinTotalTransactionFeeSatoshis = res.FeeSatoshis
          return res
        }, (err) => {
          console.error("Problem updating Bitcoin fee Satoshis Per KB", err)
          this.buyUltraFields.bitcoinTotalTransactionFeeSatoshis = '0'
          this.buyUltraFields.error = this._extractBurnError(err)
          return null
        }
      )
  }
  _numPendingTxns(txnObj) {
    if (txnObj == null) {
      return 0
    }
    return Object.keys(txnObj).length;
  }
  _clickBuyUltra() {
    if (this.appData == null || this.appData.loggedInUser == null) {
      return
    }

    if (parseFloat(this.buyUltraFields.ultraToBuy) === 0) {
      alert(Messages.ZERO_ULTRA_ERROR)
      return
    }
    if (parseFloat(this.buyUltraFields.ultraToBuy) < 0) {
      alert(Messages.NEGATIVE_ULTRA_ERROR)
      return
    }

    if (this.buyUltraFields.error != null && this.buyUltraFields.error !== '') {
      alert(this.buyUltraFields.error)
      return
    }

    let confirmBuyUltraString = sprintf(Messages.CONFIRM_BUY_ULTRA,
      this.buyUltraFields.bitcoinToExchange,
      (parseFloat(this.buyUltraFields.bitcoinTotalTransactionFeeSatoshis)/1e8).toFixed(8),
      this.buyUltraFields.ultraToBuy)

    if (!confirm(confirmBuyUltraString)) {
      return
    }

    // Update the total fee to account for the extra Bitcoin.
    return this.backendApi.BurnBitcoin(
      this.appData.localNode, this.appData.localNodeSecret,
      this.appData.loggedInUser.PublicKeyBase58Check,
      Math.floor(parseFloat(this.buyUltraFields.bitcoinToExchange)*1e8),
      Math.floor(this.buyUltraFields.bitcoinTransactionFeeRateSatoshisPerKB),
      this.buyUltraFields.password /*Password*/,
      true /*Sign*/,
      true /*Broadcast*/).toPromise().then(
        (res) => {
          console.log(res)
          if (res == null || res.FeeSatoshis == null) {
            this.buyUltraFields.bitcoinTotalTransactionFeeSatoshis = '0'
            this.buyUltraFields.error = Messages.UNKOWN_PROBLEM
            return null
          }
          this.buyUltraFields.error = ''
          this.buyUltraFields.ultraToBuy = '0'
          this.buyUltraFields.bitcoinToExchange = '0'
          this.buyUltraFields.password = ''
          this._updateBitcoinFee(parseFloat(this.buyUltraFields.bitcoinToExchange))
          return res
        }, (err) => {
          //this.buyUltraFields.bitcoinTotalTransactionFeeSatoshis = '0'
          alert(this._extractBurnError(err))
          return null
        }
      )
  }
  _clickMaxUltra() {
    this._updateBitcoinFee(-1).then(
      (res) => {
        if (res == null || res.BurnAmountSatoshis == null) {
          return
        }

        // The fee should have been updated by the time we get here so
        // just update the Bitcoin and Ultra amounts.
        this.buyUltraFields.bitcoinToExchange = (res.BurnAmountSatoshis / 1e8).toFixed(8)
        this._updateBitcoinToExchange(this.buyUltraFields.bitcoinToExchange)
      }, (err) => {
        // The error should have been set by the time we get here.
      }
    )
  }
  _updateUltraToBuy(newVal) {
    if (newVal == null || newVal === '') {
      this.buyUltraFields.ultraToBuy = '0'
    }
    // The .999 factor comes in due to having to consider BitcoinExchangeFeeBasisPoints
    // that goes to pay the miner.
    this.buyUltraFields.bitcoinToExchange = (parseFloat(this.buyUltraFields.ultraToBuy) * this.appData.satoshisPerUltraExchangeRate / .999 / 1e8).toFixed(8)

    // Update the Bitcoin fee.
    this._updateBitcoinFee(parseFloat(this.buyUltraFields.bitcoinToExchange))
  }
  _updateBitcoinToExchange(newVal) {
    if (newVal == null || newVal === '') {
      this.buyUltraFields.bitcoinToExchange = '0'
    }
    // Compute the amount of Ultra the user can buy for this amount of Bitcoin and
    // set it.
    //
    // The .999 factor comes in due to having to consider BitcoinExchangeFeeBasisPoints
    // that goes to pay the miner.
    this.buyUltraFields.ultraToBuy = (parseFloat(this.buyUltraFields.bitcoinToExchange) * 1e8 / this.appData.satoshisPerUltraExchangeRate * .999).toFixed(9)

    // Update the Bitcoin fee.
    this._updateBitcoinFee(parseFloat(this.buyUltraFields.bitcoinToExchange))
  }
  _updateSatoshisPerKB() {
    this._updateBitcoinFee(parseFloat(this.buyUltraFields.bitcoinToExchange))
  }

  intervalsSet: number[] = [];
  _repeat(funcToRepeat: () => void, timeoutMillis) {
    funcToRepeat()
    let interval: number = <any>setInterval(() => {
      funcToRepeat()
    }, timeoutMillis)
    this.intervalsSet.push(interval)
  }

  ngOnInit() {
    this.showAreYouReady = (this.appData != null && this.appData.loggedInUser != null && this.appData.loggedInUser.BalanceNanos === 0)

    // Query the website to get the fees.
    this.backendApi.GetBitcoinFeeRateSatoshisPerKB().subscribe(
      (res: any) => {
        if (res.fastestFee != null) {
          this.buyUltraFields.bitcoinTransactionFeeRateSatoshisPerKB = res.fastestFee*1000;
        } else {
          console.error("res.fastestFee was null so didn't set default fee: ", res)
        }
      },
      (error) => {
        console.error("Problem getting Bitcoin fee: ", error)
      }
    )

    this._repeat(()=>{
      this.buyUltraFields.timeBeforeNextUpdate--;
      if (this.buyUltraFields.timeBeforeNextUpdate === 0) {
        this.buyUltraFields.timeBeforeNextUpdate = Constants.UPDATE_CYCLE_TIME;
      }
    }, 1000)
  }

  ngOnDestroy() {
    for (let ii = 0; ii < this.intervalsSet.length; ii++) {
      clearInterval(this.intervalsSet[ii]);
    }
  }

}
