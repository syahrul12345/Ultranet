import { ApplicationRef, ChangeDetectorRef, Component, OnInit, Input } from '@angular/core';
import { AppData, PageType } from '../app.component';
import { Observable, throwError, interval } from 'rxjs';
import { BackendApiService, TopMerchant } from '../backend-api.service';
import { switchMap, catchError } from 'rxjs/operators'; 
import * as _ from 'underscore';
import { sprintf } from "sprintf-js";

class MarketConstants {
  static UPDATE_INTERVAL_MILLIS = 60000
  static CONFIRM_PLACE_ORDER_STRING = `You are about to place an an order for %f %s for a total cost of %f Ultra. Is this OK?`
  static PLACE_ORDER_SUCCESS = `Order placed successfully. Go to your dashboard to check on the status of the order. OrderID: %s`
  static PLACE_ORDER_PROBLEM = `There was a problem placing your order: %s`
  static PLACE_ORDER_MISSING_REQUIRED_FIELD = `You are missing required field with label: %s`
  static PLACE_ORDER_INCORRECT_PASSWORD = `The password you entered was incorrect.`
  static PLACE_ORDER_INSUFFICIENT_BALANCE = `Your balance is insufficient to process the order.`
  static PLACE_ORDER_TOTAL_ULTRA_INVALID = `The total ultra is currently an invalid value. Is your balance insufficient?`
  static PLACE_ORDER_ENCRYPTED_DATA_LENGTH = `The total length of all of your required and optional fields should not exceed 10,000 characters`
  static PLACE_ORDER_CONNECTION_PROBLEM = `There is currently a connection problem. Is your connection to your node healthy?`
}

@Component({
  selector: 'app-market',
  templateUrl: './market.component.html',
  styleUrls: ['./market.component.scss']
})
export class MarketComponent implements OnInit {
  // Keep a reference to the global app data.
  @Input() appData: AppData;

  intervalsSet: number[] = [];

  // Tooltip vars
  showNodeStatusTooltip = null;
  showTopCategoriesTooltip = null;
  showTopMerchantsTooltip = null;
  showListingSearchTooltip = null;
  showUltraListingTooltip = null;
  showMerchantScoreTooltipSingle = null;
  showSingleListingDiscountTooltip = null;
  showListingSearchDiscountTooltip = -1;
  showUltraSingleListingTooltip = -1;
  showSingleListingSearchDiscountTooltip = -1;

  constructor(
    private changeRef: ChangeDetectorRef,
    private backendApi: BackendApiService) { }

  _repeat(funcToRepeat: () => void, timeoutMillis) {
    funcToRepeat()
    let interval: number = <any>setInterval(() => {
      funcToRepeat()
    }, timeoutMillis)
    this.intervalsSet.push(interval)
  }

  _updateTopCategories() {
    // If the listingQueryNode is null, try again after a second of waiting.
    if (this.appData.listingQueryNode == null) {
      setTimeout(()=>{
        this._updateTopCategories();
      }, 1000)
      return;
    }

    this.backendApi.GetTopCategoriesWithPrefix(
      this.appData.listingQueryNode).subscribe(

      (res: any) => {
        this.appData.marketPageState.topCategories = res.TopCategories.slice(0, 100);
      },
      (error) => { console.error(error) }
    );
  }

  _updateFeaturedListings() {
    // If the listingQueryNode is null, wait a bit before trying again.
    if (this.appData.listingQueryNode == null) {
      setTimeout(()=>{
        console.log('Retrying fetch of featured listings with query node: '+this.appData.listingQueryNode)
        this._updateFeaturedListings()
      }, 1000)
      return;
    }

    this.backendApi.GetListings(
      this.appData.listingQueryNode /*endpoint*/,
      -1 /*listingIndex*/,
      "" /*searchQuery*/,
      true /*adjustPriceForCommissions*/,
      "featured" /*queryType*/).subscribe(
      (res: any) => {
        this.appData.marketPageState.listingsToShow = res.Listings;
        console.log(this.appData.marketPageState.listingsToShow)
      },
      (error) => { 
        // If there's an error set the listing list to empty.
        this.appData.marketPageState.listingsToShow = [];
        // When an error occurs, reset the listing query node so that maybe a better
        // alternative can be chosen the next time node info is fetched. Also try to
        // fetch the featured listings again after a timeout.
        this.appData.listingQueryNode = null
        setTimeout(()=>{
          console.log('Retrying fetch of featured listings with query node: '+this.appData.listingQueryNode)
          this._updateFeaturedListings()
        }, 1000)
        
        console.error(error) 
      }
    );
  }

  // Logic to handle queries from the user.
  allowedQueryOptions = [
    'Fuzzy',
    'Public Key (exact)',
    'Username (exact)',
    'Category (exact)',
    'Merchant ID (exact)',
  ]
  queryOptionMap = {
    'Fuzzy': 'title_and_body',
    'Public Key (exact)': 'public_key',
    'Username (exact)': 'username',
    'Category (exact)': 'category',
    'Merchant ID (exact)': 'merchant_id',
  }
  queryType = 'Fuzzy';
  queryBeingShown = "";
  searchQuery= "";
  recentQueries = [];
  _updateQuery(qq: string) {
    this.selectedListing = null;
    this.appData.marketPageState.listingsToShow = []

    this.queryBeingShown = qq;
    // Only adjust recent queries if the query string is non-empty.
    if(qq !== "") {
      // Only keep the first occurrence of each recent query.
      let queryMap = new Object();
      queryMap[qq] = true;
      let newQueryMap = [qq,];
      for (var ii = 0; ii < this.recentQueries.length; ii++) {
        let currentQ = this.recentQueries[ii];
        if (queryMap[currentQ] != null) {
          continue;
        }

        queryMap[currentQ] = true;
        newQueryMap.push(currentQ)
      }
      this.recentQueries = newQueryMap.slice(0, 10)
    }

    if (this.searchQuery === '') {
      this.queryType = 'Fuzzy';
    }

    if (this.appData.listingQueryNode == null) {
      // If the node is in sync, use it as the query node.
      if (this.appData != null && this.appData.nodeInfo != null &&
        this.appData.nodeInfo.UltraStatus != null &&
        this.appData.nodeInfo.UltraStatus.State != null &&
        this.appData.nodeInfo.UltraStatus.State === 'FULLY_CURRENT') {

        this.appData.listingQueryNode = this.appData.localNode;
      } else {
        // In this case we have nothing that can fulfill the query so alert an error.
        alert('There is currently no "Listing Query Node" set or the local node is '+
          'not yet in sync. Please either wait for your node to sync or set '+
          'a "Listing Query Node" in the "Node and Network Info" section and '+
          'try the query again.')
        return;
      }
    }

    this.backendApi.GetListings(
      this.appData.listingQueryNode /*endpoint*/,
      -1 /*listingIndex*/,
      qq /*searchQuery*/,
      true /*adjustPriceForCommissions*/,
      this.queryOptionMap[this.queryType] /*queryType*/).subscribe(
      (res: any) => {
        this.appData.marketPageState.listingsToShow = res.Listings;
        console.log(this.appData.marketPageState.listingsToShow)
      },
      (error) => {
        // If there's an error set the listing list to empty.
        this.appData.marketPageState.listingsToShow = [];
        // When an error occurs, reset the listing query node so that maybe a better
        // alternative can be chosen the next time node info is fetched.
        this.appData.listingQueryNode = null
        alert(sprintf('There was a problem when issuing this query. Debug string: %s', JSON.stringify(error)))
      }
    );
  }
  _searchEnterPressed(event) {
    if(event.key !== "Enter") {
      return
    }

    this._updateQuery(this.searchQuery)
  }

  // Logic to show a single listing and process an order placement.
  selectedListing = null;
  selectedListingQuantity = 0;
  selectedListingTipAmountUltra = 0;
  selectedListingRequiredFieldValues = [];
  selectedListingOptionalFieldValues = [];
  selectedListingFeeRateUltraPerKB: any = '0';
  selectedListingTotalFeeNanos = 0.0;
  selectedListingPassword = '';
  selectedListingError = '';
  _setSelectedListing(listingMessage) {
    this.selectedListing = listingMessage;
    this.selectedListingQuantity = listingMessage.MinQuantity;
    this.selectedListingTipAmountUltra = 0;
    this.selectedListingFeeRateUltraPerKB = (this.appData.defaultFeeRateNanosPerKB / 1e9).toFixed(9)
    this.selectedListingPassword = '';

    this.selectedListingRequiredFieldValues = []
    for (var ii = 0; ii < this.selectedListing.RequiredFields.length; ii++) {
      this.selectedListingRequiredFieldValues.push({})
    }
    this.selectedListingOptionalFieldValues = []
    for (var ii = 0; ii < this.selectedListing.OptionalFields.length; ii++) {
      this.selectedListingOptionalFieldValues.push({})
    }
  }
  _dismissTooltips() {
    this.showMerchantScoreTooltipSingle = false;
    this.showSingleListingDiscountTooltip = false;
    this.showListingSearchDiscountTooltip = -1;
    this.showUltraSingleListingTooltip = -1;
    this.showSingleListingSearchDiscountTooltip = -1;
  }
  _clickListingTitle(listingMessage) {
    this._setSelectedListing(listingMessage)
    this._dismissTooltips();
    this.changeRef.detectChanges();

    this.appData.scrollTop();
  }
  _clickListingPageBack() {
    this.selectedListing = null;
  }
  _clickSelectedListingReseteFeeRate() {
    this.selectedListingFeeRateUltraPerKB = (this.appData.defaultFeeRateNanosPerKB / 1e9).toFixed(9)
  }
  _placeOrder(password: string, sign: boolean, validate: boolean, broadcast: boolean): Promise<any> {
    if (this.selectedListing == null) {
      return null
    }
    let requiredFieldValues: string[] = []
    for (var ii = 0; ii < this.selectedListingRequiredFieldValues.length; ii++) {
      requiredFieldValues.push(this.selectedListingRequiredFieldValues[ii].value)
    }
    let optionalFieldValues: string[] = []
    for (var ii = 0; ii < this.selectedListingOptionalFieldValues.length; ii++) {
      optionalFieldValues.push(this.selectedListingOptionalFieldValues[ii].value)
    }

    let itemTotalNanos = this.selectedListingQuantity * this.selectedListing.PricePerUnitNanos
    return this.backendApi.PlaceOrder(
      this.appData.localNode, this.appData.localNodeSecret,
      this.appData.loggedInUser.PublicKeyBase58Check,
      this.selectedListing,
      requiredFieldValues,
      optionalFieldValues,
      this.selectedListingQuantity,
      this.selectedListingFeeRateUltraPerKB * 1e9,
      itemTotalNanos,
      this.selectedListingTipAmountUltra * 1e9,
      this.selectedListingTotalFeeNanos,
      password /*password*/,
      sign /*sign*/,
      validate /*validate*/,
      broadcast /*broadcast*/,
    ).toPromise().then((res)=>{
      return this.appData._wrapWithPromise(res)
    }, (err) => {
      return this.appData._wrapWithPromise(err)
    })
  }
  _extractErrorStringFromPlaceOrder(err: any): string {
    if (err.error != null && err.error.error != null) {
      // Is it obvious yet that I'm not a frontend gal?
      // TODO: Error handling between BE and FE needs a major redesign.
      let rawError = err.error.error;
      if (rawError.includes("password")) {
        return MarketConstants.PLACE_ORDER_INCORRECT_PASSWORD
      } else if (rawError.includes("not sufficient")) {
        return MarketConstants.PLACE_ORDER_INSUFFICIENT_BALANCE
      } else if (rawError.includes("RuleErrorEncryptedDataLen")) {
        return MarketConstants.PLACE_ORDER_ENCRYPTED_DATA_LENGTH
      } else if (rawError.includes("Listing does not exist")) {
        return 'Cannot place order before local node has synced this listing. See sync status on "Market" page for details.'
      } else {
        return rawError
      }
    }
    if (err.status != null && err.status != 200) {
      return MarketConstants.PLACE_ORDER_CONNECTION_PROBLEM;
    }
    // If we get here we have no idea what went wrong so just alert the
    // errorString.
    return sprintf(MarketConstants.PLACE_ORDER_PROBLEM, JSON.stringify(err))
  }
  callingUpdateListingTxnFee = false
  _updateSelectedListingTotalTxnFee(force: boolean): Promise<any> {
    if (this.appData.loggedInUser == null) {
      return null
    }
    if (this.callingUpdateListingTxnFee && !force) {
      console.log("Not calling _updateSelectedListingTotalTxnFee because it's already being called.")
      return null;
    }

    this.callingUpdateListingTxnFee = true
    let placeOrderPromise = this._placeOrder(
      "" /*password*/, false /*sign*/,
      false /*validate*/, false /*broadcast*/)
    if (placeOrderPromise == null) {
      this.callingUpdateListingTxnFee = false
      return null
    }
    return placeOrderPromise.then(
      (res: any)=>{
        this.callingUpdateListingTxnFee = false

        this.selectedListingTotalFeeNanos = res.FeeNanos
        this.selectedListingError = '';

        return res
      }, (err)=>{
        this.callingUpdateListingTxnFee = false

        // Set the total listing fees to zero in this case.
        this.selectedListingTotalFeeNanos = 0
        this.selectedListingError = this._extractErrorStringFromPlaceOrder(err)

        return err
      }
    );
  }
  _confirmAndPlaceOrder(res: any): Promise<any> {
    let totalUltra = this.appData.nanosToUltra(
      this.selectedListing.PricePerUnitNanos * this.selectedListingQuantity +
      this.selectedListingTipAmountUltra*1e9 +
      this.selectedListingTotalFeeNanos)
    let confirmPlaceOrderString = sprintf(
      MarketConstants.CONFIRM_PLACE_ORDER_STRING, this.selectedListingQuantity,
      this.selectedListing.UnitNamePlural, totalUltra)

    if (confirm(confirmPlaceOrderString)) {
      return this._placeOrder(
        this.selectedListingPassword, true /*sign*/, true /*validate*/,
        true /*broadcast*/)
    } else {
      return null;
    }
  }
  _clickPlaceOrder() {
    if (this.appData.loggedInUser == null) {
      alert("You must create an account or login before you can place an order. "+
        "It's anonymous, only takes a few seconds, and is only needed in order "+
        "to generate a public/private key pair. To do so, click the 'Create Account or Login' tab at the top.")
      return
    }

    if (this.selectedListingError !== '') {
      alert(this.selectedListingError);
      return null
    }

    // Verify that the required fields are set.
    for (var ii = 0; ii < this.selectedListing.RequiredFields.length; ii++) {
      let requiredFieldValue = this.selectedListingRequiredFieldValues[ii].value
      if (requiredFieldValue == null || requiredFieldValue === "") {
        alert(sprintf(MarketConstants.PLACE_ORDER_MISSING_REQUIRED_FIELD, this.selectedListing.RequiredFields[ii]))
        return
      }
    }

    // Verify the form fields are not negative.
    if (this.selectedListingQuantity < 0) {
      alert("Negative quantity not allowed.")
      return
    }
    if (this.selectedListingTipAmountUltra < 0) {
      alert("Negative tip amount not allowed.")
      return
    }
    if (this.selectedListingTotalFeeNanos < 0 || parseFloat(this.selectedListingFeeRateUltraPerKB) < 0) {
      alert("Negative fee not allowed.")
      return
    }

    let updateListingFeePromise = this._updateSelectedListingTotalTxnFee(true /*force*/)
    if (updateListingFeePromise == null) {
      console.log("Not calling PlaceOrder because update is already being called.")
      return;
    }

    updateListingFeePromise.then(
      (res: any) => {
        let confirmOrderPromise = this._confirmAndPlaceOrder(res)
        if (confirmOrderPromise == null) {
          this.selectedListingPassword = '';
          return
        }
        confirmOrderPromise.then(
          (res) => {
            let orderSuccessString = sprintf(MarketConstants.PLACE_ORDER_SUCCESS, res.OrderIDBase58Check)
            alert(orderSuccessString);
            // Go back to the search page.
            this._clickListingPageBack();
          }, (err) => {
            // Reset the password only.
            this.selectedListingPassword = '';
            // Alert the error that was returned.
            alert(this._extractErrorStringFromPlaceOrder(err))
          }
        )
      }, (err: any) => {
        alert("There was a problem updating the listing fee prior to placing the order: "+ JSON.stringify(err))
      }
    )
  }

  // Logic to show the merchant page.
  _clickMerchantUsername(merchantEntry) {
    this.queryType = 'Username (exact)';
    this.searchQuery = merchantEntry.Username;
    this._updateQuery(this.searchQuery)

    this.appData.scrollTop();
  }

  // Logic to show images.
  selectedListingForImages = null;
  selectedListingImageIndex = 0;
  _stopBubbling($event) {
    $event.stopPropagation()
  }
  _advanceSelectedImage(offset) {
    this.selectedListingImageIndex = ((this.selectedListingForImages.NumImages + this.selectedListingImageIndex + offset) % this.selectedListingForImages.NumImages)
    this.changeRef.detectChanges()
  }
  _imageSelected(index) {
    this.selectedListingImageIndex = index
  }
  _showImageView(listingMessage: any) {
    this.selectedListingForImages = listingMessage;
    this.selectedListingImageIndex = 0;
  }

  _clickCreateAccountOrLogin() {
    this.appData.selectedPage = PageType.Account;
    this.changeRef.detectChanges();
    return
  }
  _clickBuyUltra() {
    this.appData.selectedPage = PageType.BuyUltra;
    this.changeRef.detectChanges();
    return
  }
  _tstampToDate(tstampSecs) {
    return new Date(tstampSecs*1000)
  }
  _clickCategory(category: string) {
    this.queryType = 'Category (exact)';
    this.searchQuery = category;
    this._updateQuery(this.searchQuery)

    this.appData.scrollTop();
  }

  nodeWidgetInfo = {
    queryNodeManualConnection: '',
    ultraNodeManualConnection: '',
    bitcoinNodeManualConnection: '',

    widgetLocalNode: '',
    widgetLocalNodeSecret: '',
  }
  _clickChangeQueryNode() {
    if (this.nodeWidgetInfo.queryNodeManualConnection == null || this.nodeWidgetInfo.queryNodeManualConnection === '') {
      alert('Please enter a valid query node in <ip address>:<port> or <domain name>:<port> format.')
      return;
    }
    // As a sanity-check, try and get listings from this query node. If it doesn't work
    // alert.
    this.backendApi.GetListings(
      this.nodeWidgetInfo.queryNodeManualConnection /*endpoint*/,
      -1 /*listingIndex*/,
      "" /*searchQuery*/,
      true /*adjustPriceForCommissions*/,
      "featured" /*queryType*/).subscribe(
      (res: any) => {
        this.appData.listingQueryNode = this.nodeWidgetInfo.queryNodeManualConnection;
        this.nodeWidgetInfo.queryNodeManualConnection = '';
        alert('Successfully updated query node to: '+ this.appData.listingQueryNode)
        this.changeRef.detectChanges();
      },
      (error) => { 
        alert('ERROR: The query node you entered does not seem to respond to requests properly. Please choose another.')
      }
    );
  }
  _clickRandomQueryNode() {
    let allNodes = [];
    if (this.appData.nodeInfo != null) {
      if (this.appData.nodeInfo.UltraOutboundPeers != null) {
        allNodes = allNodes.concat(this.appData.nodeInfo.UltraOutboundPeers)
      }
      if (this.appData.nodeInfo.UltraInboundPeers != null) {
        allNodes = allNodes.concat(this.appData.nodeInfo.UltraInboundPeers)
      }
    }

    if (allNodes.length === 0) {
      alert('No peer nodes currently available. Is your internet connection healthy?')
      return;
    }

    let queryPeer = allNodes[Math.floor(Math.random()*allNodes.length)];
    this.nodeWidgetInfo.queryNodeManualConnection = queryPeer.IP+':'+queryPeer.JSONPort;
  }
  _clickDisconnectUltraPeer(peerAddr: string) {
    this.backendApi.NodeControl(
      this.appData.localNode, this.appData.localNodeSecret,
      peerAddr /*Address*/, 'disconnect_ultra_node' /*OperationType*/).subscribe(

      (res: any) => {
        alert('Successfully disconnected Ultra peer: '+peerAddr)
        return;
      },
      (error) => {
        alert('Problem disconnecting Ultra Peer. Debug output: '+this._extractErrorStringFromPlaceOrder(error))
        console.error(error)
      }
    );
  }
  _clickConnectUltraPeer(peerAddr: string) {
    this.backendApi.NodeControl(
      this.appData.localNode, this.appData.localNodeSecret,
      peerAddr /*Address*/, 'connect_ultra_node' /*OperationType*/).subscribe(

      (res: any) => {
        alert('Successfully connected to Ultra peer: '+peerAddr)
        this.nodeWidgetInfo.ultraNodeManualConnection = '';
        return;
      },
      (error) => {
        alert('Problem connecting to Ultra Peer. Debug output: '+this._extractErrorStringFromPlaceOrder(error))
        console.error(error)
      }
    );
  }
  currentlyConnectingBitcoinPeer = false
  _clickConnectBitcoinPeer(peerAddr: string) {
    if (this.currentlyConnectingBitcoinPeer) {
      alert('Please wait for your previous request to finish. Bitcoin connection requests can take up to thirty seconds.')
      return;
    }
    this.currentlyConnectingBitcoinPeer = true;
    this.backendApi.NodeControl(
      this.appData.localNode, this.appData.localNodeSecret,
      peerAddr /*Address*/, 'connect_bitcoin_node' /*OperationType*/).subscribe(

      (res: any) => {
        this.currentlyConnectingBitcoinPeer = false;
        alert('Successfully connected to Bitcoin node: '+peerAddr)
        this.nodeWidgetInfo.bitcoinNodeManualConnection = '';
        return;
      },
      (error) => {
        this.currentlyConnectingBitcoinPeer = false;
        alert('Problem connecting to Bitcoin node. Debug output: '+this._extractErrorStringFromPlaceOrder(error))
        console.error(error)
      }
    );
  }
  _clickChangeLocalNode() {
    if (confirm('Are you sure you want to change your local node connection? If so, make sure you note down the previous value so you can undo the change if you lose your connection.')) {
      this.appData.localNode = this.nodeWidgetInfo.widgetLocalNode;
      this.appData.localNodeSecret = this.nodeWidgetInfo.widgetLocalNodeSecret;

      // Update the main market page.
      this._updateFeaturedListings();

      // Everything else should update in a second.

      return;
    }
  }
  _clickResetLocalNode() {
    this.nodeWidgetInfo.widgetLocalNode = this.appData.localNode;
    this.nodeWidgetInfo.widgetLocalNodeSecret = this.appData.localNodeSecret;
  }

  minerPublicKeysInput = '';
  updateMiner() {
    // If nothing is changing then alert.
    if ((this.appData.nodeInfo.MinerPublicKeys == null || this.appData.nodeInfo.MinerPublicKeys.length === 0) &&
      this.minerPublicKeysInput === '') {

      alert('You must enter at least one valid public key in order to start the miner. Note that you can copy your public key from the "Account Info" box above.')
      return;
    } 

    if (this.appData.nodeInfo.MinerPublicKeys != null && this.appData.nodeInfo.MinerPublicKeys.length > 0) {
      // In this case stop the miner.
      this.backendApi.UpdateMiner(
        this.appData.localNode, this.appData.localNodeSecret, '').subscribe(
          (res: any) => {
            return;
          },
          (error) => {
            alert(sprintf('Problem updating the miner. Debug output: %s', JSON.stringify(error)))
            return
          }
        )
      

      return;
    }

    if (this.minerPublicKeysInput !== '') {
      this.appData.nodeInfo.MinerPublicKeys = this.minerPublicKeysInput.split(',');
    } else {
      this.appData.nodeInfo.MinerPublicKeys = '';
    }
    this.changeRef.detectChanges();

    this.backendApi.UpdateMiner(
      this.appData.localNode, this.appData.localNodeSecret, this.minerPublicKeysInput).subscribe(
        (res: any) => {
          return;
        },
        (error) => {
          alert(sprintf('Problem updating the miner. Debug output: %s', JSON.stringify(error)))
          return
        }
      )
  }

  ngOnInit() {
    this._repeat(() => {this._updateTopCategories()}, MarketConstants.UPDATE_INTERVAL_MILLIS)
    //this._repeat(() => {this._updateFeaturedListings()}, MarketConstants.UPDATE_INTERVAL_MILLIS)
    this._updateFeaturedListings()

    this._repeat(() => {
      this._updateSelectedListingTotalTxnFee(false /*force*/);
    }, 1000)

    setTimeout(()=>{
      this._clickResetLocalNode();
    }, 1000)

    setTimeout(()=>{
      if (this.appData.nodeInfo != null && this.appData.nodeInfo.MinerPublicKeys != null) {
        this.minerPublicKeysInput = this.appData.nodeInfo.MinerPublicKeys.join(',');
      }
    })
  }

  ngOnDestroy() {
    for (let ii = 0; ii < this.intervalsSet.length; ii++) {
      clearInterval(this.intervalsSet[ii]);
    }
  }

}
