import { ApplicationRef, ChangeDetectorRef, Component, OnInit, Input } from '@angular/core';
import { AppData, DashboardPage, PageType } from '../app.component';
import { BackendApiService, AddDraftImageResponse, GetDraftImageIDsResponse, BackendRoutes } from '../backend-api.service';
import { sprintf } from "sprintf-js";
import * as buf from '../../vendor/buffer.browserify.js'
import $ from 'jquery';

class Messages {
  static PROBLEM_SETTING_DRAFT_IMAGES: string = `Problem loading images for listing. Is your connection to your node healthy?`

  static INCORRECT_PASSWORD = `The password you entered was incorrect.`
  static CONNECTION_PROBLEM = `There is currently a connection problem. Is your connection to your node healthy?`
  static UNKOWN_PROBLEM = `There was a weird problem with the transaction. Debug output: %s`

  static TITLE_TOO_SHORT = `You must set a title for your listing.`
  static BODY_TOO_SHORT = `You must set a description for your listing.`
  static CATEGORY_TOO_SHORT = `You must set a category for your listing.`
  static QUANTITY_CONFLICT = `Min quantity cannot exceed max quantity. Please revise these parameters.`
  static UNIT_NAME_SINGULAR_TOO_SHORT = `Unit name singular must be set.`
  static UNIT_NAME_PLURAL_TOO_SHORT = `Unit name plural must be set.`
  static INSUFFICIENT_BALANCE = `You don't have enough Ultra to process the order. Try reducing the fee rate.`
  static REVIEW_TYPE_MISSING = `You must select either Negative Neutral or Positive before you can post your review.`
  static REVIEW_MIN_FEE = `For various technical reasons, review transactions require a non-zero fee. Please increase the transaction fee until you are spending at least one nano-Ultra on your transaction.`
  static SEND_ULTRA_MIN = `You must send a non-zero amount of Ultra`
  static INVALID_PUBLIC_KEY = `The public key you entered is invalid`
  static MERCHANT_REGISTRATION_NOT_READY = `Your merchant registration transaction has not yet been mined into a block. Please wait a few minutes for this to happen before you create a listing.`
}

@Component({
  selector: 'app-dashboard',
  templateUrl: './dashboard.component.html',
  styleUrls: ['./dashboard.component.scss']
})
export class DashboardComponent implements OnInit {
  @Input() appData: AppData;

  DashboardPage = DashboardPage;

  requiredFieldText: string;
  optionalFieldText: string;
  thumbnailUrl: string;
  showCategoryCompletion: boolean = false;
  topCategoryCompletion = [];

  _categoryChanged(categoryPrefix: string) {
    categoryPrefix = categoryPrefix ? categoryPrefix : '';
    this.backendApi.GetTopCategoriesWithPrefix(this.appData.listingQueryNode).subscribe(
      (res: any) => {
        if (res == null || res.TopCategories == null) {
          this.topCategoryCompletion = [];
          this.showCategoryCompletion = true;
          return;
        }
        if (categoryPrefix === '') {
          // If there is no category prefix, set the completion to just contain
          // the first ten categories.
          this.topCategoryCompletion = res.TopCategories.slice(0, 10)
          this.showCategoryCompletion = true;
          return
        }

        // Go through the top categories that were returned and queue up the ones
        // that have the prefix we care about.
        let foundExactPrefixMatch = false;
        let matchingTopCategories = []
        for (var ii = 0; ii < res.TopCategories.length; ii++) {
          let topCat = res.TopCategories[ii];
          if (topCat.Category.indexOf(categoryPrefix) === 0) {
            matchingTopCategories.push(topCat)
          }
          if (topCat.Category === categoryPrefix) {
            foundExactPrefixMatch = true;
          }
        }
        this.topCategoryCompletion = matchingTopCategories.slice(0, 10)

        //  If the prefix is not explicitly in the list then add an option
        //  at the end to create a new category.
        if (!foundExactPrefixMatch) {
          this.topCategoryCompletion.push(<any>({
            Category: categoryPrefix,
            Count: -1,
          }))
        }

        this.showCategoryCompletion = true;
      },
      (error) => {
        console.error(error)
      }
    )
  }

  _clickCreateAccountOrLogin()  {
    this.appData.selectedPage = PageType.Account;
    this.ref.detectChanges();
    return
  }

  _clickGoToBuyUltra()  {
    this.appData.selectedPage = PageType.BuyUltra;
    this.ref.detectChanges();
    return
  }
  passwordValue = '';
  pricePerUnitUltra = '';
  _clickViewOrEditListing(listingIndex: number) {
    this.pricePerUnitUltra = (this.appData.loggedInUser.Listings[listingIndex].PricePerUnitNanos  / 1e9).toFixed(9)
    this.appData.dashboardPageState.listingSelected = this.appData.loggedInUser.Listings[listingIndex]
    this.backendApi.LoadListingDraftImages(
      this.appData.localNode, this.appData.localNodeSecret,
      this.appData.dashboardPageState.listingSelected.MerchantIDBase58Check,
      this.appData.dashboardPageState.listingSelected.ListingIndex).subscribe(

      (res: any) => {
        // Once the backend has been updated, refresh the URL link and detect
        // changes to make the frontend pick it up.
        // We add random garbage to the end of the URL to force an update in
        // the frontend.
        this._setDraftImages(res.ImageIDs);
        this.ref.detectChanges();
      },
      (error) => {
        alert(Messages.PROBLEM_SETTING_DRAFT_IMAGES)
        console.error(error)
      }
    )

    this.appData.scrollTop()
  }
  _clickDeleteListing(listingToDelete: any) {
    this.backendApi.PublishListing(
    this.appData.localNode, this.appData.localNodeSecret,
    {
      MerchantIDBase58Check: listingToDelete.MerchantIDBase58Check,
      PublicKeyBase58Check: listingToDelete.PublicKeyBase58Check,
      Deleted: true,
      ListingIndex: listingToDelete.ListingIndex,
    }, this.passwordValue).subscribe(
      (res: any) => {
        this._backFromListingCreationPage()
        this.passwordValue = '';
        this.ref.detectChanges();
        this.appData.scrollTop()
      },
      (error) => {
        this.passwordValue = '';
        alert(this._extractListingError(error))
      }
    )
  }
  _clickCreateListing() {
    this._getDraftImages();
    this.pricePerUnitUltra = '1';
    this.appData.dashboardPageState.listingSelected = {
      PublicKeyBase58Check: this.appData.loggedInUser.PublicKeyBase58Check,
      Deleted: false,
      ListingIndex: -1,
      PricePerUnitNanos: 1e9,
      UnitNameSingular: 'unit',
      UnitNamePlural: 'units',
      MinQuantity: 0,
      MaxQuantity: 0,
      ProductType: 'delivered',
      RequiredFields: [`Delivery address
For example:
123 F St
Apt 11111
Frankfurt Germany 111111`],
      OptionalFields: [`Extra comments for merchant`]
    }
    this.appData.scrollTop()
  }
  _backFromListingCreationPage() {
    this.appData.dashboardPageState.listingSelected = null;
    this.appData.dashboardPageState.draftImages = [];
    this._updateDraftImages();
    this.appData.scrollTop()
  }

  _extractListingError(err: any): string {
    if (err.error != null && err.error.error != null) {
      // Is it obvious yet that I'm not a frontend gal?
      // TODO: Error handling between BE and FE needs a major redesign.
      let rawError = err.error.error;
      if (rawError.includes("password")) {
        return Messages.INCORRECT_PASSWORD
      } else if (rawError.includes("TitleTooShort")) {
        return Messages.TITLE_TOO_SHORT
      } else if (rawError.includes("BodyTooShort")) {
        return Messages.BODY_TOO_SHORT
      } else if (rawError.includes("CategoryTooShort")) {
        return Messages.CATEGORY_TOO_SHORT
      } else if (rawError.includes("QuantityConflict")) {
        return Messages.QUANTITY_CONFLICT
      } else if (rawError.includes("UnitNameSingularTooShort")) {
        return Messages.UNIT_NAME_SINGULAR_TOO_SHORT
      } else if (rawError.includes("UnitNamePluralTooShort")) {
        return Messages.UNIT_NAME_PLURAL_TOO_SHORT
      } else if (rawError.includes("ListingErrorNotTopMerchantUnauthorizedToPostListing")) {
        return Messages.MERCHANT_REGISTRATION_NOT_READY
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
  _publishListing() {
    // Set the PricePerUnitNanos to the new value.
    this.appData.dashboardPageState.listingSelected.PricePerUnitNanos = Math.floor(parseFloat(this.pricePerUnitUltra)*1e9)

    this.backendApi.PublishListing(
      this.appData.localNode, this.appData.localNodeSecret,
      this.appData.dashboardPageState.listingSelected, this.passwordValue).subscribe(
      (res: any) => {
        this._backFromListingCreationPage()
        this.passwordValue = '';
        this.ref.detectChanges();
        this.appData.scrollTop()
      },
      (error) => {
        this.passwordValue = '';
        alert(this._extractListingError(error))
      }
    )
  }
  _updatePricePerUnitNanos(val) {
    this.appData.dashboardPageState.listingSelected.PricePerUnitNanos = val * 1e9
  }
  _addRequiredField() {

    if (this.requiredFieldText == null || this.requiredFieldText.length === 0) {
      alert('You must enter a description of this extra field before adding it.')
      return
    }
    this.appData.dashboardPageState.listingSelected.RequiredFields.push(this.requiredFieldText)
    this.requiredFieldText = "";
  }
  _removeRequiredField(fieldIndex: number) {
    this.appData.dashboardPageState.listingSelected.RequiredFields.splice(fieldIndex, 1);
  }
  _addOptionalField() {

    if (this.optionalFieldText == null || this.optionalFieldText.length === 0) {
      alert('You must enter a description of this extra field before adding it.')
      return
    }
    this.appData.dashboardPageState.listingSelected.OptionalFields.push(this.optionalFieldText)
    this.optionalFieldText = "";
  }
  _removeOptionalField(fieldIndex: number) {
    this.appData.dashboardPageState.listingSelected.OptionalFields.splice(fieldIndex, 1);
  }
  _deleteImage(draftImageIndex) {
    this.appData.dashboardPageState.draftImages.splice(draftImageIndex, 1)
    // Detect changes to make sure the adjustment to the draftImages takes effect
    // in the view.
    this.ref.detectChanges();
    // Update the backend to make sure it stays consistent with our frontend.
    this._updateDraftImages();
  }
  _moveImageLeft(draftImageIndex) {
    // Nothing to do if the image is all the way left.
    if (draftImageIndex === 0) {
      return;
    }

    // Swap the image with the one right before it.
    let draftImages = this.appData.dashboardPageState.draftImages
    let tmp = draftImages[draftImageIndex]
    draftImages[draftImageIndex] = draftImages[draftImageIndex-1]
    draftImages[draftImageIndex-1] = tmp

    // Detect changes to make sure the adjustment to the draftImages takes effect
    // in the view.
    this.ref.detectChanges();
    
    this._updateDraftImages();
  }
  _makeThumbnail(draftImageIndex: number) {
    // Grab the ID of the image in question.
    let imageID = this.appData.dashboardPageState.draftImages[draftImageIndex].id  

    this.backendApi.UpdateThumbnail(
      this.appData.localNode, this.appData.localNodeSecret,
      imageID).subscribe(
      (res: any) => {
        // Once the backend has been updated, refresh the URL link and detect
        // changes to make the frontend pick it up.
        // We add random garbage to the end of the URL to force an update in
        // the frontend.
        this.thumbnailUrl = this.backendApi._makeDraftImageURL(
          0, this.appData.localNode, this.appData.localNodeSecret)+'&random='+Math.random()
        this.ref.detectChanges();
      },
      (error) => { console.error(error) }
    )
  }
  _moveImageRight(draftImageIndex) {
    let draftImages = this.appData.dashboardPageState.draftImages

    // Nothing to do if the image is all the way right.
    if (draftImageIndex === draftImages.length-1) {
      return;
    }

    // Swap the image with the one right after it.
    let tmp = draftImages[draftImageIndex]
    draftImages[draftImageIndex] = draftImages[draftImageIndex+1]
    draftImages[draftImageIndex+1] = tmp

    // Detect changes to make sure the adjustment to the draftImages takes effect
    // in the view.
    this.ref.detectChanges();
    
    this._updateDraftImages();
  }
  fileToUpload: File = null;
  fileInputVal: any = null;
  handleFileInput(files: FileList) {
    this.fileToUpload = files.item(0);
    var reader = new FileReader();
    reader.onload = (event: any)=>{
      let base64Image = btoa(event.target.result)
      
      // Call the server to try and add the image.
      this.backendApi.AddDraftImage(
        this.appData.localNode, this.appData.localNodeSecret, base64Image).subscribe(

        (res: AddDraftImageResponse) => {
          // When we get the response back, go ahead and update the images
          // shown to reflect the new image and thumbnail.
          this._getDraftImages()
        },
        (error) => { console.error(error) }
      )
      return;
    };
    reader.readAsBinaryString(this.fileToUpload)

    $('#file').value = '';
    $('#file').files = null
    this.fileInputVal = '';
  }
  _updateDraftImages() {
    // Update the backend to make sure it stays consistent with our frontend.
    let imageIDs = []
    for (let ii = 0; ii < this.appData.dashboardPageState.draftImages.length; ii++) {
      let ID = this.appData.dashboardPageState.draftImages[ii].id
      imageIDs.push(ID)
    }
    this.backendApi.UpdateDraftImages(
      this.appData.localNode, this.appData.localNodeSecret, imageIDs).subscribe(
      (res: any) => {
        // No need to do anything with the response.
      },
      (error) => { console.error(error) }
    )
  }
  _setDraftImages(imageIDs: any) {
    // The thumbnail url is always the same if it's available.
    this.thumbnailUrl = this.backendApi._makeDraftImageURL(
      0, this.appData.localNode, this.appData.localNodeSecret)+'&random='+Math.random()
    // The draft images need to be fetched. The image ui is only displayed
    // if there are images uploaded.
    this.appData.dashboardPageState.draftImages = []
    if (imageIDs == null) {
      return
    }
    for (let imageIDIndex = 0; imageIDIndex < imageIDs.length; imageIDIndex++) {
      let imageID = imageIDs[imageIDIndex]
      let imageURL = this.backendApi._makeDraftImageURL(
        imageID, this.appData.localNode, this.appData.localNodeSecret)
      this.appData.dashboardPageState.draftImages.push({
        id: imageID,
        url: imageURL,
      })
    }
    this.ref.detectChanges();
  }
  _getDraftImages() {
    // Fetch the images to display in the draft listing page.
    this.backendApi.GetDraftImageIDs(
      this.appData.localNode, this.appData.localNodeSecret).subscribe(

      (res: GetDraftImageIDsResponse) => {
        if (res == null || res.imageIDs == null) {
          return;
        }
        this._setDraftImages(res.imageIDs)
      },
      (error) => { console.error(error) }
    )
  }
  _hasAction(orderActions: string[], checkAction: string): boolean {
    if (orderActions == null) {
      return false
    }
    for (var ii = 0; ii < orderActions.length; ii++) {
      if (orderActions[ii] === checkAction) {
        return true;
      }
    }
    return false;
  }
  orderActionData = {
    rejectReason: '',
    reviewType: '',
    reviewText: '',
    feeRateUltraPerKB: '0',
  }
  _extractErrorOrderAction(err: any): string {
    if (err.error != null && err.error.error != null) {
      // Is it obvious yet that I'm not a frontend gal?
      // TODO: Error handling between BE and FE needs a major redesign.
      let rawError = err.error.error;
      if (rawError.includes("password")) {
        return Messages.INCORRECT_PASSWORD
      } else if (rawError.includes("not sufficient")) {
        return Messages.INSUFFICIENT_BALANCE
      } else if (rawError.includes("ReviewType")) {
        return Messages.REVIEW_TYPE_MISSING
      } else if (rawError.includes("RuleErrorReviewOrderRequiresNonZeroInput")) {
        return Messages.REVIEW_MIN_FEE
      } else if (rawError.includes("RuleErrorTxnMustHaveAtLeastOneInput")) {
        return Messages.SEND_ULTRA_MIN
      } else if ((rawError.includes("SendUltra: Problem") && rawError.includes("Invalid input format")) ||
        (rawError.includes("Checksum does not match"))) {

        return Messages.INVALID_PUBLIC_KEY
      } else {
        return rawError
      }
    }
    if (err.status != null && err.status != 200) {
      return Messages.CONNECTION_PROBLEM;
    }
    // If we get here we have no idea what went wrong so just alert the
    // errorString.
    return JSON.stringify(err)
  }
  _clickResetFeeRate() {
    this.orderActionData.feeRateUltraPerKB = (this.appData.defaultFeeRateNanosPerKB / 1e9).toFixed(9)
    this.sendUltraData.feeRateUltraPerKB = (this.appData.defaultFeeRateNanosPerKB / 1e9).toFixed(9)
  }
  _orderActionPromise(orderIDBase58Check: string, action: string, broadcast: boolean): Promise<any> {
    return this.backendApi.OrderAction(
      this.appData.localNode, this.appData.localNodeSecret,
      this.appData.loggedInUser.PublicKeyBase58Check, orderIDBase58Check,
      action, this.orderActionData.reviewType /*ReviewType*/,
      this.orderActionData.reviewText /*ReviewText*/, this.orderActionData.rejectReason,
      parseFloat(this.orderActionData.feeRateUltraPerKB) * 1e9 /*FeeRateNanosPerKB*/,
      '' /*Password*/, true /*Sign*/,
      true /*Validate*/,
      broadcast /*Broadcast*/).toPromise()
  }
  _clickOrderAction(order: any, action: string) {
    if (this.appData.loggedInUser == null) {
      console.log("Not calling _clickOrderAction because loggedInUser is null");
      return;
    }

    this._orderActionPromise(order.OrderIDBase58Check, action, false /*broadcast*/).then(
      (res) => {
        if (res == null) {
          alert(Messages.CONNECTION_PROBLEM)
          return null
        }
        let confirmationString = sprintf("Are you ready to commit the %s action on this order for a total fee of %s Ultra?", action, this.appData.nanosToUltra(res.FeeNanos))
        if (action === 'refund_order') {
          // When we're refunding an order, confirm the amount that will be refunded.
          confirmationString = sprintf("Are you ready to refund %s Ultra to the buyer with a network "+
            "fee of %s Ultra for a total spend of %s Ultra?",
            this.appData.nanosToUltra(order.RevenueNanos),
            this.appData.nanosToUltra(res.FeeNanos),
            this.appData.nanosToUltra(order.RevenueNanos+res.FeeNanos))
        }
        if (action === 'review') {
          // When we're reviewing an order, add 1 nano to the fee since the BE will
          // force there to be nonzero input (and output).
          confirmationString = sprintf("Are you ready to review this order for a total network fee of %s Ultra?",
            this.appData.nanosToUltra(res.FeeNanos+1))
        }
        if (confirm(confirmationString)) {
          return res
        }
        return null;
      }, (err) => {
        console.error(err)
        alert(this._extractErrorOrderAction(err))
        return null
      }
    ).then((res)=>{
      if (res == null) {
        return;
      }
      // Same as before only we're broadcasting it this time.
      this._orderActionPromise(order.OrderIDBase58Check, action, true /*broadcast*/).then(
        (res)=>{
          if (res == null) {
            alert(Messages.CONNECTION_PROBLEM)
            return null
          }
          // If we get here then we were able to successfully commit the action. Reset
          // all the fields. The next GetUsers should update the user list.
          alert(sprintf("Successfully committed the %s action on order with OrderID %s. It may take a few minutes for the update to take effect.", action, order.OrderIDBase58Check))
          this.orderActionData.rejectReason = '';
          this.orderActionData.reviewType = '';
          this.orderActionData.reviewText = '';
          this._clickResetFeeRate();
        }, (err)=>{
          console.error(err)
          alert(this._extractErrorOrderAction(err))
          return null
        }
      )
    })
  }

  sendUltraData = {
    payToPublicKey: '',
    amountToSendUltra: 0.0,
    totalFeeUltra: 0.0,
    feeRateUltraPerKB: '0',
    error: '',
  }
  callingUpdateSendUltraTxnFee = false
  _updateSendUltraTxnFee(force: boolean): Promise<any> {
    if (this.appData.loggedInUser == null) {
      return;
    }

    if (this.callingUpdateSendUltraTxnFee && !force) {
      console.log("Not calling _updateSendUltraTxnFee because callingUpdateSendUltraTxnFee is false")
      return;
    }

    if (this.sendUltraData.payToPublicKey == null || this.sendUltraData.payToPublicKey === '') {
      return;
    }

    this.callingUpdateSendUltraTxnFee = true
    return this.backendApi.SendUltra(
      this.appData.localNode, this.appData.localNodeSecret,
      this.appData.loggedInUser.PublicKeyBase58Check,
      this.sendUltraData.payToPublicKey,
      Math.floor(this.sendUltraData.amountToSendUltra*1e9),
      Math.floor(parseFloat(this.sendUltraData.feeRateUltraPerKB)*1e9),
      '' /*Password*/,
      false /*Sign*/,
      false /*Validate*/,
      false /*Broadcast*/).toPromise().then(
      (res: any) => {
        this.callingUpdateSendUltraTxnFee = false

        if (res == null || res.FeeNanos == null) {
          this.sendUltraData.error = Messages.CONNECTION_PROBLEM;

          return null;
        }

        this.sendUltraData.error = ''
        this.sendUltraData.totalFeeUltra = res.FeeNanos / 1e9
        return res
      },
      (error) => {
        this.callingUpdateSendUltraTxnFee = false

        console.error(error)
        this.sendUltraData.error = this._extractErrorOrderAction(error);
        return null
      }
    )
  }
  _clickMaxUltra() {
    this.backendApi.SendUltra(
      this.appData.localNode, this.appData.localNodeSecret,
      this.appData.loggedInUser.PublicKeyBase58Check,
      this.sendUltraData.payToPublicKey,
      // A negative amount causes the max value to be returned as the spend amount.
      -1,
      Math.floor(parseFloat(this.sendUltraData.feeRateUltraPerKB)*1e9),
      '' /*Password*/,
      false /*Sign*/,
      false /*Validate*/,
      false /*Broadcast*/).subscribe(
      (res: any) => {
        if (res == null || res.FeeNanos == null || res.SpendAmountNanos == null) {
          alert(Messages.CONNECTION_PROBLEM)
          return null;
        }

        this.sendUltraData.error = ''
        this.sendUltraData.totalFeeUltra = res.FeeNanos / 1e9
        this.sendUltraData.amountToSendUltra = res.SpendAmountNanos / 1e9
      },
      (error) => {
        console.error(error)
        this.sendUltraData.error = this._extractErrorOrderAction(error);
      }
    )
  }
  _clickSendUltra() {
    if (this.appData.loggedInUser == null) {
      alert('User must be logged in in order to send Ultra')
      return;
    }

    if (this.sendUltraData.payToPublicKey == null || this.sendUltraData.payToPublicKey === '') {
      alert('A valid pay-to public key must be set before you can send Ultra')
      return;
    }

    if (this.sendUltraData.error != null && this.sendUltraData.error !== '') {
      alert(this.sendUltraData.error)
      return;
    }

    if (this.sendUltraData.amountToSendUltra === 0 && this.sendUltraData.totalFeeUltra === 0) {
      alert(Messages.SEND_ULTRA_MIN)
      return;
    }

    // Recompute the fee one more time and offer a confirmation.
    let ultraTxnFeePromise = this._updateSendUltraTxnFee(true /*force*/)

    if (ultraTxnFeePromise == null) {
      alert("There was a problem processing this transaction.")
      return;
    }

    ultraTxnFeePromise.then((res)=>{
      // If res is null then an error should be set.
      if (res == null || res.FeeNanos == null || res.SpendAmountNanos == null) {
        alert(this.sendUltraData.error)
        return;
      }

      if (confirm(sprintf('Are you ready to send %s Ultra with a fee of %s '+
        'Ultra for a total of %s Ultra to public key %s',
        this.appData.nanosToUltra(res.SpendAmountNanos),
        this.appData.nanosToUltra(res.FeeNanos),
        this.appData.nanosToUltra(res.SpendAmountNanos+res.FeeNanos),
        this.sendUltraData.payToPublicKey))) {

        this.backendApi.SendUltra(
          this.appData.localNode, this.appData.localNodeSecret,
          this.appData.loggedInUser.PublicKeyBase58Check,
          this.sendUltraData.payToPublicKey,
          this.sendUltraData.amountToSendUltra*1e9,
          Math.floor(parseFloat(this.sendUltraData.feeRateUltraPerKB)*1e9),
          '' /*Password*/,
          true /*Sign*/,
          true /*Validate*/,
          true /*Broadcast*/).subscribe(
          (res: any) => {
            if (res == null || res.FeeNanos == null || res.SpendAmountNanos == null || res.TxIDBase58Check == null) {
              alert(Messages.CONNECTION_PROBLEM)
              return null;
            }

            this.sendUltraData.error = ''
            this.sendUltraData.totalFeeUltra = res.FeeNanos / 1e9
            this.sendUltraData.amountToSendUltra = 0.0

            alert(sprintf('Successfully completed transaction. TxID: %s', res.TxIDBase58Check))
          },
          (error) => {
            console.error(error)
            this.sendUltraData.error = this._extractErrorOrderAction(error);
            alert(this.sendUltraData.error)
          }
        )


      } else {
        return;
      }

    }, (err)=>{
      // If an error is returned then the error message should be set.
      alert(this.sendUltraData.error)
      return;
    })
  }

  signatureData = {
    messageToSign: '',
    signedMessage: '',
    messageToVerify: '',
    isValidSignature: null,
    error: '',
  }
  _signMessage() {
    if (this.appData == null || this.appData.loggedInUser == null) {
      return;
    }
    this.backendApi.Signature(
      this.appData.localNode, this.appData.localNodeSecret,
      this.appData.loggedInUser.PublicKeyBase58Check,
      this.signatureData.messageToSign,
      'sign').subscribe(
    (res: any) => {
      if (res == null || res.SignedMessage == null) {
        alert(Messages.CONNECTION_PROBLEM)
        return null;
      }

      this.signatureData.signedMessage = res.SignedMessage;
      this.signatureData.error = '';
    },
    (error) => {
      this.signatureData.signedMessage = '';
      this.signatureData.error = this._extractErrorOrderAction(error)
      console.error(error)
    })
  }

  _verifySignature() {
    if (this.appData == null || this.appData.loggedInUser == null) {
      return;
    }
    this.backendApi.Signature(
      this.appData.localNode, this.appData.localNodeSecret,
      this.appData.loggedInUser.PublicKeyBase58Check,
      this.signatureData.messageToVerify,
      'verify').subscribe(
    (res: any) => {
      if (res == null || res.IsValidSignature == null) {
        alert(Messages.CONNECTION_PROBLEM)
        return null;
      }

      this.signatureData.isValidSignature = res.IsValidSignature
    },
    (error) => {
      this.signatureData.isValidSignature = null;
      alert(this._extractErrorOrderAction(error))
      console.error(error)
    })
  }

  // Things for the order page.
  _tstampToDate(tstampSecs) {
    return new Date(tstampSecs*1000)
  }

  // Things for the transactions page.
  transactionData = {
    transactionHex: '',
    showRecentTransactions: false,
    bitcoinBlockHashOrHeight: '',
  }
  _reprocessBitcoinBlock() {
    if (this.transactionData.bitcoinBlockHashOrHeight == null ||
      this.transactionData.bitcoinBlockHashOrHeight === '') {

      alert("Please enter either a Bitcoin block hash or a Bitcoin block height.")
      return;
    }

    this.backendApi.ReprocessBitcoinBlock(
      this.appData.localNode, this.appData.localNodeSecret,
      this.transactionData.bitcoinBlockHashOrHeight).subscribe(

      (res: any) => {
        if (res == null || res.Message == null) {
          alert(Messages.CONNECTION_PROBLEM)
          return null;
        }

        this.transactionData.bitcoinBlockHashOrHeight = ''
        alert(res.Message)
      },
      (error) => {
        console.error(error)
        alert(error)
      }
    )
  }
  _numKeys(obj) {
    if (obj == null) {
      return 0;
    }
    return Object.keys(obj).length;

  }

  constructor(
    private ref: ChangeDetectorRef,
    private backendApi: BackendApiService) { }


  intervalsSet: number[] = [];
  _repeat(funcToRepeat: () => void, timeoutMillis) {
    funcToRepeat()
    let interval: number = <any>setInterval(() => {
      funcToRepeat()
    }, timeoutMillis)
    this.intervalsSet.push(interval)
  }

  ngOnInit() {
    this._clickResetFeeRate()
    setTimeout(()=>{
      this._clickResetFeeRate()
    }, 2000)

    this._repeat(() => {
      this._updateSendUltraTxnFee(false /*force*/);
    }, 1000)

    this._repeat(()=>{
      this._signMessage()
    }, 1000)

    setTimeout(()=>{
      this._getDraftImages();
      this.ref.detectChanges();
    }, 1000)

    this.callingUpdateSendUltraTxnFee = false
  }

  ngOnDestroy() {
    for (let ii = 0; ii < this.intervalsSet.length; ii++) {
      clearInterval(this.intervalsSet[ii]);
    }
  }

}
