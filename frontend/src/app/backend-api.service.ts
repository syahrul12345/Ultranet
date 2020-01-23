import { Injectable } from '@angular/core';
import {Observable, throwError } from 'rxjs';
import { map, catchError } from 'rxjs/operators'; 
import { HttpClient, HttpErrorResponse } from  "@angular/common/http";

export class BackendRoutes {
  static TopCategoriesRoute: string = '/get-top-categories'
  static TopMerchantsRoute: string = '/get-top-merchants'
  static ExchangeRateRoute: string = '/get-exchange-rate'
  static GetUsersRoute: string = '/get-users'
  static CreateUserRoute: string = '/create-user'
  static UpdateUserRoute: string = '/update-user'
  static RegistermerchantRoute: string = '/register-merchant'
  static AddDraftImageRoute: string = '/draft-images/add'
  static GetDraftImageIDsRoute: string = '/draft-images/get/ids'
  static GetDraftImageRoute: string = '/draft-images/get'
  static UpdateDraftImagesRoute: string = '/draft-images/update'
  static UpdateThumbnailRoute: string = '/draft-images/thumbnail'
  static LoadListingDraftImagesRoute: string = '/draft-images/load-listing'
  static GetListingsRoute: string = "/get-listings"
  static GetListingImageRoute: string = "/get-listing-image"
  static PlaceOrderRoute: string = "/order/place"
  static OrderActionRoute: string = "/order/action"
  static UpdateMerchantRoute: string = "/update-merchant"
  static PublishListingRoute: string = "/draft-listing/publish"
  static BurnBitcoinRoute: string = "/burn-bitcoin"
  static SendUltraRoute: string = "/send-ultra"
  static SendMessageRoute: string = "/send-message"
  static UpdateMessagesRoute: string = "/update-messages"
  static SignatureRoute: string = "/signature"
  static ReprocessBitcoinBlockRoute: string = "/reprocess-bitcoin-block"
  static NodeControlRoute: string = "/node-control"
  static MinerControlRoute: string = "/miner-control"
}

export class TopMerchant {
  username: string;
}

export class AddDraftImageResponse {
  topMerchants: TopMerchant[];
}

export class GetDraftImageIDsResponse {
  imageIDs: number[];
}

export class Transaction {
  inputs: {
    txID: string;
    index: number;
  }[];
  outputs: {
    amountNanos: number;
    publicKeyBase58Check: string;
  }[];

  txnType: string;
  publicKeyBase58Check: string;
  signatureBytesHex: string;
}

export class ActionItem {
  orderIDHex: string
	shortOrderID: string
	orderAmount: number
	actionRequired: string
}

export class Stats {
  amountBurnedNanos: number;

  paymentPlacedNanos: number;
  paymentRejectedNanos: number;
  paymentCanceledNanos: number;

  commissionsNanos: number;
  revenueConfirmedNanos: number;
  revenueFulfilledNanos: number;

  revenueNegativeNanos: number;
  revenueNeutralNanos: number;
  revenuePositiveNanos: number;

  revenueRefundedNanos: number;

  merchantRank: number;
  totalMerchants: number;
}

export class User {
  Username: string;
  PublicKeyBase58Check: string;
  MerchantEntry: any;
  Listings: any;
  SeedInfo: any;
  BalanceNanos: number;
  LocalState: any;


  NumOrderActionItems: any;
  NumListingActionItems: any;
  NumActionItems: any;
  NumMessagesToRead: any;
}

@Injectable({
  providedIn: 'root'
})
export class BackendApiService {

  _makeRequestURL(endpoint: string, secret: string, routeName: string): string {
    let queryURL = 'http://'+endpoint+routeName
    if(secret != null) {
      queryURL += '?shared_secret='+secret
    }
    console.log('_makeRequestURL: '+queryURL)
    return queryURL
  }

  _makeDraftImageURL(imageID: number, endpoint: string, secret: string) {
    let queryURL = this._makeRequestURL(endpoint, secret, BackendRoutes.GetDraftImageRoute) + '&draft_image_id=' + imageID
    console.log('_makeDraftImageURL: '+queryURL)
    return queryURL
  }

  _makeListingImageURL(publicKeyBase58Check: string, listingIndex: number, imageIndex: number, endpoint: string) {
    if (endpoint == null || endpoint === '') {
      console.error('_makeListingImageURL called with empty "endpoint" arg')
      return
    }
    // No secret for ImageURL because the endpoint is public.
    let queryURL = this._makeRequestURL(endpoint, null /*secret*/, BackendRoutes.GetListingImageRoute) + '/' + publicKeyBase58Check + '/' + listingIndex + '/' + imageIndex
    return queryURL
  }

  _handleError(error: HttpErrorResponse) {
    if (error.error instanceof ErrorEvent) {
      // A client-side or network error occurred. Handle it accordingly.
      console.error('An error occurred:', error.error.message);
    } else {
      // The backend returned an unsuccessful response code.
      // The response body may contain clues as to what went wrong,
      console.error(
        `Backend returned code ${error.status}, ` +
        `body was: ${JSON.stringify(error.error)}`);
    }
    // return an observable with a user-facing error message
    return throwError(error);
  };

  constructor(private httpClient: HttpClient) {
  }

  // Use empty string to return all top categories.
  GetTopCategoriesWithPrefix(endpoint: string): Observable<any> {

    return this.httpClient.get<any>(this._makeRequestURL(
      endpoint, null /*secret*/, BackendRoutes.TopCategoriesRoute)).pipe(

      map(res => {
        if (res == null || !Array.isArray(res.TopCategories)) {
          throw "GetTopCategories: res.topCategories returned from backend must be array: " + JSON.stringify(res, null, 2)
        }

        return res
      }),
      catchError(this._handleError),
    );
  }

  GetTopMerchants(endpoint: string): Observable<any> {
    return this.httpClient.get<any>(this._makeRequestURL(
      endpoint, null /*secret*/, BackendRoutes.TopMerchantsRoute)).pipe(

      map(res => {
        if (res == null || !Array.isArray(res.TopMerchants)) {
          throw "GetTopMerchants: res.topMerchants returned from backend must be array: " + JSON.stringify(res, null, 2)
        }
        return res
      }),
      catchError(this._handleError),
    );
  }

  GetExchangeRate(endpoint: string): Observable<any> {
    return this.httpClient.get<any>(this._makeRequestURL(
      endpoint, null /*secret*/, BackendRoutes.ExchangeRateRoute)).pipe(

      map(res => {
        return res
      }),
      catchError(this._handleError),
    );
  }

  // User-related functions.
  GetUsers(endpoint: string, secret: string): Observable<any> {
    return this.httpClient.get<any>(
      this._makeRequestURL(endpoint, secret, BackendRoutes.GetUsersRoute)).pipe(
      map(res => {
        if (res == null || res.userData == null || !Array.isArray(res.userData.userList)) {
          throw "GetUsersResponse: res.userList returned from backend must be array: " + JSON.stringify(res, null, 2)
        }

        // Use this to test the stats display.
        /*
        if (res != null && res.userData != null && res.userData.loggedInUser != null && res.userData.loggedInUser.MerchantEntry != null) {
          res.userData.loggedInUser.MerchantEntry.TotalSalesNanos = 100*1e9
          res.userData.loggedInUser.MerchantEntry.Stats.RevenueConfirmedNanos = 5*1e9
          res.userData.loggedInUser.MerchantEntry.Stats.RevenueFulfilledNanos = 10*1e9
          res.userData.loggedInUser.MerchantEntry.Stats.RevenuePositiveNanos = 20*1e9
          res.userData.loggedInUser.MerchantEntry.Stats.RevenueNeutralNanos = 40*1e9
          res.userData.loggedInUser.MerchantEntry.Stats.RevenueNegativeNanos = 25*1e9
        }
        */

        if (res != null && res.userData != null && res.userData.loggedInUser != null) {
          let numOrderActionItems = 0;
          if (res.userData.loggedInUser.Orders != null) {
            for (var orderIndex = 0; orderIndex < res.userData.loggedInUser.Orders.length; orderIndex++) {
              let currentOrder = res.userData.loggedInUser.Orders[orderIndex]

              // Set the ImageUrls on the listing attached to each order.
              if (currentOrder.ListingMessage != null) {
                currentOrder.ListingMessage.ImageUrls = []
                for (var imageIndex = 0; imageIndex < currentOrder.ListingMessage.NumImages; imageIndex++) {
                  let currentImageURL = this._makeListingImageURL(
                    currentOrder.ListingMessage.PublicKeyBase58Check,
                    currentOrder.ListingMessage.ListingIndex, imageIndex, endpoint)
                  currentOrder.ListingMessage.ImageUrls.push(currentImageURL)
                }
              }

              // Count the number of orders that require action.
              if (currentOrder.IsActionRequired) {
                numOrderActionItems++;
              }
            }
          }

          // Count up the number of messages the user has to read.
          let numMessagesToRead = 0;
          for (var contactIndex = 0; contactIndex < res.userData.loggedInUser.LocalState.OrderedContactsWithMessages.length; contactIndex++) {
            let currentContact = res.userData.loggedInUser.LocalState.OrderedContactsWithMessages[contactIndex]
            let numMessages = currentContact.Messages.length - currentContact.NumMessagesRead
            if (numMessages < 0) {
              numMessages = 0;
            }
            numMessagesToRead += numMessages;
          }

          // If the logged-in user is a merchant with no listings, encourage her to
          // create a listing.
          let numListingActionItems = 0;
          if (res.userData.loggedInUser.MerchantEntry != null &&
            (res.userData.loggedInUser.Listings == null ||
            res.userData.loggedInUser.Listings.length === 0)) {

            numListingActionItems = 1;
          }

          res.userData.loggedInUser.NumOrderActionItems = numOrderActionItems;
          res.userData.loggedInUser.NumListingActionItems = numListingActionItems;
          res.userData.loggedInUser.NumActionItems = numOrderActionItems+numListingActionItems;
          res.userData.loggedInUser.NumMessagesToRead = numMessagesToRead;
        }

        return res;
      }),
      catchError(this._handleError),
    )
  }
  CreateUser(endpoint: string, secret: string, username: string, referralPublicKey: string, entropyHex: string, mnemonic: string, extraText: string, password: string, seedHex: string): Observable<any> {
    return this.httpClient.post<any>(
      this._makeRequestURL(endpoint, secret, BackendRoutes.CreateUserRoute), {
        username: username,
        referrerPublicKeyBase58Check: referralPublicKey,
        entropyHex: entropyHex,
        mnemonic: mnemonic,
        extraText: extraText,
        password: password,
        seedHex: seedHex,
      }).pipe(
      map(res => {
        return res;
      }),
      catchError(this._handleError),
    )
  }
  Logout(endpoint: string, secret: string): Observable<any> {
    return this.httpClient.post<any>(
      this._makeRequestURL(endpoint, secret, BackendRoutes.UpdateUserRoute), {
        OperationType: "logout",
      }).pipe(
      map(res => {
        return res;
      }),
      catchError(this._handleError),
    )
  }
  Login(endpoint: string, secret: string, publicKeyBase58Check: string, password: string): Observable<any> {
    return this.httpClient.post<any>(
      this._makeRequestURL(endpoint, secret, BackendRoutes.UpdateUserRoute), {
        OperationType: "login",
        PublicKeyBase58Check: publicKeyBase58Check,
        Password: password,
      }).pipe(
      map(res => {
        return res;
      }),
      catchError(this._handleError),
    )
  }
  Update(endpoint: string, secret: string, newUsername: string): Observable<any> {
    return this.httpClient.post<any>(
      this._makeRequestURL(endpoint, secret, BackendRoutes.UpdateUserRoute), {
        OperationType: "update",
        NewUsername: newUsername,
      }).pipe(
      map(res => {
        return res;
      }),
      catchError(this._handleError),
    )
  }
  DeleteUser(endpoint: string, secret: string, publicKeyBase58Check: string): Observable<any> {
    return this.httpClient.post<any>(
      this._makeRequestURL(endpoint, secret, BackendRoutes.UpdateUserRoute), {
        PublicKeyBase58Check: publicKeyBase58Check,
        OperationType: "delete",
      }).pipe(
      map(res => {
        return res;
      }),
      catchError(this._handleError),
    )
  }

  // Merchant-related functions.
  RegisterMerchant(
    endpoint: string, secret: string,
    Username: string, MerchantDescription: string, PublicKeyBase58Check: string,
    BurnAmountNanos: number, MinFeeRateNanosPerKB: number, Password: string,
    Sign: boolean, Validate: boolean, Broadcast: boolean): Observable<any> {

    BurnAmountNanos = Math.floor(BurnAmountNanos)
    MinFeeRateNanosPerKB = Math.floor(MinFeeRateNanosPerKB)

    return this.httpClient.post<any>(
      this._makeRequestURL(endpoint, secret, BackendRoutes.RegistermerchantRoute),
      {
        Username,
        MerchantDescription,
        PublicKeyBase58Check,
        BurnAmountNanos,
        MinFeeRateNanosPerKB,
        Password,
        Sign,
        Validate,
        Broadcast,
      }).pipe(
      map(res => {
        return res;
      }),
      catchError(this._handleError),
    )
  }


  // Listing-related functions. Note that no secret is provided for GetListings because
  // the endpoint is public.
  GetListings( 
    endpoint: string,
    listingIndex: number, searchQuery: string,
    adjustPriceForCommissions: boolean,
    queryType: string): Observable<any> {

    let queryURL = this._makeRequestURL(endpoint, null /*secret*/, BackendRoutes.GetListingsRoute)
    console.log('Getting listings from '+queryURL)

    return this.httpClient.post<any>(
      queryURL,
      {
        ListingIndex: listingIndex,
        SearchQuery: searchQuery,
        AdjustPriceForCommissions: adjustPriceForCommissions,
        QueryType: queryType,
      }, {}).pipe(
      map(res => {
        if(res.Listings == null) {
          throw "GetListingsResponse: res.Listings returned from backend must be non-null array: " + JSON.stringify(res, null, 2)
        }
        for (var ii = 0; ii < res.Listings.length; ii++) {
          let currentListing = res.Listings[ii];
          currentListing.ImageUrls = []

          // Use this to test the stats display.
          /*
          currentListing.MerchantEntry.TotalSalesNanos = 100*1e9
          currentListing.MerchantEntry.Stats.RevenueConfirmedNanos = 5*1e9
          currentListing.MerchantEntry.Stats.RevenueFulfilledNanos = 10*1e9
          currentListing.MerchantEntry.Stats.RevenuePositiveNanos = 20*1e9
          currentListing.MerchantEntry.Stats.RevenueNeutralNanos = 40*1e9
          currentListing.MerchantEntry.Stats.RevenueNegativeNanos = 25*1e9
          */
          // Use this to test the min and max quantity on the listing order form.
          /*
          currentListing.MaxQuantity = 0;
          currentListing.MinQuantity = 0;
          */

          for (var imageIndex = 0; imageIndex < currentListing.NumImages; imageIndex++) {
            let currentImageURL = this._makeListingImageURL(
              currentListing.PublicKeyBase58Check, currentListing.ListingIndex, imageIndex, endpoint)
            currentListing.ImageUrls.push(currentImageURL)
          }
        }
        return res;
      }),
      catchError(this._handleError),
    )
  }

  // Image-related functions.
  AddDraftImage(endpoint: string, secret: string, imageBase64: string): Observable<AddDraftImageResponse> {
    return this.httpClient.post<AddDraftImageResponse>(
      this._makeRequestURL(endpoint, secret, BackendRoutes.AddDraftImageRoute), {
        "image_base64": imageBase64,
      }).pipe(
      map(res => {
        return res;
      }),
      catchError(this._handleError),
    )
  }
  GetDraftImageIDs(endpoint: string, secret: string): Observable<GetDraftImageIDsResponse> {
    return this.httpClient.get<GetDraftImageIDsResponse>(
      this._makeRequestURL(endpoint, secret, BackendRoutes.GetDraftImageIDsRoute)).pipe(
      catchError(this._handleError),
    )
  }
  UpdateDraftImages(endpoint: string, secret: string, imageIDs: number[]): Observable<any> {
    return this.httpClient.post<any>(
      this._makeRequestURL(endpoint, secret, BackendRoutes.UpdateDraftImagesRoute), {
        imageIDs: imageIDs,
      }).pipe(
      catchError(this._handleError),
    )
  }
  UpdateThumbnail(endpoint: string, secret: string, imageID: number): Observable<any> {
    return this.httpClient.post<any>(
      this._makeRequestURL(endpoint, secret, BackendRoutes.UpdateThumbnailRoute), {
        imageID: imageID,
      }).pipe(
      catchError(this._handleError),
    )
  }
  LoadListingDraftImages(
    endpoint: string, secret: string,
    MerchantIDBase58Check: string, ListingIndex: number): Observable<any> {

    return this.httpClient.post<any>(
      this._makeRequestURL(endpoint, secret, BackendRoutes.LoadListingDraftImagesRoute), {
        MerchantIDBase58Check,
        ListingIndex,
      }).pipe(
        map(res => {
          return res
        }),
        catchError(this._handleError),
      )
  }

  // Order-related functions
  PlaceOrder(
    endpoint: string, secret: string,
    publicKeyBase58Check: string,
    listingMessage: any, requiredFields: string[], optionalFields: string[],
    itemQuantity: number, feeRateNanosPerKB: number, itemTotalNanos: number,
    tipAmountNanos: number, expectedTotalFeeNanos: number, password: string,
    sign: boolean, validate: boolean, broadcast: boolean): Observable<any> {

    feeRateNanosPerKB = Math.floor(feeRateNanosPerKB)
    itemTotalNanos = Math.floor(itemTotalNanos)
    tipAmountNanos = Math.floor(tipAmountNanos)
    expectedTotalFeeNanos = Math.floor(expectedTotalFeeNanos)

    return this.httpClient.post<any>(
      this._makeRequestURL(endpoint, secret, BackendRoutes.PlaceOrderRoute), {
        SenderPublicKeyBase58Check: publicKeyBase58Check,
	      Listing: listingMessage,
	      RequiredFields: requiredFields,
	      OptionalFields: optionalFields,
	      ItemQuantity: itemQuantity,
	      FeeRateNanosPerKB: feeRateNanosPerKB,
        ItemTotalNanos: itemTotalNanos,
        TipAmountNanos: tipAmountNanos,
        ExpectedTotalFeeNanos: expectedTotalFeeNanos,
        Password: password,
        Sign: sign,
        Validate: validate,
        Broadcast: broadcast,
      }).pipe(
      map(res => {
        return res
      }),
      catchError(this._handleError),
    )
  }

  UpdateMerchant(
    endpoint: string, secret: string,
    publicKeyBase58Check: string, newUsername: string,
    newDescription: string, burnAmountNanos: number, minFeeRateNanosPerKB: number,
    password: string, sign: boolean, validate: boolean,
    broadcast: boolean): Observable<any> {

    burnAmountNanos = Math.floor(burnAmountNanos)
    minFeeRateNanosPerKB = Math.floor(minFeeRateNanosPerKB)

    return this.httpClient.post<any>(
      this._makeRequestURL(endpoint, secret, BackendRoutes.UpdateMerchantRoute), {
        publicKeyBase58Check,
	      // NewPublicKeyBase58Check string `json:"newPublicKeyBase58Check"`
	      newUsername,
        newDescription,
        burnAmountNanos,
        minFeeRateNanosPerKB,
        password,
        sign,
        validate,
        broadcast,
      }).pipe(
      map(res => {
        return res
      }),
      catchError(this._handleError),
    )
  }

  PublishListing(
    endpoint: string, secret: string,
    selectedListing: any, password: string): Observable<any> {
    return this.httpClient.post<any>(
      this._makeRequestURL(endpoint, secret, BackendRoutes.PublishListingRoute), {
        publicKeyBase58Check: selectedListing.PublicKeyBase58Check,
        // Always use a timestamp of zero since we're generally always updating
        // or creating a listing. This will cause the BE to assign the latest
        // timestamp possible.
        tstampSecs: 0,
        Deleted: selectedListing.Deleted,
        listingIndex: selectedListing.ListingIndex,
        title: selectedListing.Title,
        body: selectedListing.Body,
        category: selectedListing.Category,
        pricePerUnitNanos: selectedListing.PricePerUnitNanos,
        unitNameSingular: selectedListing.UnitNameSingular,
        unitNamePlural: selectedListing.UnitNamePlural,
        minQuantity: selectedListing.MinQuantity,
        maxQuantity: selectedListing.MaxQuantity,
        productType: selectedListing.ProductType,
        RequiredFields: selectedListing.RequiredFields,
        OptionalFields: selectedListing.OptionalFields,
        tipComment: selectedListing.TipComment,
        shipsTo: selectedListing.ShipsTo,
        shipsFrom: selectedListing.ShipsFrom,
        Password: password,
      }).pipe(
      map(res => {
        return res
      }),
      catchError(this._handleError),
    )
  }

  // Use empty string to return all top categories.
  GetBitcoinFeeRateSatoshisPerKB(): Observable<any> {
    return this.httpClient.get<any>('https://bitcoinfees.earn.com/api/v1/fees/recommended').pipe(
      map(res => {
        return res;
      }),
      catchError(this._handleError),
    );
  }

  BurnBitcoin(
    endpoint: string, secret: string,
    PublicKeyBase58Check: string, BurnAmountSatoshis: number,
    FeeRateSatoshisPerKB: number, Password: string, Sign: boolean,
    Broadcast: boolean): Observable<any> {

    return this.httpClient.post<any>(
      this._makeRequestURL(endpoint, secret, BackendRoutes.BurnBitcoinRoute), {
        PublicKeyBase58Check,
        BurnAmountSatoshis,
        FeeRateSatoshisPerKB,
        Password,
        Sign,
        Broadcast,
      }).pipe(
      map(res => {
        return res
      }),
      catchError(this._handleError),
    )
  }

  OrderAction(
    endpoint: string, secret: string,
    PublicKeyBase58Check: string, OrderIDBase58Check: string,
    Action: string, ReviewType: string, ReviewText: string, RejectReason: string,
    FeeRateNanosPerKB: number, Password: string, Sign: boolean,
    Validate: boolean,
    Broadcast: boolean): Observable<any> {

    return this.httpClient.post<any>(
      this._makeRequestURL(endpoint, secret, BackendRoutes.OrderActionRoute), {
        PublicKeyBase58Check,
        OrderIDBase58Check,
        Action,
        ReviewType,
        ReviewText,
        RejectReason,
        FeeRateNanosPerKB,
        Password,
        Sign,
        Validate,
        Broadcast,
      }).pipe(
      map(res => {
        return res
      }),
      catchError(this._handleError),
    )
  }

  SendUltra(
    endpoint: string, secret: string,
    SenderPublicKeyBase58Check: string,
    RecipientPublicKeyBase58Check: string,
    AmountNanos: number,
    MinFeeRateNanosPerKB: number,
    Password: string,
    Sign: boolean,
    Validate: boolean,
    Broadcast: boolean): Observable<any> {

    return this.httpClient.post<any>(
      this._makeRequestURL(endpoint, secret, BackendRoutes.SendUltraRoute), {
        SenderPublicKeyBase58Check,
        RecipientPublicKeyBase58Check,
        AmountNanos,
        MinFeeRateNanosPerKB,
        Password,
        Sign,
        Validate,
        Broadcast
      }).pipe(
      map(res => {
        return res
      }),
      catchError(this._handleError),
    )
  }

  ReprocessBitcoinBlock(
    endpoint: string, secret: string, blockHashOrBlockHeight: string): Observable<any> {

    return this.httpClient.get<any>(this._makeRequestURL(
      endpoint, secret,
      BackendRoutes.ReprocessBitcoinBlockRoute+'/'+blockHashOrBlockHeight)).pipe(
      map(res => {
        return res;
      }),
      catchError(this._handleError),
    );
  }

  SendMessage(
    endpoint: string, secret: string,
    SenderPublicKeyBase58Check: string,
    RecipientPublicKeyBase58Check: string,
    MessageText: string,
    MinFeeRateNanosPerKB: number,
    Password: string,
    Sign: boolean,
    Validate: boolean,
    Broadcast: boolean): Observable<any> {

    return this.httpClient.post<any>(
      this._makeRequestURL(endpoint, secret, BackendRoutes.SendMessageRoute), {
        SenderPublicKeyBase58Check,
        RecipientPublicKeyBase58Check,
        MessageText,
        MinFeeRateNanosPerKB,
        Password,
        Sign,
        Validate,
        Broadcast
      }).pipe(
      map(res => {
        return res
      }),
      catchError(this._handleError),
    )
  }

  UpdateMessages(endpoint: string, secret: string,
    PublicKeyBase58Check: string,
    ContactPublicKeyBase58Check: string,
    UpdateNickname: string): Observable<any> {

    return this.httpClient.post<any>(
      this._makeRequestURL(endpoint, secret, BackendRoutes.UpdateMessagesRoute), {
        PublicKeyBase58Check,
        ContactPublicKeyBase58Check,
        UpdateNickname,
      }).pipe(
      map(res => {
        return res
      }),
      catchError(this._handleError),
    )
  }

  Signature(
    endpoint: string, secret: string,
    PublicKeyBase58Check: string,
    MessageText: string,
    Action: string): Observable<any> {

    return this.httpClient.post<any>(
      this._makeRequestURL(endpoint, secret, BackendRoutes.SignatureRoute), {
        PublicKeyBase58Check,
        MessageText,
        Action,
      }).pipe(
      map(res => {
        return res
      }),
      catchError(this._handleError),
    )
  }

  NodeControl(
    endpoint: string, secret: string,
    Address: string, OperationType: string): Observable<any> {

    return this.httpClient.post<any>(
      this._makeRequestURL(endpoint, secret, BackendRoutes.NodeControlRoute), {
        Address,
        OperationType,
      }).pipe(
      map(res => {
        //return JSON.parse('{"UltraStatus":{"State":"NEED_BLOCKS","LatestHeaderHeight":9393,"LatestHeaderHash":"0000011ebbe6081db16de46e8ee09715e5332442e11b43ca98e4f1f33fde8992","LatestHeaderTstampSecs":1576043642,"LatestBlockHeight":9393,"LatestBlockHash":"0000011ebbe6081db16de46e8ee09715e5332442e11b43ca98e4f1f33fde8992","LatestBlockTstampSecs":1576043642,"HeadersRemaining":456,"BlocksRemaining":123},"BitcoinStatus":{"State":"FULLY_CURRENT","LatestHeaderHeight":1612141,"LatestHeaderHash":"00000000000001a5b034b9699da58ae8316208c6b12c11d211abf200c4d89969","LatestHeaderTstampSecs":1576042468,"LatestBlockHeight":0,"LatestBlockHash":"","LatestBlockTstampSecs":0,"HeadersRemaining":89,"BlocksRemaining":0},"UltraOutboundPeers":[{"Address":"127.0.0.13031","IsSyncPeer":false}, {"Address":"127.0.0.13031","IsSyncPeer":false}, {"Address":"127.0.0.13031","IsSyncPeer":false}, {"Address":"127.0.0.13031","IsSyncPeer":false}, {"Address":"127.0.0.13031","IsSyncPeer":false}, {"Address":"127.0.0.13031","IsSyncPeer":false}, {"Address":"127.0.0.13031","IsSyncPeer":false}, {"Address":"127.0.0.13031","IsSyncPeer":false}, {"Address":"127.0.0.13031","IsSyncPeer":false}, {"Address":"127.0.0.13031","IsSyncPeer":false}, {"Address":"127.0.0.13031","IsSyncPeer":false}, {"Address":"127.0.0.13031","IsSyncPeer":false}, {"Address":"127.0.0.13031","IsSyncPeer":false}, {"Address":"127.0.0.13031","IsSyncPeer":false}, {"Address":"127.0.0.13031","IsSyncPeer":false}],"UltraInboundPeers":[{"Address":"127.0.0.13031","IsSyncPeer":false}, {"Address":"127.0.0.13031","IsSyncPeer":false}, {"Address":"127.0.0.13031","IsSyncPeer":false}, {"Address":"127.0.0.13031","IsSyncPeer":false}, {"Address":"127.0.0.13031","IsSyncPeer":false}, {"Address":"127.0.0.13031","IsSyncPeer":false}, {"Address":"127.0.0.13031","IsSyncPeer":false}, {"Address":"127.0.0.13031","IsSyncPeer":false}, {"Address":"127.0.0.13031","IsSyncPeer":false}, {"Address":"127.0.0.13031","IsSyncPeer":false}, {"Address":"127.0.0.13031","IsSyncPeer":false}, {"Address":"127.0.0.13031","IsSyncPeer":false}, {"Address":"127.0.0.13031","IsSyncPeer":false}, {"Address":"127.0.0.13031","IsSyncPeer":false}],"UltraUnconnectedPeers":[{"Address":"127.0.0.13031","IsSyncPeer":false}],"BitcoinSyncPeer":{"Address":"18.217.207.161:18333","IsSyncPeer":false},"BitcoinUnconnectedPeers":[{"Address":"127.0.0.13031","IsSyncPeer":false}]}')
        return res
      }),
      catchError(this._handleError),
    )
  }

  UpdateMiner(
    endpoint: string, secret: string,
    MinerPublicKeys: string): Observable<any> {

    return this.httpClient.post<any>(
      this._makeRequestURL(endpoint, secret, BackendRoutes.NodeControlRoute), {
        MinerPublicKeys,
        OperationType: "update_miner",
      }).pipe(
      map(res => {
        return res
      }),
      catchError(this._handleError),
    )
  }
}
