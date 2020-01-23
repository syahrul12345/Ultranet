import { ChangeDetectorRef, Component, OnInit } from '@angular/core';
import { Subject, Observable } from 'rxjs';
import * as _ from "lodash";
import { sprintf } from "sprintf-js";
import { Injectable } from '@angular/core';
import { WindowRefService } from './window-ref.service';
import * as classTransformer from 'class-transformer';
import { HttpClient } from  "@angular/common/http";
import { BackendApiService, User, TopMerchant } from './backend-api.service';
import { map, catchError } from 'rxjs/operators'; 
import { Router, ActivatedRoute, Params } from '@angular/router';

class Messages {
  static FAILED_TO_CONNECT = `Couldn't connect to the Ultranet Network!`;
}

class Constants {
  static UPDATE_INTERVAL_MILLIS = 60000
}

export enum PageType {
  Market,
  Dashboard,
  Messages,
  BuyUltra,
  Account,
}

export enum DashboardPage {
  Orders,
  Listings,
  SendUltra,
  Signatures,
  Transactions,
}

export class AppData {
  selectedPage: PageType;

  loggedInUser: User;
  userList: User[];
  nodeInfo: any;
  // The node we fetch listings from. After we're finished syncing, we switch this
  // over automatically to the local node.
  listingQueryNode: string = null;
  // The node we connect to to actually do all of the heavy lifting behind all of
  // our operations.
  localNodeSecret: string = null;
  localNode: string = null;
  // Whether or not the node is running on the testnet or mainnet.
  isTestnet: boolean = false;
  // Whether or not to show the advanced node info to the user. We default this to
  // true because it seems beneficial to show the user how sophisticated everything
  // behind the scenes is and to emphasize the true level decentralization of the
  // software.
  showAdvancedNodeInfo = true;

  satoshisPerUltraExchangeRate: number;
  nanosPerUSDExchangeRate: number;
  usdPerBitcoinExchangeRate: number;
  defaultFeeRateNanosPerKB: number;
  nanosLeftInTranche: number;
  // Keep topMerchants at the top level as it's used in a few places.
  topMerchants: TopMerchant[];
  merchantScoreMultiplier: number;

  marketPageState: {
    showRecentTransactions: boolean;
    showListings: boolean;
    topCategories: [];
    listingsToShow: any[];
  } = {
    showRecentTransactions: true,
    showListings: true,
    topCategories: null,
    listingsToShow: null,
  }

  dashboardPageState: {
    selectedPage: DashboardPage;
    listingSelected: any;
    draftImages: {
      id: number;
      url: string;
    }[]
  } = { 
    selectedPage: DashboardPage.Orders,
    listingSelected: null,
    draftImages: [],
  }

  accountPageState: {
    showAccountInfo: boolean;
    showAccountsList: boolean;
  } = {
    showAccountInfo: true,
    showAccountsList: true,
  }

  nanosToUltra(nanos: number, fixedDigits?: number) : string {
    if (fixedDigits == null) {
      fixedDigits = 9;
    }
    return (nanos / 1e9).toFixed(fixedDigits)
  }
  formatUSD(num: number, decimal: number): string {
    return Number(num).toLocaleString("en-US", { style: "currency", currency: "USD", minimumFractionDigits: decimal })
  }
  nanosToUSD(nanos: number, decimal: number) : string {
    if (decimal == null) {
      decimal = 4
    }
    return this.formatUSD(nanos / this.nanosPerUSDExchangeRate, decimal)
  }

  _copyText(val: string) {
    const selBox = document.createElement('textarea');
    selBox.style.position = 'fixed';
    selBox.style.left = '0';
    selBox.style.top = '0';
    selBox.style.opacity = '0';
    selBox.value = val;
    document.body.appendChild(selBox);
    selBox.focus();
    selBox.select();
    document.execCommand('copy');
    document.body.removeChild(selBox);
  }

  _stripHttp(input: string): string {
    if (input == null) {
      return;
    }
    if (input.includes('http://')) {
      input = input.slice(7, input.length)
    }
    return input;
  }

  _wrapWithPromise(res: any): Promise<any> {
    return new Promise((resolve, reject) => {
      if (res == null || res.error != null || (res.status != null && res.status !== 200)) {
        reject(res)
      } else {
        resolve(res)
      }
    })
  }

  scrollTop() {
    document.body.scrollTop = 0; // For Safari
    document.documentElement.scrollTop = 0; // For Chrome, Firefox, IE and Opera
  }

  /*
  GetMainArgs() {
    return (<any>window).remote.process.argv;
  }
  IsTestMode() {
    return this.GetMainArgs().indexOf('--test') >= 0;
  }
  GetRequiredFlag(flagNameWithEqualSign : string) : string {
    let flagStringValue = null
    let args = this.GetMainArgs()
    for (var ii = 0; ii < args.length; ii++) {
      var currentArg = args[ii];
      if (currentArg.indexOf(flagNameWithEqualSign) >= 0) {
        flagStringValue = currentArg.substring(flagNameWithEqualSign.length)
      }
    }
    if (flagStringValue == null) {
      throw (flagNameWithEqualSign + ' is required for the frontend to run')
    }
    return flagStringValue
  }
  */

  constructor(
      selectedPage: PageType,
      loggedInUser: User,
      userList: User[],
      private route: ActivatedRoute,
      private router: Router) {
    this.selectedPage = selectedPage;
    this.loggedInUser = loggedInUser;
    this.userList = userList;
    this.satoshisPerUltraExchangeRate = 10000
    this.nanosPerUSDExchangeRate = 1000000000;
    this.usdPerBitcoinExchangeRate = 10000;
    this.defaultFeeRateNanosPerKB = 0.0;
    this.nanosLeftInTranche = 10000e9;

    this.route.queryParams.subscribe((params: Params) => {
      // If we have params but the argument is empty then we don't have anything
      // to do. Note this prevents a bug in angular routing that calls this function
      // empty before calling it with the real params.
      if (Object.keys(params).length === 0 && (<any>window.location.href).includes('?')) {
        return;
      }

      if (params['testnet'] == 'true') {
        this.isTestnet = true;
      } else {
        this.isTestnet = false;
      }

      // Set the local variables based on what's in the query params.
      this.localNode = params['local_node']
      if (this.localNode == null) {
        if (this.isTestnet) {
          this.localNode = (<any>window).location.hostname + ':18001'
        } else {
          this.localNode = (<any>window).location.hostname + ':17001'
        }
        //let debugStr = 'local_node not found in query params. Defaulting to: '+this.localNode;
      }
      console.log('localNode from query params is: '+this.localNode)
      this.localNodeSecret = params['shared_secret']
      if (this.localNodeSecret == null) {
        this.localNodeSecret = ''
      }
      console.log('localNodeSecret from query params is: '+this.localNodeSecret)

      // Set the listingQueryNode to the param if we have one. Otherwise, default it
      // to the localNode.
      let listingQueryNodeParam = params['listing_query_node']
      if (listingQueryNodeParam != null) {
        this.listingQueryNode = listingQueryNodeParam;
      } else {
        this.listingQueryNode = this.localNode;
      }
      console.log('listingQueryNode from query params is: '+this.listingQueryNode)
    });
  }
}

@Component({
  selector: 'app-root',
  templateUrl: './app.component.html',
  styleUrls: ['./app.component.scss']
})
export class AppComponent implements OnInit {
  // Pull some external variables into the class so we can use them
  // in the template.
  PageType = PageType; 

  // This is the data we store for the entire app. We pass a reference to this to the
  // children of the app root module.
  appData: AppData = new AppData(
    PageType.Market, // selectedPage
    null, // loggedInUser
    null, // userList
    this.route, // route
    this.router, // route
  );

  constructor(
      private ref: ChangeDetectorRef,
      private windowRef: WindowRefService,
      private httpClient: HttpClient,
      private backendApi: BackendApiService,
      private route: ActivatedRoute,
      private router: Router) {

    // Nuke the referrer so we don't leak our localNodeSecret to the listingQueryNode
    // We also have a meta tag in index.html that does this in a different way to make
    // sure it's nuked.
    //
    // TODO: I'm pretty sure all of this could fail on IE so we should make sure people
    // only use the app with chrome.
    Object.defineProperty(document, "referrer", {get : function(){ return ""; }});
    Object.defineProperty(document, "referer", {get : function(){ return ""; }});
  }

  ultraToUSDExchangeRateToDisplay = 'fetching...';

  // This stringifies the user object after first zeroing out fields that make
  // comparisons problematic.
  _cleanStringifyUser(user: any) {
    let userCopy = JSON.parse(JSON.stringify(user))
  }

  // Throttle the calls to update the top-level data so they only happen after a
  // previous call has finished.
  callingUpdateTopLevelData = false
  problemWithNodeConnection = false;
  _updateTopLevelData() {
    if (this.callingUpdateTopLevelData) {
      return;
    }
    this.callingUpdateTopLevelData = true;
    this.backendApi.GetUsers(
      this.appData.localNode, this.appData.localNodeSecret).subscribe(
      (res: any) => {
        this.problemWithNodeConnection = false;
        this.callingUpdateTopLevelData = false;
        if (res == null || res.userData == null) {
          alert("There seems to be a connection issue; make sure you're connected to your node.")
          return;
        }
        // Only do swaps if things have changed to avoid unnecessary DOM manipulation.
        if (JSON.stringify(this.appData.loggedInUser) !== JSON.stringify(res.userData.loggedInUser)) {
          console.log("Updating LoggedInUser: ", res.userData.loggedInUser)
          /*
          let xxx = JSON.stringify(this.appData.loggedInUser);
          let yyy = JSON.stringify(res.userData.loggedInUser);
          let indx = -1;
          for (var ii = 0; ii < xxx.length; ii++) {
            if (xxx[ii] !== yyy[ii]) {
              indx = ii;
              break;
            }
          }
          console.log(indx, xxx, yyy)
          debugger;
          console.log(indx, xxx, yyy)
          */
          this.appData.loggedInUser = res.userData.loggedInUser;
        }
        if (JSON.stringify(this.appData.userList) !== JSON.stringify(res.userData.userList)) {
          console.log("Updating UserList: ", res.userData.loggedInUser)
          this.appData.userList = res.userData.userList;
        }
        this.appData.defaultFeeRateNanosPerKB = res.DefaultFeeRateNanosPerKB
        this.ref.detectChanges()
      },
      (error) => {
        this.problemWithNodeConnection = true;
        this.callingUpdateTopLevelData = false;
        console.error(error)
      }
    );
  }
  callingUpdateNodeInfo = false
  // We define this variable so that if the user decides later to switch off local
  // querying we don't change it back on them.
  hasSetQueryNodeToLocal = false;
  _updateNodeInfo() {
    if (this.callingUpdateNodeInfo) {
      return;
    }
    this.callingUpdateNodeInfo = true;
    this.backendApi.NodeControl(
      this.appData.localNode, this.appData.localNodeSecret,
      '' /*Address*/, 'get_info' /*OperationType*/).subscribe(
      (res: any) => {
        this.callingUpdateNodeInfo = false;
        if (res == null || res.UltraStatus == null) {
          return;
        }

        this.appData.nodeInfo = res

        // Set the listing query node if it's not set yet.
        if (this.appData.listingQueryNode == null) {
          // Only use outbound peers as query nodes, since inbound peers could be behind
          // a NAT and fail.
          if (res.UltraOutboundPeers != null && res.UltraOutboundPeers.length > 0) {
            let queryPeer = res.UltraOutboundPeers[Math.floor(Math.random()*res.UltraOutboundPeers.length)];
            this.appData.listingQueryNode = queryPeer.IP+':'+queryPeer.JSONPort;
            
          }
        }
        // If the node is fully current set the query node to the local server.
        if (!this.hasSetQueryNodeToLocal &&
          this.appData.nodeInfo != null &&
          this.appData.localNode != null &&
          this.appData.nodeInfo.UltraStatus.State === 'FULLY_CURRENT') {

          this.hasSetQueryNodeToLocal = true;
          if (this.appData.listingQueryNode !== this.appData.localNode) {
            alert(sprintf('Listing query node updated from %s to %s because node is fully synced.', this.appData.listingQueryNode, this.appData.localNode))
            this.appData.listingQueryNode = this.appData.localNode;
          }
        }
      },
      (error) => {
        this.callingUpdateNodeInfo = false;
        console.error(error)
        this.appData.nodeInfo = null
      }
    );
  }

  _updateTopMerchants() {
    if (this.appData.listingQueryNode == null) {
      // If the query node is null, try again after a second of waiting.
      setTimeout(()=>{
        this._updateTopMerchants();
      }, 1000);

      return;
    }

    this.backendApi.GetTopMerchants(
      this.appData.listingQueryNode,
    ).subscribe(
      (res: any) => {
        this.appData.topMerchants = res.TopMerchants.slice(0, 100);
        this.appData.merchantScoreMultiplier = res.CurrentScoreMultiple
      },
      (error) => {
        console.error(error)
        // If we hit an error, try again a second later with the hope that the query
        // node has refreshed.
        setTimeout(()=>{
          this._updateTopMerchants();
        }, 1000)
      }
    );
  }

  _updateUltraExchangeRate() {
    this.backendApi.GetExchangeRate(
      this.appData.listingQueryNode,
    ).subscribe(
      (res: any) => {
        this.appData.satoshisPerUltraExchangeRate = res.SatoshisPerUltraExchangeRate
        this.appData.nanosLeftInTranche = res.NanosLeftInTranche

        // The exchange rate requires getting the current Bitcoin price in USD.
        this.httpClient.get<any>(
          "https://blockchain.info/ticker").subscribe(
          (res: any) => {
            if (res.USD != null && res.USD.last != null) {
              this.appData.usdPerBitcoinExchangeRate = res.USD.last;
              // nonaperunit / satoshiperunit / usdperbitcoin * satoshiperbitcoin
              let nanosPerUnit = 1e9
              let satoshisPerBitcoin = 1e8
              this.appData.nanosPerUSDExchangeRate =  (
                nanosPerUnit /
                this.appData.satoshisPerUltraExchangeRate /
                this.appData.usdPerBitcoinExchangeRate *
                satoshisPerBitcoin)
              // Add noise to avoid giving the impression of an exact price, which
              // would be misleading.
              let noise = Math.random() * .01
              this.ultraToUSDExchangeRateToDisplay = this.appData.nanosToUSD(1e9 * (1+noise), null) 

              this.ref.detectChanges()
            }
          },
          (error) => { console.error(error) }
        );
      },
      (error) => {
        console.error(error)
      }
    );
  }


  _repeat(funcToRepeat: () => void, timeoutMillis) {
    funcToRepeat()
    let interval: number = <any>setInterval(() => {
      funcToRepeat()
    }, timeoutMillis)
  }

  ngOnInit() {
    // Delay the first call so that the node can be fetched properly from the URL.
    setTimeout(()=>{
      this._updateTopLevelData();
      this._updateNodeInfo();
      this._updateUltraExchangeRate();
    }, 100)
    setInterval(()=>{
      this._updateTopLevelData();
      this._updateNodeInfo();
      this._updateUltraExchangeRate();
      this.ref.detectChanges();
    }, 1000)

    // Update the top merchants at the top level of the app as it's used in a few
    // places.
    this._repeat(() => {this._updateTopMerchants()}, Constants.UPDATE_INTERVAL_MILLIS)
  }
}
