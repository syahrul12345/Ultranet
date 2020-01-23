import { ApplicationRef, ChangeDetectorRef, Component, OnInit, Input } from '@angular/core';
import { AppData, DashboardPage, PageType } from '../app.component';
import { BackendApiService, AddDraftImageResponse, GetDraftImageIDsResponse, BackendRoutes } from '../backend-api.service';
import { sprintf } from "sprintf-js";
import $ from 'jquery';

class Messages {
  static INCORRECT_PASSWORD = `The password you entered was incorrect.`
  static CONNECTION_PROBLEM = `There is currently a connection problem. Is your connection to your node healthy?`
  static UNKOWN_PROBLEM = `There was a weird problem with the transaction. Debug output: %s`

  static INSUFFICIENT_BALANCE = `You don't have enough Ultra to process the message. Try reducing the fee rate or buying some Ultra on the "Buy Ultra" page.`
  static SEND_ULTRA_MIN = `You must send a non-zero amount of Ultra`
  static INVALID_PUBLIC_KEY = `The public key you entered is invalid`
}

@Component({
  selector: 'app-messages',
  templateUrl: './messages.component.html',
  styleUrls: ['./messages.component.scss']
})
export class MessagesComponent implements OnInit {
  @Input() appData: AppData;

  // Tooltip vars
  showContactsTooltip = null;

  constructor(
    private ref: ChangeDetectorRef,
    private backendApi: BackendApiService) { }

  _clickCreateAccountOrLogin()  {
    this.appData.selectedPage = PageType.Account;
    this.ref.detectChanges();
    return
  }

  _extractError(err: any): string {
    if (err.error != null && err.error.error != null) {
      // Is it obvious yet that I'm not a frontend gal?
      // TODO: Error handling between BE and FE needs a major redesign.
      let rawError = err.error.error;
      if (rawError.includes("password")) {
        return Messages.INCORRECT_PASSWORD
      } else if (rawError.includes("not sufficient")) {
        return Messages.INSUFFICIENT_BALANCE
      } else if (rawError.includes("RuleErrorTxnMustHaveAtLeastOneInput")) {
        return Messages.SEND_ULTRA_MIN
      } else if ((rawError.includes("decoding") && rawError.includes("public key"))) {

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

  messageText = '';
  newContactPublicKey = ''
  feeRateUltraPerKB: any = '0';
  currentContactObj = null
  contactNickname = '';
  _resetScroll() {
    setTimeout(()=>{
      var xx = $('.message-container')
      xx.scrollTop(xx.scrollHeight);
      xx[0].scrollTo(0, xx[0].scrollHeight)
    })
  }
  _setContact(contactObj) {
    this.newContactPublicKey='';
    this.currentContactObj = contactObj
    this.contactNickname = contactObj.Nickname
    this._resetScroll();
  }
  _startNewConversation(publicKeyBase58Check: string) {
    if (this.appData.loggedInUser == null) {
      console.log("Not calling _startNewConversation() because loggedInUser is null.")
      return;
    }

    if (publicKeyBase58Check === '' || publicKeyBase58Check.length < 15) {
      alert("Please enter a valid public key to start a conversation.")
      return;
    }

    if (publicKeyBase58Check === this.appData.loggedInUser.PublicKeyBase58Check) {
      alert("You can't send messages to yourself.")
      return;
    }

    // If the public key entered corresponds to an existing contact then load that
    // conversation.
    let contactSelected = null
    if (this.appData.loggedInUser.LocalState != null && this.appData.loggedInUser.LocalState.OrderedContactsWithMessages != null) {
      let contacts = this.appData.loggedInUser.LocalState.OrderedContactsWithMessages
      for (var contactIndex = 0; contactIndex < contacts.length; contactIndex++) {
        let currentContact = contacts[contactIndex];
        if (currentContact.PublicKeyBase58Check === publicKeyBase58Check) {
          contactSelected = currentContact;
          break;
        }
      }
    }

    // If we didn't find the contact in the list then set it to a new contact object.
    if (contactSelected == null) {
      contactSelected = {
        PublicKeyBase58Check: publicKeyBase58Check,
        Nickname: '',
        Messages: [],
      }
    }

    this._setContact(contactSelected);
  }
  _messageTextChanged(event) {
    if (event == null) {
      return;
    }
    // When the shift key is pressed ignore the signal.
    if (event.shiftKey) {
      return;
    }
    if (event.key === "Enter") {
      this._sendMessage()
    }
  }
  _resetMessageText(textVal: string) {
    // Make sure the contact has her messages read set to zero.
    if (this.currentContactObj != null) {
      this.currentContactObj.NumMessagesRead = this.currentContactObj.Messages.length;
    }
    setTimeout(()=>{
      this.messageText = textVal;
      this._resetScroll()
    }, 0)
  }
  sendMessageBeingCalled = false;
  _sendMessage() {
    // If we get here then it means Enter has been pressed without the shift
    // key held down.
    if (this.messageText == null || this.messageText === '') {
      alert('Please enter a message to send.')
      setTimeout(()=>{
        this.messageText = '';
        this._resetScroll();
      }, 0)
      return;
    }
    if (this.sendMessageBeingCalled) {
      alert('Still processing your previous message. Please wait a few seconds.')
      return;
    }

    // Immediately add the message to the list  to make it feel instant.
    let messageObj = {
      SenderPublicKeyBase58Check: this.appData.loggedInUser.PublicKeyBase58Check,
      RecipientPublicKeyBase58Check: this.currentContactObj.PublicKeyBase58Check,
      DecryptedText: this.messageText,
      TstampNanos: (new Date()).getTime()*1e9,
      IsSender: true,
    }
    this.currentContactObj.Messages.push(messageObj)
    this._resetMessageText('');

    // If we get here then we have a message to send to the currentContactObj.
    this.sendMessageBeingCalled = true;
    let textSent = this.messageText;
    this.backendApi.SendMessage(
      this.appData.localNode, this.appData.localNodeSecret,
      this.appData.loggedInUser.PublicKeyBase58Check,
      this.currentContactObj.PublicKeyBase58Check,
      this.messageText,
      parseFloat(this.feeRateUltraPerKB)*1e9,
      '' /*Password*/,
      true /*Sign*/,
      true /*Validate*/,
      true /*Broadcast*/).subscribe(
      (res: any) => {
        this.sendMessageBeingCalled = false;
        // Set the timestamp in this case since it's normally set by the BE.
        messageObj.TstampNanos = res.TstampNanos;
        // Only clear the text box if it still contains the message we sent.
        if (this.messageText === textSent) {
          this._resetMessageText('');
        }
      },
      (error) => {
        // Remove the previous message since it didn't actually post and rest
        // the text area to the old message.
        this.currentContactObj.Messages.pop()
        this._resetMessageText(textSent);

        alert(this._extractError(error))

        this.sendMessageBeingCalled = false;
        console.error(error)
        return;
      }
    );
  }
  _clickResetFeeRate() {
    this.feeRateUltraPerKB = (this.appData.defaultFeeRateNanosPerKB / 1e9).toFixed(9)
  }
  _updateCurrentContactMessages() {
    // If there's no contact object set then there's nothing to do.
    if (this.currentContactObj == null || this.appData.loggedInUser == null) {
      return;
    }

    // Find the current contact in the user list.
    let contactFound = null
    if (this.appData.loggedInUser.LocalState != null && this.appData.loggedInUser.LocalState.OrderedContactsWithMessages != null) {
      let contacts = this.appData.loggedInUser.LocalState.OrderedContactsWithMessages;
      for (var contactIndex = 0; contactIndex < contacts.length; contactIndex++) {
        let currentContact = contacts[contactIndex];
        if (currentContact.PublicKeyBase58Check === this.currentContactObj.PublicKeyBase58Check) {
          contactFound = currentContact;
          break;
        }
      }
    }

    // If the current contact was not found just return.
    if (contactFound == null) {
      return;
    }

    // Check if anything has changed since the last update. If not then return.
    if (JSON.stringify(contactFound) === JSON.stringify(this.currentContactObj)) {
      return;
    } 

    // If the contact found has fewer messages then ignore the change since it's
    // likely due to staleness.
    if (contactFound.Messages.length < this.currentContactObj.Messages.length) {
      return;
    }

    // If we get here then we detected a change in the contact so update it.
    console.log('Detected change in contact: ', contactFound)
    this._setContact(contactFound)
  }

  _setNickname(contactNickname: string) {
    if (this.appData.loggedInUser == null || this.currentContactObj == null) {
      return;
    }

    this.backendApi.UpdateMessages(
      this.appData.localNode, this.appData.localNodeSecret,
      this.appData.loggedInUser.PublicKeyBase58Check,
      this.currentContactObj.PublicKeyBase58Check, contactNickname).subscribe(
      (res) => {
        alert('Successfully updated user nickname to: '+contactNickname)
      }, (err) => {
        alert('There was a problem updating the contact nickname. Debug message: '+this._extractError(err))
      }
    )
  }

  callingUpdateMessagesData = false;
  _updateMessagesData() {
    if (this.appData.loggedInUser == null) {
      return;
    }

    // If no contact is currently being messaged with then there's nothing to update.
    if (this.currentContactObj == null) {
      return;
    }

    // If all of our messages are up-to-date, don't bother updating.
    if (this.currentContactObj.Messages.length === this.currentContactObj.NumMessagesRead) {
      return;
    }

    if (this.callingUpdateMessagesData) {
      console.log("Not calling _updateMessagesData() because it's already being called")
      return;
    }

    // If we get here then we have something to update. Set the messages read
    // equal to the number of messages to make the change feel instant.
    this.currentContactObj.NumMessagesRead = this.currentContactObj.Messages.length

    // This call will basically mark all of our messages as "read."
    this.callingUpdateMessagesData = true;
    this.backendApi.UpdateMessages(
      this.appData.localNode, this.appData.localNodeSecret,
      this.appData.loggedInUser.PublicKeyBase58Check,
      this.currentContactObj.PublicKeyBase58Check, '').subscribe(
      (res) => {
        this.callingUpdateMessagesData = false;
        console.log('calling!')
      }, (err) => {
        this.callingUpdateMessagesData = false;
        console.error(err)
      }
    )

  }

  _tstampToDate(tstampNanos: number) {
    return (new Date(tstampNanos/1e9)).toString()
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
    this.feeRateUltraPerKB = (this.appData.defaultFeeRateNanosPerKB / 1e9).toFixed(9)
    setTimeout(()=>{
      this.feeRateUltraPerKB = (this.appData.defaultFeeRateNanosPerKB / 1e9).toFixed(9)
    }, 1000)

    this._repeat(() => {
      this._updateCurrentContactMessages();
    }, 200)

    this._repeat(() => {
      this._updateMessagesData();
    }, 200)
  }

  ngOnDestroy() {
    for (let ii = 0; ii < this.intervalsSet.length; ii++) {
      clearInterval(this.intervalsSet[ii]);
    }
  }

}
