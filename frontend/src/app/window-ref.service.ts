// Create an injectable window reference so we can swap out all of
// the node stuff during testing.

import { Injectable } from '@angular/core';
import * as _ from "lodash";

@Injectable({
  providedIn: 'root'
})
export class WindowRefService {
  get ecies(): any {
    return (<any>window).ecies;
  }
  get blockexplorer(): any {
    return (<any>window).blockexplorer;
  }
  get bip32(): any {
    return (<any>window).bip32;
  }
  get bitcoinjs(): any {
    return (<any>window).bitcoinjs;
  }
  get bip39Custom(): any {
    return (<any>window).bip39Custom;
  }
  get nodeCrypto(): any {
    return (<any>window).nodeCrypto;
  }
  get pbkdf2(): any {
    return (<any>window).pbkdf2;
  }
  get storage(): any {
    return (<any>window).storage;
  }
  get bigInt(): any {
    return (<any>window).bigInt;
  }
  get validator(): any {
    return (<any>window).validator;
  }
  get net(): any {
    return (<any>window).net;
  }
  get ip(): any {
    return (<any>window).ip;
  }
}
