import { AppData, PageType } from '../app.component';
import { ApplicationRef, ChangeDetectorRef, Component, OnInit, Input } from '@angular/core';
import { TemporaryEntropy } from './entropy-generator/entropy-generator.component';
import { first } from 'rxjs/operators'
import { isHexadecimal } from 'validator';
import * as _ from "lodash";
import { sprintf } from "sprintf-js";
import { WindowRefService } from '../window-ref.service';
import { grpc } from "@improbable-eng/grpc-web";
import { AdjectiveList } from '../../vendor/random-words/adjectives'
import { NounList } from '../../vendor/random-words/nouns'


@Component({
  selector: 'app-account',
  templateUrl: './account.component.html',
  styleUrls: ['./account.component.scss']
})
export class AccountComponent implements OnInit {
  // Keep a reference to the parent app data.
  @Input() appData: AppData;

  // Reference for updating the view if it's being stubborn and not
  // updating for some reason.
  constructor(private changeRef: ChangeDetectorRef,
              private appRef: ApplicationRef,
              private windowRef: WindowRefService) { }

  ngOnInit() {}
}
