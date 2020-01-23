import { BrowserModule } from '@angular/platform-browser';
import { NgModule } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { HttpClientModule } from '@angular/common/http';
import { HttpClientInMemoryWebApiModule } from 'angular-in-memory-web-api';

import { AppRoutingModule } from './app-routing.module';
import { AppComponent } from './app.component';
import { MarketComponent } from './market/market.component';
import { AccountComponent } from './account/account.component';
import { ForumComponent } from './forum/forum.component';
import { TrustGraphComponent } from './trust-graph/trust-graph.component';
import { BuyUltraComponent } from './buy-ultra/buy-ultra.component';
import { DashboardComponent } from './dashboard/dashboard.component';
import { MessagesComponent } from './messages/messages.component';
import { TabModule } from 'angular-tabs-component';
import { EntropyGeneratorComponent } from './account/entropy-generator/entropy-generator.component';
import { WindowRefService } from './window-ref.service';
import { BackendApiService } from './backend-api.service';
import { SetupUserComponent } from './account/setup-user/setup-user.component';

@NgModule({
  declarations: [
    AppComponent,
    MarketComponent,
    AccountComponent,
    ForumComponent,
    TrustGraphComponent,
    BuyUltraComponent,
    DashboardComponent,
    MessagesComponent,
    EntropyGeneratorComponent,
    SetupUserComponent,
  ],
  imports: [
    BrowserModule,
    AppRoutingModule,
    FormsModule,
    HttpClientModule,
    TabModule,
  ],
  providers: [ WindowRefService, BackendApiService ],
  bootstrap: [ AppComponent ]
})
export class AppModule { }
