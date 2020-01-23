import { async, ComponentFixture, TestBed } from '@angular/core/testing';

import { AccountComponent } from './account.component';
import { FormsModule } from '@angular/forms';
import { WindowRefService } from '../window-ref.service';
import { EntropyGeneratorComponent } from './entropy-generator/entropy-generator.component';
import { TabModule } from 'angular-tabs-component';

describe('AccountComponent', () => {
  let component: AccountComponent;
  let fixture: ComponentFixture<AccountComponent>;

  beforeEach(async(() => {
    class MockWindowRefService {
    }
    TestBed.overrideProvider(
        WindowRefService, { useValue:  new MockWindowRefService()});
    TestBed.configureTestingModule({
      imports: [
        FormsModule,
        TabModule,
      ],
      providers: [
        WindowRefService,
      ],
      declarations: [
        AccountComponent,
        EntropyGeneratorComponent
      ]
    })
    .compileComponents();
  }));

  it('should create', () => {
    fixture = TestBed.createComponent(AccountComponent);
    component = fixture.componentInstance;
    expect(component).toBeTruthy();
  });
});
