import { async, ComponentFixture, TestBed, fakeAsync, tick } from '@angular/core/testing';

import { EntropyGeneratorComponent, TemporaryEntropy, Messages } from './entropy-generator.component';
import { FormsModule } from '@angular/forms';
import { WindowRefService } from '../../window-ref.service';

describe('EntropyGeneratorComponent', () => {
  // If tests become flaky, make this longer.
  jasmine.DEFAULT_TIMEOUT_INTERVAL = 1000;
  let mockCrypto: any = null;
  let mockBIP39: any = null;
  let mockBigInt: any = null;

  let component: EntropyGeneratorComponent;
  let fixture: ComponentFixture<EntropyGeneratorComponent>;

  beforeEach(async(() => {
    mockCrypto = {
      randomBytes() { throw new Error(
          'unexpected call to nodeCrypto.randomBytes()') }
    };
    mockBIP39 = {
      entropyToMnemonic() { throw new Error(
          'unexpected call to bip39Custom.entropyToMnemonic()')
      }
    };
    mockBigInt = () => {
      throw new Error(
        'unexpected call to bigInt')
    }
    class MockWindowRefService {
      get nodeCrypto() {
        return mockCrypto;
      }
      get bip39Custom() {
        return mockBIP39;
      }
      get bigInt() {
        return mockBigInt;
      }
    }
    TestBed.overrideProvider(
        WindowRefService, { useValue:  new MockWindowRefService()});
    TestBed.configureTestingModule({
      imports: [
        FormsModule,
      ],
      providers: [
        WindowRefService,
      ],
      declarations: [ EntropyGeneratorComponent ]
    })
    .compileComponents();
  }));

  let _emptyEntropy = () => {
    return {
      entropy: null,
      isVerified: false,
      mnemonic: '',
      extraText: '',

      customEntropyHex: '',
      customEntropyHexMessage: '',

      customEntropyDice: '',
      customEntropyDiceMessage: '',

      customEntropyDecimal: '',
      customEntropyDecimalMessage: '',

      customMnemonicMessage: ''
    }
  }

  it('should create', () => {
    fixture = TestBed.createComponent(EntropyGeneratorComponent);
    component = fixture.componentInstance;
    component.temporaryEntropy = {
      value: null,
    }

    let currentEntropy = _emptyEntropy();
    spyOn(component, 'generateEntropy').and.callFake(() => {
      return currentEntropy;
    })

    fixture.detectChanges();
    expect(component).toBeTruthy();
    expect(component.temporaryEntropy).not.toBeNull();
    expect(component.temporaryEntropy.value).toEqual(currentEntropy);
    expect(component.generateEntropy).toHaveBeenCalledTimes(1);
  });

  it(`shouldn't generate entropy if temporaryEntropy is non-null`,
      () => {
    fixture = TestBed.createComponent(EntropyGeneratorComponent);
    component = fixture.componentInstance;
    component.temporaryEntropy = {
      value: _emptyEntropy(),
    }
    spyOn(component, 'generateEntropy').and.callFake(() => {
    })

    fixture.detectChanges();
    expect(component).toBeTruthy();
    expect(component.generateEntropy).toHaveBeenCalledTimes(0);
  });

  it('should generate entropy reasonably', fakeAsync(() => {
    fixture = TestBed.createComponent(EntropyGeneratorComponent);
    component = fixture.componentInstance;

    component.temporaryEntropy = {
      value: null,
    }
    let entropy = Buffer.from('abcdef', 'hex');
    spyOn(mockCrypto, 'randomBytes').and.callFake(
        (numBytes: number) => {
      return entropy;
    })
    let mnemonic = 'a b c';
    spyOn(mockBIP39, 'entropyToMnemonic').and.callFake((ent) => {
      expect(ent).toEqual(entropy)
      return mnemonic;
    })
    let dice = '123'
    spyOn(component, '_entropyToDice').and.callFake((ent) => {
      expect(ent).toEqual(entropy)
      return dice;
    })
    let decimal = '321'
    mockBigInt = (stringNum: string) => {
      expect(stringNum).toEqual(entropy.toString('hex'))
      return {
        toString: () => {
          return decimal;
        }
      }
    }

    let generatedEntropy = component.generateEntropy();
    expect(generatedEntropy).toEqual({
      entropy: entropy,
      isVerified: false,
      mnemonic: mnemonic,
      extraText: '',

      customEntropyHex: entropy.toString('hex'),
      customEntropyHexMessage: '',

      customEntropyDice: dice,
      customEntropyDiceMessage: '',

      customEntropyDecimal: decimal,
      customEntropyDecimalMessage: '',

      customMnemonicMessage: ''
    })
    fixture.detectChanges();

    // Tick so that the DOM updates.
    tick();

    // Check that the UI is showing the numbers as intended.
    const compiled = fixture.debugElement.nativeElement;
    expect(compiled.querySelector(
        '.custom-entropy-hex-input').value).toBe('abcdef');
    expect(compiled.querySelector(
        '.custom-entropy-decimal-input').value).toBe('321');
    expect(compiled.querySelector(
        '.custom-entropy-dice-input').value).toBe('123');
    expect(compiled.querySelector(
        '.custom-entropy-mnemonic-input').value).toBe('a b c');
  }));

  it(`customEntropyHex should error under the right circumstances.`, () => {
    fixture = TestBed.createComponent(EntropyGeneratorComponent);
    component = fixture.componentInstance;
    component.temporaryEntropy = {
      value: _emptyEntropy(),
    }

    component.temporaryEntropy.value = _emptyEntropy();
    component.customEntropyHexChanged('');
    let expected = _emptyEntropy();
    expected.customEntropyHex = '';
    expected.customEntropyHexMessage = Messages.NO_ENTROPY;
    expect(component.temporaryEntropy.value).toEqual(expected);
    
  });
});
