import { async, ComponentFixture, TestBed } from '@angular/core/testing';

import { TrustGraphComponent } from './trust-graph.component';

describe('TrustGraphComponent', () => {
  let component: TrustGraphComponent;
  let fixture: ComponentFixture<TrustGraphComponent>;

  beforeEach(async(() => {
    TestBed.configureTestingModule({
      declarations: [ TrustGraphComponent ]
    })
    .compileComponents();
  }));

  beforeEach(() => {
    fixture = TestBed.createComponent(TrustGraphComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
