import { ComponentFixture, TestBed } from '@angular/core/testing';

import { AngularCsvComponent } from './angular-csv.component';

describe('AngularCsvComponent', () => {
  let component: AngularCsvComponent;
  let fixture: ComponentFixture<AngularCsvComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      declarations: [ AngularCsvComponent ]
    })
    .compileComponents();
  });

  beforeEach(() => {
    fixture = TestBed.createComponent(AngularCsvComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
