import { ComponentFixture, TestBed, waitForAsync } from '@angular/core/testing';

import { HistoryExperimentoComponent } from './history-experimento.component';

describe('HistoryExperimentoComponent', () => {
  let component: HistoryExperimentoComponent;
  let fixture: ComponentFixture<HistoryExperimentoComponent>;

  beforeEach(waitForAsync(() => {
    TestBed.configureTestingModule({
      declarations: [ HistoryExperimentoComponent ]
    })
    .compileComponents();
  }));

  beforeEach(() => {
    fixture = TestBed.createComponent(HistoryExperimentoComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
