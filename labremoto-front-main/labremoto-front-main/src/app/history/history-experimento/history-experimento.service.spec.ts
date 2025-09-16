import { TestBed } from '@angular/core/testing';

import { HistoryExperimentoService } from './history-experimento.service';

describe('HistoryExperimentoService', () => {
  let service: HistoryExperimentoService;

  beforeEach(() => {
    TestBed.configureTestingModule({});
    service = TestBed.inject(HistoryExperimentoService);
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });
});
