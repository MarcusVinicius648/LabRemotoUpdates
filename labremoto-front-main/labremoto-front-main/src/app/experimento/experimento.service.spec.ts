import { TestBed } from '@angular/core/testing';

import { ExperimentoService } from './experimento.service';

describe('ExperimentoService', () => {
  beforeEach(() => TestBed.configureTestingModule({}));

  it('should be created', () => {
    const service: ExperimentoService = TestBed.get(ExperimentoService);
    expect(service).toBeTruthy();
  });
});
