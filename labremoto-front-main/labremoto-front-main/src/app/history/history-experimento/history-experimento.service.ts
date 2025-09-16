import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { environment } from 'environments/environment';

@Injectable({
  providedIn: 'root'
})
export class HistoryExperimentoService {

  constructor(private http: HttpClient) { }

  getExperimentoById(id: number) {
    return this.http.get(environment.URLS.experimentoId + '&codigo=' + id)
  }
}
