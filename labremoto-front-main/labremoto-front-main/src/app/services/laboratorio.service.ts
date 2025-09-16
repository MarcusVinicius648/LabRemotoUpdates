import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { environment } from 'environments/environment';

@Injectable()
export class LaboratorioService {


  constructor(private http: HttpClient) {
  }

  findSessaoAtiva() {
    return this.http.get(environment.URLS.sessaoAtiva);
  }

  getLaboratorioStatus() {
    return this.http.get(environment.URLS.laboratorioStatus);
  }

  startSession() {
    return this.http.post(environment.URLS.startSession, null, { observe: 'response' });
  }

}
