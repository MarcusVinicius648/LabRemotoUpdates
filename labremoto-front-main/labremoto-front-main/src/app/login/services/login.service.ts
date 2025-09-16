import { environment } from 'environments/environment';
import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
@Injectable()
export class LoginService {

  constructor(private _http: HttpClient) { }

  authUser(dto: any) {
    return this._http.post(environment.URLS.login, dto);
  }
}
