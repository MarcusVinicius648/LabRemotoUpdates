import {Injectable} from '@angular/core';

@Injectable()
export class TokenService {

  private token: string = null;

  constructor() {
  }

  setToken(token: string): void {
    this.token = token;
    localStorage.setItem('token', token);
  }

  getToken() {
    return this.token !== null ?
      this.token :
      localStorage.getItem('token');
  }

  parseToken() {
    const _token = this.getToken();
    if (_token == null) {
      return null;
    }
    if ( typeof (_token ) == 'undefined') {
      return null;
    }
    const token = _token.split('.');
    try {
      return atob(token[1]);
    } catch (e) {
      return null;
    }
  }

  getMatricula() {
    const token = this.parseToken();
    if (token === null) {
      return null;
    }
    const obj = JSON.parse(token);
    return obj.data.matricula;
  }

  getNome() {
    const token = this.parseToken();
    if (token === null) {
      return null;
    }
    const obj = JSON.parse(token);
    console.log(obj);
    return obj.data.nome;
  }

}
