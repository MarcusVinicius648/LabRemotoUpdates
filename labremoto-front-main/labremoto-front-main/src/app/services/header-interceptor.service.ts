import { Observable } from 'rxjs';
import { TokenService } from './token.service';
import { Injectable, Injector } from '@angular/core';
import { HttpEvent, HttpInterceptor, HttpHandler, HttpRequest, HttpErrorResponse, HttpResponse, HttpClient } from '@angular/common/http';
import 'rxjs/add/observable/throw';
import 'rxjs/add/operator/catch';
import 'rxjs/add/operator/do';
import { Router } from '@angular/router';
import { ToastrService } from 'ngx-toastr';
import { environment } from 'environments/environment';


@Injectable()
export class HeaderInterceptorService implements HttpInterceptor {

  constructor(private token: TokenService, private router: Router,private toastr: ToastrService, private httpClient: HttpClient) { }
  intercept(req: HttpRequest<any>, next: HttpHandler): Observable<HttpEvent<any>> {
    if (typeof (this.token.getToken()) === 'undefined' || this.token.getToken() === null) {

      if (this.checkUrl(req.url)) {
        localStorage.clear();
        window.location.href = environment.BASE_REF;
        this.router.navigateByUrl(`/login`);
        return Observable.throw('Sem token de autenticação.');
      }
    }
    
    const newReq = req.clone({
      setHeaders: {
        Authorization: `Bearer ${this.token.getToken()}`
      }
    });

    return next.handle(newReq);

  }
  private handleError(err: any): Observable<any> {
    if (err instanceof HttpErrorResponse) {
      if (err.status === 401) {
        this.router.navigateByUrl(`/login`);
        return Observable.throw(err);
      } else if (err.status === 206) {
        console.log('ERRO 206');
      } else if (err.status === 500) {
        console.log('ERRO 500');
      } else if (err.status === 0) {
        setTimeout(() => {
          this.toastr
            .error(
              'Não foi possível se conectar ao servidor, verifique seu acesso à internet.',
              `Falha de conexão`,
              {
                positionClass: 'toast-top-center',
                progressBar: true,
                timeOut: 20000,
                closeButton: true
              })
            .onHidden.subscribe(resp => {
              // this.router.navigateByUrl(`/`);
              console.log('erro');
            });
        }, 300);
      } else if (err.status === 409) {
        setTimeout(() => {
          this.toastr
            .error(
              err.error.message,
              `Erro ${err.status}`,
              {
                positionClass: 'toast-top-center',
                progressBar: true,
                disableTimeOut: true,
                enableHtml: true,
                closeButton: true
              })
            .onHidden.subscribe(resp => {
              // this.router.navigateByUrl(`/`);
              console.log('erro');
            });
        }, 300);
      } else {
        setTimeout(() => {
          this.toastr
            .error(
              err.error.message,
              `Erro ${err.status}`,
              {
                positionClass: 'toast-top-center',
                progressBar: true,
                timeOut: 2000,
                closeButton: true
              })
            .onHidden.subscribe(resp => {
              // this.router.navigateByUrl(`/`);
              console.log('erro');
            });
        }, 300);
      }
    }
    // handle your auth error or rethrow
    return Observable.throw(err);
  }

  checkUrl(url) {
    const reg = new RegExp('/login');
    return !reg.test(url);
  }
}
