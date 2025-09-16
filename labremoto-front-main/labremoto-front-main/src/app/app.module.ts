import { AgendaModule } from './calendar/Agenda.module';
import { HistoryModule } from './history/history.module';
import { SessionModule } from './session/session.module';
import { LaboratorioService } from './services/laboratorio.service';
import { MainPageModule } from './main-page/main-page.module';
import { WonderwallComponent } from './wonderwall/wonderwall.component';
import { LoginService } from './login/services/login.service';
import { BrowserModule } from '@angular/platform-browser';
import { NgModule, LOCALE_ID } from '@angular/core';
import { NgHttpLoaderModule } from 'ng-http-loader';
import { AppRoutingModule } from './app-routing.module';
import { AppComponent } from './app.component';
import { LoginModule } from './login/login.module';
import { SharedDataService } from './services/SharedDataService';
import { HeaderInterceptorService } from './services/header-interceptor.service';
import { HttpClientModule, HttpClient, HTTP_INTERCEPTORS } from '@angular/common/http';
import { JwtModule } from '@auth0/angular-jwt';
import { TokenService } from './services/token.service';
import { Router } from '@angular/router';
import { ToastrService, ToastrModule } from 'ngx-toastr';
import { environment } from 'environments/environment';
import { MenuComponent } from './menu/menu.component';
import ptBr from '@angular/common/locales/pt';
import { registerLocaleData } from '@angular/common';
import { ExperimentoModule } from './experimento/experimento.module';
import { BrowserAnimationsModule } from '@angular/platform-browser/animations';
import { CalendarModule, DateAdapter } from 'angular-calendar';
import { adapterFactory } from 'angular-calendar/date-adapters/date-fns';
import { NgxMatNativeDateModule } from '@angular-material-components/datetime-picker';

registerLocaleData(ptBr);
export function tokenGetter() {
  return localStorage.getItem('token');
}


@NgModule({
  declarations: [
    AppComponent,
    WonderwallComponent,
    MenuComponent
  ],
  imports: [
    BrowserModule,
    LoginModule,
    HttpClientModule,
    HistoryModule,
    AgendaModule,
    SessionModule,
    MainPageModule,
    NgHttpLoaderModule.forRoot(),
    ExperimentoModule,
    ToastrModule.forRoot(),
    BrowserAnimationsModule,
    NgxMatNativeDateModule,
    AppRoutingModule,
     JwtModule.forRoot({
      config: {
        tokenGetter: tokenGetter,
        whitelistedDomains: [ environment.BASE_REF ],
        blacklistedRoutes: [ `${environment.BASE_REF}/login`],
        skipWhenExpired: true
      }
    }),
     CalendarModule.forRoot({ provide: DateAdapter, useFactory: adapterFactory })
  ],
  providers: [SharedDataService, LoginService, TokenService, LaboratorioService,
    ToastrService,
    { provide: LOCALE_ID, useValue: 'pt-PT' },
    {
      provide: HTTP_INTERCEPTORS,
      useFactory: function(token: TokenService, router: Router, toastr: ToastrService, http: HttpClient) {
          return new HeaderInterceptorService(token, router, toastr, http);
      },
      multi: true,
      deps: [TokenService, Router, ToastrService, HttpClient]
    },],
  bootstrap: [AppComponent]
})
export class AppModule { }
