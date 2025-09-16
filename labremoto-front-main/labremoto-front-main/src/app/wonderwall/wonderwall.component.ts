import { environment } from '../../environments/environment';
import { Router, ActivatedRoute, NavigationExtras } from '@angular/router';
import { Component, OnInit } from '@angular/core';
import { TokenService } from '../services/token.service';
import { SharedDataService } from '../services/SharedDataService';

@Component({
  template: '',
  selector: 'app-wonderwall',
})
export class WonderwallComponent implements OnInit {

  private token = '';
  constructor(
    private tokenService: TokenService,
    private router: Router,
    private route: ActivatedRoute,
    private sharedDataService: SharedDataService ) {
    this.route.params.subscribe(params => {
      this.token = params.token;
      if(this.token === 'logout') {
        localStorage.removeItem('token');
        window.location.href = '/'
        return;
      }
      this.tokenService.setToken(this.token);
      localStorage.setItem('token', this.token);
      window.location.href = '/'
    });
  }

  ngOnInit() {

  }

}
