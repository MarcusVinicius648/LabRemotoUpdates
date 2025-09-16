import { Component, OnInit } from '@angular/core';
import { TokenService } from './services/token.service';
import { Router } from '@angular/router';

@Component({
  selector: 'app-root',
  templateUrl: './app.component.html',
  styleUrls: ['./app.component.css']
})
export class AppComponent implements OnInit {
  title = 'labremoto-front';
  usuario: String;
  menuCollapsed = false;

  constructor(private tokenService: TokenService, private router: Router) {
  }

  ngOnInit() {
    if (this.tokenService.getToken() == null || this.tokenService.getToken() == "undefined") {
      this.router.navigateByUrl('/login');
      this.usuario = null;
    } else {
      this.usuario = this.tokenService.getToken();
    }

  }

  toggleMenu($event) {
    this.menuCollapsed = !this.menuCollapsed;
  }

}
