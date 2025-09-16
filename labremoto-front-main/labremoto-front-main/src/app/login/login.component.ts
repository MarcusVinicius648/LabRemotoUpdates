import { Component, OnInit } from '@angular/core';
import { FormGroup, FormBuilder, FormControl, Validators } from '@angular/forms';
import { LoginDTO } from './dto/login-dto';
import { LoginService } from './services/login.service';
import { TokenService } from 'app/services/token.service';
import { Router } from '@angular/router';

@Component({
  selector: 'app-login',
  templateUrl: './login.component.html',
  styleUrls: ['./login.component.css']
})
export class LoginComponent implements OnInit {

  loginForm: FormGroup;
  loginDTO: LoginDTO = new LoginDTO();
  errMessage = null;
  constructor( private loginService: LoginService, private tokenService: TokenService, private router: Router) { }

  ngOnInit() {
    this.loginForm = new FormGroup({
      login: new FormControl('', Validators.required),
      password: new FormControl('', Validators.required)
    });
  }

  authUser() {
      this.loginDTO = this.loginForm.value;
      this.loginService.authUser(this.loginDTO).subscribe((resp: any) => {
        if( typeof( resp.token ) !== 'undefined' && resp.token !== '' ) {
          this.router.navigateByUrl(`wonderwall/${resp.token}`);
        }

      }, (err: any) => {
        console.log(err);
        this.errMessage = err.error.error; 

      });
  }
}
