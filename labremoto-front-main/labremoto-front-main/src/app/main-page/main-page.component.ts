import { LaboratorioService } from './../services/laboratorio.service';
import { Component, OnInit } from '@angular/core';
import { RouterModule, ActivatedRoute, Router } from '@angular/router';
import { TokenService } from '../services/token.service';

@Component({
  selector: 'app-main-page',
  templateUrl: './main-page.component.html',
  styleUrls: ['./main-page.component.css']
})
export class MainPageComponent implements OnInit {

  constructor(private laboratorioService: LaboratorioService,
    private router: Router,
    private tokenService: TokenService) { }

  laboratorioAtivo: any = null;

  ngOnInit() {
    this.laboratorioService.getLaboratorioStatus().subscribe((resp: any) => {
      if (resp == true) {
        this.laboratorioService.findSessaoAtiva().subscribe((resp2: any) => {
          if (resp2 === null || resp2 === []) {
            this.laboratorioAtivo = null;
            return;
          } else {
            this.laboratorioAtivo = resp2;
            if (this.laboratorioAtivo.matricula == this.tokenService.getMatricula()) {
              this.router.navigateByUrl("/experimento");
            }
          }
        });
      } else {
        this.laboratorioAtivo = null;
        this.laboratorioService.findSessaoAtiva().subscribe((resp2: any) => {
          if (resp2 === null || resp2 === []) {
            return;
          } else {
            this.laboratorioAtivo = resp2;
            if (resp2.matricula == this.tokenService.getMatricula()) {
              this.router.navigateByUrl("/experimento");
            }
          }
        });
      }
      this.laboratorioAtivo = resp;
      if (this.laboratorioAtivo.matricula == this.tokenService.getMatricula()) {
        this.router.navigateByUrl("/experimento");
      }
    })

  }

}
