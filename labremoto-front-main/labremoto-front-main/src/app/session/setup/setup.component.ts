import { LaboratorioService } from './../../services/laboratorio.service';
import { Component, OnInit } from '@angular/core';
import { Router } from '@angular/router';

@Component({
  selector: 'app-setup',
  templateUrl: './setup.component.html',
  styleUrls: ['./setup.component.css']
})
export class SetupComponent implements OnInit {

  laboratorioAtivo: any = null;

  constructor(private laboratorioService: LaboratorioService, private router: Router) { }

  ngOnInit() {
    this.laboratorioService.findSessaoAtiva().subscribe((resp: any) => {
      this.laboratorioAtivo = resp;
      console.log(this.laboratorioAtivo);
      if (this.laboratorioAtivo != null && this.laboratorioAtivo.ativo == 1) {
        this.router.navigateByUrl("/");
      }    })
  }

  startSession() {
    this.laboratorioService.startSession().subscribe((resp: any) => {
      if(resp.body != null && resp.body.ativo === true) {
        this.router.navigateByUrl("/experimento");
      }


    }, (err: any) => {

    });
  }

}
