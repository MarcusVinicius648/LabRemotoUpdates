import { Component, OnInit, Output, EventEmitter } from '@angular/core';
import { RouterModule } from '@angular/router';
import { TokenService } from 'app/services/token.service';

@Component({
  selector: 'app-menu',
  templateUrl: './menu.component.html',
  styleUrls: ['./menu.component.css']
})
export class MenuComponent implements OnInit {

  collapse = false;
  @Output() toggleMenu = new EventEmitter();
  usuario = {
    nome: null,
    matricula: null
  }
  itens = [
    { label: 'Início', route: '/' },
    { label: 'Meus Experimentos', route: '/historico' },
    { label: 'Agenda', route: '/agenda' },
    { label: 'Sair', route: '/wonderwall/logout' },
  ];
  constructor(private router: RouterModule, private tokenService: TokenService) { }

  ngOnInit() {
    this.usuario.matricula = this.tokenService.getMatricula();
    this.usuario.nome = this.tokenService.getNome();
    console.log(this.usuario)
  }

  toggleCollapse() {
    this.collapse = !this.collapse;    
    this.toggleMenu.emit(this.collapse);
  }
}
