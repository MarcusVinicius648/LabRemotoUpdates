import { Component, OnInit, OnDestroy, ViewChild, ElementRef, AfterViewInit } from '@angular/core';
import { LaboratorioService } from 'app/services/laboratorio.service';
import { Router } from '@angular/router';
import { TokenService } from 'app/services/token.service';
import { environment } from 'environments/environment';
import { ExperimentoService } from './experimento.service';
import { Ev3Data } from './entities/ev3data';
import { FormBuilder, FormGroup, FormControl, Validators } from '@angular/forms';
import { ParametrosExperimentoRequest } from './entities/parametrosExperimentoRequest';
import { ToastrService } from 'ngx-toastr';
import { InstrucaoTrajetoria } from './entities/instrucaoTrajetoria';
import { Observable } from 'rxjs/Observable';
import 'rxjs/add/observable/fromEvent';

declare var jquery: any;
declare var $: any;

@Component({
  selector: 'app-experimento',
  templateUrl: './experimento.component.html',
  styleUrls: ['./experimento.component.css']
})
export class ExperimentoComponent implements OnInit, OnDestroy {

  // URLs das câmeras
  cameraVideoUrl;
  mapeamentoVideoUrl;
  trajetoriaVideoUrl;

  // Dados do usuário
  user: any = null;

  // Dados da Sessão e Experimento
  sessaoAtiva: any = null;
  sessionCountdown = null;
  currentExperimento = null;
  currentExperimentoInstrucoes = [];
  apontar = { // Posição a ser apontada
    goalX: 0,
    goalY: 0
  }
  experimentoRunStatus = 0;
  // Dados recebidos do ev3
  ev3Data: Ev3Data = new Ev3Data();
  experimentoResultados: any[] = [];

  // Teleoperacao
  teleoperacao = false;

  // Listas
  experimentos = [];

  // Timestamp de recuperação dos dados
  cameraTimestamp = 0;
  currentTimestamp: any;

  // Intervalos de checagem
  interval;
  intervalResults;
  intervalSessao;
  refreshTime = 50;

  // Variáveis de formulário e controle da página
  experimentoParametroForm: FormGroup;
  parametrosSalvosErr = false;
  parametrosSalvosOk = false;
  expInstrucaoForm: FormGroup;
  cameraNavTab = 1;
  @ViewChild('cameraWrap') cameraWrapEl: ElementRef;

  constructor(private labolatorioService: LaboratorioService,
    private tokenService: TokenService,
    private toastrService: ToastrService,
    private experimentoService: ExperimentoService,
    private formBuilder: FormBuilder,
    private router: Router) { }

  ngOnDestroy() {
    clearInterval(this.interval);
    clearInterval(this.intervalResults);
    clearInterval(this.intervalSessao);
  }

  ngOnInit() {
    this.updateExperimentoData();
    this.interval = setInterval(() => { this.updateExperimentoData(); }, this.refreshTime);
    this.intervalResults = setInterval(() => { this.getExperimentoResults(); }, 3000);
    this.intervalSessao = setInterval(() => { this.checkSessaoAtiva(); }, 3000);
    this.cameraVideoUrl = environment.URLS.cameraImg;
    this.trajetoriaVideoUrl = environment.URLS.trajetoriaImg;
    this.mapeamentoVideoUrl = environment.URLS.mapeamentoImg;
    this.currentTimestamp = + new Date();
    this.getSessaoAtiva();

  }

  updateRefreshTime() {
    clearInterval(this.interval);
    this.interval = setInterval(() => { this.updateExperimentoData(); }, this.refreshTime);
  }

  checkSessaoAtiva() {
    if (this.sessaoAtiva == null || this.sessaoAtiva == undefined) {
      return;
    }

    this.labolatorioService.findSessaoAtiva().subscribe((resp: any) => {
      if (resp == null || resp == undefined || resp.ativo === 0 || resp.matricula != this.tokenService.getMatricula()) {
        this.router.navigateByUrl("/");
      } else {
        if (resp.codigo != this.sessaoAtiva.codigo) {
          this.router.navigateByUrl("/");
        }
      }

    });

  }

  getSessaoAtiva() {
    this.labolatorioService.findSessaoAtiva().subscribe((resp: any) => {
      if (resp == null || resp == undefined || resp.ativo === 0 || resp.matricula != this.tokenService.getMatricula()) {
        this.router.navigateByUrl("/");
      } else {
        this.sessaoAtiva = resp;
        this.sessaoAtiva.dtFim = new Date(resp.dtFim);
        const now = new Date();
        let countDown = Math.floor((this.sessaoAtiva.dtFim.getTime() - now.getTime()) / 1000);


        this.sessionCountdown = {
          leftTime: countDown
        }
        this.user = this.tokenService.getNome();
        this.getExperimentoAtivo();
      }
    });
  }

  getCameraImage() {
    return this.cameraVideoUrl + '?t' + this.currentTimestamp + '-' + this.cameraTimestamp;
  }

  getMapeamentoImage() {
    return this.mapeamentoVideoUrl + '?t' + this.currentTimestamp + this.cameraTimestamp;
  }

  getTrajetoriaImage() {
    return this.trajetoriaVideoUrl + '?t' + this.currentTimestamp + this.cameraTimestamp;
  }

  updateExperimentoData() {
    this.cameraTimestamp++;
    this.getEv3Data()
  }

  getEv3Data() {
    this.experimentoService.getEv3Data(this.currentTimestamp, this.cameraTimestamp).subscribe((resp: Ev3Data) => {
      this.ev3Data = resp;
      if (this.ev3Data.running == 1) {
        this.experimentoRunStatus = 2;
      } else if (this.ev3Data.running == 2) {
        this.router.navigateByUrl("/experimento/" + this.currentExperimento.codigo);
      }
      else {
        if (this.experimentoRunStatus == 2) {
          this.experimentoRunStatus = 0;
          this.toastrService.error('Seu experimento falhou.', 'Erro');
          this.getExperimentoAtivo();
        }
      }
    });
  }

  openNewExperimentoModal() {
    $('#novoExperimentoModal').modal('show');
    this.experimentoService.getExperimentos().subscribe((resp: any) => {
      this.experimentos = resp;
    });
  }

  startExperimento(codigo: number) {
    if (isNaN(codigo)) {
      return;
    }

    this.experimentoService.startExperimento(codigo).subscribe((resp: any) => {
      if (resp.status === 200) {
        window.location.reload();
      }

    }, (err: any) => {

    });

  }

  getExperimentoAtivo() {
    this.experimentoService.getExperimentoAtivo().subscribe((resp: any) => {
      this.currentExperimento = resp;
      if (resp != null) {
        this.experimentoParametroForm = this.formBuilder.group(
          {
            tipoControlador: new FormControl(1),
            algoritmoBusca: new FormControl(1),
            heuristica: new FormControl(1, Validators.required),
            mapScale: new FormControl(5, Validators.required),
            safeScale: new FormControl(5, Validators.required),
            obstaculos: new FormControl(true, Validators.required),
            kp: new FormControl(0, Validators.required),
            kd: new FormControl(0, Validators.required),
            ki: new FormControl(0, Validators.required),
            kp_ang: new FormControl(0, Validators.required),
            kd_ang: new FormControl(0, Validators.required),
            ki_ang: new FormControl(0, Validators.required),
          }
        );
        this.getExperimentoParametros();
        if (resp.codExperimento == 2) {
          this.getExperimentoInstrucoes();
        }
      } else {
        this.currentExperimento = null;
      }
    })
  }

  getExperimentoParametros() {
    if (this.currentExperimento == null) {
      return;
    }

    this.experimentoService.getExperimentoParametros(this.currentExperimento.codigo).subscribe((resp: any) => {
      this.experimentoParametroForm.get("obstaculos").setValue(Boolean(resp.obstaculos));
      this.experimentoParametroForm.get("kp").setValue(resp.kp);
      this.experimentoParametroForm.get("ki").setValue(resp.ki);
      this.experimentoParametroForm.get("kd").setValue(resp.kd);
      if (parseInt(this.currentExperimento.codExperimento) === 1) {
        this.experimentoParametroForm.get("kp_ang").setValue(resp.kp_ang);
        this.experimentoParametroForm.get("ki_ang").setValue(resp.ki_ang);
        this.experimentoParametroForm.get("kd_ang").setValue(resp.kd_ang);
        this.experimentoParametroForm.get("tipoControlador").setValue(resp.tipoControlador);
        this.experimentoParametroForm.get("algoritmoBusca").setValue(resp.algoritmoBusca);
        this.experimentoParametroForm.get("heuristica").setValue(resp.heuristica);
        this.experimentoParametroForm.get("mapScale").setValue(resp.tamanhoMapaBusca);
        this.experimentoParametroForm.get("safeScale").setValue(resp.tamanhoAreaSeguranca);
      }
    });

  }

  salvarParametrosExperimento() {
    const parametrosRequest = new ParametrosExperimentoRequest();
    if (parseInt(this.currentExperimento.codExperimento) === 1) {
      parametrosRequest.objetivoX = this.apontar.goalX;
      parametrosRequest.objetivoY = this.apontar.goalY;
      parametrosRequest.tipoControlador = this.experimentoParametroForm.get("tipoControlador").value;
      parametrosRequest.algoritmoBusca = this.experimentoParametroForm.get("algoritmoBusca").value;
      parametrosRequest.safeScale = this.experimentoParametroForm.get("safeScale").value;
      parametrosRequest.heuristica = this.experimentoParametroForm.get("heuristica").value;
      parametrosRequest.mapScale = this.experimentoParametroForm.get("mapScale").value;
      parametrosRequest.kp_ang = this.experimentoParametroForm.get("kp_ang").value;
      parametrosRequest.ki_ang = this.experimentoParametroForm.get("ki_ang").value;
      parametrosRequest.kd_ang = this.experimentoParametroForm.get("kd_ang").value;
    } else {
      parametrosRequest.algoritmoBusca = 0
    }

    parametrosRequest.obstaculos = this.experimentoParametroForm.get("obstaculos").value;
    parametrosRequest.kp = this.experimentoParametroForm.get("kp").value;
    parametrosRequest.ki = this.experimentoParametroForm.get("ki").value;
    parametrosRequest.kd = this.experimentoParametroForm.get("kd").value;

    this.experimentoService.setExperimentoParametros(parametrosRequest).subscribe((resp: any) => {
      if (resp.body === true) {
        this.toastrService.success("Parâmetros salvos com sucesso.", "Sucesso");
        this.parametrosSalvosErr = false;
        this.parametrosSalvosOk = true;
      } else {
        this.parametrosSalvosErr = true;
        this.parametrosSalvosOk = false;
      }
    }, (err: any) => {
      this.parametrosSalvosErr = true;
      this.parametrosSalvosOk = false;
    });

  }

  openInstrucoesModal() {
    $('#instrucoesModal').modal('show');
    this.expInstrucaoForm = this.formBuilder.group({
      tipoInstrucao: new FormControl(1),
      velLinear: new FormControl(null),
      velAngular: new FormControl(null),
      rotAngulo: new FormControl(null),
      timer: new FormControl(null)
    });
  }

  resetExpInstrucaoQuant() {
    this.expInstrucaoForm.get("velLinear").setValue(null);
    this.expInstrucaoForm.get("velAngular").setValue(null);
    this.expInstrucaoForm.get("rotAngulo").setValue(null);
  }

  addInstrucaoToArray() {
    const instrucao = new InstrucaoTrajetoria();
    instrucao.tipo = parseInt(this.expInstrucaoForm.get("tipoInstrucao").value);
    switch (instrucao.tipo) {
      case 1:
        instrucao.velLinear = this.expInstrucaoForm.get("velLinear").value;
        instrucao.timer = this.expInstrucaoForm.get("timer").value;
        if (instrucao.velLinear == null || instrucao.timer == null) {
          return;
        }
        break;
      case 2:
        instrucao.velLinear = this.expInstrucaoForm.get("velLinear").value;
        instrucao.velAngular = this.expInstrucaoForm.get("velAngular").value;
        instrucao.timer = this.expInstrucaoForm.get("timer").value;

        if (instrucao.velLinear == null || instrucao.timer == null || instrucao.velAngular == null) {
          return;
        }
        break;
      case 3:
        instrucao.rotAngulo = this.expInstrucaoForm.get("rotAngulo").value;
        instrucao.timer = this.expInstrucaoForm.get("timer").value;
        if (instrucao.rotAngulo == null || instrucao.timer == null) {
          return;
        }
        break;
      case 4:
        instrucao.timer = this.expInstrucaoForm.get("timer").value;
        if (instrucao.timer == null) {
          return;
        }
        break;
    }

    this.currentExperimentoInstrucoes.push(instrucao);
    this.resetExpInstrucaoQuant();
  }

  getTipoInstrucaoLabel(tipo: number) {
    switch (tipo) {
      case 1:
        return "Andar Reto";
      case 2:
        return "Realizar Curva";
      case 3:
        return "Rotacionar";
      case 4:
        return "Parar";
    }
  }

  getTipoInstrucaoValor(instrucao: InstrucaoTrajetoria) {
    switch (instrucao.tipo) {
      case 1:
        return "Vel Linear: " + instrucao.velLinear + "m/s";
      case 2:
        return "Vel Linear: " + instrucao.velLinear + "m/s | Vel Angular: " + instrucao.velLinear + "rad/s";
      case 3:
        let rot = instrucao.rotAngulo;
        parseFloat(rot.toString()).toFixed(2);
        return "Ângulo: " + rot + "º";
      case 4:
        return "-";
    }
  }

  updateInstrucoesExperimento() {
    this.experimentoService.setExperimentoInstrucoes(this.currentExperimentoInstrucoes).subscribe((resp: any) => {
      if (resp.body === true) {
        $('#instrucoesModal').modal('hide');
      }
    });
  }

  getExperimentoInstrucoes() {
    this.experimentoService.getExperimentoInstrucoes(this.currentExperimento.codigo).subscribe((resp: any) => {
      this.currentExperimentoInstrucoes = this.parseInstrucoes(resp);
    });
  }

  parseInstrucoes(instrucoesArr: any) {
    let parsedInstrucoes = [];
    for (let instrucaoBack of instrucoesArr) {
      console.log(instrucaoBack);
      const instrucao = new InstrucaoTrajetoria();
      instrucao.velLinear = instrucaoBack.velLinear;
      instrucao.velAngular = instrucaoBack.velAngular;
      instrucao.timer = instrucaoBack.timer;

      if (instrucao.velLinear == 0 && instrucao.velAngular == 0) {
        instrucao.tipo = 4;
      } else if (instrucao.velAngular == 0) {
        instrucao.tipo = 1;
      } else if (instrucao.velLinear == 0) {
        instrucao.tipo = 3;
        const deltaTheta = instrucao.velAngular * (instrucao.timer / 1000);
        instrucao.rotAngulo = (deltaTheta * (180 / Math.PI));
      } else {
        instrucao.tipo = 2
      }

      parsedInstrucoes.push(instrucao);
    }

    return parsedInstrucoes
  }

  getCameraMouseEvent(event: MouseEvent) {
    const offsetX = event.offsetX;
    const offsetY = event.offsetY;

    const height = this.cameraWrapEl.nativeElement.offsetHeight;
    const width = this.cameraWrapEl.nativeElement.offsetWidth;

    const cameraHeight = 720;
    const cameraWidth = 1280;

    const x = Math.floor((offsetX * cameraWidth) / width);
    const y = Math.floor((offsetY * cameraHeight) / height);

    this.apontar.goalX = x;
    this.apontar.goalY = y;
    if (this.currentExperimento != null && this.currentExperimento.codExperimento == 1) {
      let objetivos = {
        objetivoX: this.apontar.goalX,
        objetivoY: this.apontar.goalY
      }

      this.experimentoService.setApontarGoals(objetivos).subscribe((resp: any) => {

      });
    }
  }

  playExperimento() {
    this.experimentoService.setStatusExperimento(1).subscribe((resp: any) => {
      if (resp.status === 200) {
        this.experimentoRunStatus = 1;
      }

    });

  }

  stopExperimento() {
    this.experimentoService.setStatusExperimento(0).subscribe((resp: any) => {
      if (resp.status === 200) {
        this.experimentoRunStatus = 0;
      }
    });
  }

  changeCameraNavTab(tab: number) {
    this.cameraNavTab = tab;
  }

  getExperimentoResults() {
    //this.getExperimentoAtivo();
    if (this.currentExperimento == null) {
      return;
    }

    this.experimentoService.getExperimentoResultados(this.currentExperimento.codigo).subscribe((resp: any) => {
      this.experimentoResultados = resp;
    });

  }

  finishExperimento() {
    this.experimentoService.encerrarExperimento().subscribe((resp: any) => {
      this.currentExperimento = null;
      this.currentExperimentoInstrucoes = null;
      this.experimentoResultados = [];
      this.experimentoRunStatus = 0;
      this.stopExperimento();
    })
  }

  iniciarTeleoperacao() {
    this.experimentoService.setTeleoperacao(1).subscribe((resp) => {
      this.teleoperacao = true;
    }, (err) => {
      this.teleoperacao = false;
      this.toastrService.error('Não foi possível inicializar a teleoperação', 'Erro');
    });
  }

  finalizarTeleoperacao() {
    this.experimentoService.setTeleoperacao(0).subscribe((resp) => {
      this.teleoperacao = false;
    }, (err) => {
      this.toastrService.error('Não foi possível finalizar a teleoperação a teleoperação', 'Erro');
    });
  }

  teleoperacaoInstrucao(instrucao: number) {
    this.experimentoService.addTeleoperacaoInstrucao(instrucao).subscribe((resp) => {
    }, (err) => {
      this.toastrService.error('Não foi possível adicionar a instrução.', 'Erro');
    });
  }



}
