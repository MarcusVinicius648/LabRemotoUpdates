import { Component, OnInit, ViewChild, ElementRef, AfterViewInit } from '@angular/core';
import { HistoryExperimentoService } from './history-experimento.service';
import { Route, Router, ActivatedRoute } from '@angular/router';
import { LaboratorioService } from 'app/services/laboratorio.service';
import { ExperimentoService } from 'app/experimento/experimento.service';

@Component({
  selector: 'app-history-experimento',
  templateUrl: './history-experimento.component.html',
  styleUrls: ['./history-experimento.component.css']
})
export class HistoryExperimentoComponent implements OnInit, AfterViewInit {

  experimento: any;
  experimentoResultados = [];
  experimentoParametros: any;
  experimentoInstrucoes: any;
  drawOptionsArr = [true, true, true, true];
  @ViewChild('canvasContainer', { static: false, read: ElementRef })
  canvasContainer: ElementRef;
  @ViewChild('graphContainer', { static: false, read: ElementRef })
  graphContainer: ElementRef;
  @ViewChild('graphCanvas', { static: false, read: ElementRef })
  canvas: ElementRef<HTMLCanvasElement>;
  private graph: CanvasRenderingContext2D;

  multi: any[];
  view: any[] = [0, 0];

  // Opções do gráfico
  legend: boolean = false;
  showLabels: boolean = true;
  animations: boolean = true;
  xAxis: boolean = true;
  yAxis: boolean = true;
  showYAxisLabel: boolean = true;
  showXAxisLabel: boolean = true;
  xAxisLabel: string = 'Tempo';
  yAxisLabel: string = 'Valor';
  timeline: boolean = true;

  // Opções CSV
  csvOptions = {
    fieldSeparator: ',',
    quoteStrings: '"',
    decimalseparator: '.',
    showLabels: true,
    headers: [],
    showTitle: false,
    title: '',
    useBom: false,
    removeNewLines: true,
    keys: ['time', 'linearVel', 'angularVel', 'posX', 'posY', 'goalX', 'goalY', 'linearError', 'angularError']
  };

  csvData = [];


  colorScheme = {
    domain: ['#5AA454', '#E44D25', '#CFC0BB', '#7aa3e5', '#a8385d', '#aae3f5']
  };

  constructor(private service: HistoryExperimentoService,
    private experimentoService: ExperimentoService,
    private route: ActivatedRoute) {
  }

  ngAfterViewInit() {
    this.graph = this.canvas.nativeElement.getContext('2d');
    this.canvas.nativeElement.width = this.canvasContainer.nativeElement.clientWidth - 45;
    this.canvas.nativeElement.height = (9 / 16) * (this.canvasContainer.nativeElement.clientWidth - 45);
    this.view[0] = this.graphContainer.nativeElement.clientWidth - 50;
    this.view[1] = (5 / 16) * (this.graphContainer.nativeElement.clientWidth - 50);
  }
  ngOnInit() {
    this.route.params.subscribe(params => {
      this.loadExperimento(params.codigo);
    });
  }

  loadExperimento(codigo: number) {
    this.service.getExperimentoById(codigo).subscribe((resp: any) => {
      this.experimento = resp;

      if (this.experimento.codExperimento == 2) {
        this.experimentoService.getExperimentoInstrucoes(codigo).subscribe((resp2: any) => {
          this.experimentoInstrucoes = resp2;
        });
      }


      this.experimentoService.getExperimentoParametros(codigo).subscribe((resp: any) => {
        this.experimentoParametros = resp;
        if (this.experimento.codExperimento == 1) {
          this.experimentoParametros.estatisticasBusca = JSON.parse(this.experimentoParametros.estatisticasBusca);
          this.drawCanvas();
        } else {
          this.drawCanvas();
        }
      });

    });
    this.experimentoService.getExperimentoResultados(codigo).subscribe((resp: any) => {
      this.experimentoResultados = resp;
      this.loadExperimentoGraphCsv();
    });
  }



  graphClick(event: any) {
    const offsetX = event.offsetX;
    const offsetY = event.offsetY;

    const height = this.canvas.nativeElement.offsetHeight;
    const width = this.canvas.nativeElement.offsetWidth;

    const cameraHeight = 720;
    const cameraWidth = 1280;

    const x = Math.floor((offsetX * cameraWidth) / width);
    const y = Math.floor((offsetY * cameraHeight) / height);


  }

  drawCanvas() {
    // Define a resolucao correta do grafico
    const fatorMapa = (this.canvas.nativeElement.width * this.experimentoParametros.tamanhoMapaBusca) / 1280;
    const fatorMapaReal = (this.canvas.nativeElement.width) / 1280
    this.graph.clearRect(0, 0, this.canvas.nativeElement.width, this.canvas.nativeElement.height);
    this.graph.beginPath();
    if (this.drawOptionsArr[0] === true) {
      this.graph.strokeStyle = 'red';
      for (const pathItem of this.experimentoResultados) {
        this.graph.arc(pathItem.posX * fatorMapaReal, pathItem.posY * fatorMapaReal, 3, 0, 2 * Math.PI);
        this.graph.stroke();
      }
      this.graph.font = '15px Arial';
      this.graph.fillText('Início', (this.experimentoResultados[0].posX * fatorMapaReal) + 25, (this.experimentoResultados[0].posY * fatorMapaReal) +5);
      this.graph.fillText('Fim', (this.experimentoResultados[this.experimentoResultados.length - 1].posX * fatorMapaReal) + 25, (this.experimentoResultados[this.experimentoResultados.length - 1].posY * fatorMapaReal) +5);

    }
    this.graph.closePath();
    this.graph.beginPath();
    if (this.drawOptionsArr[1] === true && this.experimentoParametros.estatisticasBusca != null) {
      this.graph.strokeStyle = 'blue';
      for (const pathItem of this.experimentoParametros.estatisticasBusca.path) {
        this.graph.arc(pathItem[0] * fatorMapa, pathItem[1] * fatorMapa, 1, 0, 2 * Math.PI);
        this.graph.stroke();
      }
    }

    if (this.drawOptionsArr[2] === true && this.experimentoParametros.estatisticasBusca != null) {
      this.graph.fillStyle = '#000000';
      for (const x in this.experimentoParametros.estatisticasBusca.map) {
        for (const y in this.experimentoParametros.estatisticasBusca.map[x]) {
          if (this.experimentoParametros.estatisticasBusca.map[x][y] == (parseInt(this.experimentoParametros.tamanhoAreaSeguranca) + 1))
            this.graph.fillRect(parseInt(x) * fatorMapa, parseInt(y) * fatorMapa, 1 * 2, 1);
        }
      }
    }

    if (this.drawOptionsArr[3] === true && this.experimentoParametros.estatisticasBusca != null) {
      this.graph.fillStyle = '#999999';
      for (const x in this.experimentoParametros.estatisticasBusca.map) {
        for (const y in this.experimentoParametros.estatisticasBusca.map[x]) {
          if (this.experimentoParametros.estatisticasBusca.map[x][y] > 0 && this.experimentoParametros.estatisticasBusca.map[x][y] != (parseInt(this.experimentoParametros.tamanhoAreaSeguranca) + 1))
            this.graph.fillRect(parseInt(x) * fatorMapa, parseInt(y) * fatorMapa, 1 * 2, 1);
        }
      }
    }
  }

  drawOptions(index: number) {
    this.drawOptionsArr[index] = !this.drawOptionsArr[index];
    this.drawCanvas();

  }


  loadExperimentoGraphCsv() {
    this.multi = [
      {
        name: "Erro Linear (x100)",
        series: []
      },
      {
        name: "Erro Angular (rad)",
        series: []
      },
      {
        name: "Vel. Linear",
        series: []
      },
      {
        name: "Vel. Angular",
        series: []
      }
    ]
    this.experimentoResultados.forEach(resultado => {
      const rho = Math.sqrt((resultado.data.objetivoX - resultado.posX) ** 2 + (resultado.data.objetivoY - resultado.posY) ** 2);
      const timestamp = (new Date(resultado.dtCriacao).getTime() - new Date(resultado.startTime).getTime()) / 1000;
      if (resultado.data.angularError == null || isNaN(resultado.data.angularError)) {
        resultado.data.angularError = 0;
      }
      this.multi[0].series.push(
        {
          "name": timestamp,
          "value": resultado.data.linearError / 100
        }
      );
      this.multi[1].series.push(
        {
          "name": timestamp,
          "value": resultado.data.angularError
        }
      );
        this.multi[2].series.push(
          {
            "name": timestamp,
            "value": resultado.linearVel
          }
        );
      this.multi[3].series.push(
        {
          "name": timestamp,
          "value": resultado.angularVel
        }
      );

      const csvRow = {
        time: timestamp,
        linearVel: resultado.linearVel,
        angularVel: resultado.angularVel,
        posX: resultado.posX,
        posY: resultado.posY,
        goalX: resultado.data.objetivoX,
        goalY: resultado.data.objetivoY,
        linearError: rho,
        angularError: resultado.data.angularError
      }
      this.csvData.push(csvRow);

    });
  }

  onSelect(data): void {
    console.log('Item clicked', JSON.parse(JSON.stringify(data)));
  }

  onActivate(data): void {
    console.log('Activate', JSON.parse(JSON.stringify(data)));
  }

  onDeactivate(data): void {
    console.log('Deactivate', JSON.parse(JSON.stringify(data)));
  }
}
