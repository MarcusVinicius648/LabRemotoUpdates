import { Component, OnInit } from '@angular/core';
import { HistoryService } from '../history.service';
import { HistoryExperimento } from '../dto/history-experimento';
import { ExperimentoService } from 'app/experimento/experimento.service';

@Component({
  selector: 'app-history-list',
  templateUrl: './history-list.component.html',
  styleUrls: ['./history-list.component.css']
})
export class HistoryListComponent implements OnInit {

  experimentos: HistoryExperimento[] = [];

  constructor(private historyService: HistoryService) { }

  ngOnInit() {
    this.historyService.getHistoricoList().subscribe((resp: any[]) => {
      resp.forEach((exp) => {
        const expObj = new HistoryExperimento();
        expObj.build(exp[0], exp[1], exp[2], exp[4], exp[5]);
        this.experimentos.push(expObj);
      });
    });
  }

}
