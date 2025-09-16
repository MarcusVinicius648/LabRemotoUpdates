import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { environment } from 'environments/environment';
import { ParametrosExperimentoRequest } from './entities/parametrosExperimentoRequest';
import { InstrucaoTrajetoria } from './entities/instrucaoTrajetoria';

@Injectable({
  providedIn: 'root'
})
export class ExperimentoService {

  constructor(private http: HttpClient) { }

  getEv3Data(currentTimestamp: number, timeStamp: number) {
    return this.http.get(environment.URLS.ev3Data + '?' + currentTimestamp + '-' + timeStamp);
  }

  getExperimentos() {
    return this.http.get(environment.URLS.getExperimentos);
  }

  startExperimento(codigo: number) {
    return this.http.post(environment.URLS.setExperimento, { codigo: codigo }, { observe: 'response' });
  }

  getExperimentoAtivo() {
    return this.http.get(environment.URLS.getExperimentoAtivo);
  }

  getExperimentoParametros(codigo: number) {
    return this.http.get(environment.URLS.experimentoParametros + "&codigo=" + codigo);
  }

  setExperimentoParametros(parametros: ParametrosExperimentoRequest) {
    return this.http.post(environment.URLS.experimentoParametros, parametros, { observe: "response" });
  }

  setExperimentoInstrucoes(instrucoes: InstrucaoTrajetoria[]) {
    return this.http.post(environment.URLS.experimentoInstrucoes, instrucoes, { observe: 'response' });
  }

  getExperimentoInstrucoes(codigo: number) {
    return this.http.get(environment.URLS.experimentoInstrucoes + "&codigo=" + codigo);
  }

  setApontarGoals(goals: any) {
    return this.http.post(environment.URLS.experimentoGoals, goals, { observe: "response" });
  }

  setStatusExperimento(status: any) {
    return this.http.post(environment.URLS.experimentoStatus, { status: status }, { observe: "response" });
  }

  getExperimentoResultados(codigo: number) {
    return this.http.get(environment.URLS.experimentoResultados + "&codigo=" + codigo);
  }

  encerrarExperimento() {
    return this.http.get(environment.URLS.encerrarExperimento);
  }

  setTeleoperacao(status: number) {
    return this.http.post(environment.URLS.teleoperacao, { status: status }, { observe: "response" });
  }

  addTeleoperacaoInstrucao(instrucao: number) {
    return this.http.post(environment.URLS.teleoperacaoInstrucao, { instrucao: instrucao }, { observe: "response" });
  }
}
