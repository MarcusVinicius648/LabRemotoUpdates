export class HistoryExperimento {
    codigo: number;
    codSessao: number;
    codExperimento: number;
    dtInicio: Date;
    label: String;

    build(codigo, codSessao, codExperimento, dtInicio, label) {
        this.codigo = codigo;
        this.codSessao = codSessao;
        this.codExperimento = codExperimento;
        this.dtInicio = dtInicio;
        this.label = label;
    }
}