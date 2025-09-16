export default class URLS {

    constructor() {}
    static env( HOST: string, LOGIN: string, BASE_REF: string, FLASK_REF: string) {
        return {
            laboratorioStatus:                HOST + '/laboratorio/laboratorio-status',
            login:                            HOST + '/login',
            sessaoAtiva:                      HOST + '/laboratorio/sessao-ativa',
            startSession:                     HOST + '/laboratorio/sessao',
            cameraImg:                        FLASK_REF + '/static/imgVideo.jpg',
            mapeamentoImg:                    FLASK_REF + '/static/imgGraph.jpg',
            trajetoriaImg:                    FLASK_REF + '/static/imgTraje.jpg',
            ev3Data:                          FLASK_REF + '/static/ev3data.json',
            getExperimentos:                  HOST + '/laboratorio/experimentos',
            setExperimento:                   HOST + '/laboratorio/experimento',
            experimentoParametros:            HOST + '/laboratorio/experimento-parametros',
            experimentoInstrucoes:            HOST + '/laboratorio/experimento-instrucoes',
            getExperimentoAtivo:              HOST + '/laboratorio/experimento-ativo',
            experimentoGoals:                 HOST + '/laboratorio/experimento-objetivo',
            experimentoStatus:                HOST + '/laboratorio/experimento-status',
            experimentoResultados:            HOST + '/laboratorio/experimento-resultados',
            encerrarExperimento:              HOST + '/laboratorio/encerrar-experimento',
            experimentoId:                    HOST + '/laboratorio/experimento-id',
            teleoperacao:                     HOST + '/laboratorio/teleoperacao',
            teleoperacaoInstrucao:            HOST + '/laboratorio/teleoperacao-instrucao',
            getExperimentosHistory:           HOST + '/historico/list',
            getListAgendaAll:                 HOST + '/agenda/list',
            getListAgendaUsuario:             HOST + '/agenda/list-usuario',
            agenda:                           HOST + '/agenda'
          };
        }
    }
