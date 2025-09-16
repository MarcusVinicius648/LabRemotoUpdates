<?php

/*
 *            __   __   ___        __  ___  __  
 * |     /\  |__) |__) |__   |\/| /  \  |  /  \ 
 * |___ /~~\ |__) |  \ |___  |  | \__/  |  \__/ 
 * =============================================
 * Laboratório Remoto de Robótica Móvel                                           
 * Autor: Paulo Felipe P. Parreira - paulof (at) ufop.edu.br
 * =============================================
 * Arquivo: routes.php
 * Descrição: Arquivo responsável por armazenar as rotas da API.
 */


/*
 * Estrutura da rota: 
 * "raiz" => ["controller,
 *              [ 
 *                  "metodo" => [
 *                      "url" => ["funcao", [variaveis]]
 *                  ]
 *              ]
 *          ]
 */

class Routes {

    static $routes = [
        "login" => ["LoginController",
            [
                "GET" => [
                    "" => ["authUser", []]
                ],
                "POST" => [
                    "" => ["authUser", []]
                ],
                "PUT" => [],
                "DELETE" => []
            ]],
        "historico" => ["HistoricoController",
            [
                "GET" => [
                    "list" => ["getExperimentosMatricula", []]
                ],
                "POST" => [
                ],
                "PUT" => [],
                "DELETE" => []
            ]],
        "agenda" => ["AgendaController",
            [
                "GET" => [
                    "list-usuario" => ["getAgendaUsuario", []],
                    "list" => ["getAgendaFull", []]
                ],
                "POST" => [
                    "" => ["setRegistroAgenda", []]
                ],
                "PUT" => [],
                "DELETE" => [
                    "" => ["removerAgendamento", []]
                ]
            ]],
        "laboratorio" => ["LaboratorioController",
            [
                "GET" => [
                    "laboratorio-status" => ["getLaboratorioStatus", []],
                    "sessao-ativa" => ["getSessaoAtiva", []],
                    "experimentos" => ["getExperimentos", []],
                    "experimento-ativo" => ["getExperimentoAtivo", []],
                    "experimento-parametros" => ["getExperimentoParametros", []],
                    "experimento-instrucoes" => ["getExperimentoInstrucoes", []],
                    "experimento-resultados" => ["getExperimentoResults", []],
                    "encerrar-experimento" => ["encerrarExperimento", []],
                    "experimento-id" => ["getSessaoExperimentoById",[]]
                ],
                "POST" => [
                    "sessao" => ["startSessao", []],
                    "experimento" => ["startExperimento", []],
                    "experimento-parametros" => ["setExperimentoParametros", []],
                    "experimento-instrucoes" => ["setExperimentoInstrucoes", []],
                    "experimento-objetivo" => ["setApontarObjetivo", []],
                    "experimento-status" => ["setStatusExperimento", []],
                    "teleoperacao" => ["setModoTeleoperacao", []],
                    "teleoperacao-instrucao" => ["addTeleoperacaoInstrucao", []]
                ],
                "PUT" => [],
                "DELETE" => []
            ]]
    ];

}

?>
