<?php

/*
 *            __   __   ___        __  ___  __  
 * |     /\  |__) |__) |__   |\/| /  \  |  /  \ 
 * |___ /~~\ |__) |  \ |___  |  | \__/  |  \__/ 
 * =============================================
 * Laboratório Remoto de Robótica Móvel                                           
 * Autor: Paulo Felipe P. Parreira - paulof (at) ufop.edu.br
 * =============================================
 * Arquivo: histroricoController.php
 * Descrição: Controller utilizado para gerenciar as operações gerais do histórico.
 */

require_once(__DIR__ . "/../service/historicoService.php");

class HistoricoController {

    private $historicoService;

    public function __construct() {
        $this->historicoService = new HistoricoService();
    }
    public function getExperimentosMatricula() {
        try {
            echo json_encode(InputHelper::utf8ize($this->historicoService->listExperimentosByMatriculaAtiva()));
        } catch (Exception $ex) {
            http_response_code(400);
            echo json_encode(["status" => 400, "error" => $ex->getMessage()]);
        }
    }

}

?>
