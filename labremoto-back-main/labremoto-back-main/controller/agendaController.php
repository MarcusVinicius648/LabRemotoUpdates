<?php

/*
 *            __   __   ___        __  ___  __  
 * |     /\  |__) |__) |__   |\/| /  \  |  /  \ 
 * |___ /~~\ |__) |  \ |___  |  | \__/  |  \__/ 
 * =============================================
 * Laboratório Remoto de Robótica Móvel                                           
 * Autor: Paulo Felipe P. Parreira - paulof (at) ufop.edu.br
 * =============================================
 * Arquivo: agendaController.php
 * Descrição: Controller utilizado para gerenciar as operações gerais da agenda.
 */

require_once(__DIR__ . "/../service/agendaService.php");

class AgendaController {

    private $agendaService;

    public function __construct() {
        $this->agendaService = new AgendaService();
    }

    public function getAgendaUsuario() {
        try {
            echo json_encode(InputHelper::utf8ize($this->agendaService->listAgendaUsuario()));
        } catch (Exception $ex) {
            http_response_code(400);
            echo json_encode(["status" => 400, "error" => $ex->getMessage()]);
        }
    }

    public function getAgendaFull() {
        try {
            $dtInicio = filter_input(INPUT_GET, "dtInicio");
            $dtFim = filter_input(INPUT_GET, "dtFim");
            echo json_encode(InputHelper::utf8ize($this->agendaService->listAgendaFull($dtInicio, $dtFim)));
        } catch (Exception $ex) {
            http_response_code(400);
            echo json_encode(["status" => 400, "error" => $ex->getMessage()]);
        }
    }
    
    public function setRegistroAgenda() {
        try {
            $body = InputHelper::getBodyJson();
            echo json_encode($this->agendaService->setRegistroAgenda($body));     
        } catch (Exception $ex) {
            http_response_code(400);
            echo json_encode(["status" => 400, "error" => $ex->getMessage()]);

        }
    }
    
    
    public function removerAgendamento() {
        try {
            $codigo = filter_input(INPUT_GET, "codigo");
            echo json_encode(InputHelper::utf8ize($this->agendaService->removerAgendamento($codigo)));
        } catch (Exception $ex) {
            http_response_code(400);
            echo json_encode(["status" => 400, "error" => $ex->getMessage()]);
        }
    }

}

?>
