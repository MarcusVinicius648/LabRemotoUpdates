<?php

/*
 *            __   __   ___        __  ___  __  
 * |     /\  |__) |__) |__   |\/| /  \  |  /  \ 
 * |___ /~~\ |__) |  \ |___  |  | \__/  |  \__/ 
 * =============================================
 * Laboratório Remoto de Robótica Móvel                                           
 * Autor: Paulo Felipe P. Parreira - paulof (at) ufop.edu.br
 * =============================================
 * Arquivo: laboratorioController.php
 * Descrição: Controller utilizado para gerenciar as operações gerais do laboratório.
 */

require_once(__DIR__ . "/../service/laboratorioService.php");

class LaboratorioController
{

    private $laboratorioService;

    public function __construct()
    {
        $this->laboratorioService = new LaboratorioService();
    }

    public function getSessaoAtiva()
    {
        try {
            echo json_encode($this->laboratorioService->getSessaoAtiva());
        } catch (Exception $ex) {
            http_response_code(400);
            echo json_encode(["status" => 400, "error" => $ex->getMessage()]);
        }
    }

    public function getLaboratorioStatus()
    {
        try {
            echo json_encode($this->laboratorioService->getLaboratorioStatus());
        } catch (Exception $ex) {
            http_response_code(400);
            echo json_encode(["status" => 400, "error" => $ex->getMessage()]);
        }
    }

    public function startSessao()
    {
        try {
            echo $this->laboratorioService->startSessao();
        } catch (Exception $ex) {
            http_response_code(400);
            echo json_encode(["status" => 400, "error" => $ex->getMessage()]);
        }
    }

    public function startExperimento()
    {
        try {
            $body = InputHelper::getBodyJson();
            echo json_encode($this->laboratorioService->startExperimento($body));
        } catch (Exception $ex) {
            http_response_code(400);
            echo json_encode(["status" => 400, "error" => $ex->getMessage()]);
        }
    }

    public function getExperimentos()
    {
        try {
            echo $this->laboratorioService->getExperimentos();
        } catch (Exception $ex) {
            http_response_code(400);
            echo json_encode(["status" => 400, "error" => $ex->getMessage()]);
        }
    }

    public function getExperimentoAtivo()
    {
        try {
            echo json_encode(($this->laboratorioService->getExperimentoAtivo()));
        } catch (Exception $ex) {
            http_response_code(400);
            echo json_encode(["status" => 400, "error" => $ex->getMessage()]);
        }
    }

    public function setExperimentoParametros()
    {
        try {
            $body = InputHelper::getBodyJson();
            echo json_encode($this->laboratorioService->setExperimentoParametro($body));
        } catch (Exception $ex) {
            http_response_code(400);
            echo json_encode(["status" => 400, "error" => $ex->getMessage()]);
        }
    }

    public function setApontarObjetivo()
    {
        try {
            $body = InputHelper::getBodyJson();
            echo json_encode($this->laboratorioService->setApontarObjetivo($body));
        } catch (Exception $ex) {
            http_response_code(400);
            echo json_encode(["status" => 400, "error" => $ex->getMessage()]);
        }
    }

    public function getExperimentoParametros()
    {
        try {
            $codExperimento = filter_input(INPUT_GET, "codigo");
            echo json_encode($this->laboratorioService->getExperimentoParametros($codExperimento));
        } catch (Exception $ex) {
            http_response_code(400);
            echo json_encode(["status" => 400, "error" => $ex->getMessage()]);
        }
    }

    public function setExperimentoInstrucoes()
    {
        try {
            $body = InputHelper::getBodyJson();
            echo json_encode($this->laboratorioService->setExperimentoInstrucoes($body));
        } catch (Exception $ex) {
            http_response_code(400);
            echo json_encode(["status" => 400, "error" => $ex->getMessage()]);
        }
    }

    public function getExperimentoInstrucoes()
    {
        try {
            $codSessaoExperimento = filter_input(INPUT_GET, "codigo");
            echo json_encode($this->laboratorioService->getExperimentoInstrucoes($codSessaoExperimento));
        } catch (Exception $ex) {
            http_response_code(400);
            echo json_encode(["status" => 400, "error" => $ex->getMessage()]);
        }
    }

    public function setStatusExperimento()
    {
        try {
            $body = InputHelper::getBodyJson();
            echo json_encode($this->laboratorioService->setStatusExperimento($body));
        } catch (Exception $ex) {
            http_response_code(400);
            echo json_encode(["status" => 400, "error" => $ex->getMessage()]);
        }
    }

    public function getExperimentoResults()
    {
        try {
            $codSessaoExperimento = filter_input(INPUT_GET, "codigo");
            echo json_encode($this->laboratorioService->getExperimentoResults($codSessaoExperimento));
        } catch (Exception $ex) {
            http_response_code(400);
            echo json_encode(["status" => 400, "error" => $ex->getMessage()]);
        }
    }

    public function encerrarExperimento()
    {
        try {
            echo json_encode($this->laboratorioService->encerrarExperimento());
        } catch (Exception $ex) {
            http_response_code(400);
            echo json_encode(["status" => 400, "error" => $ex->getMessage()]);
        }
    }

    public function getSessaoExperimentoById()
    {
        try {
            $codExperimento = filter_input(INPUT_GET, "codigo");
            echo json_encode($this->laboratorioService->getSessaoExperimentoById($codExperimento));
        } catch (Exception $ex) {
            http_response_code(400);
            echo json_encode(["status" => 400, "error" => $ex->getMessage()]);
        }
    }

    public function setModoTeleoperacao()
    {
        try {
            $body = InputHelper::getBodyJson();
            echo json_encode($this->laboratorioService->setModoTeleoperacao($body));
        } catch (Exception $ex) {
            http_response_code(400);
            echo json_encode(["status" => 400, "error" => $ex->getMessage()]);
        }
    }

    public function addTeleoperacaoInstrucao()
    {
        try {
            $body = InputHelper::getBodyJson();
            echo json_encode($this->laboratorioService->addTeleoperacaoInstrucao($body));
        } catch (Exception $ex) {
            http_response_code(400);
            echo json_encode(["status" => 400, "error" => $ex->getMessage()]);
        }
    }
}
