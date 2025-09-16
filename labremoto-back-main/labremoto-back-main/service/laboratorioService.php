<?php

/*
 *            __   __   ___        __  ___  __  
 * |     /\  |__) |__) |__   |\/| /  \  |  /  \ 
 * |___ /~~\ |__) |  \ |___  |  | \__/  |  \__/ 
 * =============================================
 * Laboratório Remoto de Robótica Móvel                                           
 * Autor: Paulo Felipe P. Parreira - paulof (at) ufop.edu.br
 * =============================================
 * Arquivo: laboratorioService.php
 * Descrição: Service com as regras de gerais do laboratório.
 */

require_once __DIR__ . '/../repository/laboratorioRepository.php';
require_once __DIR__ . '/../entities/sessao.php';
require_once __DIR__ . '/../entities/experimento.php';
require_once __DIR__ . '/../entities/experimentoApontarParametros.php';
require_once __DIR__ . '/../entities/experimentoTrajetoriaParametros.php';
require_once __DIR__ . '/../entities/experimentoTrajetoriaInstrucao.php';
require_once __DIR__ . '/../entities/teleoperacaoInstrucao.php';
require_once __DIR__ . '/../entities/experimentoResultado.php';

class LaboratorioService {

    private $repository;
    private $loginService;
    private $agendaService;

    function __construct() {
        $this->repository = new LaboratorioRepository();
        $this->loginService = new LoginService();
        $this->agendaService = new AgendaService();
    }

    public function getSessaoAtiva() {
        $sessaoAtivaArr = $this->repository->getSessaoAtiva();
        if (!is_array($sessaoAtivaArr) || count($sessaoAtivaArr) == 0) {
            return (null);
        }
        $sessaoAtiva = new Sessao(null, null, null, null);
        $sessaoAtiva->setCodigo($sessaoAtivaArr[0]["codigo"]);
        $sessaoAtiva->setMatricula($sessaoAtivaArr[0]["matricula"]);
        $sessaoAtiva->setDtInicio($sessaoAtivaArr[0]["dt_inicio"]);
        $sessaoAtiva->setDtFim($sessaoAtivaArr[0]["dt_fim"]);
        $sessaoAtiva->setAtivo($sessaoAtivaArr[0]["ativo"]);
        return $sessaoAtiva;
    }

    public function getLaboratorioStatus() {
        if ($this->getSessaoAtiva() != null) {
            return false;
        }

        if (!$this->agendaService->checkDisponibilidadeAgenda(new DateTime(), true)) {
            return false;
        }

        return true;
    }

    public function getExperimentos() {
        return json_encode(InputHelper::utf8ize($this->repository->getExperimentos()));
    }

    public function getExperimentoAtivo() {
        $experimentoAtivoArr = $this->repository->getExperimentoAtivo();
        if (count($experimentoAtivoArr) != 1) {
            return null;
        }
        $experimentoAtivoRepo = $experimentoAtivoArr[0];

        $experimentoAtivo = new Experimento();
        $experimentoAtivo->setCodigo($experimentoAtivoRepo["codigo"]);
        $experimentoAtivo->setCodExperimento($experimentoAtivoRepo["cod_experimento"]);
        $experimentoAtivo->setCodSessao($experimentoAtivoRepo["cod_sessao"]);
        $experimentoAtivo->setDtInicio($experimentoAtivoRepo["dt_inicio"]);
        $experimentoAtivo->setParametros($experimentoAtivoRepo["parametros"]);
        $experimentoAtivo->setAtivo($experimentoAtivoRepo["ativo"]);
        $experimentoAtivo->setLabel(utf8_encode($experimentoAtivoRepo["label"]));
        return ($experimentoAtivo);
    }

    public function getSessaoExperimentoById($codExperimento) {
        $experimentoAtivoArr = $this->repository->getSessaoExperimentoById($codExperimento);
        if (count($experimentoAtivoArr) != 1) {
            return null;
        }
        $experimentoAtivoRepo = $experimentoAtivoArr[0];

        $experimentoAtivo = new Experimento();
        $experimentoAtivo->setCodigo($experimentoAtivoRepo["codigo"]);
        $experimentoAtivo->setCodExperimento($experimentoAtivoRepo["cod_experimento"]);
        $experimentoAtivo->setCodSessao($experimentoAtivoRepo["cod_sessao"]);
        $experimentoAtivo->setDtInicio($experimentoAtivoRepo["dt_inicio"]);
        $experimentoAtivo->setParametros($experimentoAtivoRepo["parametros"]);
        $experimentoAtivo->setAtivo($experimentoAtivoRepo["ativo"]);
        $experimentoAtivo->setLabel(utf8_encode($experimentoAtivoRepo["label"]));
        return ($experimentoAtivo);
    }

    public function startSessao() {
        $token = $this->loginService->getToken();
        if ($token == null) {
            throw new Exception("Token de acesso não encontrado.");
        }

        if ($this->getSessaoAtiva() != null) {
            throw new Exception("Já existe uma sessão ativa no momento, tente novamente mais tarde ou agende um horário para utilizar o laboratório.");
        }

        $dtInicio = new DateTime();
        $dtFim = new DateTime("+25 minutes");

        // Desabilita experimentos ativos - se existirem
        $this->repository->desabilitaExperimentos();

        if ($this->repository->startSessao($token->matricula, $dtInicio->format("Y-m-d H:i:s"), $dtFim->format("Y-m-d H:i:s"))) {
            return json_encode(new Sessao($token->matricula, true, $dtInicio->format("Y-m-d H:i:s"), $dtFim->format("Y-m-d H:i:s")));
        }
        return json_encode($token);
    }

    public function startExperimento($body) {
        $token = $this->loginService->getToken();
        if ($token == null) {
            throw new Exception("Token de acesso não encontrado.");
        }

        if (!is_numeric($body->codigo)) {
            throw new Exception("Código do experimento em formato inválido.");
        }

        if (count($this->repository->getExperimentoById($body->codigo)) == 0) {
            throw new Exception("Experimento não encontrado.");
        }

        $sessao = ($this->getSessaoAtiva());
        if ($sessao->matricula != $token->matricula) {
            throw new Exception("Você não é o usuário da sessão atual.");
        }
        $this->repository->setPararExperimento();
        $dtInicio = new DateTime();
        $experimentoSessao["cod_sessao"] = $sessao->codigo;
        $experimentoSessao["cod_experimento"] = $body->codigo;
        $experimentoSessao["parametros"] = "";
        $experimentoSessao["dt_inicio"] = $dtInicio->format("Y-m-d H:i:s");
        $experimentoSessao["ativo"] = true;
        $this->repository->desabilitaExperimentos();
        $experimentoAtivo = $this->repository->startExperimento($experimentoSessao);
        if ($experimentoAtivo != false) {
            $experimento = new Experimento($experimentoAtivo, $experimentoSessao["cod_sessao"], $experimentoSessao["cod_experimento"], $experimentoSessao["parametros"], $experimentoSessao["dt_inicio"], $experimentoSessao["ativo"]);
            $this->gerarParametrosExperimentoDefault($experimento);
            return $experimento;
        } else {
            throw new Exception("Não foi possível criar seu novo experimento, erro ao inserir registro.");
        }
    }

    public function setExperimentoParametro($body) {
        $token = $this->loginService->getToken();
        if ($token == null) {
            throw new Exception("Token de acesso não encontrado.");
        }

        $sessao = $this->getSessaoAtiva();
        $experimento = $this->getExperimentoAtivo();
        if ($sessao->matricula != $token->matricula) {
            throw new Exception("Você não é o usuário da sessão atual.");
        }

        if ($experimento->codSessao != $sessao->codigo) {
            throw new Exception("O experimento não faz parte da sessão atual.");
        }

        if ($experimento->ativo == false) {
            throw new Exception("O experimento não está ativo.");
        }

        switch ($experimento->codExperimento) {
            case 1:
                $params = new ExperimentoApontarParametros();
                $params->setCodSessaoExperimento($experimento->codigo);
                $params->setAlgoritmoBusca($body->algoritmoBusca);
                $params->setObstaculos($body->obstaculos);
                $params->setKp($body->kp);
                $params->setKd($body->kd);
                $params->setKi($body->ki);
                $params->setTipoControlador($body->tipoControlador);
                $params->setKp_ang($body->kp_ang);
                $params->setKd_ang($body->kd_ang);
                $params->setKi_ang($body->ki_ang);
                $params->setObjetivoX($body->objetivoX);
                $params->setObjetivoY($body->objetivoY);
                $params->setTamanhoMapaBusca($body->mapScale);
                $params->setTamanhoAreaSeguranca($body->safeScale);
                $params->setHeuristica($body->heuristica);
                $this->validateExperimentoParams($params);
                return $this->repository->updateExperimentoApontarParametro($params);
                break;
            case 2:
                $params = new ExperimentoTrajetoriaParametros();
                $params->setCodSessaoExperimento($experimento->codigo);
                $params->setObstaculos($body->obstaculos);
                $params->setKp($body->kp);
                $params->setKd($body->kd);
                $params->setKi($body->ki);
                $this->validateExperimentoParams($params);
                return $this->repository->updateExperimentoTrajetoriaParametro($params);
                break;
        }
    }

    public function gerarParametrosExperimentoDefault($experimento) {
        switch ($experimento->codExperimento) {
            case 1:
                $params = new ExperimentoApontarParametros();
                $params->setCodSessaoExperimento($experimento->codigo);
                $params->setAlgoritmoBusca(1);
                $params->setHeuristica(1);
                $params->setObstaculos(true);
                $params->setKp(0.001);
                $params->setKd(0.0002);
                $params->setKi(0.00003);
                $params->setKp_ang(0.5);
                $params->setKd_ang(0.0002);
                $params->setKi_ang(0.00003);
                $params->setTipoControlador(1);
                $params->setTamanhoMapaBusca(5);
                $params->setTamanhoAreaSeguranca(5);
                return $this->repository->createExperimentoApontarParametro($params);
                break;
            case 2:
                $params = new ExperimentoTrajetoriaParametros();
                $params->setCodSessaoExperimento($experimento->codigo);
                $params->setObstaculos(true);
                $params->setKp(1);
                $params->setKd(1);
                $params->setKi(1);
                return $this->repository->createExperimentoTrajetoriaParametro($params);
                break;
        }
    }

    public function validateExperimentoParams($params) {
        if (!is_numeric($params->kp) || !is_numeric($params->kd) || !is_numeric($params->ki)) {
            throw new Exception("Os parâmetros do controlador precisam ser numéricos.");
        }
    }

    public function getExperimentoParametros($codExperimento) {
        if (!is_numeric($codExperimento)) {
            throw new Exception("Formato do código do experimento inválido." . $codExperimento);
        }

        $experimento = $this->repository->getSessaoExperimentoById($codExperimento)[0];
        switch ($experimento["cod_experimento"]) {
            case 1:
                $paramArr = $this->repository->getExperimentoApontarParamsByCodSessaoExperimento($codExperimento);
                return new ExperimentoApontarParametros($paramArr["cod_sessao_experimento"],
                        $paramArr["tipo_controlador"],
                        $paramArr["algoritmo_busca"],
                        $paramArr["obstaculos"],
                        $paramArr["kp_ang"], $paramArr["kd_ang"], 
                        $paramArr["ki_ang"],
                        $paramArr["kp"], $paramArr["kd"], 
                        $paramArr["ki"], $paramArr["tamanho_mapa_busca"], 
                        $paramArr["tamanho_area_seguranca"], $paramArr["heuristica"]
                        ,$paramArr["dt_criacao"], $paramArr["estatisticas_busca"]);
            case 2:
                $paramArr = $this->repository->getExperimentoTrajetoriaParamsByCodSessaoExperimento($codExperimento);
                return new ExperimentoTrajetoriaParametros($paramArr["cod_sessao_experimento"],
                        $paramArr["obstaculos"],
                        $paramArr["kp"], $paramArr["kd"], $paramArr["ki"]
                        , $paramArr["dt_criacao"]);
        }
    }

    public function setExperimentoInstrucoes($body) {
        $token = $this->loginService->getToken();
        if ($token == null) {
            throw new Exception("Token de acesso não encontrado.");
        }

        $sessao = $this->getSessaoAtiva();
        $experimento = $this->getExperimentoAtivo();
        if ($sessao->matricula != $token->matricula) {
            throw new Exception("Você não é o usuário da sessão atual.");
        }

        if ($experimento->codExperimento != 2) {
            throw new Exception("Esse tipo de experimento não permite instruções.");
        }

        if ($experimento->codSessao != $sessao->codigo) {
            throw new Exception("O experimento não faz parte da sessão atual.");
        }

        if ($experimento->ativo == false) {
            throw new Exception("O experimento não está ativo.");
        }

        if (!$this->repository->deleteInstrucoesByCodSessaoExperimento($experimento->codigo)) {
            throw new Exception("Não foi possível remover as instruções anteriores.");
        }

        foreach ($body as $idx => $instrucaoReq) {
            $instrucao = new ExperimentoTrajetoriaInstrucao();
            $instrucao->setCodSessaoExperimento($experimento->getCodigo());
            switch ($instrucaoReq->tipo) {
                case 1: // Movimento reto
                    $instrucao->setVelLinear($instrucaoReq->velLinear);
                    $instrucao->setVelAngular(0);
                    break;
                case 2: // Curva
                    $instrucao->setVelLinear($instrucaoReq->velLinear);
                    $instrucao->setVelAngular($instrucaoReq->velAngular);
                    break;
                case 3: // Rotação
                    $instrucao->setVelLinear(0);

                    // Cálculo da vel angular
                    $radAngle = ($instrucaoReq->rotAngulo * pi()) / 180;
                    $sec = $instrucaoReq->timer / 1000;
                    $angularVel = $radAngle / $sec;

                    $instrucao->setVelAngular($angularVel);
                    break;
                case 4: // Parado
                    $instrucao->setVelLinear(0);
                    $instrucao->setVelAngular(0);
                    break;
            }
            $instrucao->timer = $instrucaoReq->timer;
            if (!$this->repository->setExperimentoInstrucao($instrucao)) {
                throw new Exception("Ocorreu um erro ao adicionar a instrução. (" . 1 + $idx . ")");
            }
        }

        return true;
    }

    public function getExperimentoInstrucoes($codSessaoExperimento) {
        if (!is_numeric($codSessaoExperimento)) {
            throw new Exception("Formato do código do experimento inválido." . $codSessaoExperimento);
        }

        $experimento = $this->repository->getSessaoExperimentoById($codSessaoExperimento)[0];
        if ($experimento["cod_experimento"] != 2) {
            throw new Exception("Experimento não suporta instruções. ".$experimento["cod_experimento"]);
        }

        $instrucoesArr = $this->repository->getExperimentoInstrucaoByCodSessaoExperimento($codSessaoExperimento);
        $returnArr = [];
        foreach ($instrucoesArr as $idx => $instrucaoArr) {
            $instrucao = new ExperimentoTrajetoriaInstrucao();
            $instrucao->setCodigo($instrucaoArr["codigo"]);
            $instrucao->setCodSessaoExperimento($instrucaoArr["cod_sessao_experimento"]);
            $instrucao->setVelLinear($instrucaoArr["velocidade_linear"]);
            $instrucao->setVelAngular($instrucaoArr["velocidade_angular"]);
            $instrucao->setTimer($instrucaoArr["timer"]);
            $instrucao->setDtCriacao($instrucaoArr["dt_criacao"]);
            $instrucao->setDtInicializacao($instrucaoArr["dt_inicializacao"]);
            $instrucao->setDtFinalizacao($instrucaoArr["dt_finalizacao"]);
            $returnArr[] = $instrucao;
        }

        return $returnArr;
    }

    public function setApontarObjetivo($body) {
        $token = $this->loginService->getToken();
        if ($token == null) {
            throw new Exception("Token de acesso não encontrado.");
        }

        $sessao = $this->getSessaoAtiva();
        $experimento = $this->getExperimentoAtivo();
        if ($sessao->matricula != $token->matricula) {
            throw new Exception("Você não é o usuário da sessão atual.");
        }

        if ($experimento->codSessao != $sessao->codigo) {
            throw new Exception("O experimento não faz parte da sessão atual.");
        }

        $params = new ExperimentoApontarParametros();
        $params->setCodSessaoExperimento($experimento->getCodigo());
        $params->setObjetivoX($body->objetivoX);
        $params->setObjetivoY($body->objetivoY);
        return $this->repository->updateExperimentoApontarObjetivo($params);
    }

    public function setStatusExperimento($body) {
        $token = $this->loginService->getToken();
        if ($token == null) {
            throw new Exception("Token de acesso não encontrado.");
        }

        $sessao = $this->getSessaoAtiva();
        $experimento = $this->getExperimentoAtivo();
        if ($sessao->matricula != $token->matricula) {
            throw new Exception("Você não é o usuário da sessão atual.");
        }

        if ($experimento->codSessao != $sessao->codigo) {
            throw new Exception("O experimento não faz parte da sessão atual.");
        }

        if (!in_array($body->status, [0, 1, 2])) {
            throw new Exception("Status inválido");
        }

        switch ($body->status) {
            case 0:
                return $this->repository->setPararExperimento();
                break;
            case 1:
                return $this->repository->setIniciarExperimento();
                break;
        }

        return false;
    }

    public function getExperimentoResults($codExperimento) {
        if (!is_numeric($codExperimento)) {
            throw new Exception("Formato do código do experimento inválido." . $codExperimento);
        }

        $resultsArr = $this->repository->getExperimentoResultsByCodSessaoExperimento($codExperimento);
        $returnArr = [];
        foreach ($resultsArr as $i => $res) {
            $returnArr[] = new ExperimentoResultado(
                    $res["codigo"], $res["cod_sessao_experimento"],
                    $res["pos_x"], $res["pos_y"],
                    $res["linear_vel"], $res["angular_vel"],
                    $res["experimento_starttime"],
                    json_decode($res["data"]), $res["dt_criacao"]
            );
        }

        return $returnArr;
    }

    public function encerrarExperimento() {
        $token = $this->loginService->getToken();
        if ($token == null) {
            throw new Exception("Token de acesso não encontrado.");
        }

        $sessao = $this->getSessaoAtiva();
        $experimento = $this->getExperimentoAtivo();
        if ($sessao->matricula != $token->matricula) {
            throw new Exception("Você não é o usuário da sessão atual.");
        }

        if ($experimento->codSessao != $sessao->codigo) {
            throw new Exception("O experimento não faz parte da sessão atual.");
        }

        if (!$this->repository->encerrarExperimento()) {
            throw new Exception("Não foi possível encerrar o experimento.");
        }
        return true;
    }

    public function setModoTeleoperacao($body) {
        $token = $this->loginService->getToken();
        if ($token == null) {
            throw new Exception("Token de acesso não encontrado.");
        }

        $sessao = $this->getSessaoAtiva();
        if ($sessao->matricula != $token->matricula) {
            throw new Exception("Você não é o usuário da sessão atual.");
        }

        if($body->status == 1) {
            $this->repository->setIniciarTeleoperacao();
        } else {
            $this->repository->setPararExperimento();
        }


    }
    public function addTeleoperacaoInstrucao($body) {
        $token = $this->loginService->getToken();
        if ($token == null) {
            throw new Exception("Token de acesso não encontrado.");
        }

        $sessao = $this->getSessaoAtiva();
        if ($sessao->matricula != $token->matricula) {
            throw new Exception("Você não é o usuário da sessão atual.");
        }

        if(!in_array($body->instrucao, [1,2,3,4])) {
            throw new Exception("Instrução inválida.");
        }

        $teleopInstrucao = new TeleoperacaoInstrucao();
        $teleopInstrucao->setCodSessaoExperimento($sessao->codigo);
        $teleopInstrucao->setInstrucao($body->instrucao);
        return $this->repository->addTeleoperacaoInstrucao($teleopInstrucao);
    }

}

?>
