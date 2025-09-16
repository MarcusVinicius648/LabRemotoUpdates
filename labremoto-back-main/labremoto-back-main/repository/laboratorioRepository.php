<?php

/*
 *            __   __   ___        __  ___  __  
 * |     /\  |__) |__) |__   |\/| /  \  |  /  \ 
 * |___ /~~\ |__) |  \ |___  |  | \__/  |  \__/ 
 * =============================================
 * Laboratório Remoto de Robótica Móvel                                           
 * Autor: Paulo Felipe P. Parreira - paulof (at) ufop.edu.br
 * =============================================
 * Arquivo: loginRepository.php
 * Descrição: Repository para as consultas de login.
 */
require_once(__DIR__ . "/../lib/medoo/medoo.php");

use Medoo\Medoo;

class LaboratorioRepository {

    private $db;

    public function __construct() {
        $this->db = new Medoo(Config::$dbConfiguration);
    }

    public function getSessaoAtiva() {
        $sessao = $this->db->select('sessao', ["codigo", "ativo", "dt_inicio", "dt_fim", "matricula"], ["ativo" => true]);
        return $sessao;
    }

    public function startSessao($matricula, $dt_inicio, $dt_fim) {
        if ($this->db->insert("sessao", [
                    "matricula" => $matricula,
                    "ativo" => true,
                    "dt_inicio" => $dt_inicio,
                    "dt_fim" => $dt_fim
                ]) == true) {
            return true;
        } else {
            return false;
        }
    }

    public function startExperimento($experimentoSessao) {
        if ($this->db->insert("sessao_experimento", [
                    "cod_sessao" => $experimentoSessao["cod_sessao"],
                    "cod_experimento" => $experimentoSessao["cod_experimento"],
                    "parametros" => $experimentoSessao["parametros"],
                    "dt_inicio" => $experimentoSessao["dt_inicio"],
                    "ativo" => $experimentoSessao["ativo"]
                ]) == true) {
            return $this->db->id();
        } else {
            return false;
        }
    }

    public function getExperimentos() {
        return $this->db->query('SELECT codigo, label, descricao FROM experimento')->fetchAll();
    }

    public function getExperimentoById($codigo) {
        $experimento = $this->db->select('experimento', ["codigo", "label", "descricao"], ["codigo" => $codigo]);
        return $experimento;
    }

    public function getSessaoExperimentoById($codExperimento) {
        return $this->db->query('SELECT a.codigo, a.cod_sessao, a.cod_experimento, a.parametros, a.dt_inicio, a.ativo, e.label as label FROM sessao_experimento a INNER JOIN experimento e ON a.cod_experimento = e.codigo WHERE a.codigo = :codigo', [
                    ":codigo" => $codExperimento
                ])->fetchAll();
    }

    public function getExperimentoApontarParamsByCodSessaoExperimento($codigo) {
        $params = $this->db->select('experimento_apontar_parametros',
                ["cod_sessao_experimento", "algoritmo_busca", "tipo_controlador","kp_ang", "kd_ang", "ki_ang", "kp", "kd", "ki", "obstaculos", "dt_criacao", "heuristica", "tamanho_mapa_busca", "tamanho_area_seguranca", "estatisticas_busca"],
                ["cod_sessao_experimento" => $codigo]);
        return $params[0];
    }

    public function getExperimentoTrajetoriaParamsByCodSessaoExperimento($codigo) {
        $params = $this->db->select('experimento_trajetoria_parametros',
                ["cod_sessao_experimento", "kp", "kd", "ki", "obstaculos", "dt_criacao"],
                ["cod_sessao_experimento" => $codigo]);
        return $params[0];
    }

    public function desabilitaExperimentos() {
        return $this->db->update("sessao_experimento", ["ativo" => false], ["ativo" => true]);
    }

    public function getExperimentoAtivo() {
        return $this->db->query('SELECT a.codigo, a.cod_sessao, a.cod_experimento, a.parametros, a.dt_inicio, a.ativo, e.label as label FROM sessao_experimento a INNER JOIN experimento e ON a.cod_experimento = e.codigo WHERE a.ativo = true')->fetchAll();
    }

    public function createExperimentoApontarParametro($experimentoApontar) {
        if ($this->db->insert("experimento_apontar_parametros", [
                    "cod_sessao_experimento" => $experimentoApontar->getCodSessaoExperimento(),
                    "algoritmo_busca" => $experimentoApontar->getAlgoritmoBusca(),
                    "obstaculos" => $experimentoApontar->getObstaculos(),
                    "kp" => $experimentoApontar->getKp(),
                    "kd" => $experimentoApontar->getKd(),
                    "ki" => $experimentoApontar->getKi(),
                    "kp_ang" => $experimentoApontar->getKp_ang(),
                    "kd_ang" => $experimentoApontar->getKd_ang(),
                    "ki_ang" => $experimentoApontar->getKi_ang(),
                    "tipo_controlador" => $experimentoApontar->getTipoControlador(),
                    "heuristica" => $experimentoApontar->getHeuristica(),
                    "tamanho_mapa_busca" => $experimentoApontar->getTamanhoMapaBusca(),
                    "tamanho_area_seguranca" => $experimentoApontar->getTamanhoAreaSeguranca(),
                ]) == true) {
            return true;
        } else {
            return false;
        }
    }

    public function createExperimentoTrajetoriaParametro($experimentoTrajetoria) {
        if ($this->db->insert("experimento_trajetoria_parametros", [
                    "cod_sessao_experimento" => $experimentoTrajetoria->getCodSessaoExperimento(),
                    "obstaculos" => $experimentoTrajetoria->getObstaculos(),
                    "kp" => $experimentoTrajetoria->getKp(),
                    "kd" => $experimentoTrajetoria->getKd(),
                    "ki" => $experimentoTrajetoria->getKi(),
                ]) == true) {
            return true;
        } else {
            return false;
        }
    }

    public function updateExperimentoApontarParametro($experimentoApontar) {
        if ($this->db->update("experimento_apontar_parametros", [
                    "objetivo_x" => $experimentoApontar->getObjetivoX(),
                    "objetivo_y" => $experimentoApontar->getObjetivoY(),
                    "algoritmo_busca" => $experimentoApontar->getAlgoritmoBusca(),
                    "obstaculos" => $experimentoApontar->getObstaculos(),
                    "kp" => $experimentoApontar->getKp(),
                    "kd" => $experimentoApontar->getKd(),
                    "ki" => $experimentoApontar->getKi(),
                    "kp_ang" => $experimentoApontar->getKp_ang(),
                    "kd_ang" => $experimentoApontar->getKd_ang(),
                    "ki_ang" => $experimentoApontar->getKi_ang(),
                    "tipo_controlador" => $experimentoApontar->getTipoControlador(),
                    "heuristica" => $experimentoApontar->getHeuristica(),
                    "tamanho_mapa_busca" => $experimentoApontar->getTamanhoMapaBusca(),
                    "tamanho_area_seguranca" => $experimentoApontar->getTamanhoAreaSeguranca(),
                        ], ["cod_sessao_experimento" => $experimentoApontar->getCodSessaoExperimento()]) == true) {
            return true;
        } else {
            return false;
        }
    }

    public function updateExperimentoApontarObjetivo($experimentoApontar) {
        if ($this->db->update("experimento_apontar_parametros", [
                    "objetivo_x" => $experimentoApontar->getObjetivoX(),
                    "objetivo_y" => $experimentoApontar->getObjetivoY()
                        ], ["cod_sessao_experimento" => $experimentoApontar->getCodSessaoExperimento()]) == true) {
            return true;
        } else {
            return false;
        }
    }

    public function updateExperimentoTrajetoriaParametro($experimentoTrajetoria) {
        if ($this->db->update("experimento_trajetoria_parametros", [
                    "obstaculos" => $experimentoTrajetoria->getObstaculos(),
                    "kp" => $experimentoTrajetoria->getKp(),
                    "kd" => $experimentoTrajetoria->getKd(),
                    "ki" => $experimentoTrajetoria->getKi(),
                        ], ["cod_sessao_experimento" => $experimentoTrajetoria->getCodSessaoExperimento()]) == true) {
            return true;
        } else {
            return false;
        }
    }

    public function deleteInstrucoesByCodSessaoExperimento($codSessaoExperimento) {
        if ($this->db->delete("experimento_trajetoria_instrucoes", ["cod_sessao_experimento" => $codSessaoExperimento]) == true) {
            return true;
        } else {
            return false;
        }
    }

    public function setExperimentoInstrucao($instrucao) {
        if ($this->db->insert("experimento_trajetoria_instrucoes", [
                    "cod_sessao_experimento" => $instrucao->getCodSessaoExperimento(),
                    "velocidade_linear" => $instrucao->getVelLinear(),
                    "velocidade_angular" => $instrucao->getVelAngular(),
                    "timer" => $instrucao->getTimer()
                ]) == true) {
            return true;
        } else {
            return false;
        }
    }

    public function getExperimentoInstrucaoByCodSessaoExperimento($codSessaoExperimento) {
        return $this->db->select("experimento_trajetoria_instrucoes",
                        ["codigo", "cod_sessao_experimento", "velocidade_linear", "velocidade_angular",
                            "timer", "dt_criacao", "dt_inicializacao", "dt_finalizacao"], [
                    "cod_sessao_experimento" => $codSessaoExperimento
        ]);
    }

    public function setPararExperimento() {
        if ($this->db->update("configuracoes", ["valor" => 0], ["label" => "experimento_status"]) == true) {
            return true;
        } else {
            return false;
        }
    }

    public function setIniciarExperimento() {
        if ($this->db->update("configuracoes", ["valor" => 1], ["label" => "experimento_status"]) == true) {
            return true;
        } else {
            return false;
        }
    }

    public function setIniciarTeleoperacao() {
        if ($this->db->update("configuracoes", ["valor" => 2], ["label" => "experimento_status"]) == true) {
            return true;
        } else {
            return false;
        }
    }

    public function getExperimentoResultsByCodSessaoExperimento($codSessaoExperimento) {
        return $this->db->select("experimento_resultados",
                        ["codigo", "cod_sessao_experimento", "pos_x", "pos_y",
                            "linear_vel", "angular_vel", "experimento_starttime",
                            "data", "dt_criacao"], [
                    "cod_sessao_experimento" => $codSessaoExperimento
        ]);
    }

    public function encerrarExperimento() {
        if ($this->db->update("sessao_experimento", ["ativo" => 1], ["ativo" => "0"]) == true) {
            return true;
        } else {
            return false;
        }
    }

    public function listSessaoExperimentoByCodSessaoExperimento($codSessao) {
        return $this->db->select("experimento_resultados",
                        ["codigo", "cod_experimento"], [
                    "cod_sessao" => $codSessao
        ]);
    }


    public function addTeleoperacaoInstrucao($instrucao) {
        if ($this->db->insert("teleoperacao_instrucoes", [
                    "cod_sessao" => $instrucao->getCodSessaoExperimento(),
                    "instrucao" => $instrucao->getInstrucao()
                ]) == true) {
            return true;
        } else {
            return false;
        }
    }

}

?>  