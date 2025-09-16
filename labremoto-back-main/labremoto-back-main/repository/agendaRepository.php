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

class AgendaRepository {

    private $db;

    public function __construct() {
        $this->db = new Medoo(Config::$dbConfiguration);
    }

    
    public function getAgendamentoByCodigo($codigo) {
        return $this->db->query("SELECT a.codigo, a.matricula, a.dt_agendamento FROM agenda a "
                        . "WHERE a.codigo = :codigo", [
                    ":codigo" => $codigo
                ])->fetchAll()[0];
    }
    
    public function listAgendaUsuario($matricula) {
        return $this->db->query("SELECT a.codigo, a.matricula, a.dt_agendamento FROM agenda a "
                        . "WHERE a.matricula = :matricula and dt_agendamento > NOW() ORDER BY a.dt_agendamento ASC", [
                    ":matricula" => $matricula
                ])->fetchAll();
    }

    public function listAgendaAllBetweenDates($dtInicio, $dtFim) {
        return $this->db->query("SELECT u.nome as nome, a.codigo, a.matricula, a.dt_agendamento FROM agenda a JOIN usuario u ON a.matricula = u.matricula "
                        . "WHERE a.dt_agendamento BETWEEN :dtInicio AND :dtFim ORDER BY a.dt_agendamento DESC", [
                    ":dtInicio" => $dtInicio,
                    ":dtFim" => $dtFim
                ])->fetchAll();
    }
    
    
    public function setRegistroAgenda($registroAgenda) {
        if ($this->db->insert("agenda", [
                    "matricula" => $registroAgenda["matricula"],
                    "dt_agendamento" => $registroAgenda["dtAgendamento"]
                ]) == true) {
            return $this->db->id();
        } else {
            return false;
        }
    }
    
    public function checkDisponibilidadeAgenda($dtInicio, $dtFim) {
        return $this->db->query("SELECT count(a.codigo) FROM agenda a "
                        . "WHERE a.dt_agendamento BETWEEN :dtInicio AND :dtFim", [
                    ":dtInicio" => $dtInicio,
                    ":dtFim" => $dtFim
                ])->fetchAll();
    }
    
    public function checkDisponibilidadeAgendaExcludeCurrentUser($dtInicio, $dtFim, $user) {
        return $this->db->query("SELECT count(a.codigo) FROM agenda a "
                        . "WHERE a.dt_agendamento BETWEEN :dtInicio AND :dtFim AND a.matricula != :user", [
                    ":dtInicio" => $dtInicio,
                    ":dtFim" => $dtFim,
                            ":user" => $user
                ])->fetchAll();
    }
    
    
    public function removerAgendamento($codigo, $matricula) {
        if ($this->db->delete("agenda", [
                    "codigo" => $codigo,
                    "matricula" => $matricula
                ]) == true) {
            return true;
        } else {
            return false;
        }
    }

}
?>  

