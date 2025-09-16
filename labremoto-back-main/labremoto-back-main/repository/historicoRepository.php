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

class HistoricoRepository {

    private $db;

    public function __construct() {
        $this->db = new Medoo(Config::$dbConfiguration);
    }

    public function listExperimentoBySessaoMatricula($matricula) {
        return $this->db->query("SELECT e.codigo, e.cod_sessao, e.cod_experimento,"
                        . " e.parametros, e.dt_inicio, v.label FROM sessao_experimento e JOIN sessao s ON e.cod_sessao = s.codigo JOIN experimento v ON e.cod_experimento = v.codigo "
                        . "WHERE s.matricula = :matricula ORDER BY e.dt_inicio DESC", [
                    ":matricula" => $matricula
                ])->fetchAll();
    }

}
?>  

