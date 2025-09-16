<?php

/*
 *            __   __   ___        __  ___  __  
 * |     /\  |__) |__) |__   |\/| /  \  |  /  \ 
 * |___ /~~\ |__) |  \ |___  |  | \__/  |  \__/ 
 * =============================================
 * Laboratório Remoto de Robótica Móvel                                           
 * Autor: Paulo Felipe P. Parreira - paulof (at) ufop.edu.br
 * =============================================
 * Arquivo: configuracaoRepository.php
 * Descrição: Repository para as consultas de configurações.
 */
require_once(__DIR__ . "/../lib/medoo/medoo.php");

use Medoo\Medoo;

class ConfiguracaoRepository {

    private $db;

    public function __construct() {
        $this->db = new Medoo(Config::$dbConfiguration);
    }

    public function getConfiguracao($codigo) {
        return $this->db->query("SELECT label, valor FROM configuracoes "
                        . "WHERE id = :codigo", [
                    ":codigo" => $codigo
                ])->fetchAll();
    }

}
?>  

