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

require_once __DIR__ . '/../repository/historicoRepository.php';
require_once __DIR__ . '/../service/loginService.php';
require_once __DIR__ . '/../entities/sessao.php';

class HistoricoService {

    private $repository;
    private $loginService;

    function __construct() {
        $this->repository = new HistoricoRepository();
        $this->loginService = new LoginService();
    }
    
    function listExperimentosByMatriculaAtiva() {
        $token = $this->loginService->getToken();
        if($token == null) {
            throw new Exception("Nenhuma usuário ativo encontrado.");
        }
        return $this->repository->listExperimentoBySessaoMatricula($token->matricula);
    }

}

?>
