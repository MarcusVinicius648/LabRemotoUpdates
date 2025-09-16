<?php

/*
 *            __   __   ___        __  ___  __  
 * |     /\  |__) |__) |__   |\/| /  \  |  /  \ 
 * |___ /~~\ |__) |  \ |___  |  | \__/  |  \__/ 
 * =============================================
 * Laboratório Remoto de Robótica Móvel                                           
 * Autor: Paulo Felipe P. Parreira - paulof (at) ufop.edu.br
 * =============================================
 * Arquivo: loginController.php
 * Descrição: Controller utilizado para gerenciar as operações de autenticação.
 */

require_once(__DIR__ . "/../service/loginService.php");

class LoginController {

    private $loginService;

    public function __construct() {
        $this->loginService = new LoginService();
    }

    public function authUser() {
        try {
            $body = InputHelper::getBodyJson();
            $this->loginService->authUser($body->login, $body->password);
        } catch (Exception $ex) {
            http_response_code(400);
            echo json_encode(["status" => 400, "error" => $ex->getMessage()]);
        }
    }
    
    public function checkAuth() {
        try {
//            if($this->)
        } catch (Exception $ex) {
            http_response_code(400);
            echo json_encode(["status" => 400, "error" => $ex->getMessage()]);
        }
    }

}

?>
