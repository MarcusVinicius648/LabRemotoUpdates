<?php

/*
 *            __   __   ___        __  ___  __  
 * |     /\  |__) |__) |__   |\/| /  \  |  /  \ 
 * |___ /~~\ |__) |  \ |___  |  | \__/  |  \__/ 
 * =============================================
 * Laboratório Remoto de Robótica Móvel                                           
 * Autor: Paulo Felipe P. Parreira - paulof (at) ufop.edu.br
 * =============================================
 * Arquivo: router.php
 * Descrição: Arquivo responsável por gerenciar as rotas da API.
 */

require_once("routes.php");
require_once(__DIR__ . "/../service/loginService.php");
$files = glob(__DIR__ . "/../controller/*.php");
foreach ($files as $file) {
    require($file);
}

class Router {
    
    public static $whiteList = ["login"];

    public static function init() {
        $method = $_SERVER['REQUEST_METHOD'];
        $requestUrlVars = explode("/", $_GET['vars']);
        if(!Router::validateToken($requestUrlVars)) {
            http_response_code(400);
            echo json_encode(["status" => 403, "error" => "Sem permissão para acessar o recurso."]);
            return;
        }
        Router::route($requestUrlVars, $method);
    }

    private static function route($requestUrlVars, $method) {
        try {
            $route = Routes::$routes[$requestUrlVars[0]];
            $routeClass = $route[0];
            $class = new ReflectionClass($routeClass);
            $obj = $class->newInstance();

            if (!key_exists(1, $requestUrlVars)) {
                $requestUrlVars[1] = "";
            }
            $method = $class->getMethod($route[1][$method][$requestUrlVars[1]][0]);
            $method->invoke($obj);
        } catch (Exception $ex) {
            echo $ex->getMessage();
            http_response_code(404);
            echo json_encode(["status" => 404, "error" => "Rota não encontrada"]);
        }
        //$class = new ReflectionClass($requestUrlVars[0]);
    }
    
    private static function validateToken($url) {
        if(in_array($url[0], Router::$whiteList)) {
            return true;
        }
        return LoginService::checkToken();
    }

}

?>
