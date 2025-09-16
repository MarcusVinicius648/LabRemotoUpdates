<?php

/*
 *            __   __   ___        __  ___  __  
 * |     /\  |__) |__) |__   |\/| /  \  |  /  \ 
 * |___ /~~\ |__) |  \ |___  |  | \__/  |  \__/ 
 * =============================================
 * Laboratório Remoto de Robótica Móvel                                           
 * Autor: Paulo Felipe P. Parreira - paulof (at) ufop.edu.br
 * =============================================
 * Arquivo: index.php
 * Descrição: Página inicial para inicializar o sistema.
 */


require_once("utils/inputHelper.php");

// Tratamento do CORS
// Allow from any origin
if (isset($_SERVER['HTTP_ORIGIN'])) {
    // should do a check here to match $_SERVER['HTTP_ORIGIN'] to a
    // whitelist of safe domains
    header("Access-Control-Allow-Origin: {$_SERVER['HTTP_ORIGIN']}");
    header('Access-Control-Allow-Credentials: true');
    header('Access-Control-Max-Age: 86400');    // cache for 1 day
}
// Access-Control headers are received during OPTIONS requests
if ($_SERVER['REQUEST_METHOD'] == 'OPTIONS' || $_SERVER['REQUEST_METHOD'] == 'options') {
      
        header("Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS");
       if (isset($_SERVER['HTTP_ACCESS_CONTROL_REQUEST_HEADERS']))
            header("Access-Control-Allow-Headers: {$_SERVER['HTTP_ACCESS_CONTROL_REQUEST_HEADERS']}");

        header("Access-Control-Expose-Headers", "xsrf-token, Location");
    
        exit(0);
}

ini_set('display_errors', 1);
ini_set('display_startup_errors', 0);
error_reporting(E_ALL);
require_once("config/config.php");
require_once("config/router.php");
require_once("utils/inputHelper.php");

Router::init();
?>
