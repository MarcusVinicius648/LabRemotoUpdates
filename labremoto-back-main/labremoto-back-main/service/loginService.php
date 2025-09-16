<?php

/*
 *            __   __   ___        __  ___  __  
 * |     /\  |__) |__) |__   |\/| /  \  |  /  \ 
 * |___ /~~\ |__) |  \ |___  |  | \__/  |  \__/ 
 * =============================================
 * Laboratório Remoto de Robótica Móvel                                           
 * Autor: Paulo Felipe P. Parreira - paulof (at) ufop.edu.br
 * =============================================
 * Arquivo: loginService.php
 * Descrição: Service com as regras de negócio do login.
 */

require_once __DIR__ . '/../repository/loginRepository.php';
require_once __DIR__ . '/../lib/php-jwt/src/BeforeValidException.php';
require_once __DIR__ . '/../lib/php-jwt/src/ExpiredException.php';
require_once __DIR__ . '/../lib/php-jwt/src/SignatureInvalidException.php';
require_once __DIR__ . '/../lib/php-jwt/src/JWT.php';

use \Firebase\JWT\JWT;

class LoginService
{

    private $repository;

    function __construct()
    {
        $this->repository = new LoginRepository();
    }

    public function authUser($login, $password)
    {

        if (!isset($password) || !isset($login) || trim($login) == "" || trim($password) == "") {
            throw new Exception("Dados necessários não foram preenchidos (1).");
        }

        /**
         * Valida login no MinhaUFOP
         */
        $ufopToken = $this->authFromUFOP($login, $password);
        if ($ufopToken == false) {
            throw new Exception("Usuário não existente ou senha inválida (2).");
        }

        $jwtUfop = $this->parseBase64Token($ufopToken->token);
        $jwtUfop = json_decode($jwtUfop);

        $user = $this->repository->findUserById($jwtUfop->cpf);
        if (!is_array($user) || count($user) == 0) {
            $this->repository->insertUser($jwtUfop->cpf, 'h45sh', $jwtUfop->email, $jwtUfop->username);
            $user = $this->repository->findUserById($jwtUfop->cpf);
            if(!is_array($user) || count($user) == 0) {
                throw new Exception("Ocorreu um erro ao buscar usuário. (1).");
            }
        }
        $token = array(
            "iss" => Config::$iss,
            "aud" => Config::$aud,
            "data" => array(
                "matricula" => $user[0]["matricula"],
                "nome" => $user[0]["nome"],
                "perfil" => "1"
            )
        );

        $jwt = JWT::encode($token, Config::$key);
        http_response_code(200);

        echo json_encode(
            array(
                "token" => $jwt
            )
        );
    }

    public static function checkToken()
    {
        $token = null;
        $headers = apache_request_headers();
        if (isset($headers['Authorization'])) {
            $matches = array();
            preg_match('/Bearer (.*)/', $headers['Authorization'], $matches);
            if (isset($matches[1])) {
                $token = $matches[1];
            }
            try {
                // decode jwt
                $decoded = JWT::decode($token, Config::$key, array('HS256'));
                return true;
            } catch (Exception $e) {
                return false;
            }
        }
        return false;
    }

    public function getToken()
    {
        $token = null;
        $headers = apache_request_headers();
        if (isset($headers['Authorization'])) {
            $matches = array();
            preg_match('/Bearer (.*)/', $headers['Authorization'], $matches);
            if (isset($matches[1])) {
                $token = $matches[1];
            }
            try {
                // decode jwt
                $decoded = JWT::decode($token, Config::$key, array('HS256'));
                return $decoded->data;
            } catch (Exception $e) {
                return null;
            }
        }
        return null;
    }

    public function authFromUFOP($login, $password, $perfil = null, $identificacao = null)
    {
        $url = 'https://app.ufop.br/api/v1/nti/login/public/login';

        $identificacao = '12.2.1165';
        $perfil = 'G';

        if($perfil == null || $identificacao == null) {
            $data = array(
                'chave' => '192d450b-8d74-4ff7-a0e7-b672a2bce383',
                'identificador' => $login,
                'senha' => $password
            );
        } else {
             $data = array(
                'chave' => '192d450b-8d74-4ff7-a0e7-b672a2bce383',
                'identificador' => $login,
                'senha' => $password,
                'identificacao' => $identificacao,
                'perfil' => $perfil
            );
        }

        $payload = json_encode($data);

        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
        curl_setopt($ch, CURLOPT_POST, 1);
        curl_setopt($ch, CURLOPT_HTTPHEADER, array('Content-Type:application/json'));
        curl_setopt($ch, CURLOPT_POSTFIELDS, $payload);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 1);
        $output = curl_exec($ch);

        if(curl_getinfo($ch, CURLINFO_HTTP_CODE) == 200) {
            $outputJson = json_decode($output);
            if($perfil == null || $identificacao == null) {
                if(is_array($outputJson)) {                    
                    foreach ($outputJson as $profile) {
                        if($profile['perfil'] == 'G' || $profile['perfil'] == 'S') {
                            return $this->authFromUFOP($login, $password, $profile['perfil'], $profile['identificacao']);
                        }                        
                    }
                } 
            } else {
                return ($outputJson);
            }
        } else {
            return false;
        }

        curl_close($ch);
    }

    public function parseBase64Token($token) {
        $token = explode(".", $token);
        $token = base64_decode($token[1]);
        return $token;
    }
}
