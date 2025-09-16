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

class LoginRepository {
    
    private $db;
    
    public function __construct() {
        $this->db = new Medoo(Config::$dbConfiguration);
    }
    
    public function findUserByIdAndPassword($login, $password) {
        $password = md5($password);
        $user = $this->db->select('usuario', '*', ["matricula" => $login, "senha" => $password]);
        return $user;
    }

    public function findUserById($login) {
        $user = $this->db->select('usuario', '*', ["matricula" => $login]);
        return $user;
    }


    public function insertUser($login, $password, $email, $username) {
        $password = md5("h4sh");
        if ($this->db->insert("usuario", [
            "matricula" => $login,
            "senha" => $password,
            "nome" => $username,
            "email" => $email,
            "tipo_usuario" => 0,
            "dt_criacao" => date('Y-m-d')
        ]) == true) {
    return true;
} else {
    return false;
}
    }
    
}

?>
