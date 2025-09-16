<?php

class ExperimentoTrajetoriaParametros {
    
    public $codSessaoExperimento;
    public $obstaculos;
    public $kp;
    public $kd;
    public $ki;
    public $dtCriacao;
    
    function __construct($codSessaoExperimento = null, $obstaculos = null, $kp = null, $kd = null, $ki = null, $dtCriacao = null) {
        $this->codSessaoExperimento = $codSessaoExperimento;
        $this->obstaculos = $obstaculos;
        $this->kp = $kp;
        $this->kd = $kd;
        $this->ki = $ki;
        $this->dtCriacao = $dtCriacao;
    }

    function getCodSessaoExperimento() {
        return $this->codSessaoExperimento;
    }

    function getObstaculos() {
        return $this->obstaculos;
    }

    function getKp() {
        return $this->kp;
    }

    function getKd() {
        return $this->kd;
    }

    function getKi() {
        return $this->ki;
    }

    function getDtCriacao() {
        return $this->dtCriacao;
    }

    function setCodSessaoExperimento($codSessaoExperimento) {
        $this->codSessaoExperimento = $codSessaoExperimento;
    }

    function setObstaculos($obstaculos) {
        $this->obstaculos = $obstaculos;
    }

    function setKp($kp) {
        $this->kp = $kp;
    }

    function setKd($kd) {
        $this->kd = $kd;
    }

    function setKi($ki) {
        $this->ki = $ki;
    }
    function setDtCriacao($dtCriacao) {
        $this->dtCriacao = $dtCriacao;
    }


}
