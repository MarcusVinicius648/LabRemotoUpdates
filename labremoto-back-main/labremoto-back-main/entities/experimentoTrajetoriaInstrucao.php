<?php

class ExperimentoTrajetoriaInstrucao {

    public $codigo;
    public $codSessaoExperimento;
    public $velLinear;
    public $velAngular;
    public $timer;
    public $dtCriacao;
    public $dtInicializacao;
    public $dtFinalizacao;

    function __construct($codigo = null, $codSessaoExperimento = null, 
            $velLinear = null, $velAngular = null, $timer = null, 
            $dtCriacao = null, $dtInicializacao = null, $dtFinalizacao = null) {
        $this->codigo = $codigo;
        $this->codSessaoExperimento = $codSessaoExperimento;
        $this->velLinear = $velLinear;
        $this->velAngular = $velAngular;
        $this->timer = $timer;
        $this->dtCriacao = $dtCriacao;
        $this->dtInicializacao = $dtInicializacao;
        $this->dtFinalizacao = $dtFinalizacao;
    }

    function getCodigo() {
        return $this->codigo;
    }

    function getCodSessaoExperimento() {
        return $this->codSessaoExperimento;
    }

    function getVelLinear() {
        return $this->velLinear;
    }

    function getVelAngular() {
        return $this->velAngular;
    }

    function getTimer() {
        return $this->timer;
    }

    function getDtCriacao() {
        return $this->dtCriacao;
    }

    function getDtInicializacao() {
        return $this->dtInicializacao;
    }

    function getDtFinalizacao() {
        return $this->dtFinalizacao;
    }

    function setCodigo($codigo) {
        $this->codigo = $codigo;
    }

    function setCodSessaoExperimento($codSessaoExperimento) {
        $this->codSessaoExperimento = $codSessaoExperimento;
    }

    function setVelLinear($velLinear) {
        $this->velLinear = $velLinear;
    }

    function setVelAngular($velAngular) {
        $this->velAngular = $velAngular;
    }

    function setTimer($timer) {
        $this->timer = $timer;
    }

    function setDtCriacao($dtCriacao) {
        $this->dtCriacao = $dtCriacao;
    }

    function setDtInicializacao($dtInicializacao) {
        $this->dtInicializacao = $dtInicializacao;
    }

    function setDtFinalizacao($dtFinalizacao) {
        $this->dtFinalizacao = $dtFinalizacao;
    }


}
