<?php

class Sessao {

    public $codigo;
    public $matricula;
    public $ativo;
    public $dtInicio;
    public $dtFim;

    function __construct($matricula, $ativo, $dtInicio, $dtFim) {
        $this->matricula = $matricula;
        $this->ativo = $ativo;
        $this->dtInicio = $dtInicio;
        $this->dtFim = $dtFim;
    }

    function getMatricula() {
        return $this->matricula;
    }

    function getAtivo() {
        return $this->ativo;
    }

    function getDtInicio() {
        return $this->dtInicio;
    }

    function getDtFim() {
        return $this->dtFim;
    }

    function setMatricula($matricula) {
        $this->matricula = $matricula;
    }

    function setAtivo($ativo) {
        $this->ativo = $ativo;
    }

    function setDtInicio($dtInicio) {
        $this->dtInicio = $dtInicio;
    }

    function setDtFim($dtFim) {
        $this->dtFim = $dtFim;
    }
    
    function getCodigo() {
        return $this->codigo;
    }

    function setCodigo($codigo) {
        $this->codigo = $codigo;
    }



}
