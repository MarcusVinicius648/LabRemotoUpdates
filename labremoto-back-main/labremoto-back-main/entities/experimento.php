<?php

class Experimento {

    public $codigo;
    public $codSessao;
    public $codExperimento;
    public $parametros;
    public $ativo;
    public $dtInicio;
    public $label;

    function __construct($codigo = "", $codSessao = "", $codExperimento = "", $parametros = "", $dtInicio = "", $ativo = "") {
        $this->codigo = $codigo;
        $this->codSessao = $codSessao;
        $this->codExperimento = $codExperimento;
        $this->parametros = $parametros;
        $this->ativo = $ativo;
        $this->dtInicio = $dtInicio;
    }

    function getCodigo() {
        return $this->codigo;
    }

    function getCodSessao() {
        return $this->codSessao;
    }

    function getCodExperimento() {
        return $this->codExperimento;
    }

    function getParametros() {
        return $this->parametros;
    }

    function getAtivo() {
        return $this->ativo;
    }

    function getDtInicio() {
        return $this->dtInicio;
    }

    function setCodigo($codigo) {
        $this->codigo = $codigo;
    }

    function setCodSessao($codSessao) {
        $this->codSessao = $codSessao;
    }

    function setCodExperimento($codExperimento) {
        $this->codExperimento = $codExperimento;
    }

    function setParametros($parametros) {
        $this->parametros = $parametros;
    }

    function setAtivo($ativo) {
        $this->ativo = $ativo;
    }

    function setDtInicio($dtInicio) {
        $this->dtInicio = $dtInicio;
    }
    
    function getLabel() {
        return $this->label;
    }

    function setLabel($label) {
        $this->label = $label;
    }



}
