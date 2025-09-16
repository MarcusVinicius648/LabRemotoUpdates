<?php

class ExperimentoResultado {

    public $codigo;
    public $codSessaoExperimento;
    public $posX;
    public $posY;
    public $linearVel;
    public $angularVel;
    public $startTime;
    public $data;
    public $dtCriacao;
    
    function __construct($codigo = null, $codSessaoExperimento = null, $posX = null, $posY, 
            $linearVel = null, $angularVel = null, $startTime = null, $data = null, $dtCriacao = null) {
        $this->codigo = $codigo;
        $this->codSessaoExperimento = $codSessaoExperimento;
        $this->posX = $posX;
        $this->posY = $posY;
        $this->linearVel = $linearVel;
        $this->angularVel = $angularVel;
        $this->startTime = $startTime;
        $this->data = $data;
        $this->dtCriacao = $dtCriacao;
    }
    
    function getCodigo() {
        return $this->codigo;
    }

    function getCodSessaoExperimento() {
        return $this->codSessaoExperimento;
    }

    function getPosX() {
        return $this->posX;
    }

    function getPosY() {
        return $this->posY;
    }

    function getLinearVel() {
        return $this->linearVel;
    }

    function getAngularVel() {
        return $this->angularVel;
    }

    function getStartTime() {
        return $this->startTime;
    }

    function getData() {
        return $this->data;
    }

    function getDtCriacao() {
        return $this->dtCriacao;
    }

    function setCodigo($codigo) {
        $this->codigo = $codigo;
    }

    function setCodSessaoExperimento($codSessaoExperimento) {
        $this->codSessaoExperimento = $codSessaoExperimento;
    }

    function setPosX($posX) {
        $this->posX = $posX;
    }

    function setPosY($posY) {
        $this->posY = $posY;
    }

    function setLinearVel($linearVel) {
        $this->linearVel = $linearVel;
    }

    function setAngularVel($angularVel) {
        $this->angularVel = $angularVel;
    }

    function setStartTime($startTime) {
        $this->startTime = $startTime;
    }

    function setData($data) {
        $this->data = $data;
    }

    function setDtCriacao($dtCriacao) {
        $this->dtCriacao = $dtCriacao;
    }



}
