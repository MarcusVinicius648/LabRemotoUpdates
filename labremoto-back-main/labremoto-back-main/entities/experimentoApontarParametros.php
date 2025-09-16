<?php

class ExperimentoApontarParametros {

    public $codSessaoExperimento;
    public $objetivoX;
    public $objetivoY;
    public $algoritmoBusca;
    public $tipoControlador;
    public $obstaculos;
    public $heuristica;
    public $kp;
    public $kd;
    public $ki;
    public $kp_ang;
    public $kd_ang;
    public $ki_ang;
    public $tamanhoMapaBusca;
    public $tamanhoAreaSeguranca;
    public $dtCriacao;
    public $estatisticasBusca;

    function __construct($codSessaoExperimento = null, $tipoControlador = null, $algoritmoBusca = null, $obstaculos = null, $kp_ang = null, $kd_ang = null, $ki_ang = null, $kp = null, $kd = null, $ki = null, $tamanhoMapaBusca = null, $tamanhoAreaSeguranca = null, $heuristica = null, $dtCriacao = null, $estatisticaBusca = null) {
        $this->codSessaoExperimento = $codSessaoExperimento;
        $this->algoritmoBusca = $algoritmoBusca;
        $this->tipoControlador = $tipoControlador;
        $this->obstaculos = $obstaculos;
        $this->kp = $kp;
        $this->kd = $kd;
        $this->ki = $ki;
        $this->kp_ang = $kp_ang;
        $this->kd_ang = $kd_ang;
        $this->ki_ang = $ki_ang;
        $this->tamanhoMapaBusca = $tamanhoMapaBusca;
        $this->tamanhoAreaSeguranca = $tamanhoAreaSeguranca;
        $this->dtCriacao = $dtCriacao;
        $this->heuristica = $heuristica;
        $this->estatisticasBusca = $estatisticaBusca;
    }

    function getCodSessaoExperimento() {
        return $this->codSessaoExperimento;
    }

    function getAlgoritmoBusca() {
        return $this->algoritmoBusca;
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
    
    function getKp_ang() {
        return $this->kp_ang;
    }

    function getKd_ang() {
        return $this->kd_ang;
    }

    function getKi_ang() {
        return $this->ki_ang;
    }

    function getTamanhoMapaBusca() {
        return $this->tamanhoMapaBusca;
    }

    function getTamanhoAreaSeguranca() {
        return $this->tamanhoAreaSeguranca;
    }

    function getDtCriacao() {
        return $this->dtCriacao;
    }

    function setCodSessaoExperimento($codSessaoExperimento) {
        $this->codSessaoExperimento = $codSessaoExperimento;
    }

    function setAlgoritmoBusca($algoritmoBusca) {
        $this->algoritmoBusca = $algoritmoBusca;
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


    function setKp_ang($kp) {
        $this->kp_ang = $kp;
    }

    function setKd_ang($kd) {
        $this->kd_ang = $kd;
    }

    function setKi_ang($ki) {
        $this->ki_ang = $ki;
    }


    function setTamanhoMapaBusca($tamanhoMapaBusca) {
        $this->tamanhoMapaBusca = $tamanhoMapaBusca;
    }

    function setTamanhoAreaSeguranca($tamanhoAreaSeguranca) {
        $this->tamanhoAreaSeguranca = $tamanhoAreaSeguranca;
    }

    function setDtCriacao($dtCriacao) {
        $this->dtCriacao = $dtCriacao;
    }

    function getObjetivoX() {
        return $this->objetivo_x;
    }

    function getObjetivoY() {
        return $this->objetivo_y;
    }

    function setObjetivoX($objetivo_x) {
        $this->objetivo_x = $objetivo_x;
    }

    function setObjetivoY($objetivo_y) {
        $this->objetivo_y = $objetivo_y;
    }

    function getHeuristica() {
        return $this->heuristica;
    }

    function setHeuristica($heuristica) {
        $this->heuristica = $heuristica;
    }

    function getEstatisticaBusca() {
        return $this->estatisticasBusca;
    }

    function setEstatisticaBusca($estatisticaBusca) {
        $this->estatisticasBusca = $estatisticaBusca;
    }

    function getTipoControlador() {
        return $this->tipoControlador;
    }

    function setTipoControlador($tipoControlador) {
        $this->tipoControlador = $tipoControlador;
    }




}
