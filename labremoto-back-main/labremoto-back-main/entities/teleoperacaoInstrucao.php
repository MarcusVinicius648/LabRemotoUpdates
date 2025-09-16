<?php

class TeleoperacaoInstrucao {

    public $codigo;
    public $codSessaoExperimento;
    public $instrucao;
    public $dtCriacao;

    function __construct($codigo = null, $codSessaoExperimento = null, 
            $instrucao = null, $dtCriacao = null) {
        $this->codigo = $codigo;
        $this->codSessaoExperimento = $codSessaoExperimento;
        $this->instrucao = $instrucao;
        $this->dtCriacao = $dtCriacao;
    }

    /**
     * Get the value of codSessaoExperimento
     */ 
    public function getCodSessaoExperimento()
    {
        return $this->codSessaoExperimento;
    }

    /**
     * Set the value of codSessaoExperimento
     *
     * @return  self
     */ 
    public function setCodSessaoExperimento($codSessaoExperimento)
    {
        $this->codSessaoExperimento = $codSessaoExperimento;

        return $this;
    }

    /**
     * Get the value of instrucao
     */ 
    public function getInstrucao()
    {
        return $this->instrucao;
    }

    /**
     * Set the value of instrucao
     *
     * @return  self
     */ 
    public function setInstrucao($instrucao)
    {
        $this->instrucao = $instrucao;

        return $this;
    }

    /**
     * Get the value of dtCriacao
     */ 
    public function getDtCriacao()
    {
        return $this->dtCriacao;
    }

    /**
     * Set the value of dtCriacao
     *
     * @return  self
     */ 
    public function setDtCriacao($dtCriacao)
    {
        $this->dtCriacao = $dtCriacao;

        return $this;
    }

    /**
     * Get the value of codigo
     */ 
    public function getCodigo()
    {
        return $this->codigo;
    }

    /**
     * Set the value of codigo
     *
     * @return  self
     */ 
    public function setCodigo($codigo)
    {
        $this->codigo = $codigo;

        return $this;
    }
}
