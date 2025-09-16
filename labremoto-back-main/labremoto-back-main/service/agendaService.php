<?php

/*
 *            __   __   ___        __  ___  __  
 * |     /\  |__) |__) |__   |\/| /  \  |  /  \ 
 * |___ /~~\ |__) |  \ |___  |  | \__/  |  \__/ 
 * =============================================
 * Laboratório Remoto de Robótica Móvel                                           
 * Autor: Paulo Felipe P. Parreira - paulof (at) ufop.edu.br
 * =============================================
 * Arquivo: laboratorioService.php
 * Descrição: Service com as regras de gerais do laboratório.
 */

require_once __DIR__ . '/../repository/agendaRepository.php';
require_once __DIR__ . '/../repository/configuracaoRepository.php';
require_once __DIR__ . '/../service/loginService.php';
require_once __DIR__ . '/../entities/sessao.php';

class AgendaService {

    private $repository;
    private $configuracaoRepository;
    private $loginService;

    function __construct() {
        $this->repository = new AgendaRepository();
        $this->configuracaoRepository = new ConfiguracaoRepository();
        $this->loginService = new LoginService();
    }

    function listAgendaUsuario() {
        $token = $this->loginService->getToken();
        if ($token == null) {
            throw new Exception("Nenhuma usuário ativo encontrado.");
        }
        return $this->repository->listAgendaUsuario($token->matricula);
    }

    function listAgendaFull($dtInicio, $dtFim) {

        $format = 'Y-m-d H:i:s';
        $dtInicioFrmt = DateTime::createFromFormat($format, $dtInicio . " 00:00:00");
        $dtFimFrmt = DateTime::createFromFormat($format, $dtFim . " 23:59:59");
        return $this->repository->listAgendaAllBetweenDates($dtInicioFrmt->format('Y-m-d H:i:s'), $dtFimFrmt->format('Y-m-d H:i:s'));
    }

    function setRegistroAgenda($registroAgenda) {
        $token = $this->loginService->getToken();
        if ($token == null) {
            throw new Exception("Nenhuma usuário ativo encontrado.");
        }

        if(strlen($registroAgenda->minutoAgendamento) == 1) {
            $registroAgenda->minutoAgendamento = '0'.$registroAgenda->minutoAgendamento;
        }
        $strDtInicio = $registroAgenda->dtAgendamento . ' ' . $registroAgenda->horaAgendamento . ':' . $registroAgenda->minutoAgendamento;
        if (!$dtInicio = DateTime::createFromFormat("Y-m-d H:i", $strDtInicio)) {
            throw new Exception("Não foi possível reconhecer a data informada. " . $strDtInicio);
        }

        if ((new DateTime()) > $dtInicio) {
            throw new Exception("A data informada já passou.");
        }

        if (!$this->checkDisponibilidadeAgenda($dtInicio)) {
            throw new Exception("Já existe agendamento para o horário selecionado.");
        }

        if (count($this->listAgendaUsuario()) >= 5) {
            throw new Exception("Você não pode possuir mais de 5 agendamentos no laboratório.");
        }

        if (!$this->repository->setRegistroAgenda(["matricula" => $token->matricula, "dtAgendamento" => $strDtInicio])) {
            throw new Exception("Não foi possível realizar o agendamento.");
        } else {
            return true;
        }
    }

    function checkDisponibilidadeAgenda($dtInicio, $excludeUser = false) {
        $duracaoSessao = $this->configuracaoRepository->getConfiguracao(1)[0]['valor'];
        $dtFim = clone $dtInicio;
        $dtInicio->modify('-' . $duracaoSessao . ' minutes');
        $dtFim->modify('+' . $duracaoSessao . ' minutes');
        if (!$excludeUser) {
            if ($this->repository->checkDisponibilidadeAgenda($dtInicio->format('Y-m-d H:i:s'), $dtFim->format('Y-m-d H:i:s'))[0][0] > 0) {
                return false;
            } else {
                return true;
            }
        } else {
            $token = $this->loginService->getToken();
            if ($token == null) {
                throw new Exception("Nenhuma usuário ativo encontrado.");
            }
            if ($this->repository->checkDisponibilidadeAgendaExcludeCurrentUser($dtInicio->format('Y-m-d H:i:s'), $dtFim->format('Y-m-d H:i:s'), $token->matricula)[0][0] > 0) {
                return false;
            } else {
                return true;
            }
        }
    }

    function removerAgendamento($codigo) {
        $token = $this->loginService->getToken();
        if ($token == null) {
            throw new Exception("Nenhuma usuário ativo encontrado.");
        }

        $agendamento = $this->repository->getAgendamentoByCodigo($codigo);
        if ($agendamento["matricula"] != $token->matricula) {
            throw new Exception("Você não pode excluir um agendamento que não é seu.");
        }

        if (!$this->repository->removerAgendamento($codigo, $token->matricula)) {
            throw new Exception("Não foi possível remover o agendamento.");
        }

        return true;
    }

}

?>
