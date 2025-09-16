import { Component, OnInit, Input, Output, EventEmitter } from '@angular/core';
declare var jquery: any;
declare var $: any;
/**
 * teste comentario
 */
@Component({
  selector: 'modal-alert',
  templateUrl: './modal-alert.component.html',
  styleUrls: ['./modal-alert.component.css']
})
export class ModalAlertComponent implements OnInit {

  // Controla o título do modal. Este é o valor padrão
  @Input() title: string = 'Modal title';

  // Controla o id do modal
  @Input() modalId: string = 'myModal';


  //Define se os botões de controles serão utilizados
  @Input() noButtons: Boolean = false;


  /** Controla o body do modal.
   * O Valor padrão é definido dentro de uma tag <ng-content></ng-content> na view que está chamando o componente
   * Ex.:
   * <modal-alert>
   *    <ng-content></ng-content>
   * </modal-alert>
   */
  @Input() body: string = null;

  //Redefine o texto no botão de Confirmar. Este é o valor padrão
  @Input() confirmText: string = 'Salvar';

  //Redefine o texto no botão de Cancelar. Este é o valor padrão
  @Input() cancelText: string = 'Cancelar';

  //Define se será necessário enviar um evento indicando se o botão close foi clicado
  @Input() triggerOnClose: boolean = false;

  //Define qual Objeto será repassado para a view que chamou o componente
  @Input() triggerSaveObject: any = null;

  //Controla se o modal será fechado ao clicar no botão de confirmar. Este é o valor padrão
  @Input() modalDismissOnSave: boolean = true;

  //Define o tamanho do modal, sendo: 0 - Padrão | 1 - Grande | 2- Pequeno
  @Input() modalSize: number = 0;

  @Input() zIndex = 1042;

  @Input() block = false;

  modalSizeClass: string = 'modal-lg';

  @Output() salvar$ = new EventEmitter();
  @Output() close$ = new EventEmitter();
  constructor() { }

  ngOnInit() {
    switch (this.modalSize) {
      case 1:
        this.modalSizeClass = 'modal-lg';
        break;
      case 2:
        this.modalSizeClass = 'modal-sm';
        break;
      case 3:
        this.modalSizeClass = 'modal-gg';
        break;
    }

    $(document).ready(function () {
      // Código para parar o vídeo do youtube quando o modal é fechado.
      $('.modal').each(function () {
        var src = $(this).find('iframe').attr('src');

        $(this).on('hidden.bs.modal', function () {
          $(this).find('iframe').attr('src', '');
          $(this).find('iframe').attr('src', src);

        });
      });
    });
  }

  salvarFn() {
    if (this.triggerSaveObject !== null) {
      this.salvar$.emit(this.triggerSaveObject);
    } else {
      this.salvar$.emit();
    }
  }

  closeFn() {
    this.close$.emit();
  }
  printConfirmText() {
    return this.confirmText;
  }
  printCancelText() {
    return this.cancelText;
  }

  showDisplay() {
    return (this.block) ? 'block' : 'none';
  }
}
