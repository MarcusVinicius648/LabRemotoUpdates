import { AgendaService } from './agenda.service';
import { ChangeDetectorRef, Component, EventEmitter, OnInit } from '@angular/core';
import {
  ChangeDetectionStrategy,
  ViewChild,
  TemplateRef,
} from '@angular/core';
import {
  startOfDay,
  endOfDay,
  subDays,
  addDays,
  endOfMonth,
  isSameDay,
  isSameMonth,
  addHours,
  startOfWeek,
  startOfMonth,
  endOfWeek,
  format,
} from 'date-fns';
import { Observable, Subject } from 'rxjs';
import { DatePipe, registerLocaleData } from '@angular/common';
import localePt from '@angular/common/locales/pt';

registerLocaleData(localePt);
import {
  CalendarEvent,
  CalendarEventAction,
  CalendarEventTimesChangedEvent,
  CalendarView,
} from 'angular-calendar';
import { ThemePalette } from '@angular/material/core';
import { FormBuilder, FormControl, FormGroup } from '@angular/forms';
import { map } from 'rxjs/operators';
import { ToastrService } from 'ngx-toastr';
const colors: any = {
  red: {
    primary: '#ad2121',
    secondary: '#FAE3E3',
  },
  blue: {
    primary: '#1e90ff',
    secondary: '#D1E8FF',
  },
  yellow: {
    primary: '#e3bc08',
    secondary: '#FDF1BA',
  },
};
@Component({
  selector: 'app-agenda',
  templateUrl: './agenda.component.html',
  styleUrls: ['./agenda.component.css'],
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class AgendaComponent implements OnInit {

  /**  
   *  Parametros do calendario
   **/
  view: CalendarView = CalendarView.Month;
  CalendarView = CalendarView;
  locale: string = 'pt-BR';
  viewDate: Date = new Date();
  events$: Observable<CalendarEvent<{ film: any }>[]>;
  public disabled = false;
  public showSpinners = true;
  public showSeconds = false;
  public touchUi = false;
  public enableMeridian = false;
  public minDate: Date;
  public maxDate: Date;
  public stepHour = 1;
  public stepMinute = 1;
  public stepSecond = 1;
  public color: ThemePalette = 'primary';
  public disableMinute = false;
  public hideTime = false;
  public dateControl = new FormControl(null);
  refresh: Subject<any> = new Subject();
  viewChange = new EventEmitter<CalendarView>();
  activeDayIsOpen: boolean = true;


  /**
   *  Parametros do formulario de agendamento[]
   */

  public agendarHorarioForm: FormGroup;
  public registroAgendaSent = false;
  public registroAgendaMsg = '';


  /**
   * Lista de Agendamentos do usuário
   */

  public listaAgendamentos: any[];



  constructor(private agendaService: AgendaService,
    private datePipe: DatePipe,
    private formBuilder: FormBuilder,
    private changeDetectRef: ChangeDetectorRef,
    private toastrService: ToastrService) { }

  ngOnInit() {
    this.agendaService.getListaAgendaUsuario().subscribe((resp: any) => {
      this.listaAgendamentos = resp;
    });
    this.listAgendaFull();
    this.initAgendaHorarioForm();
  }


  initAgendaHorarioForm() {
    let dtInicio = new Date();
    let dtFim = new Date(dtInicio).setMinutes(dtInicio.getMinutes() + 20);
    this.agendarHorarioForm = this.formBuilder.group({
      dtAgendamento: new FormControl(this.datePipe.transform(dtInicio, 'yyyy-MM-dd')),
      horaAgendamento: new FormControl(this.datePipe.transform(dtInicio, 'HH')),
      minutoAgendamento: new FormControl(this.datePipe.transform(dtInicio, 'm')),
      horaFim: new FormControl(this.datePipe.transform(dtFim, 'HH')),
      minutoFim: new FormControl(this.datePipe.transform(dtFim, 'm'))
    });
  }

  updateHorarioFim() {
    let dtInicio = new Date();
    let dtFim = new Date();
    dtInicio.setHours(this.agendarHorarioForm.get('horaAgendamento').value);
    dtInicio.setMinutes(this.agendarHorarioForm.get('minutoAgendamento').value);
    console.log(dtInicio);
    dtFim.setHours(dtInicio.getHours());
    dtFim.setMinutes(dtInicio.getMinutes() + 20);
    this.agendarHorarioForm.get('horaFim').setValue(dtFim.getHours());
    this.agendarHorarioForm.get('minutoFim').setValue(dtFim.getMinutes());
  }

  setRegistroAgenda() {
    if (!this.agendarHorarioForm.valid) {
      return;
    }
    this.agendaService.setRegistroAgenda(this.agendarHorarioForm.value).subscribe((resp: any) => {
      this.registroAgendaSent = true;
      this.registroAgendaMsg = '';
      this.listAgendaFull();
      this.agendaService.getListaAgendaUsuario().subscribe((resp: any) => {
        this.listaAgendamentos = resp;
      });
      this.changeDetectRef.detectChanges();
    }, (err) => {
      this.registroAgendaSent = true;
      this.registroAgendaMsg = err.error.error;
      this.changeDetectRef.detectChanges();
    });

  }


  handleEvent(action: string, event: CalendarEvent): void {
  }

  setView(view: CalendarView) {
    this.view = view;
    this.listAgendaFull();
  }

  listAgendaFull() {
    this.activeDayIsOpen = false;
    const getStart: any = {
      month: startOfMonth,
      week: startOfWeek,
      day: startOfDay,
    }[this.view];

    const getEnd: any = {
      month: endOfMonth,
      week: endOfWeek,
      day: endOfDay,
    }[this.view];
    this.events$ = this.agendaService.getListaAgendaFull(format(getStart(this.viewDate), 'yyyy-MM-dd'), format(getEnd(this.viewDate), 'yyyy-MM-dd'))
      .pipe(
        map((results: any) => {
          return results.map((result: any) => {
            return {
              title: result[0] + ' - ' + this.datePipe.transform(new Date(result[3]), 'dd/MM/yyyy HH:mm '),
              start: new Date(result[3]
              ),
              end: new Date(result[3]),
              color: colors.blue,
              allDay: false,
              meta: {
                result,
              },
            };
          });
        })
      );
  }

  removerAgendamento(codigo: number) {
    this.agendaService.removerAgendamento(codigo).subscribe((resp: any) => {
      this.toastrService.success("Agendamento removido com sucesso.", "Sucesso",  { positionClass: 'toast-top-center' });
      this.listAgendaFull();
      this.agendaService.getListaAgendaUsuario().subscribe((resp: any) => {
        this.listaAgendamentos = resp;
      });
      this.changeDetectRef.detectChanges();

    }, (err: any) => {
      this.toastrService.error(err.error.error, "Ocorreu um Erro",  { positionClass: 'toast-top-center' });
    });
  }

}
