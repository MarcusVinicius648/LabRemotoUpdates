import { NgModule } from '@angular/core';
import { CommonModule } from '@angular/common';
import { ModalAlertComponent } from './modal-alert/modal-alert.component';
import { AngularCsvComponent } from './angular-csv/angular-csv.component';
import { Angular2CsvModule } from 'angular2-csv';



@NgModule({
  declarations: [ModalAlertComponent, AngularCsvComponent],
  imports: [
    CommonModule,
    Angular2CsvModule
  ],
  exports: [ModalAlertComponent, AngularCsvComponent]
})
export class ComponentsModule { }
