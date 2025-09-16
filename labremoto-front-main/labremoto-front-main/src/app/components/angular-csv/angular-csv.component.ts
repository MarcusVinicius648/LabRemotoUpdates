import { Component, OnInit } from '@angular/core';
import { Angular2CsvComponent } from 'angular2-csv';

@Component({
  selector: 'angular-csv-btn',
  template: '<div (click)=\"onDownload()\"><ng-content></ng-content></div>',
  styleUrls: ['./angular-csv.component.css']
})
export class AngularCsvComponent extends Angular2CsvComponent {}
