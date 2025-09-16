import { NgModule } from '@angular/core';
import { CommonModule, DatePipe } from '@angular/common';
import { HistoryListComponent } from './history-list/history-list.component';
import { HistoryService } from './history.service';
import { RouterModule } from '@angular/router';
import { HistoryExperimentoComponent } from './history-experimento/history-experimento.component';
import { BrowserAnimationsModule } from '@angular/platform-browser/animations';
import { NgxChartsModule } from '@swimlane/ngx-charts';
import { Angular2CsvModule } from 'angular2-csv';
import { ComponentsModule } from 'app/components/components.module';

@NgModule({
  declarations: [HistoryListComponent, HistoryExperimentoComponent],
  imports: [
    CommonModule,
    RouterModule, 
    NgxChartsModule,
    BrowserAnimationsModule,
    Angular2CsvModule,
    ComponentsModule
  ],
  providers: [HistoryService, DatePipe]
})
export class HistoryModule { }
