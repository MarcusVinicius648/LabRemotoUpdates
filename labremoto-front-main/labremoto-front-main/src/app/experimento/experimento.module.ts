import { NgModule } from '@angular/core';
import { CommonModule, DatePipe } from '@angular/common';
import { ExperimentoComponent } from './experimento.component';
import { CountdownModule } from 'ngx-countdown';
import { ExperimentoService } from './experimento.service';
import { ComponentsModule } from 'app/components/components.module';
import { FormsModule, ReactiveFormsModule } from '@angular/forms';
import { BrowserAnimationsModule } from '@angular/platform-browser/animations';

@NgModule({
  declarations: [ExperimentoComponent],
  imports: [
    CommonModule,
    ComponentsModule,
    CountdownModule,
    FormsModule,
    ReactiveFormsModule
  ],
  providers: [ExperimentoService, DatePipe]
})
export class ExperimentoModule { }
