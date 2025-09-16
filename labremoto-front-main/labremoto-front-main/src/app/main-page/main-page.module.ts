import { NgModule } from '@angular/core';
import { CommonModule, DatePipe } from '@angular/common';
import { MainPageComponent } from './main-page.component';
import { RouterModule } from '@angular/router';

@NgModule({
  declarations: [MainPageComponent],
  imports: [
    CommonModule,
    RouterModule
  ],
  providers: [
    DatePipe
  ]
})
export class MainPageModule { }
