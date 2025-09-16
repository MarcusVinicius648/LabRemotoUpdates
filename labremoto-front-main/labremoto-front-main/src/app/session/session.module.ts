import { NgModule } from '@angular/core';
import { CommonModule } from '@angular/common';
import { SetupComponent } from './setup/setup.component';
import { RouterModule } from '@angular/router';

@NgModule({
  declarations: [SetupComponent],
  imports: [
    CommonModule,
    RouterModule
  ]
})
export class SessionModule { }