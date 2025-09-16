import { Injectable } from '@angular/core';
import {BehaviorSubject} from 'rxjs/BehaviorSubject';
import { Subscription } from 'rxjs/Subscription';

@Injectable()
export class SharedDataService {

  subscripions: Subscription[] = [];
  chanels: Map< any, any > = new Map();
  observable: Map< any, any > = new Map();
  constructor() { }

  verifyChannel(label: any) {
    if ( !this.chanels.has(label) ) {
      const hashmap = new BehaviorSubject<string>('');
      this.chanels.set( label, hashmap );
      this.observable.set(label, this.chanels.get(label).asObservable() );
    }
  }
  publish(label: any, mensagem: any) {
    if ( !mensagem || typeof(mensagem) === 'undefined') { return; }
    this.verifyChannel(label);
    this.chanels.get(label).next(mensagem);
  }
  subscribe(label: any, callback) {
    this.verifyChannel(label);
    this.subscripions.push(this.observable.get(label).subscribe(callback));

  }

  unsubscribe(label: any) {
    this.subscripions.forEach((subs: Subscription) => {
      subs.unsubscribe();
    });
    this.subscripions = [];
  }

}
