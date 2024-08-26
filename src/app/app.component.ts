import { Component } from '@angular/core';
import { FormBuilder, FormGroup, Validators } from '@angular/forms';
import { HackService } from './hack.service';

@Component({
  selector: 'app-root',
  templateUrl: './app.component.html',
  styleUrls: ['./app.component.scss']
})
export class AppComponent {

  result: any[] = [];
  err: string = '';
  form: FormGroup;

  constructor(
    public fb: FormBuilder,
    public hackService: HackService,
  ) {
    this.form = this.fb.group({
      serial: ['', Validators.required],
      mac: ['', Validators.required],
      config: [null, Validators.required],
      data: [],
    });
  }

  submit() {
    const { serial, mac, data } = this.form.value;

    this.err = '';
    this.result = [];

    this.hackService.letsPawn(serial, mac, data).then((res) => {
      this.result = res;
    }, err => {
      this.err = err || 'Something went wrong';
    });
  }

  onFileChange(event: any) {
    const file: File = event.target.files[0];

    if (file) {
      const reader = new FileReader();

      reader.onload = (e: any) => {
        // 'e.target.result' contains the file data as an ArrayBuffer
        const fileData: ArrayBuffer = e.target.result;
        this.form.patchValue({
          data: new Uint8Array(fileData),
        })
      };

      reader.readAsArrayBuffer(file);
    }
  }

}
