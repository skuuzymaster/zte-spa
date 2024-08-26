import { Injectable } from '@angular/core';
import { parseString } from 'browser-xml2js';
import { inflate } from 'pako';
import { crc32 } from '@foxglove/crc';
import { AES, enc, mode, pad, SHA256 } from 'crypto-js';
import { fromByteArray } from 'base64-js';

@Injectable({ providedIn: 'root' })
export class HackService {
  constructor() { }

  letsPawn(serial: string, mac: string, file: Uint8Array): Promise<any> {
    return new Promise(async (ok, nook) => {
      try {
        if (!!!file) {
          return nook('Invalid config.bin');
        }

        if (/^[0-9a-z]{12,12}$/i.test(serial) === false) {
          return nook('Invalid Serial');
        }

        if (/^[0-9a-f]{12,12}$/i.test(mac) === false) {
          return nook('Invalid MAC Address');
        }

        const key = this.getKey(serial, mac);

        const header = this.readHeader(file);

        const signature = this.readSignature(header.value, header.pos);

        const payloadType = this.readPayloadType(header.value, signature.pos);

        const decrypted = await this.decrypt(header.value, payloadType.pos, key) as any;

        const decompress = this.decompress(decrypted.value, decrypted.pos);

        parseString(new TextDecoder('utf-8').decode(decompress.value), (err, result) => {
          if (err) {
            console.error('Error parsing XML:', err);
            return;
          }

          const rows = result.DB.Tbl.find((tbl: any) => tbl.$.name === 'DevAuthInfo')?.Row;

          const credentials: { username: string; password: string, level: string }[] = [];

          for (const row of rows) {
            const appId = row.DM.find((dm: any) => dm.$.name === 'AppID')?.$.val;
            if (!!!appId || appId === '1') {
              const username = row.DM.find((dm: any) => dm.$.name === 'User')?.$.val;
              const password = row.DM.find((dm: any) => dm.$.name === 'Pass')?.$.val;
              const level = row.DM.find((dm: any) => dm.$.name === 'Level')?.$.val;

              if (username && password) {
                credentials.push({ username, password, level });
              }
            }
          }

          return ok(credentials);
        });

      } catch (err: any) {
        console.error(err);
        return nook(err?.message || 'Something went wrong');
      }
    });
  }

  getKey(serial: string, mac: string) {
    let macAddr = '';
    for (let i = 12; i > 0; i -= 2) {
      const m = Array.from(String(mac).toLowerCase());
      macAddr += `${m[i - 2]}${m[i - 1]}`;
    }
    return String(serial).toUpperCase().slice(4) + macAddr;
  }

  readHeader(file: Uint8Array) {
    const data = file.buffer;
    const buffer = data.slice(0, 16);

    const magic = this.unpack(buffer, 4, true).map((x) => x.toString(16)).join('');

    if (magic !== '999999994444444455555555aaaaaaaa') {
      console.log('Invalid magic');
      return { value: data, pos: 0 };
    }

    const header = data.slice(16, 128);
    const h2 = this.unpack(header, 4, true);

    if (h2[2] !== 4) {
      throw new Error('Invalid header');
    }

    const size = h2[13];
    const fileSize = h2[14];

    if (size + fileSize !== data.byteLength) {
      throw new Error('Invalid file size');
    }

    return { value: data, pos: 128 };
  }

  readSignature(buffer: ArrayBuffer, pos: number) {
    const ret = this.unpack(buffer.slice(pos, pos + 12), 4);
    pos += 12;

    if (ret[0] !== 0x04030201) {
      console.log('Invalid signature');
      return { value: null, pos: 0 };
    }

    const length = ret[2];

    const signature = new TextDecoder('utf-8').decode(buffer.slice(pos, pos + length));
    pos += length;

    return { value: signature, pos };
  }

  unpack(buffer: ArrayBuffer, size: number, littleEndian = false) {
    const h2: number[] = [];
    let x = 0;
    for (let i = 0; i < buffer.byteLength; i += size) {
      x += 1;
      const intValue = new DataView(buffer, i, size).getUint32(0, littleEndian);
      h2.push(intValue);
    }
    return h2;
  }

  readPayloadType(data: ArrayBuffer, pos: number) {
    const ret = this.readPayload(data, pos);
    return { value: ret.value[1], pos: ret.pos };
  }

  readPayload(data: ArrayBuffer, pos: number) {
    const buffer = data.slice(pos, pos + 60);
    pos += 60;
    const ret = this.unpack(buffer, 4);
    if (ret[0] !== 0x01020304) {
      throw new Error('Payload header does not start with the payload magic');
    }

    return { value: ret, pos };
  }

  async decrypt(data: ArrayBuffer, pos: number, key: string) {
    try {
      const chunk = this.readChunk(data, pos);
      const encrypted = chunk.value;
      pos = chunk.pos;

      // const key256 = enc.Utf8.parse(SHA256(key));
      const key256 = SHA256(key);
      const iv256 = SHA256('ZTE%FN$GponNJ025');
      const encryptedBase64 = fromByteArray(new Uint8Array(encrypted));

      const decrypted = AES.decrypt({ ciphertext: enc.Base64.parse(encryptedBase64) } as any, key256, {
        iv: iv256,
        mode: mode.CBC,
        padding: pad.NoPadding,
      }) as CryptoJS.lib.WordArray;

      const decryptedData = this.CryptJsWordArrayToUint8Array(decrypted);

      const payloadChedk = this.readPayloadType(decryptedData.buffer, 0);
      // const payloadChedk = this.readPayloadType(this.CryptJsWordArrayToUint8Array(decrypted), 0);

      return { value: decryptedData.buffer, pos: payloadChedk.pos };
    } catch (err) {
      console.error(err)
      throw new Error('Invalid Key');
    }

  }

  CryptJsWordArrayToUint8Array(wordArray: CryptoJS.lib.WordArray) {
    const l = wordArray.sigBytes;
    const words = wordArray.words;
    const result = new Uint8Array(l);
    var i = 0 /*dst*/, j = 0 /*src*/;
    while (true) {
      // here i is a multiple of 4
      if (i == l)
        break;
      var w = words[j++];
      result[i++] = (w & 0xff000000) >>> 24;
      if (i == l)
        break;
      result[i++] = (w & 0x00ff0000) >>> 16;
      if (i == l)
        break;
      result[i++] = (w & 0x0000ff00) >>> 8;
      if (i == l)
        break;
      result[i++] = (w & 0x000000ff);
    }
    return result;
  }

  readChunk(data: ArrayBuffer, pos: number) {
    let encrypted = new Uint8Array();
    let size = 0;
    while (true) {
      const ret = this.unpack(data.slice(pos, pos + 12), 4);
      const encryptedSize = ret[1];
      const moreData = ret[2];
      pos += 12;
      size += ret[0];
      const chunk = new Uint8Array(data, pos, encryptedSize);
      const concatenated = new Uint8Array(encrypted.length + chunk.length);
      concatenated.set(encrypted);
      concatenated.set(chunk, encrypted.length);
      encrypted = concatenated;
      pos += encryptedSize;
      if (moreData === 0) {
        break;
      }
    }
    return { value: encrypted.buffer, pos };
  }


  decompress(data: ArrayBuffer, pos: number) {
    let decompressed = new Uint8Array();
    let crc = 0;
    while (true) {
      const ret = this.unpack(data.slice(pos, pos + 12), 4);
      pos += 12;
      const decompressedSize = ret[0];
      const compressedSize = ret[1];
      const moreData = ret[2];
      const compressedChunk = new Uint8Array(data, pos, compressedSize);
      crc = crc32(compressedChunk);
      const decompressedChunk = inflate(compressedChunk);
      if (decompressedChunk.buffer.byteLength !== decompressedSize) {
        throw new Error('Invalid decompressed size');
      }
      const concatenated = new Uint8Array(decompressed.length + decompressedChunk.length);
      concatenated.set(decompressed);
      concatenated.set(decompressedChunk, decompressed.length);
      decompressed = concatenated;
      pos += compressedSize;
      if (moreData === 0) {
        break;
      }
    }
    return { value: decompressed.buffer, pos };
  }

  arrayBufferToHex(buffer: ArrayBuffer): string {
    return Array.from(new Uint8Array(buffer))
      .map((byte) => byte.toString(16).padStart(2, '0'))
      .join('');
  }

  hex2Arr(str: string) {
    if (!str) {
      return new Uint8Array();
    }
    const arr = [];
    for (let i = 0, len = str.length; i < len; i += 2) {
      arr.push(parseInt(str.substr(i, 2), 16));
    }
    return new Uint8Array(arr);
  };
}
