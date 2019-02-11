import { MD5 } from './md5';

export class Response {

  public static generate(ha1: string, nonce: string, ha2: string): string {
    return MD5.createHex(`${ha1}:${nonce}:${ha2}`);
  }

  public static generateProtected(ha1: string, nonce: string, ha2: string, nonceCount: string, cnonce: string, qop: string): string {
    return MD5.createHex(`${ha1}:${nonce}:${nonceCount}:${cnonce}:${qop}:${ha2}`);
  }
}
