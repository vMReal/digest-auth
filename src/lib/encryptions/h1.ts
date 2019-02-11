import { MD5 } from './md5';

export class HA1 {

  public static generate(username: string, password: string, realm: string): string{
    return MD5.createHex(`${username}:${realm}:${password}`);
  }

  public static generateSess(h1: string, nonce: string, cnonce: string): string {
    return MD5.createHex(`${h1}:${nonce}:${cnonce}`);
  }
}
