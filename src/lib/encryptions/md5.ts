import cryptoMD5 from 'crypto-js/md5';

export class MD5 {
  public static createHex(raw: string): string {
    return cryptoMD5(raw).toString();
  }
}
