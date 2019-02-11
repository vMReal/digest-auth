import * as crypto from 'crypto';

export class MD5 {
  public static createHex(raw: string): string {
    return crypto
      .createHash('md5')
      .update(raw)
      .digest('hex');
  }
}
