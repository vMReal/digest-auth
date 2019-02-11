import * as crypto from 'crypto';

export class Nonce {

  public static generate(length: number = 48): string {
    if (length < 1)
      return '';

    const byteSize = (length < 2)
      ? 1
      : length / 2;

    return crypto.randomBytes(byteSize).toString('hex').substring(0, length);
  }
}
