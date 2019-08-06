import {lib, enc} from 'crypto-js';

export class Nonce {

  public static generate(length: number = 48): string {
    if (length < 1)
      return '';

    const byteSize = (length < 2)
      ? 1
      : length / 2;

    return enc.Hex.stringify(lib.WordArray.random(byteSize)).substring(0, length);

  }
}
