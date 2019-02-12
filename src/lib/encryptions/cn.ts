const INT32_MAX_VALUE = 2147483647;

export class Cn {

  public static toHex(value: number): string {
    if (value > INT32_MAX_VALUE)
      return '00000000';

    const buf = Buffer.allocUnsafe(4);
    buf.writeInt32BE(value, 0);
    return buf.toString('hex');
  }

  public fromHex(value: string) {
    return parseInt(value, 16);
  }
}
