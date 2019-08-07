const INT32_MAX_VALUE = 2147483647;

export const CN_MAX_INT_VALUE = INT32_MAX_VALUE;

export class Cn {

  public static toHex(value: number): string {
    if (value > INT32_MAX_VALUE)
      return '00000000';

    const hex = value.toString(16);
    return '0'.repeat(8 - hex.length) + hex;
  }

  public static fromHex(value: string) {
    return parseInt(value, 16);
  }
}
