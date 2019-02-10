export class Response {
  // @ts-ignore
  public static generate(ha1: string, nonce: string, ha2: string): string;
  // @ts-ignore
  public static generateProtected(ha1: string, nonce: string, ha2: string, nonceCount: string, cnonce: string, qop: string): string;
}
