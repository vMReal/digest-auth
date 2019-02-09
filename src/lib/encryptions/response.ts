export class Response {
  public static generate(ha1: string, nonce: string, ha2: string): string;
  public static generateProtected(ha1: string, nonce: string, ha2: string, nonceCount: string, cnonce: string, qop: string): string;
}
