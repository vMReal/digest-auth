export class HA1 {
  public static generate(username: string, password: string, realm: string): string;
  public static generateSess(h1: string, nonce: string, cnonce: string): string;
}
