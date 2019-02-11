import { MD5 } from './md5';

export class HA2 {

  public static generate(method: string, digestURI: string): string {
    return MD5.createHex(`${method}:${digestURI}`);
  }

  public static generateInt(method: string, digestURI: string, entityBody: string): string {
    return MD5.createHex(`${method}:${digestURI}:${MD5.createHex(entityBody)}`);
  }
}
