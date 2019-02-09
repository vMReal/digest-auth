export class Header {
  public static parce<T>(header: string): T;
  public static generate<T>(digest: T): string;
}

export interface ClientDigest {
  username: string;
  realm: string
  nonce: string,
  cnonce: string,
  nc: string,
  uri: string,
  qop: string,
  algorithm: string
  response: string
}


export interface ServerDigest {
  username: string;
  realm: string
  nonce: string,
  qop?: string,
  domain?: string,
  opaque?: string,
  stale?: string,
  algorithm?: string
}

