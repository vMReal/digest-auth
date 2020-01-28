export interface ClientDigest {
  scheme: string,
  username: string;
  realm: string
  nonce: string,
  cnonce: string,
  nc: string,
  uri: string,
  qop: string,
  algorithm: string
  response: string,
  opaque: string,
}


export interface ServerDigest {
  realm: string
  nonce: string,
  qop?: string,
  domain?: string,
  opaque?: string,
  stale?: string,
  algorithm?: string
}
