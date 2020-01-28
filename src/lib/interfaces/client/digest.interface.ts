export interface ClientUnprotectedDigest {
  username: string,
  realm: string,
  nonce: string,
  response: string,
}

export interface ClientProtectedDigest extends ClientUnprotectedDigest {
  cnonce: string,
  nc: string,
  uri: string,
  qop: string,
  algorithm: string
  opaque?: string,
}


export interface ServerDigest {
  scheme: string,
  realm: string,
  nonce: string,
  qop?: string,
  domain?: string,
  opaque?: string,
  stale?: string,
  algorithm?: string
}
