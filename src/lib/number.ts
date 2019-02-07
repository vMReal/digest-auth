

export class Header {
  parceAuthorization(header);
  generateAuthorization(header);
  parceAuthenticate(header: string): AuthenticateParams;
  generateAuthenticate(nonce: AuthenticateParams): string
}

export interface AuthenticateParams {
  realm: string;
  nonce : string;
  domain?: string;
  opaque?: string
  stale?: boolean
  algorithm?: 'MD5' | 'MD5-sess';
  qop?: 'auth' | 'auth-int';
}

export interface AuthenticateParams {
  realm: string;
  nonce : string;
  domain?: string;
  opaque?: string
  stale?: boolean
  algorithm?: 'MD5' | 'MD5-sess';
  qop?: 'auth' | 'auth-int';
}
