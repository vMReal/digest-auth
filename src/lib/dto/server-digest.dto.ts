import {ServerDigest} from "../header";

export class ServerDigestDto implements ServerDigest {
  username: string;
  realm: string;
  nonce: string;
  qop?: string;
  domain?: string;
  opaque?: string;
  stale?: string;
  algorithm?: string;
}

