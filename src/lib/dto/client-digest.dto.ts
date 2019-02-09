import {ClientDigest} from "../header";

export class ClientDigestDto implements ClientDigest{
  username: string;
  realm: string;
  nonce: string;
  cnonce: string;
  nc: string;
  uri: string;
  qop: string;
  algorithm: string
  response: string
}
