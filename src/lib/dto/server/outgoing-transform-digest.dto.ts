import { Expose } from 'class-transformer';
import { AddQuotes } from '../../decorators/add-quotes.decorator';
import {ServerDigest} from "../../interfaces/server/digest.interface";

/*
 * @Link RFC-7616 (quoted string) https://tools.ietf.org/html/rfc7616#section-3.3
 */
export class OutgoingTransformDigestDto implements ServerDigest {

  @Expose()
  @AddQuotes()
  realm: string;

  @Expose()
  @AddQuotes()
  nonce: string;

  @Expose()
  @AddQuotes()
  qop?: string;

  @Expose()
  @AddQuotes()
  domain?: string;

  @Expose()
  @AddQuotes()
  opaque?: string;

  @Expose()
  stale?: string;

  @Expose()
  algorithm?: string;
}

