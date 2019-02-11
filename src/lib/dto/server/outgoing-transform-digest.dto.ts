import {ServerDigest} from "../../header";
import { Expose } from 'class-transformer';
import { AddQuotes } from '../../decorators/add-quotes.decorator';

export class OutgoingTransformDigestDto implements ServerDigest {

  @Expose()
  @AddQuotes()
  realm: string;

  @Expose()
  @AddQuotes()
  nonce: string;

  @Expose()
  qop?: string;

  @Expose()
  @AddQuotes()
  domain?: string;

  @Expose()
  @AddQuotes()
  opaque?: string;

  @Expose()
  @AddQuotes()
  stale?: string;

  @Expose()
  @AddQuotes()
  algorithm?: string;
}

