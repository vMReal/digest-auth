import {ServerDigest} from "../../header";
import { Expose } from 'class-transformer';
import { AddQuotes } from '../../decorators/add-quotes.decorator';

export class OutgoingTransformDigestDto implements ServerDigest {

  @Expose()
  @AddQuotes()
  username: string;

  @Expose()
  @AddQuotes()
  realm: string;

  @Expose()
  @AddQuotes()
  nonce: string;

  @Expose()
  @AddQuotes()
  cnonce?: string;

  @Expose()
  nc?: string;

  @Expose()
  @AddQuotes()
  uri?: string;

  @Expose()
  qop?: string;

  @Expose()
  @AddQuotes()
  algorithm?: string;

  @Expose()
  @AddQuotes()
  response: string;

  @Expose()
  @AddQuotes()
  opaque?: string;
}

