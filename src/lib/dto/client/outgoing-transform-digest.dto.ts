import { Expose } from 'class-transformer';
import { AddQuotes } from '../../decorators/add-quotes.decorator';
import {ClientProtectedDigest, ClientUnprotectedDigest} from "../../interfaces/client/digest.interface";



export class OutgoingTransformUnprotectedDigestDto implements ClientUnprotectedDigest {

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
  response: string;
}

export class OutgoingTransformProtectedDigestDto extends OutgoingTransformUnprotectedDigestDto implements ClientProtectedDigest {

  @Expose()
  @AddQuotes()
  cnonce: string;

  @Expose()
  nc: string;

  @Expose()
  @AddQuotes()
  uri: string;

  @Expose()
  @AddQuotes()
  qop: string;

  @Expose()
  @AddQuotes()
  algorithm: string;

  @Expose()
  @AddQuotes()
  opaque?: string;
}

