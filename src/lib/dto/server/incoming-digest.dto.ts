import {Expose} from "class-transformer";
import {IsOptional, IsString} from "class-validator";
import {RemoveQuotes} from "../../decorators/remove-quotes.decorator";
import {ClientDigest} from "../../interfaces/server/digest.interface";

export class IncomingDigestDto implements ClientDigest {
  @Expose()
  @IsString()
  scheme: string;

  @Expose()
  @RemoveQuotes()
  @IsString()
  username: string;

  @Expose()
  @RemoveQuotes()
  @IsString()
  realm: string;

  @Expose()
  @RemoveQuotes()
  @IsString()
  nonce: string;

  @Expose()
  @RemoveQuotes()
  @IsString()
  @IsOptional()
  cnonce: string;

  @Expose()
  @RemoveQuotes()
  @IsString()
  @IsOptional()
  nc: string;

  @Expose()
  @RemoveQuotes()
  @IsString()
  @IsOptional()
  uri: string;

  @Expose()
  @RemoveQuotes()
  @IsString()
  @IsOptional()
  @RemoveQuotes()
  qop: string;

  @Expose()
  @RemoveQuotes()
  @IsString()
  @IsOptional()
  algorithm: string;

  @Expose()
  @RemoveQuotes()
  @IsString()
  response: string;

  @Expose()
  @RemoveQuotes()
  @IsString()
  @IsOptional()
  opaque: string;
}
