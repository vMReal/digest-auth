import {ClientDigest} from "../header";
import {Expose} from "class-transformer";
import {RemoveQuotes} from "../decorators/remove-quotes.decorator";
import {IsOptional, IsString} from "class-validator";

export class ClientDigestDto implements ClientDigest{

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
  @IsString()
  @IsOptional()
  nc: string;

  @Expose()
  @RemoveQuotes()
  @IsString()
  @IsOptional()
  uri: string;

  @Expose()
  @IsString()
  @IsOptional()
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
