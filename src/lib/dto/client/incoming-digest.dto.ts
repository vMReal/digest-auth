import { Expose } from 'class-transformer';
import { IsOptional, IsString } from 'class-validator';
import {RemoveQuotes} from "../../decorators/remove-quotes.decorator";
import {ServerDigest} from "../../interfaces/client/digest.interface";

export class IncomingDigestDto implements ServerDigest {

  @Expose()
  @RemoveQuotes()
  @IsString()
  realm: string;

  @Expose()
  @RemoveQuotes()
  @IsString()
  nonce: string;

  @Expose()
  @IsOptional()
  @IsString()
  qop?: string;

  @Expose()
  @IsOptional()
  @RemoveQuotes()
  @IsString()
  domain?: string;

  @Expose()
  @IsOptional()
  @RemoveQuotes()
  @IsString()
  opaque?: string;

  @Expose()
  @IsOptional()
  @RemoveQuotes()
  @IsString()
  stale?: string;

  @Expose()
  @IsOptional()
  @RemoveQuotes()
  @IsString()
  algorithm?: string;
}

