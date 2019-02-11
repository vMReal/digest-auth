import {ServerDigest} from "../../header";
import { Expose } from 'class-transformer';
import { IsOptional, IsString } from 'class-validator';

export class OutgoingDigestDto implements ServerDigest {

  @Expose()
  @IsString()
  username: string;

  @Expose()
  @IsString()
  realm: string;

  @Expose()
  @IsString()
  nonce: string;

  @Expose()
  @IsOptional()
  @IsString()
  qop?: string;

  @Expose()
  @IsOptional()
  @IsString()
  domain?: string;

  @Expose()
  @IsOptional()
  @IsString()
  opaque?: string;

  @Expose()
  @IsOptional()
  @IsString()
  stale?: string;

  @Expose()
  @IsOptional()
  @IsString()
  algorithm?: string;
}

