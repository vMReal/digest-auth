import { Expose } from 'class-transformer';
import { IsOptional, IsString } from 'class-validator';
import {ServerDigest} from "../../interfaces/server/digest.interface";

export class OutgoingDigestDto implements ServerDigest {

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

