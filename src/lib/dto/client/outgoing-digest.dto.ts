import {ClientDigest} from "../../header";
import {Expose} from "class-transformer";
import {IsOptional, IsString} from "class-validator";

export class OutgoingDigestDto implements ClientDigest {

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
  @IsString()
  @IsOptional()
  cnonce?: string;

  @Expose()
  @IsString()
  @IsOptional()
  nc?: string;

  @Expose()
  @IsString()
  @IsOptional()
  uri?: string;

  @Expose()
  @IsString()
  @IsOptional()
  qop?: string;

  @Expose()
  @IsString()
  @IsOptional()
  algorithm?: string;

  @Expose()
  @IsString()
  response: string;

  @Expose()
  @IsString()
  @IsOptional()
  opaque?: string;
}
