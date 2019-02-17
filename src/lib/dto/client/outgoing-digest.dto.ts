import {Expose} from "class-transformer";
import {IsOptional, IsString} from "class-validator";
import {ClientProtectedDigest, ClientUnprotectedDigest} from "../../interfaces/client/digest.interface";

export class OutgoingUnprotectedDigestDto implements ClientUnprotectedDigest {

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
  response: string;
}

export class OutgoingProtectedDigestDto extends OutgoingUnprotectedDigestDto implements ClientProtectedDigest {

  @Expose()
  @IsString()
  cnonce: string;

  @Expose()
  @IsString()
  nc: string;

  @Expose()
  @IsString()
  uri: string;

  @Expose()
  @IsString()
  @IsOptional()
  qop: string;

  @Expose()
  @IsString()
  algorithm: string;

  @Expose()
  @IsString()
  opaque?: string;
}
