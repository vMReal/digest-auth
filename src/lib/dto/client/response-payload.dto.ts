import {Expose} from "class-transformer";
import {IsNumber, IsOptional, IsString} from "class-validator";

export class ResponsePayloadDto {

  @Expose()
  @IsNumber()
  @IsOptional()
  counter?: string;

  @Expose()
  @IsString()
  @IsOptional()
  force_qop?: string;

  @Expose()
  @IsString()
  @IsOptional()
  force_algorithm?: string;

  @Expose()
  @IsString()
  entryBody: string;

  @Expose()
  @IsString()
  method: string;

  @Expose()
  @IsString()
  uri: string;

}
