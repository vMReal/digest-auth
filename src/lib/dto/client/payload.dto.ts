import {Expose} from "class-transformer";
import {
  IsIn,
  IsNumber,
  IsOptional,
  IsString,
  Max,
  Min
} from 'class-validator';
import { ALGORITHM_MD5, ALGORITHM_MD5_SESS } from '../../constants';
import {CN_MAX_INT_VALUE} from "../../encryptions/cn";
import {
  PayloadProtectionAuth,
  PayloadProtectionAuthInt,
  PayloadUnprotected
} from "../../interfaces/client/payload.interface";


export class PayloadUnprotectedDto implements PayloadUnprotected {
  @Expose()
  @IsString()
  method: string;

  @Expose()
  @IsString()
  uri: string;
}


export class PayloadProtectionAuthDto extends PayloadUnprotectedDto implements PayloadProtectionAuth {
  @Expose()
  @IsNumber()
  @Min(1)
  @Max(CN_MAX_INT_VALUE)
  counter: number;

  @Expose()
  @IsIn([ALGORITHM_MD5, ALGORITHM_MD5_SESS])
  @IsOptional()
  @IsString()
  force_algorithm?: string;
}

export class PayloadProtectionAuthIntDto extends PayloadProtectionAuthDto implements PayloadProtectionAuthInt {
  @Expose()
  @IsString()
  entryBody: string;
}
