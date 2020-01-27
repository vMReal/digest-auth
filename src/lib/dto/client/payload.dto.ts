import {Expose} from "class-transformer";
import {IsNumber, IsString, Max, Min} from "class-validator";
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

// tslint:disable:variable-name
export class PayloadProtectionAuthDto extends PayloadUnprotectedDto implements PayloadProtectionAuth {
  @Expose()
  @IsString()
  entryBody: string;

  @Expose()
  @IsNumber()
  @Min(1)
  @Max(CN_MAX_INT_VALUE)
  counter: number;

  @Expose()
  @IsString()
  force_qop: string;

  @Expose()
  @IsString()
  force_algorithm: string;
}

export class PayloadProtectionAuthIntDto extends PayloadProtectionAuthDto implements PayloadProtectionAuthInt {
  @Expose()
  @IsString()
  entryBody: string;
}
