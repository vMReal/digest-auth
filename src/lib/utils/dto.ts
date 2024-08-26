import {plainToInstance } from "class-transformer";
import { ClassConstructor } from 'class-transformer/types/interfaces';
import { validateSync } from 'class-validator';
import {
  BASE_CODE_VALIDATE,
  BaseException
} from '../exceptions/base-exception';

export class Dto {

  public static validate<T extends object, V>(dto:  ClassConstructor<T>, data: V, transform?: undefined): V
  public static validate<T extends object, V>(dto:  ClassConstructor<T>, data: V, transform: true): T
  public static validate<T extends object, V>(dto:  ClassConstructor<T>, data: V, transform: undefined | true): T | V {
    const entity = plainToInstance(dto, data, {strategy: "excludeAll"});
    const validationRes = validateSync(entity, {forbidUnknownValues: false});
    if (validationRes.length)
      throw new BaseException(BASE_CODE_VALIDATE, validationRes);

    return (transform === true)
      ? entity
      : this.toPlain(entity);
  }

  public static toPlain<V>(data: V) {
    return JSON.parse(JSON.stringify(data));
  }
}
