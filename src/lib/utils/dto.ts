import {plainToClass} from "class-transformer";
import {ClassType} from "class-transformer/ClassTransformer";

export class Dto {

  public static validate<T extends Object, V>(dto:  ClassType<T>, data: V, transform?: undefined): V
  public static validate<T extends Object, V>(dto:  ClassType<T>, data: V, transform: true): T
  public static validate<T extends Object, V>(dto:  ClassType<T>, data: V, transform: any): T | V {
    const entity = plainToClass(dto, data, {strategy: "excludeAll"});
    return (transform === true)
      ? entity
      : this.toPlain(entity);
  }

  public static toPlain<V>(data: V) {
    return JSON.parse(JSON.stringify(data));
  }
}
