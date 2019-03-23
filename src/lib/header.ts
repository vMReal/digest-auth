import {get, reduce, isUndefined} from 'lodash';

export type Params = {
  [prop: string]: string | number | undefined;
}

export class Header {
  public static parse(header: string): any { // @TODO fix return type
    const components = header.split(' ');
    const params = reduce(components.slice(1).join(' ').split(', '), (acc: object, param: string) => {
      const pair = param.split('=');
      return {
        ...acc,
        [get(pair, '0', 'unknown')]: get(pair, '1', 'unknown')
      };
    }, {});
    return {
      ...params,
      scheme: get(components, '0', 'unknown')
    };
  }

  public static generate(digest: Params): string {
    return 'Digest ' + reduce(digest, (acc: string[], value: string | number | undefined, key: string) => {
      if (isUndefined(value))
        return acc;
      
      return [...acc, `${key}=${value}`];
    }, []).join(', ');
  }
}

