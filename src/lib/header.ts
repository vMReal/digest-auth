import {chain, first, isUndefined, last, reduce} from 'lodash';

const SCHEME_REGEXP = /(?:^|\,\s|\,)([A-Z][a-zA-Z0-9_]+)\s/gm;
const SPECIAL_SYMBOL_REGEXP = /\s|\,/gm;
export const SCHEME_DIGEST = 'Digest';

export type ParseParams = {
  readonly scheme: string;
  readonly raw: string;
  readonly [prop: string]: string | number | undefined;
}

export type GenerateParams = {
  readonly [prop: string]: string | number | undefined;
}

export class Header {

  public static parse(header: string): ReadonlyArray<ParseParams> { // @RFC https://tools.ietf.org/html/rfc7235#section-4
    const schemes = (header.match(SCHEME_REGEXP) || []).map((scheme) => scheme.replace(SPECIAL_SYMBOL_REGEXP, ''));
    const contents = header.replace(SCHEME_REGEXP, '{scheme}').split('{scheme}').slice(1);
    return chain(schemes)
      .reduce((res: ReadonlyArray<ParseParams>, scheme, index) => [...res, { raw: contents[index], scheme }], [])
      .map((challenge) => {
        return challenge.scheme === SCHEME_DIGEST
          ? {...challenge, ...Header.parseDigest(challenge.raw)}
          : {...challenge}
      })
      .value();
  }

  public static generate(digest: GenerateParams): string {
    return `${SCHEME_DIGEST} ` + reduce(digest, (acc: ReadonlyArray<string>, value: string | number | undefined, key: string) => {
      return (isUndefined(value))
        ? acc
        : [...acc, `${key}=${value}`];
    }, []).join(', ');
  }

  protected static parseDigest(content: string): {[key: string]: string} {
    return content
      .replace(/\,\s/gm, ',')
      .split(',')
      .reduce((res, param) => {
        const pair = param.split('=', 2);
        return {
          ...res,
          [first(pair) || 'unknown']: last(pair) || 'unknown'
        };
      }, {});
  }
}

