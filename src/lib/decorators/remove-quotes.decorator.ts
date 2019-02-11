import { Transform } from 'class-transformer';
import {isString} from "lodash";

export function RemoveQuotes() {
  return Transform((value: string) => {
    if (!isString(value))
      return value;

    return value
      .replace(/^"/, '')
      .replace(/"$/, '')
  });
}
