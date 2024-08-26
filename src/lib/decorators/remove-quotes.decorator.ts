import { Transform } from 'class-transformer';
import {isString} from "lodash";

export function RemoveQuotes() {
  return Transform((params) => {
    if (!isString(params.value))
      return params.value;

    return params.value
      .replace(/^"/, '')
      .replace(/"$/, '')
  });
}
