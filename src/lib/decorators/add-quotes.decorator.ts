import { Transform } from 'class-transformer';
import {isString} from "lodash";

export function AddQuotes() {
  return Transform((value: string) => {
    if (!isString(value))
      return value;

    return `"${value}"`;
  });
}
