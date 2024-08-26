import { Transform } from 'class-transformer';
import {isString} from "lodash";

export function AddQuotes() {
  return Transform((params) => {
    if (!isString(params.value))
      return params.value;

    return `"${params.value}"`;
  });
}
