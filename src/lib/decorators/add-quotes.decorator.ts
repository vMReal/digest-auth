import { Transform } from 'class-transformer';

export function AddQuotes() {
  return Transform((value: string) => {
    return `"${value}"`;
  });
}
