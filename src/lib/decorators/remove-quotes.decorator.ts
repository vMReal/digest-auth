import { Transform } from 'class-transformer';

export function RemoveQuotes() {
  return Transform((value: string) => {
    return value
      .replace(/^"/, '')
      .replace(/"$/, '')
  });
}
