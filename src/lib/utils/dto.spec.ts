// tslint:disable:no-expression-statement
import test from 'ava';
import { Expose } from 'class-transformer';
import { IsNumber } from 'class-validator';
import { BASE_CODE_VALIDATE } from '../exceptions/base-exception';
import { Dto } from './dto';

class Test {
  @IsNumber()
  @Expose()
  public field: number
}

test('Dto:validate validate and return only defined in Dto fields', t => {
  t.deepEqual(
    Dto.validate(Test, {field: 1, field2: 2}),
    {field: 1},
  );
});

test('Dto:validate validate by default returns a raw object', t => {
  t.false(Dto.validate(Test, {field: 1, field2: 2}) instanceof Test);
});

test('Dto:validate validate with transform option returns instanceof a Dto', t => {
  t.true(Dto.validate(Test, {field: 1, field2: 2}, true) instanceof Test);
});

test('Dto:validate with invalid payload throws exception with the validate code', t => {
  t.throws(() => Dto.validate(Test, {field: 'string'}), BASE_CODE_VALIDATE);
})

