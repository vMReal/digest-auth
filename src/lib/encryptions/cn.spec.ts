import test from 'ava';
import { Cn, CN_MAX_INT_VALUE } from './cn';

test('toHex - correct convert', t => {
  t.is(Cn.toHex(1025), '00000401');
  t.is(Cn.toHex(CN_MAX_INT_VALUE), '7fffffff');
});

test('toHex - correct convert with max', t => {
  t.is(Cn.toHex(CN_MAX_INT_VALUE + 1), '00000000');
});

test('fromHex - correct convert', t => {
  t.is(Cn.fromHex('00000401'), 1025);
  t.is(Cn.fromHex('7fffffff'), CN_MAX_INT_VALUE);
})
