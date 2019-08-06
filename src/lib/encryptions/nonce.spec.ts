import test from 'ava';
import { Nonce } from './nonce';


test('generate - return string', t => {
  t.is(typeof Nonce.generate(), 'string');
  t.is(typeof Nonce.generate(10), 'string');
  t.is(typeof Nonce.generate(1), 'string');
});


test('generate - default length equal 48', t => {
  t.is(Nonce.generate().length, 48);
});


test('generate - custom length equal 20', t => {
  t.is(Nonce.generate(20).length, 20);
});

test('generate - custom length equal 2', t => {
  t.is(Nonce.generate(2).length, 2);
});


test('generate - custom length equal 1', t => {
  t.is(Nonce.generate(1).length, 1);
});

test('generate - custom length lees then 1', t => {
  t.is(Nonce.generate(0).length, 0);
  t.is(Nonce.generate(-1).length, 0);
});
