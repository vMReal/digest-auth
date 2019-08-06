import test from 'ava';
import { MD5 } from './md5';


test('generate - return string', t => {
  t.is(MD5.createHex('test:test'), 'c4f961b4380ee24d982fed76ef36be9f');
});
