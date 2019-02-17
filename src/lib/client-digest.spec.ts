// tslint:disable:no-expression-statement
import test from 'ava';
import {ALGORITHM_MD5, ALGORITHM_MD5_SESS, QOP_AUTH, QOP_AUTH_INT} from './constants';
import {ClientDigestAuth} from "./client-digest-auth";


const HEADER_UNPROTECTED = 'Digest realm="test-realm", nonce="test-nonce"';
const HEADER_HEADER_UNPROTECTED_MD5 = 'Digest realm="test-realm", nonce="test-nonce", algorithm="MD5"';
const HEADER_AUTH_MD5 = 'Digest realm="test-realm", nonce="test-nonce", algorithm="MD5", qop=auth';
const HEADER_AUTH_SESS = 'Digest realm="test-realm", nonce="test-nonce", algorithm="MD5-sess", qop=auth';
const HEADER_AUTHINT_MD5 = 'Digest realm="test-realm", nonce="test-nonce", algorithm="MD5", qop=auth-int';
const HEADER_AUTHINT_MD5_OPAQUE = 'Digest realm="test-realm", nonce="test-nonce", algorithm="MD5", qop=auth-int, opaque="test-opaque"';
// @TODO add stale and domain


//const TEST_BODY = '{"key": "value"}';
//const TEST_PASS = 'pass';
//const TEST_USER = 'user';
const TEST_REALM = 'test-realm';
const TEST_NONCE = 'test-nonce';
//const TEST_CNONCE = 'test-cnonce';
//const TEST_NC = '00000001';
//const TEST_URI = '/auth';
const TEST_OPAQUE = 'test-opaque';

test('analyze - unprotected', t => {
  t.deepEqual(
    ClientDigestAuth.analyze(HEADER_UNPROTECTED),
    {
      realm: TEST_REALM,
      nonce: TEST_NONCE,
    });
});


test('analyze - unprotected + MD5', t => {
  t.deepEqual(
    ClientDigestAuth.analyze(HEADER_HEADER_UNPROTECTED_MD5),
    {
      algorithm: 'MD5',
      realm: TEST_REALM,
      nonce: TEST_NONCE,
    });
});


test('analyze - auth + MD5', t => {
  t.deepEqual(
    ClientDigestAuth.analyze(HEADER_AUTH_MD5),
    {
      qop: QOP_AUTH,
      algorithm: ALGORITHM_MD5,
      realm: TEST_REALM,
      nonce: TEST_NONCE,
    });
});



test('analyze - auth + MD5-sess', t => {
  t.deepEqual(
    ClientDigestAuth.analyze(HEADER_AUTH_SESS),
    {
      qop: QOP_AUTH,
      algorithm: ALGORITHM_MD5_SESS,
      realm: TEST_REALM,
      nonce: TEST_NONCE,
    });
});



test('analyze - auth-int + MD5', t => {
  t.deepEqual(
    ClientDigestAuth.analyze(HEADER_AUTHINT_MD5),
    {
      qop: QOP_AUTH_INT,
      algorithm: ALGORITHM_MD5,
      realm: TEST_REALM,
      nonce: TEST_NONCE,
    });
});


test('analyze - auth-int + MD5 + opaque', t => {
  t.deepEqual(
    ClientDigestAuth.analyze(HEADER_AUTHINT_MD5_OPAQUE),
    {
      qop: QOP_AUTH_INT,
      algorithm: ALGORITHM_MD5,
      realm: TEST_REALM,
      nonce: TEST_NONCE,
      opaque: TEST_OPAQUE,
    });
});
