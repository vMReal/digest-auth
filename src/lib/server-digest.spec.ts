// tslint:disable:no-expression-statement
import test from 'ava';
import {ServerDigestAuth} from "./server-digest-auth";
import { ALGORITHM_MD5, QOP_AUTH, QOP_AUTH_INT } from './constants';
import {includes} from "lodash";

//const HEADER_GET_QOPLESS_MD5 = 'Digest username="user", realm="test-realm", nonce="test-nonce", uri="/auth", algorithm="MD5", response="48388ab4ca0c46a73e4d2f23ccc7632e"';
//const HEADER_GET_QOPLESS_SESS = 'Digest username="user", realm="test-realm", nonce="test-nonce", uri="/auth", algorithm="MD5-sess", cnonce="", response="02dfe2629099f3c569fc5cde9bf1e233"';
const HEADER_GET_AUTH_MD5 = 'Digest username="user", realm="test-realm", nonce="test-nonce", uri="/auth", algorithm="MD5", qop=auth, nc=00000001, cnonce="test-cnonce", response="e524170b3e02dedaf6a1110131fb5a50", opaque="test-opaque"';
const HEADER_GET_AUTH_SESS = 'Digest username="user", realm="test-realm", nonce="test-nonce", uri="/auth", algorithm="MD5-sess", qop=auth, nc=00000001, cnonce="test-cnonce", response="6f2b8d1c4fddae124e66f2d5980cee64", opaque="test-opaque"';
const HEADER_POST_AUTH_MD5 = 'Digest username="user", realm="test-realm", nonce="test-nonce", uri="/auth", algorithm="MD5", qop=auth, nc=00000001, cnonce="test-cnonce", response="f0881ed8e522e40c0f56ee31e351636d", opaque="test-opaque"';
const HEADER_POSTNESS_AUTH_MD5 = 'Digest username="user", realm="test-realm", nonce="test-nonce", uri="/auth", algorithm="MD5", qop=auth, nc=00000001, cnonce="test-cnonce", response="f0881ed8e522e40c0f56ee31e351636d", opaque="test-opaque"';
const HEADER_POSTNESS_INT_MD5 = 'Digest username="user", realm="test-realm", nonce="test-nonce", uri="/auth", algorithm="MD5", qop=auth-int, nc=00000001, cnonce="test-cnonce", response="dda8edbd09a4e74f283f2b3d439bc7b6", opaque="test-opaque"';
const HEADER_POSTNESS_INT_SESS = 'Digest username="user", realm="test-realm", nonce="test-nonce", uri="/auth", algorithm="MD5-sess", qop=auth-int, nc=00000001, cnonce="test-cnonce", response="d717aab31fbc3987322356a9faf0fd49", opaque="test-opaque"';

const TEST_BODY = '{"key": "value"}';
const TEST_PASS = 'pass';
const TEST_USER = 'user';
const TEST_REALM = 'test-realm';
const TEST_NONCE = 'test-nonce';
const TEST_CNONCE = 'test-cnonce';
const TEST_NC = '00000001';
const TEST_URI = '/auth';
const TEST_OPAQUE = 'test-opaque';

test('analyze', t => {
  t.deepEqual(
    ServerDigestAuth.analyze(HEADER_GET_AUTH_MD5, [QOP_AUTH]),
    {
      qop: 'auth',
      algorithm: 'MD5',
      response: 'e524170b3e02dedaf6a1110131fb5a50',
      username: TEST_USER,
      realm: TEST_REALM,
      nonce: TEST_NONCE,
      cnonce: TEST_CNONCE,
      nc: TEST_NC,
      uri: TEST_URI,
      opaque: TEST_OPAQUE,
    });
});



test('analyze GET:AUTH:MD5 ', t => {
  const headerPayload = ServerDigestAuth.analyze(HEADER_GET_AUTH_MD5, [QOP_AUTH]);
  t.true(ServerDigestAuth.verifyByPassword(headerPayload, TEST_PASS, {entryBody: '', method: 'GET', uri: TEST_URI}));
});

test('analyze GET:AUTH:MD5-sess ', t => {
  const headerPayload = ServerDigestAuth.analyze(HEADER_GET_AUTH_SESS, [QOP_AUTH]);
  t.true(ServerDigestAuth.verifyByPassword(headerPayload, TEST_PASS, {entryBody: '', method: 'GET', uri: TEST_URI}));
});

test('analyze POST(content-):QOP(auth):MD5', t => {
  const headerPayload = ServerDigestAuth.analyze(HEADER_POST_AUTH_MD5, [QOP_AUTH]);
  t.true(ServerDigestAuth.verifyByPassword(headerPayload, TEST_PASS, {entryBody: '', method: 'POST', uri: TEST_URI}));
});

test('analyze POST(content+):QOP(auth):MD5 ', t => {
  const headerPayload = ServerDigestAuth.analyze(HEADER_POSTNESS_AUTH_MD5, [QOP_AUTH]);
  t.true(ServerDigestAuth.verifyByPassword(headerPayload, TEST_PASS, {entryBody: TEST_BODY, method: 'POST', uri: TEST_URI}));
});

test('analyze POST(content+):QOP(auth-int):MD5 ', t => {
  const headerPayload = ServerDigestAuth.analyze(HEADER_POSTNESS_INT_MD5, [QOP_AUTH_INT]);
  t.true(ServerDigestAuth.verifyByPassword(headerPayload, TEST_PASS, {entryBody: TEST_BODY, method: 'POST', uri: TEST_URI}));
});

test('analyze POST(content+):QOP(auth-int):MD5-sess', t => {
  const headerPayload = ServerDigestAuth.analyze(HEADER_POSTNESS_INT_SESS, [QOP_AUTH_INT]);
  t.true(ServerDigestAuth.verifyByPassword(headerPayload, TEST_PASS, {entryBody: TEST_BODY, method: 'POST', uri: TEST_URI}));
});


test('analyze GET:AUTH:MD5 - uri changed', t => {
  const headerPayload = ServerDigestAuth.analyze(HEADER_GET_AUTH_MD5, [QOP_AUTH]);
  t.false(ServerDigestAuth.verifyByPassword(headerPayload, TEST_PASS, {entryBody: '', method: 'GET', uri: '/test'}));
});

test('analyze GET:AUTH:MD5 - method changed', t => {
  const headerPayload = ServerDigestAuth.analyze(HEADER_GET_AUTH_MD5, [QOP_AUTH]);
  t.false(ServerDigestAuth.verifyByPassword(headerPayload, TEST_PASS, {entryBody: '', method: 'PUT', uri: TEST_URI}));
});


test('analyze POST(content+):QOP(auth-int):MD5 - body changed', t => {
  const headerPayload = ServerDigestAuth.analyze(HEADER_POSTNESS_INT_MD5, [QOP_AUTH_INT]);
  t.false(ServerDigestAuth.verifyByPassword(headerPayload, TEST_PASS, {entryBody: 'test', method: 'POST', uri: TEST_URI}));
});



/* ================= =============== */

test('generateResponse QOP(auth)', t => {
  const res = ServerDigestAuth.generateResponse(TEST_REALM, {
    opaque: TEST_OPAQUE,
    qop: QOP_AUTH,
    algorithm: ALGORITHM_MD5,
  });

  t.is(res.qop, QOP_AUTH);
  t.is(res.opaque, TEST_OPAQUE);
  t.is(typeof res.nonce, 'string');
  t.is(res.nonce.length, 48);

  t.true(includes(res.raw, `realm="${TEST_REALM}"`));
  t.true(includes(res.raw, `nonce="${res.nonce}"`));
  t.true(includes(res.raw, `qop=${QOP_AUTH}`));
  t.true(includes(res.raw, `algorithm="${ALGORITHM_MD5}"`));
  t.true(includes(res.raw, `opaque="${TEST_OPAQUE}"`));
});
