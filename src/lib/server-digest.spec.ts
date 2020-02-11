// tslint:disable:no-expression-statement
import test from 'ava';
import { includes } from "lodash";
import { ClientDigestAuth } from './client-digest-auth';
import { ALGORITHM_MD5, QOP_AUTH, QOP_AUTH_INT } from './constants';
import { ANALYZE_CODE_VALIDATE } from './exceptions/analyze-exception';
import { SCHEME_DIGEST } from './header';
import { ServerDigestAuth } from "./server-digest-auth";

const HEADER_VALIDATION_PROBLEM = 'Digest realm="test-realm", uri="/auth", algorithm=MD5';
const HEADER_GET_QOPLESS_MD5 = 'Digest username="user", realm="test-realm", nonce="test-nonce", uri="/auth", algorithm=MD5, response="48388ab4ca0c46a73e4d2f23ccc7632e"';
const HEADER_GET_AUTH_MD5 = 'Digest username="user", realm="test-realm", nonce="test-nonce", uri="/auth, algorithm=MD5, qop="auth", nc=00000001, cnonce="test-cnonce", response=e524170b3e02dedaf6a1110131fb5a50", opaque="test-opaque"';
const HEADER_GET_AUTH_MD5_INCORRECT_QUOTES = 'Digest username=user", realm="test-realm", nonce="test-nonce", uri="/auth", algorithm="MD5", qop="auth", nc="00000001", cnonce="test-cnonce", response="e524170b3e02dedaf6a1110131fb5a50", opaque="test-opaque"';
const HEADER_GET_AUTH_SESS = 'Digest username="user", realm="test-realm", nonce="test-nonce", uri="/auth", algorithm=MD5-sess, qop="auth", nc=00000001, cnonce="test-cnonce", response="6f2b8d1c4fddae124e66f2d5980cee64", opaque="test-opaque"';
const HEADER_POST_AUTH_MD5 = 'Digest username="user", realm="test-realm", nonce="test-nonce", uri="/auth", algorithm=MD5, qop="auth", nc=00000001, cnonce="test-cnonce", response="f0881ed8e522e40c0f56ee31e351636d", opaque="test-opaque"';
const HEADER_POSTNESS_AUTH_MD5 = 'Digest username="user", realm="test-realm", nonce="test-nonce", uri="/auth", algorithm=MD5, qop="auth", nc=00000001, cnonce="test-cnonce", response="f0881ed8e522e40c0f56ee31e351636d", opaque="test-opaque"';
const HEADER_POSTNESS_INT_MD5 = 'Digest username="user", realm="test-realm", nonce="test-nonce", uri="/auth", algorithm=MD5, qop="auth-int", nc=00000001, cnonce="test-cnonce", response="dda8edbd09a4e74f283f2b3d439bc7b6", opaque="test-opaque"';
const HEADER_POSTNESS_INT_SESS = 'Digest username="user", realm="test-realm", nonce="test-nonce", uri="/auth", algorithm=MD5-sess, qop="auth-int", nc=00000001, cnonce="test-cnonce", response="d717aab31fbc3987322356a9faf0fd49", opaque="test-opaque"';
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
      scheme: SCHEME_DIGEST,
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

test('analyze - validation', t => {
  t.throws(() => ClientDigestAuth.analyze(HEADER_VALIDATION_PROBLEM), ANALYZE_CODE_VALIDATE);
});

test('analyze multi auth with multi false', t => {
  t.deepEqual(
    ServerDigestAuth.analyze(`Test test, ${HEADER_GET_AUTH_MD5},Test2 test2`, [QOP_AUTH]),
      {
        scheme: SCHEME_DIGEST,
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


test('analyze multi auth with multi true', t => {
  t.deepEqual(
    ServerDigestAuth.analyze(`Test test, ${HEADER_GET_AUTH_MD5},Test2 test2`, [QOP_AUTH], true),
    [
      {scheme: 'Test', raw: 'test'},
      {
        scheme: SCHEME_DIGEST,
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
      },
      {scheme: 'Test2', raw: 'test2'},
    ]);
});

/*
 * @Link RFC-7616 (quoted string) https://tools.ietf.org/html/rfc7616#section-3.4
 */
test('analyze - You should not assume that headers you parse follow rules (quoted string) according rfc7616#3.4', t => {
  t.deepEqual(
    ServerDigestAuth.analyze(HEADER_GET_AUTH_MD5_INCORRECT_QUOTES, [QOP_AUTH]),
    {
      scheme: SCHEME_DIGEST,
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


test('analyze - allowQop as unprotected', t => {
  t.notThrows(() => { ServerDigestAuth.analyze(HEADER_GET_QOPLESS_MD5, false) })
  t.throws(() => { ServerDigestAuth.analyze(HEADER_POSTNESS_INT_MD5, false) })
});

test('analyze - allowQop as auth', t => {
  t.notThrows(() => { ServerDigestAuth.analyze(HEADER_GET_AUTH_MD5, [QOP_AUTH]) })
  t.throws(() => { ServerDigestAuth.analyze(HEADER_GET_QOPLESS_MD5, [QOP_AUTH]) })
  t.throws(() => { ServerDigestAuth.analyze(HEADER_POSTNESS_INT_MD5, [QOP_AUTH]) })
});

test('analyze - allowQop as auth-in', t => {
  t.notThrows(() => { ServerDigestAuth.analyze(HEADER_POSTNESS_INT_MD5, [QOP_AUTH_INT]) })
  t.throws(() => { ServerDigestAuth.analyze(HEADER_GET_QOPLESS_MD5, [QOP_AUTH_INT]) })
  t.throws(() => { ServerDigestAuth.analyze(HEADER_GET_AUTH_MD5, [QOP_AUTH_INT]) })
});

test('analyze - allowQop as auth&auth-in', t => {
  t.notThrows(() => { ServerDigestAuth.analyze(HEADER_POSTNESS_INT_MD5, [QOP_AUTH, QOP_AUTH_INT]) })
  t.notThrows(() => { ServerDigestAuth.analyze(HEADER_GET_AUTH_MD5, [QOP_AUTH, QOP_AUTH_INT]) })
  t.throws(() => { ServerDigestAuth.analyze(HEADER_GET_QOPLESS_MD5, [QOP_AUTH, QOP_AUTH_INT]) })
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
  t.true(includes(res.raw, `qop="${QOP_AUTH}"`));
  t.true(includes(res.raw, `algorithm=${ALGORITHM_MD5}`));
  t.true(includes(res.raw, `opaque="${TEST_OPAQUE}"`));
});

/*
 * @Link RFC-7616 (quoted string) https://tools.ietf.org/html/rfc7616#section-3.3
 */
test('generateResponse WWW-Authenticate  MUST generate the quoted string syntax values for: realm, domain, nonce, opaque, and qop.', t => {

  const res = ServerDigestAuth.generateResponse(TEST_REALM, {
    opaque: TEST_OPAQUE,
    qop: QOP_AUTH,
    algorithm: ALGORITHM_MD5,
    domain: 'test.com'
  });

  t.true(includes(res.raw, `realm="${res.realm}"`));
  t.true(includes(res.raw, `domain="${res.domain}"`))
  t.true(includes(res.raw, `nonce="${res.nonce}"`));
  t.true(includes(res.raw, `opaque="${res.opaque}"`));
  t.true(includes(res.raw, `qop="${QOP_AUTH}"`));
});

/*
 * @Link RFC-7616 (quoted string) https://tools.ietf.org/html/rfc7616#section-3.3
 */
test('generateResponse WWW-Authenticate  MUST NOT generate the quoted string syntax values for:  stale and algorithm', t => {

  const res = ServerDigestAuth.generateResponse(TEST_REALM, {
    opaque: TEST_OPAQUE,
    qop: QOP_AUTH,
    algorithm: ALGORITHM_MD5,
    domain: 'test.com',
    stale: 'true',
  });

  t.is(res.qop, QOP_AUTH);
  t.is(res.opaque, TEST_OPAQUE);
  t.is(typeof res.nonce, 'string');
  t.is(res.nonce.length, 48);

  t.true(includes(res.raw, `algorithm=${res.algorithm}`));
  t.true(includes(res.raw, `stale=${res.stale}`));
});


/* ===============  ================ */
