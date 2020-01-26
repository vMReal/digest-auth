// tslint:disable:no-expression-statement
import test from 'ava';
import {includes} from "lodash";
import {ClientDigestAuth} from "./client-digest-auth";
import {ALGORITHM_MD5, ALGORITHM_MD5_SESS, QOP_AUTH, QOP_AUTH_INT} from './constants';
import { ServerDigestAuth } from './server-digest-auth';


const HEADER_UNPROTECTED = 'Digest realm="test-realm", nonce="test-nonce"';
const HEADER_HEADER_UNPROTECTED_MD5 = 'Digest realm="test-realm", nonce="test-nonce", algorithm="MD5"';
const HEADER_AUTH_MD5 = 'Digest realm="test-realm", nonce="test-nonce", algorithm="MD5", qop=auth';
const HEADER_AUTH_SESS = 'Digest realm="test-realm", nonce="test-nonce", algorithm="MD5-sess", qop=auth';
const HEADER_AUTHINT_MD5 = 'Digest realm="test-realm", nonce="test-nonce", algorithm="MD5", qop=auth-int';
const HEADER_AUTHINT_MD5_OPAQUE = 'Digest realm="test-realm", nonce="test-nonce", algorithm="MD5", qop=auth-int, opaque="test-opaque"';
// @TODO add stale and domain


const TEST_BODY = '{"key": "value"}';
const TEST_PASS = 'pass';
const TEST_USER = 'user';
const TEST_REALM = 'test-realm';
const TEST_NONCE = 'test-nonce';
//const TEST_CNONCE = 'test-cnonce';
const TEST_NC = '00000001';
const TEST_URI = '/auth';
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
})


test('analyze - ISSUE-8', t => {
  const res = ClientDigestAuth.analyze(`Digest qop="auth",algorithm=MD5,realm="monero-rpc",nonce="RfLCEIHjDR7DgKXvotSMMg==",stale=false, Digest qop="auth",algorithm=MD5-sess,realm="monero-rpc",nonce="RfLCEIHjDR7DgKXvotSMMg==",stale=false`);
  t.log(res);
  t.deepEqual(
    res,
    {
      qop: QOP_AUTH_INT,
      algorithm: ALGORITHM_MD5,
      realm: TEST_REALM,
      nonce: TEST_NONCE,
      opaque: TEST_OPAQUE,
    });
});


/************** analyze ******************/
/*
 *
 *
 *
 */

// generate** full flow

test('generateUnprotected unprotected)', t => {

  const digest = ClientDigestAuth.analyze(HEADER_UNPROTECTED);
  const res = ClientDigestAuth.generateUnprotected(digest, TEST_USER, TEST_PASS, {
    method: 'GET', uri: TEST_URI
  });

  t.is(res.username, TEST_USER);
  t.is(res.realm, TEST_REALM);
  t.is(res.nonce, digest.nonce);
  t.is(typeof res.response, 'string');

  t.true(includes(res.raw, `username="${TEST_USER}"`));
  t.true(includes(res.raw, `realm="${TEST_REALM}"`));
  t.true(includes(res.raw, `nonce="${res.nonce}"`));
  t.true(includes(res.raw, `response="${res.response}"`));
});


test('generateUnprotected unprotected - check with server-digest)', t => {

  const digest = ClientDigestAuth.analyze(HEADER_UNPROTECTED);
  const res = ClientDigestAuth.generateUnprotected(digest, TEST_USER, TEST_PASS, {
    method: 'GET', uri: TEST_URI
  });

  const incomingDigest = ServerDigestAuth.analyze(res.raw, false);
  const status = ServerDigestAuth.verifyByPassword(incomingDigest, TEST_PASS, {entryBody: '', method: 'GET', uri: TEST_URI});
  t.true(status);
});


test('generateUnprotected protected auth)', t => {

  const digest = ClientDigestAuth.analyze(HEADER_AUTH_MD5);
  const res = ClientDigestAuth.generateProtectionAuth(digest, TEST_USER, TEST_PASS, {
    method: 'POST', uri: TEST_URI, counter: 1,
  });

  t.is(res.username, TEST_USER);
  t.is(res.realm, TEST_REALM);
  t.is(res.nonce, digest.nonce);
  t.is(res.nc, TEST_NC);
  t.is(res.qop, QOP_AUTH);
  t.is(res.uri, TEST_URI);
  t.is(res.algorithm, ALGORITHM_MD5);

  t.is(typeof res.cnonce, 'string');
  t.is(res.cnonce.length, 48);

  t.is(typeof res.response, 'string');

  t.true(includes(res.raw, `username="${TEST_USER}"`));
  t.true(includes(res.raw, `realm="${TEST_REALM}"`));
  t.true(includes(res.raw, `nonce="${res.nonce}"`));
  t.true(includes(res.raw, `nc=${res.nc}`));
  t.true(includes(res.raw, `qop=${res.qop}`));
  t.true(includes(res.raw, `uri="${res.uri}"`));
  t.true(includes(res.raw, `algorithm="${res.algorithm}"`));
  t.true(includes(res.raw, `response="${res.response}"`));
});


test('generateUnprotected protected auth - check with server-digest)', t => {

  const digest = ClientDigestAuth.analyze(HEADER_AUTH_MD5);
  const res = ClientDigestAuth.generateProtectionAuth(digest, TEST_USER, TEST_PASS, {
    method: 'POST', uri: TEST_URI, counter: 1,
  });

  const incomingDigest = ServerDigestAuth.analyze(res.raw, [QOP_AUTH]);
  const status = ServerDigestAuth.verifyByPassword(incomingDigest, TEST_PASS, {entryBody: TEST_BODY, method: 'POST', uri: TEST_URI});
  t.true(status);
});


test('generateUnprotected protected auth-int)', t => {

  const digest = ClientDigestAuth.analyze(HEADER_AUTHINT_MD5);
  const res = ClientDigestAuth.generateProtectionAuthInt(digest, TEST_USER, TEST_PASS, {
    method: 'POST', uri: TEST_URI, counter: 1, entryBody: TEST_BODY,
  });

  t.is(res.username, TEST_USER);
  t.is(res.realm, TEST_REALM);
  t.is(res.nonce, digest.nonce);
  t.is(res.nc, TEST_NC);
  t.is(res.qop, QOP_AUTH_INT);
  t.is(res.uri, TEST_URI);
  t.is(res.algorithm, ALGORITHM_MD5);

  t.is(typeof res.cnonce, 'string');
  t.is(res.cnonce.length, 48);

  t.is(typeof res.response, 'string');

  t.true(includes(res.raw, `username="${TEST_USER}"`));
  t.true(includes(res.raw, `realm="${TEST_REALM}"`));
  t.true(includes(res.raw, `nonce="${res.nonce}"`));
  t.true(includes(res.raw, `nc=${res.nc}`));
  t.true(includes(res.raw, `qop=${res.qop}`));
  t.true(includes(res.raw, `uri="${res.uri}"`));
  t.true(includes(res.raw, `algorithm="${res.algorithm}"`));
  t.true(includes(res.raw, `response="${res.response}"`));
});

test('generateUnprotected protected auth-int - check with server-digest)', t => {

  const digest = ClientDigestAuth.analyze(HEADER_AUTHINT_MD5);
  const res = ClientDigestAuth.generateProtectionAuthInt(digest, TEST_USER, TEST_PASS, {
    method: 'POST', uri: TEST_URI, counter: 1, entryBody: TEST_BODY,
  });

  const incomingDigest = ServerDigestAuth.analyze(res.raw, [QOP_AUTH_INT]);
  const status = ServerDigestAuth.verifyByPassword(incomingDigest, TEST_PASS, {entryBody: TEST_BODY, method: 'POST', uri: TEST_URI});
  t.true(status);
});

// generate** force QOP

test('generateProtectionAuthInt correct force server unprotected QOP)', t => {

  const digest = ClientDigestAuth.analyze(HEADER_UNPROTECTED);
  const res = ClientDigestAuth.generateProtectionAuthInt(digest, TEST_USER, TEST_PASS, {
    method: 'POST', uri: TEST_URI, counter: 1, entryBody: TEST_BODY,
  });

  t.is(res.qop, QOP_AUTH_INT);
  t.true(includes(res.raw, `qop=${res.qop}`));
});

test('generateProtectionAuthInt correct force server auth QOP)', t => {

  const digest = ClientDigestAuth.analyze(HEADER_UNPROTECTED);
  const res = ClientDigestAuth.generateProtectionAuthInt(digest, TEST_USER, TEST_PASS, {
    method: 'POST', uri: TEST_URI, counter: 1, entryBody: TEST_BODY,
  });

  t.is(res.qop, QOP_AUTH_INT);
  t.true(includes(res.raw, `qop=${res.qop}`));
});


test('generateProtectionAuth correct force server unprotected QOP)', t => {

  const digest = ClientDigestAuth.analyze(HEADER_UNPROTECTED);
  const res = ClientDigestAuth.generateProtectionAuth(digest, TEST_USER, TEST_PASS, {
    method: 'POST', uri: TEST_URI, counter: 1,
  });

  t.is(res.qop, QOP_AUTH);
  t.true(includes(res.raw, `qop=${res.qop}`));
});

test('generateProtectionAuth correct force server auth-int QOP)', t => {

  const digest = ClientDigestAuth.analyze(HEADER_AUTHINT_MD5);
  const res = ClientDigestAuth.generateProtectionAuth(digest, TEST_USER, TEST_PASS, {
    method: 'POST', uri: TEST_URI, counter: 1,
  });

  t.is(res.qop, QOP_AUTH);
  t.true(includes(res.raw, `qop=${res.qop}`));
});


test('generateUnprotected correct force server auth QOP)', t => {

  const digest = ClientDigestAuth.analyze(HEADER_AUTH_MD5);
  const res = ClientDigestAuth.generateUnprotected(digest, TEST_USER, TEST_PASS, {
    method: 'POST', uri: TEST_URI
  });

  t.false('qop' in res);
  t.true(!includes(res.raw, `qop=`));
});

test('generateUnprotected correct force server auth-int QOP)', t => {

  const digest = ClientDigestAuth.analyze(HEADER_AUTHINT_MD5);
  const res = ClientDigestAuth.generateUnprotected(digest, TEST_USER, TEST_PASS, {
    method: 'POST', uri: TEST_URI,
  });

  t.false('qop' in res);
  t.true(!includes(res.raw, `qop=`));
});

// generate** force algorithm


test('generateProtectionAuth correct force server algorithm md5-sess)', t => {

  const digest = ClientDigestAuth.analyze(HEADER_AUTH_MD5);
  const res = ClientDigestAuth.generateProtectionAuth(digest, TEST_USER, TEST_PASS, {
    method: 'POST', uri: TEST_URI, counter: 1, force_algorithm: ALGORITHM_MD5_SESS
  });

  t.is(res.algorithm, ALGORITHM_MD5_SESS);
  t.true(includes(res.raw, `algorithm="${res.algorithm}"`));
});

test('generateProtectionAuth correct force server algorithm md5)', t => {

  const digest = ClientDigestAuth.analyze(HEADER_AUTH_SESS);
  const res = ClientDigestAuth.generateProtectionAuth(digest, TEST_USER, TEST_PASS, {
    method: 'POST', uri: TEST_URI, counter: 1, force_algorithm: ALGORITHM_MD5  });

  t.is(res.algorithm, ALGORITHM_MD5);
  t.true(includes(res.raw, `algorithm="${res.algorithm}"`));
});

