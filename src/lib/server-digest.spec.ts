// tslint:disable:no-expression-statement
import test from 'ava';
import {ServerDigestAuth} from "./server-digest-auth";
import {QOP_AUTH} from "./constants";

test('analyze', t => {
  const header = 'Digest username="user", realm="test-realm", nonce="test-nonce", uri="/auth", algorithm="MD5", qop=auth, nc=00000001, cnonce="test-cnonce", response="e524170b3e02dedaf6a1110131fb5a50", opaque="test-opaque"';
  t.deepEqual(
    ServerDigestAuth.analyze(header, [QOP_AUTH]),
    {
      username: 'user',
      realm: 'test-realm',
      nonce: 'test-nonce',
      cnonce: 'test-cnonce',
      nc: '00000001',
      uri: '/auth',
      qop: 'auth',
      algorithm: 'MD5',
      response: 'e524170b3e02dedaf6a1110131fb5a50',
      opaque: 'test-opaque',
    });
});
