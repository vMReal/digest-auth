// tslint:disable:no-expression-statement
import test from 'ava';
import { Header } from './header';

test('parse', t => {
  const header = 'Digest username="user", realm="test-realm", nonce="test-nonce", uri="/auth", algorithm="MD5", qop="auth", nc=00000001, cnonce="test-cnonce", response="e524170b3e02dedaf6a1110131fb5a50", opaque="test-opaque"';
  t.deepEqual(
    Header.parse(header),
    [{
      raw: header.replace('Digest ', ''),
      scheme: 'Digest',
      username: '"user"',
      realm: '"test-realm"',
      nonce: '"test-nonce"',
      cnonce: '"test-cnonce"',
      nc: '00000001',
      uri: '"/auth"',
      qop: '"auth"',
      algorithm: '"MD5"',
      response: '"e524170b3e02dedaf6a1110131fb5a50"',
      opaque: '"test-opaque"'
    }]);
});

test('parse with special characters', t => {
  const header = 'Digest username="user", realm="test-re=alm", nonce="test-nonce", uri="/auth", algorithm="MD5", qop="auth", nc=00000001, cnonce="RfLCEIHjDR7DgKXvotSMMg==", response="e524170b3e02dedaf6a1110131fb5a50", opaque="test-opaque"';
  t.deepEqual(
    Header.parse(header),
    [{
      raw: header.replace('Digest ', ''),
      scheme: 'Digest',
      username: '"user"',
      realm: '"test-re=alm"',
      nonce: '"test-nonce"',
      cnonce: '"RfLCEIHjDR7DgKXvotSMMg=="',
      nc: '00000001',
      uri: '"/auth"',
      qop: '"auth"',
      algorithm: '"MD5"',
      response: '"e524170b3e02dedaf6a1110131fb5a50"',
      opaque: '"test-opaque"'
    }]);
});

test('parse multi authorization', t => {
  const firstDigest = 'username="user", realm="test-realm", nonce="test-nonce", uri="/auth", algorithm="MD5", qop="auth", nc=00000001, cnonce="test-cnonce", response="e524170b3e02dedaf6a1110131fb5a50", opaque="test-opaque"';
  const secondDigest = 'username="user2",realm="test-realm2",nonce="test-nonce2",uri="/auth2",algorithm="MD5",qop="auth",nc=00000001,cnonce="test-cnonce2",response="e524170b3e02dedaf6a1110131fb5a502",opaque="test-opaque2"';
  const multiAuth =
    `Digest ${firstDigest}`
    + `, Digest ${secondDigest}`
    + ', Basic YWxhZGRpbjpvcGVuc2VzYW1l'
    + ', Bearer mF_9.B5f-4.1JqM';

  t.deepEqual(
    Header.parse(multiAuth),
    [
      {
        raw: firstDigest,
        scheme: 'Digest',
        username: '"user"',
        realm: '"test-realm"',
        nonce: '"test-nonce"',
        cnonce: '"test-cnonce"',
        nc: '00000001',
        uri: '"/auth"',
        qop: '"auth"',
        algorithm: '"MD5"',
        response: '"e524170b3e02dedaf6a1110131fb5a50"',
        opaque: '"test-opaque"'
      },
      {
        raw: secondDigest,
        scheme: 'Digest',
        username: '"user2"',
        realm: '"test-realm2"',
        nonce: '"test-nonce2"',
        cnonce: '"test-cnonce2"',
        nc: '00000001',
        uri: '"/auth2"',
        qop: '"auth"',
        algorithm: '"MD5"',
        response: '"e524170b3e02dedaf6a1110131fb5a502"',
        opaque: '"test-opaque2"'
      },
      {
        scheme: 'Basic',
        raw: 'YWxhZGRpbjpvcGVuc2VzYW1l',
      },
      {
        scheme: 'Bearer',
        raw: 'mF_9.B5f-4.1JqM',
      }
    ]);
});


test('generate', t => {
  const header = Header.generate({
    realm: '"test-realm"',
    nonce: '"test-nonce"',
    qop: '"auth"',
    algorithm: '"MD5"',
    opaque: '"test-opaque"'
  });

  t.is(header, 'Digest realm="test-realm", nonce="test-nonce", qop="auth", algorithm="MD5", opaque="test-opaque"');
});

