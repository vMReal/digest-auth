import {find, pick} from "lodash";
import {ALGORITHM_MD5, ALGORITHM_MD5_SESS, QOP_AUTH, QOP_AUTH_INT} from "./constants";
import {IncomingDigestDto} from "./dto/client/incoming-digest.dto";
import {OutgoingProtectedDigestDto, OutgoingUnprotectedDigestDto} from "./dto/client/outgoing-digest.dto";
import {
  OutgoingTransformProtectedDigestDto,
  OutgoingTransformUnprotectedDigestDto
} from "./dto/client/outgoing-transform-digest.dto";
import {PayloadProtectionAuthDto, PayloadProtectionAuthIntDto, PayloadUnprotectedDto} from "./dto/client/payload.dto";
import {Cn} from "./encryptions/cn";
import {HA1} from "./encryptions/h1";
import {HA2} from "./encryptions/h2";
import {Nonce} from "./encryptions/nonce";
import {Response} from "./encryptions/response";
import {
  ANALYZE_CODE_UNEXPECTED,
  AnalyzeException,
  NOT_ALLOW_DIGEST
} from './exceptions/analyze-exception';
import { BaseException } from './exceptions/base-exception';
import { Header, SCHEME_DIGEST } from './header';
import {ClientProtectedDigest, ClientUnprotectedDigest, ServerDigest} from "./interfaces/client/digest.interface";
import {
  GeneratedProtectedResponse,
  GeneratedUnprotectedResponse
} from "./interfaces/client/generated-response.interface";
import {
  PayloadProtectionAuth,
  PayloadProtectionAuthInt,
  PayloadUnprotected
} from "./interfaces/client/payload.interface";
import {Dto} from "./utils/dto";

export class ClientDigestAuth {
  public static analyze(header: string): ServerDigest
  public static analyze(header: string, multipleAuthentication: true): ReadonlyArray<{readonly scheme: string, readonly raw: string} | ServerDigest>
  public static analyze(header: string, multipleAuthentication: boolean = false): ReadonlyArray<{readonly scheme: string, readonly raw: string} | ServerDigest> | ServerDigest  {
    try {
      const challenges = Header.parse(header);
      const analyzeChallenges = challenges.map((challenge) => {
        if (challenge.scheme !== SCHEME_DIGEST)
          return {...pick(challenge, ['scheme', 'raw'])};

        const digest: ServerDigest = Dto.validate(IncomingDigestDto, challenge as unknown) as ServerDigest;

        return {... digest};
      });

      if (multipleAuthentication)
        return analyzeChallenges;

      const firstDigest = find(analyzeChallenges, {scheme: SCHEME_DIGEST}) as ServerDigest;
      if (!firstDigest)
        throw new AnalyzeException(NOT_ALLOW_DIGEST);

      return firstDigest;
    } catch (e) {
      if (e instanceof BaseException)
        throw  e;

      throw new AnalyzeException(ANALYZE_CODE_UNEXPECTED);
    }
  }

  public static generateUnprotected(serverDigest: ServerDigest, username: string, password: string, payload: PayloadUnprotected): GeneratedUnprotectedResponse {
    const validPayload = Dto.validate(PayloadUnprotectedDto, payload);
    const h1 = HA1.generate(username, password, serverDigest.realm);
    const h2 = HA2.generate(validPayload.method, validPayload.uri);
    const response = Response.generate(h1, serverDigest.nonce, h2);
    const digest: ClientUnprotectedDigest = Dto.validate(OutgoingUnprotectedDigestDto, {nonce: serverDigest.nonce, realm: serverDigest.realm, response, username});
    return {
      ...digest,
      raw: Header.generate({...Dto.validate(OutgoingTransformUnprotectedDigestDto, digest)}),
    };
  }

  public static generateProtectionAuth(serverDigest: ServerDigest, username: string, password: string, payload: PayloadProtectionAuth): GeneratedProtectedResponse {
    return this.generateQOP(
      {...serverDigest, qop: QOP_AUTH},
      username,
      password,
      Dto.validate(PayloadProtectionAuthDto, {...payload, entryBody: ''})
    );
  }

  public static generateProtectionAuthInt(serverDigest: ServerDigest, username: string, password: string, payload: PayloadProtectionAuthInt): GeneratedProtectedResponse {
    return this.generateQOP(
      {...serverDigest, qop: QOP_AUTH_INT},
      username,
      password,
      Dto.validate(PayloadProtectionAuthIntDto, payload)
    );
  }

  protected static generateQOP(serverDigest: ServerDigest & {readonly qop: string}, username: string, password: string, payload: PayloadProtectionAuthInt): GeneratedProtectedResponse {
    const cnonce = Nonce.generate();
    const nc = Cn.toHex(payload.counter);
    const algorithm: string = (payload.force_algorithm)
      ? payload.force_algorithm
      : serverDigest.algorithm || ALGORITHM_MD5;

    const initialH1 = HA1.generate(username, password, serverDigest.realm);
    const h1 = (algorithm === ALGORITHM_MD5_SESS)
      ? HA1.generateSess(initialH1, serverDigest.nonce, cnonce)
      : initialH1;

    const h2 = (serverDigest.qop === QOP_AUTH_INT)
      ? HA2.generateInt(payload.method, payload.uri, payload.entryBody)
      : HA2.generate(payload.method, payload.uri)

    const response = Response.generateProtected(h1, serverDigest.nonce, h2, nc, cnonce, serverDigest.qop)
    const digest: ClientProtectedDigest = Dto.validate(OutgoingProtectedDigestDto,{
      nonce: serverDigest.nonce,
      realm: serverDigest.realm,
      opaque: serverDigest.opaque,
      algorithm,
      qop: serverDigest.qop,
      uri: payload.uri,
      response,
      username,
      cnonce,
      nc
    });

    return {
      ...digest,
      raw: Header.generate({...Dto.validate(OutgoingTransformProtectedDigestDto, digest)}),
    };
  }
}
