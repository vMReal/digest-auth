import {plainToClass} from "class-transformer";
import {isIn} from "class-validator";
import { find, isUndefined, omitBy, pick } from 'lodash';
import {ALGORITHM_MD5_SESS, QOP_AUTH_INT} from "./constants";
import {IncomingDigestDto} from "./dto/server/incoming-digest.dto";
import {OutgoingDigestDto} from "./dto/server/outgoing-digest.dto";
import { OutgoingTransformDigestDto } from './dto/server/outgoing-transform-digest.dto';
import {HA1} from "./encryptions/h1";
import {HA2} from "./encryptions/h2";
import {Nonce} from "./encryptions/nonce";
import {Response} from "./encryptions/response";
import {
  ANALYZE_CODE_NOT_SUPPORT_QOP, ANALYZE_CODE_UNEXPECTED,
  AnalyzeException,
  NOT_ALLOW_DIGEST
} from './exceptions/analyze-exception';
import { BaseException } from './exceptions/base-exception';
import {
  GENERATE_RESPONSE_CODE_UNEXPECTED,
  GenerateResponseException
} from './exceptions/generate-response.exception';
import { Header, SCHEME_DIGEST } from './header';;
import {ClientDigest} from "./interfaces/server/digest.interface";
import {GeneratedResponse} from "./interfaces/server/generated-response.interface";
import {GenerateResponseOption} from "./interfaces/server/options.interface";
import {VerifyPayload} from "./interfaces/server/payload.interface";
import { Dto } from './utils/dto';

export class ServerDigestAuth {
  public static analyze(header: string, allowQop: ReadonlyArray<string> | false): ClientDigest
  public static analyze(header: string,  allowQop: ReadonlyArray<string> | false, multipleAuthentication: true): ReadonlyArray<{readonly scheme: string, readonly raw: string} | ClientDigest>
  public static analyze(header: string, allowQop: ReadonlyArray<string> | false, multipleAuthentication: boolean = false): ReadonlyArray<{readonly scheme: string, readonly raw: string} | ClientDigest> | ClientDigest  {
    try {
      const challenges = Header.parse(header);
      const analyzeChallenges = challenges.map((challenge) => {
        if (challenge.scheme !== SCHEME_DIGEST)
          return {...pick(challenge, ['scheme', 'raw'])};

        const digest: IncomingDigestDto = Dto.validate(IncomingDigestDto, challenge as unknown) as IncomingDigestDto;

        if (allowQop === false && !isUndefined(digest.qop))
          throw new AnalyzeException(ANALYZE_CODE_NOT_SUPPORT_QOP);

        if (allowQop !== false && !isIn(digest.qop, [...allowQop]))
          throw new AnalyzeException(ANALYZE_CODE_NOT_SUPPORT_QOP);

        return {...digest};
      });

      if (multipleAuthentication)
        return analyzeChallenges;

      const firstDigest = find(analyzeChallenges, {scheme: SCHEME_DIGEST}) as ClientDigest;
      if (!firstDigest)
        throw new AnalyzeException(NOT_ALLOW_DIGEST);

      return firstDigest;
    } catch (e) {
      if (e instanceof AnalyzeException)
        throw  e;

      throw new AnalyzeException(ANALYZE_CODE_UNEXPECTED);
    }
  }


  public static verifyByPassword(digest: ClientDigest, password: string, payload: VerifyPayload): boolean {
    return this.verifyBySecret(digest, HA1.generate(digest.username, password, digest.realm), payload);
  }


  public static verifyBySecret(digest: ClientDigest, secret: string, payload: VerifyPayload): boolean {
    const h1 = (digest.algorithm === ALGORITHM_MD5_SESS)
      ? HA1.generateSess(secret, digest.nonce, digest.cnonce)
      : secret;

    const h2 = (digest.qop === QOP_AUTH_INT)
      ? HA2.generateInt(payload.method, payload.uri, payload.entryBody)
      : HA2.generate(payload.method, payload.uri)

    const response = (!digest.qop)
      ? Response.generate(h1, digest.nonce, h2)
      : Response.generateProtected(h1, digest.nonce, h2, digest.nc, digest.cnonce, digest.qop)

    return (response === digest.response);
  }


  public static generateResponse(realm: string, option: GenerateResponseOption = {}): GeneratedResponse {
    try {
      const plainDigest = {
        realm,
        ...option,
        nonce: Nonce.generate()
      };

      const digest: OutgoingDigestDto = Dto.validate(OutgoingDigestDto, plainDigest as unknown) as OutgoingDigestDto;
      const finalDigest: OutgoingTransformDigestDto = plainToClass(OutgoingTransformDigestDto, plainDigest, {strategy: "excludeAll"});

      return {
        ...digest, // @TODO remove undefined
        raw: Header.generate(omitBy(finalDigest, isUndefined))
      }
    } catch (e) {
      if (e instanceof BaseException)
        throw  e;

      throw new GenerateResponseException(GENERATE_RESPONSE_CODE_UNEXPECTED);
    }
  }
}
