import {Header} from "./header";
import {plainToClass} from "class-transformer";
import {validateSync, Validator} from "class-validator";
import {GENERATE_RESPONSE_CODE_VALIDATE, GenerateResponseException} from "./exceptions/generate-response.exception";
import {OutgoingDigestDto} from "./dto/server/outgoing-digest.dto";
import {IncomingDigestDto} from "./dto/server/incoming-digest.dto";
import {Nonce} from "./encryptions/nonce";
import {Response} from "./encryptions/response";
import {ALGORITHM_MD5_SESS, QOP_AUTH_INT} from "./constants";
import {HA2} from "./encryptions/h2";
import {HA1} from "./encryptions/h1";
import {ANALYZE_CODE_NOT_SUPPORT_QOP, ANALYZE_CODE_VALIDATE, AnalyzeException} from "./exceptions/analyze-exception";
import { OutgoingTransformDigestDto } from './dto/server/outgoing-transform-digest.dto';
import {omitBy, isUndefined} from "lodash";
import {ClientDigest} from "./interfaces/server/digest.interface";
import {GeneratedResponse} from "./interfaces/server/generated-response.interface";
import {GenerateResponseOption} from "./interfaces/server/options.interface";
import {VerifyPayload} from "./interfaces/server/payload.interface";

export class ServerDigestAuth {
  public static analyze(header: string, allowQop: string[] | false): ClientDigest  {
    try {
      const plainDigest: IncomingDigestDto = Header.parse(header);
      const digest: IncomingDigestDto = plainToClass(IncomingDigestDto, plainDigest, {strategy: "excludeAll"});
      validateSync(digest, {})

      if (allowQop === false && !isUndefined(plainDigest.qop))
        throw new AnalyzeException(ANALYZE_CODE_NOT_SUPPORT_QOP);

      if (allowQop !== false && !new Validator().isIn(plainDigest.qop, allowQop))
        throw new AnalyzeException(ANALYZE_CODE_NOT_SUPPORT_QOP);

      return {...digest};
    } catch (e) {
      if (e instanceof AnalyzeException)
        throw  e;

      throw new AnalyzeException(ANALYZE_CODE_VALIDATE);
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

      const digest: OutgoingDigestDto = plainToClass(OutgoingDigestDto, plainDigest, {strategy: "excludeAll"});
      validateSync(digest, {});

      const finalDigest: OutgoingTransformDigestDto = plainToClass(OutgoingTransformDigestDto, plainDigest, {strategy: "excludeAll"});

      return {
        ...digest, // @TODO remove undefined
        raw: Header.generate(omitBy(finalDigest, isUndefined))
      }
    } catch (e) {
      throw new GenerateResponseException(GENERATE_RESPONSE_CODE_VALIDATE);
    }
  }
}