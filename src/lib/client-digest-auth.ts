import {ClientDigest, Header, ServerDigest} from "./header";
import {plainToClass} from "class-transformer";
import {validateSync, Validator} from "class-validator";
import {GENERATE_RESPONSE_CODE_VALIDATE, GenerateResponseException} from "./exceptions/generate-response.exception";
import {Nonce} from "./encryptions/nonce";
import {Response} from "./encryptions/response";
import {ALGORITHM_MD5_SESS, QOP_AUTH_INT} from "./constants";
import {HA2} from "./encryptions/h2";
import {HA1} from "./encryptions/h1";
import {ANALYZE_CODE_NOT_SUPPORT_QOP, ANALYZE_CODE_VALIDATE, AnalyzeException} from "./exceptions/analyze-exception";
import {omitBy, isUndefined} from "lodash";
import {IncomingDigestDto} from "./dto/client/incoming-digest.dto";

export class ClientDigestAuth {
  public static analyze(header: string): ServerDigest  {
    try {
      const plainDigest = Header.parse(header);
      const digest: IncomingDigestDto = plainToClass(IncomingDigestDto, plainDigest, {strategy: "excludeAll"});
      validateSync(digest, {})

      return {...digest};
    } catch (e) {
      if (e instanceof AnalyzeException)
        throw  e;

      throw new AnalyzeException(ANALYZE_CODE_VALIDATE);
    }
  }


  public static verifyByCredentials(digest: ServerDigest, username: string, password: string, payload: VerifyPayload): boolean {
    return this.verifyBySecret(digest, HA1.generate(username, password, digest.realm), payload);
  }


  public static verifyBySecret(digest: ServerDigest, secret: string, payload: VerifyPayload, cn: number = 1): boolean {
    const cnonce = (digest.qop)
      ? Nonce.generate()
      : '';

    const hexCn = const buf = Buffer.allocUnsafe(4);

    buf.writeInt32BE(11, 0);

    buf.toString('hex')

    const h1 = (digest.algorithm === ALGORITHM_MD5_SESS)
      ? HA1.generateSess(secret, digest.nonce, cnonce)
      : secret;

    const h2 = (digest.qop === QOP_AUTH_INT)
      ? HA2.generateInt(payload.method, payload.uri, payload.entryBody)
      : HA2.generate(payload.method, payload.uri)

    const response = (!digest.qop)
      ? Response.generate(h1, digest.nonce, h2)
      : Response.generateProtected(h1, digest.nonce, h2, digest.nc, cnonce, digest.qop)

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


export interface GeneratedResponse extends ServerDigest {
  raw: string
}

export interface GenerateResponseOption {
  domain?: string, opaque?: string, stale?: string, algorithm?: string, qop?:string,
}

export interface VerifyPayload {
  entryBody: string, method: string, uri: string
}
