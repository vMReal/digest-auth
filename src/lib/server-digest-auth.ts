import {ClientDigest, Header, ServerDigest} from "./header";
import {plainToClass} from "class-transformer";
import {validateSync, Validator} from "class-validator";
import {GENERATE_RESPONSE_CODE_VALIDATE, GenerateResponseException} from "./exceptions/generate-response.exception";
import {ServerDigestDto} from "./dto/server-digest.dto";
import {ClientDigestDto} from "./dto/client-digest.dto";
import {Nonce} from "./encryptions/nonce";
import {Response} from "./encryptions/response";
import {ALGORITHM_MD5_SESS, QOP_AUTH_INT} from "./constants";
import {HA2} from "./encryptions/h2";
import {HA1} from "./encryptions/h1";
import {ANALYZE_CODE_NOT_SUPPORT_QOP, ANALYZE_CODE_VALIDATE, AnalyzeException} from "./exceptions/analyze-exception";

export class ServerDigestAuth {
  public static analyze(header: string, allowQop: string[]): ClientDigest  {
    try {
      const plainDigest = Header.parce<ClientDigest>(header);
      const digest: ClientDigestDto = plainToClass(ClientDigestDto, plainDigest, {strategy: "excludeAll"});
      validateSync(digest, {})

      if (!new Validator().isIn(plainDigest.qop, allowQop))
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

      const digest: ClientDigestDto = plainToClass(ServerDigestDto, plainDigest, {strategy: "excludeAll"});
      validateSync(digest, {})

      return {
        ...digest,
        raw: Header.generate<ServerDigest>({...digest})
      }
    } catch (e) {
      throw new GenerateResponseException(GENERATE_RESPONSE_CODE_VALIDATE);
    }
  }
}


export interface GeneratedResponse extends ServerDigest {
  domain?: string, opaque?: string, stale?: string, algorithm?: string, qop?:string,
}

export interface GenerateResponseOption {
  domain?: string, opaque?: string, stale?: string, algorithm?: string, qop?:string,
}

export interface VerifyPayload {
  entryBody: string, method: string, uri: string
}
