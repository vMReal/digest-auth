import {ClientDigest, Header, ServerDigest} from "./header";
import {plainToClass} from "class-transformer";
import {validateSync, Validator} from "class-validator";
import {GENERATE_RESPONSE_CODE_VALIDATE, GenerateResponseException} from "./exceptions/generate-response.exception";
import {Nonce} from "./encryptions/nonce";
import {Response} from "./encryptions/response";
import {ALGORITHM_MD5_SESS, QOP_AUTH, QOP_AUTH_INT} from "./constants";
import {HA2} from "./encryptions/h2";
import {HA1} from "./encryptions/h1";
import {ANALYZE_CODE_NOT_SUPPORT_QOP, ANALYZE_CODE_VALIDATE, AnalyzeException} from "./exceptions/analyze-exception";
import {omitBy, isUndefined, pick} from "lodash";
import {IncomingDigestDto} from "./dto/client/incoming-digest.dto";
import {Cn} from "./encryptions/cn";
import {Dto} from "./utils/dto";
import {ResponsePayloadDto} from "./dto/client/response-payload.dto";
import {OutgoingTransformDigestDto} from "./dto/client/outgoing-transform-digest.dto";

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



  public static generateResponse(digest: ServerDigest, username: string, password: string, clientPayload: ResponsePayload): boolean {
    const payload = Dto.validate(ResponsePayloadDto, clientPayload);

    if (payload.force_algorithm)
      digest.algorithm = payload.force_algorithm;

    if (payload.force_qop)
      digest.qop = payload.force_qop;

    const response = (digest.qop)
      ? this.generateWithQOP(digest, username, password, clientPayload)
      : this.generateWithoutQOP(digest, username, password, clientPayload)

    return {
      ...responce,
      raw: Header.generate(Dto.validate(OutgoingTransformDigestDto, response))
    };
  }

  protected static generate(digest: ServerDigest, username: string, password: string, payload: Payload) {
    const h1 = HA1.generate(username, password, digest.realm);
    const h2 = HA2.generate(payload.method, payload.uri)
    const response = Response.generate(h1, digest.nonce, h2)
    return {nonce: digest.nonce, realm: digest.realm, response, username};
  }

  protected static generateAuth(digest: ServerDigest, username: string, password: string, payload: PayloadAuth) {
    return this.generateQOP({...digest, qop: QOP_AUTH}, username, password, {...payload, entryBody: ''});
  }

  protected static generateAuthInt(digest: ServerDigest, username: string, password: string, payload: PayloadAuthInt) {
    return this.generateQOP({...digest, qop: QOP_AUTH_INT}, username, password, {...payload, entryBody: ''});
  }

  protected static generateQOP(digest: ServerDigest, username: string, password: string, payload: PayloadAuth | PayloadAuthInt) {
    const cnonce = Nonce.generate();
    const nc = Cn.toHex(payload.counter);

    const initialH1 = HA1.generate(username, password, digest.realm);
    const h1 = (digest.algorithm === ALGORITHM_MD5_SESS)
      ? HA1.generateSess(initialH1, digest.nonce, cnonce)
      : initialH1;

    const h2 = (digest.qop === QOP_AUTH_INT)
      ? HA2.generateInt(payload.method, payload.uri, payload.entryBody)
      : HA2.generate(payload.method, payload.uri)

    const response = Response.generateProtected(h1, digest.nonce, h2, nc, cnonce, digest.qop)

    return {
      nonce: digest.nonce,
      realm: digest.realm,
      opaque: digest.opaque,
      algorithm: digest.algorithm,
      qop: digest.qop,
      response,
      username,
      cnonce,
      nc
    };
  }
}


export interface GeneratedResponse extends ServerDigest {
  raw: string
}

export interface GenerateResponseOption {
  domain?: string, opaque?: string, stale?: string, algorithm?: string, qop?:string,
}

export interface ResponsePayload {
  entryBody: string, method: string, uri: string, counter?: number, force_qop?: string, force_algorithm?: string
}


export interface Payload {
  method: string, uri: string
}

export interface PayloadAuth {
  entryBody: string, method: string, uri: string, counter: number, force_qop: string, force_algorithm: string
}

export interface PayloadAuthInt extends PayloadAuth {
  entryBody: string
}
