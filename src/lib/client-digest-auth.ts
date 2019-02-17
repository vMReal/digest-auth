import {Header} from "./header";
import {validateSync} from "class-validator";
import {Nonce} from "./encryptions/nonce";
import {Response} from "./encryptions/response";
import {ALGORITHM_MD5, ALGORITHM_MD5_SESS, QOP_AUTH, QOP_AUTH_INT} from "./constants";
import {HA2} from "./encryptions/h2";
import {HA1} from "./encryptions/h1";
import {ANALYZE_CODE_VALIDATE, AnalyzeException} from "./exceptions/analyze-exception";
import {IncomingDigestDto} from "./dto/client/incoming-digest.dto";
import {Cn} from "./encryptions/cn";
import {Dto} from "./utils/dto";
import {
  OutgoingTransformProtectedDigestDto,
  OutgoingTransformUnprotectedDigestDto
} from "./dto/client/outgoing-transform-digest.dto";
import {
  PayloadProtectionAuth,
  PayloadProtectionAuthInt,
  PayloadUnprotected
} from "./interfaces/client/payload.interface";
import {OutgoingProtectedDigestDto, OutgoingUnprotectedDigestDto} from "./dto/client/outgoing-digest.dto";
import {ClientProtectedDigest, ClientUnprotectedDigest, ServerDigest} from "./interfaces/client/digest.interface";
import {
  GeneratedProtectedResponse,
  GeneratedUnprotectedResponse
} from "./interfaces/client/generated-response.interface";
import {PayloadProtectionAuthDto, PayloadProtectionAuthIntDto, PayloadUnprotectedDto} from "./dto/client/payload.dto";

export class ClientDigestAuth {
  public static analyze(header: string): ServerDigest  {
    try {
      const plainDigest = Header.parse(header);
      const digest: ServerDigest = Dto.validate(IncomingDigestDto, plainDigest) as ServerDigest;
      validateSync(digest, {})

      return {...digest};
    } catch (e) {
      if (e instanceof AnalyzeException)
        throw  e;

      throw new AnalyzeException(ANALYZE_CODE_VALIDATE);
    }
  }

  protected static generateUnprotected(serverDigest: ServerDigest, username: string, password: string, payload: PayloadUnprotected): GeneratedUnprotectedResponse {
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

  public static generateAuthInt(serverDigest: ServerDigest, username: string, password: string, payload: PayloadProtectionAuthInt): GeneratedProtectedResponse {
    return this.generateQOP(
      {...serverDigest, qop: QOP_AUTH_INT},
      username,
      password,
      Dto.validate(PayloadProtectionAuthIntDto, payload)
    );
  }

  protected static generateQOP(serverDigest: ServerDigest & {qop: string}, username: string, password: string, payload: PayloadProtectionAuthInt): GeneratedProtectedResponse {
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
      algorithm: algorithm,
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
