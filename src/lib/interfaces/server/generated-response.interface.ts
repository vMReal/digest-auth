import {ServerDigest} from "./digest.interface";

export interface GeneratedResponse extends ServerDigest {
  raw: string
}
