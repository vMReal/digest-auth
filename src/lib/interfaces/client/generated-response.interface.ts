import {ClientProtectedDigest, ClientUnprotectedDigest} from "./digest.interface";

export interface GeneratedUnprotectedResponse extends ClientUnprotectedDigest {
  raw: string;
}

export interface GeneratedProtectedResponse extends ClientProtectedDigest {
  raw: string;
}
