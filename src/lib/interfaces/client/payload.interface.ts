export interface PayloadUnprotected {
  method: string, uri: string
}

export interface PayloadProtectionAuth extends PayloadUnprotected {
  entryBody: string, counter: number, force_qop: string, force_algorithm?: string
}

export interface PayloadProtectionAuthInt extends PayloadProtectionAuth {
  entryBody: string
}
