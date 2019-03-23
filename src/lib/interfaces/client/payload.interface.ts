export interface PayloadUnprotected {
  method: string, uri: string
}

export interface PayloadProtectionAuth extends PayloadUnprotected {
  counter: number, force_algorithm?: string
}

export interface PayloadProtectionAuthInt extends PayloadProtectionAuth {
  entryBody: string
}
