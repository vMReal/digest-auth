import { ValidationError } from 'class-validator/validation/ValidationError';

export class BaseException extends Error {

    constructor(code: string)
    constructor(code: 'validate', validationDetails: ReadonlyArray<ValidationError>)
    constructor(code: string, public readonly validationDetails: ReadonlyArray<ValidationError> = []) {
      super(code);
    }
}

export const BASE_CODE_UNEXPECTED = 'unexpected';
export const BASE_CODE_VALIDATE = 'validate';
