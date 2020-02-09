import { BaseException } from './base-exception';
export {BASE_CODE_VALIDATE as ANALYZE_CODE_VALIDATE, BASE_CODE_UNEXPECTED as ANALYZE_CODE_UNEXPECTED} from './base-exception';

export class AnalyzeException extends BaseException {

}

export const ANALYZE_CODE_NOT_SUPPORT_QOP = 'not_support_qop';
export const NOT_ALLOW_DIGEST = 'not_allow_digest';
