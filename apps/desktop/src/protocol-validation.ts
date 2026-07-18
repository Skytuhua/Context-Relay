import Ajv2020 from 'ajv/dist/2020.js';

const utf8 = new TextEncoder();
const canonicalBase64Url =
  /^(?:[A-Za-z0-9_-]{4})*(?:[A-Za-z0-9_-][AQgw]|[A-Za-z0-9_-]{2}[AEIMQUYcgkosw048])?$/;

export const createProtocolSchemaValidator = () => {
  const ajv = new Ajv2020({ allErrors: true, strict: true });
  ajv.addKeyword({
    keyword: 'x-utf8-maxBytes',
    schemaType: 'number',
    type: 'string',
    validate: (limit: number, value: string) => utf8.encode(value).byteLength <= limit,
  });
  return ajv;
};

export const assertSha256Hex = (value: string) => {
  if (!/^[0-9a-f]{64}$/.test(value)) throw new TypeError('invalid SHA-256 hex');
};

export const assertBase64UrlBytes = (value: string, bytes: number) => {
  if (value.length !== Math.ceil((bytes * 4) / 3) || !canonicalBase64Url.test(value)) {
    throw new TypeError('invalid fixed-size base64url');
  }
};
