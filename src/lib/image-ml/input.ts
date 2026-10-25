import { sha3_256 } from "js-sha3";

export type RuntimeImageInput = { code: string; sourceHash: string };
/** Never classify a previous contract's runtime after the source editor changes. */
export function selectImageBytecode(body: string, runtime?: RuntimeImageInput): string {
  if (/^(?:0x)?[\da-f]+$/i.test(body.trim())) return body;
  return runtime?.sourceHash === sha3_256(body) ? runtime.code : body;
}
