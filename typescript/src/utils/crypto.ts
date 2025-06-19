import * as crypto from 'crypto';

export function computeHMAC(
  algorithm: string,
  secret: string,
  message: string | Buffer
): string {
  return crypto
    .createHmac(algorithm, secret)
    .update(message)
    .digest('hex');
}

export function computeHMACBase64(
  algorithm: string,
  secret: string,
  message: string | Buffer
): string {
  return crypto
    .createHmac(algorithm, secret)
    .update(message)
    .digest('base64');
}

export function timingSafeCompare(a: string, b: string): boolean {
  if (a.length !== b.length) {
    return false;
  }
  
  const bufferA = Buffer.from(a);
  const bufferB = Buffer.from(b);
  
  return crypto.timingSafeEqual(bufferA, bufferB);
}

export function isWithinTolerance(timestamp: number, toleranceSeconds: number): boolean {
  const now = Math.floor(Date.now() / 1000);
  const diff = Math.abs(now - timestamp);
  return diff <= toleranceSeconds;
}