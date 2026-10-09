import { SigningService } from '@unicitylabs/state-transition-sdk/lib/crypto/secp256k1/SigningService.js';
import { CborSerializer } from '@unicitylabs/state-transition-sdk/lib/serialization/cbor/CborSerializer.js';
import { HexConverter } from '@unicitylabs/state-transition-sdk/lib/util/HexConverter.js';

import { decodePayload, TimestampPayload, TimestampPayloadError } from '../../../src/lib/TimestampPayload.js';
import { TEST_DIGEST, TEST_DIGEST_HEX, TEST_PRIVATE_KEY, TEST_PUBLIC_KEY_HEX } from '../../support/fixtures.js';

const ANONYMOUS_HEX = `840158${'20'}${TEST_DIGEST_HEX}f6f6`;
const SIGNED_MESSAGE_HEX = '1e439a1c479923d40d2306ed530cc1cdbc977d9c5ec5986260525b7f8a7238d8';
const SIGNATURE_HEX =
  '0739c13ee4c3d785d82902a0d73cba7587a6491c226b68254fed2303e109492c3edd2a5a0343249fab0a3a318fcad83d375f83d44b8cffac2a3c70617a40b3bc00';
const SIGNED_HEX = `840158${'20'}${TEST_DIGEST_HEX}5821${TEST_PUBLIC_KEY_HEX}5841${SIGNATURE_HEX}`;
const SIGNATURE = HexConverter.decode(SIGNATURE_HEX);
const PUBLIC_KEY = HexConverter.decode(TEST_PUBLIC_KEY_HEX);

const uint = (value: number | bigint): Uint8Array => CborSerializer.encodeUnsignedInteger(value);
const bytes = (value: Uint8Array): Uint8Array => CborSerializer.encodeByteString(value);
const nil = (): Uint8Array => CborSerializer.encodeNull();
const array = (...items: Uint8Array[]): Uint8Array => CborSerializer.encodeArray(...items);
const payloadOf = (digest: Uint8Array, key: Uint8Array, signature: Uint8Array): TimestampPayload =>
  TimestampPayload.fromCBOR(array(uint(1), bytes(digest), bytes(key), bytes(signature)));
const flipped = (input: Uint8Array, index: number, value = 0x01): Uint8Array => {
  const copy = new Uint8Array(input);
  copy[index] ^= value;
  return copy;
};

describe('TimestampPayload', () => {
  const signer = new SigningService(TEST_PRIVATE_KEY);

  describe('anonymous', () => {
    it('encodes to the documented bytes and decodes back', async () => {
      const payload = TimestampPayload.anonymous(TEST_DIGEST);
      expect(HexConverter.encode(payload.toCBOR())).toEqual(ANONYMOUS_HEX);
      expect(payload.toCBOR()).toHaveLength(38);
      expect(payload.isSigned).toBe(false);
      expect(payload.signer).toBeNull();
      expect(payload.signature).toBeNull();

      const decoded = TimestampPayload.fromCBOR(payload.toCBOR());
      expect(HexConverter.encode(decoded.digest)).toEqual(TEST_DIGEST_HEX);
      expect(decoded.isSigned).toBe(false);
      await expect(decoded.verifySignature()).resolves.toBe(true);
    });

    it('rejects a digest that is not 32 bytes', () => {
      expect(() => TimestampPayload.anonymous(TEST_DIGEST.subarray(0, 31))).toThrow(TimestampPayloadError);
      expect(() => TimestampPayload.anonymous(new Uint8Array(33))).toThrow(
        'Digest must be 32 bytes (SHA-256), got 33 bytes.',
      );
    });
  });

  describe('signed', () => {
    it('reproduces the design vectors byte for byte', async () => {
      expect(HexConverter.encode(signer.publicKey)).toEqual(TEST_PUBLIC_KEY_HEX);
      expect(HexConverter.encode((await TimestampPayload.signedMessage(TEST_DIGEST)).data)).toEqual(SIGNED_MESSAGE_HEX);

      const payload = await TimestampPayload.sign(TEST_DIGEST, signer);
      expect(payload.isSigned).toBe(true);
      expect(HexConverter.encode(payload.signer!)).toEqual(TEST_PUBLIC_KEY_HEX);
      expect(HexConverter.encode(payload.signature!.encode())).toEqual(SIGNATURE_HEX);
      expect(HexConverter.encode(payload.toCBOR())).toEqual(SIGNED_HEX);
      expect(payload.toCBOR()).toHaveLength(138);
    });

    it('decodes and verifies the signed vector', async () => {
      const decoded = TimestampPayload.fromCBOR(HexConverter.decode(SIGNED_HEX));
      expect(HexConverter.encode(decoded.digest)).toEqual(TEST_DIGEST_HEX);
      expect(HexConverter.encode(decoded.signer!)).toEqual(TEST_PUBLIC_KEY_HEX);
      await expect(decoded.verifySignature()).resolves.toBe(true);
      expect(decoded.hash.toString()).toEqual(`[SHA-256]${TEST_DIGEST_HEX}`);
    });

    it('rejects a digest that is not 32 bytes', async () => {
      await expect(TimestampPayload.sign(new Uint8Array(16), signer)).rejects.toThrow(TimestampPayloadError);
    });
  });

  describe('fromCBOR rejects', () => {
    const invalidPoint = new Uint8Array(33).fill(0xff);
    invalidPoint[0] = 0x02;

    it.each<[string, Uint8Array, string]>([
      ['a byte string instead of an array', bytes(TEST_DIGEST), 'Payload is not a CBOR array of 4 elements.'],
      [
        'an array of 3 elements',
        array(uint(1), bytes(TEST_DIGEST), nil()),
        'Payload is not a CBOR array of 4 elements.',
      ],
      [
        'an array of 5 elements',
        array(uint(1), bytes(TEST_DIGEST), nil(), nil(), nil()),
        'Payload is not a CBOR array of 4 elements.',
      ],
      ['version 0', array(uint(0), bytes(TEST_DIGEST), nil(), nil()), 'Unsupported payload version 0; expected 1.'],
      ['version 2', array(uint(2), bytes(TEST_DIGEST), nil(), nil()), 'Unsupported payload version 2; expected 1.'],
      [
        'a 31-byte digest',
        array(uint(1), bytes(TEST_DIGEST.subarray(0, 31)), nil(), nil()),
        'Digest must be 32 bytes (SHA-256), got 31 bytes.',
      ],
      [
        'a signer without a signature',
        array(uint(1), bytes(TEST_DIGEST), bytes(PUBLIC_KEY), nil()),
        'Signer and signature must both be present or both be null.',
      ],
      [
        'a signature without a signer',
        array(uint(1), bytes(TEST_DIGEST), nil(), bytes(SIGNATURE)),
        'Signer and signature must both be present or both be null.',
      ],
      [
        'a 32-byte signer',
        array(uint(1), bytes(TEST_DIGEST), bytes(PUBLIC_KEY.subarray(1)), bytes(SIGNATURE)),
        'Signer must be a 33-byte compressed public key, got 32 bytes.',
      ],
      [
        'a signer that is not a point on the curve',
        array(uint(1), bytes(TEST_DIGEST), bytes(invalidPoint), bytes(SIGNATURE)),
        'Signer is not a valid secp256k1 public key.',
      ],
      [
        'a 64-byte signature',
        array(uint(1), bytes(TEST_DIGEST), bytes(PUBLIC_KEY), bytes(SIGNATURE.subarray(0, 64))),
        'Signature must be 65 bytes, got 64 bytes.',
      ],
      [
        'a signature with an impossible recovery id',
        array(uint(1), bytes(TEST_DIGEST), bytes(PUBLIC_KEY), bytes(flipped(SIGNATURE, 64, 0x07))),
        'Signature is malformed.',
      ],
    ])('%s', (_name, input, message) => {
      expect(() => TimestampPayload.fromCBOR(input)).toThrow(TimestampPayloadError);
      expect(() => TimestampPayload.fromCBOR(input)).toThrow(message);
    });
  });

  describe('verifySignature is false for', () => {
    it.each<[string, Uint8Array, Uint8Array, Uint8Array]>([
      ['a flipped signature byte', TEST_DIGEST, PUBLIC_KEY, flipped(SIGNATURE, 0)],
      ['a different digest under the same signature', flipped(TEST_DIGEST, 5), PUBLIC_KEY, SIGNATURE],
      ['a different, valid signer key', TEST_DIGEST, SigningService.generate().publicKey, SIGNATURE],
    ])('%s', async (_name, digest, key, signature) => {
      await expect(payloadOf(digest, key, signature).verifySignature()).resolves.toBe(false);
    });
  });

  describe('decodePayload', () => {
    it('returns the payload or the reason there is none', () => {
      expect(decodePayload(null)).toEqual({ error: 'Mint transaction carries no data payload.', payload: null });
      expect(decodePayload(bytes(TEST_DIGEST))).toEqual({
        error: 'Payload is not a CBOR array of 4 elements.',
        payload: null,
      });
      const decoded = decodePayload(HexConverter.decode(ANONYMOUS_HEX));
      expect(decoded.error).toBeNull();
      expect(decoded.payload?.isSigned).toBe(false);
    });
  });
});
