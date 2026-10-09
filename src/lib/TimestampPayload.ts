import { DataHash } from '@unicitylabs/state-transition-sdk/lib/crypto/hash/DataHash.js';
import { DataHasher } from '@unicitylabs/state-transition-sdk/lib/crypto/hash/DataHasher.js';
import { HashAlgorithm } from '@unicitylabs/state-transition-sdk/lib/crypto/hash/HashAlgorithm.js';
import { Signature } from '@unicitylabs/state-transition-sdk/lib/crypto/secp256k1/Signature.js';
import { SigningService } from '@unicitylabs/state-transition-sdk/lib/crypto/secp256k1/SigningService.js';
import { CborDeserializer } from '@unicitylabs/state-transition-sdk/lib/serialization/cbor/CborDeserializer.js';
import { CborSerializer } from '@unicitylabs/state-transition-sdk/lib/serialization/cbor/CborSerializer.js';

import { PAYLOAD_VERSION, TIMESTAMP_TAG } from './constants.js';

/** Message for a mint transaction without a `data` field. */
export const NO_PAYLOAD_MESSAGE = 'Mint transaction carries no data payload.';

/** Outcome of {@link decodePayload}: the payload, or why there is none. */
export type DecodedPayload =
  { readonly error: null; readonly payload: TimestampPayload } | { readonly error: string; readonly payload: null };

/** Thrown when bytes do not form a valid timestamp payload. */
export class TimestampPayloadError extends Error {
  public constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = 'TimestampPayloadError';
  }
}

/**
 * Application payload stored in the mint transaction's `data` field:
 *
 * ```
 * [ 1, digest(32), signer(33) | null, signature(65) | null ]
 * ```
 *
 * The signer and signature are both present or both null. A signed payload
 * carries the signer's compressed secp256k1 public key and a recoverable
 * signature over `SHA-256(CBOR["unicity-timestamp", 1, digest])`.
 */
export class TimestampPayload {
  public static readonly DIGEST_LENGTH = 32;
  public static readonly ELEMENT_COUNT = 4;
  public static readonly PUBLIC_KEY_LENGTH = 33;
  public static readonly SIGNATURE_LENGTH = 65;

  private constructor(
    private readonly _digest: Uint8Array,
    private readonly _signer: Uint8Array | null,
    public readonly signature: Signature | null,
  ) {
    this._digest = new Uint8Array(_digest);
    this._signer = _signer ? new Uint8Array(_signer) : null;
  }

  /** @returns {Uint8Array} Copy of the 32-byte SHA-256 digest. */
  public get digest(): Uint8Array {
    return new Uint8Array(this._digest);
  }

  /** @returns {DataHash} The digest as an SDK hash value. */
  public get hash(): DataHash {
    return new DataHash(HashAlgorithm.SHA256, this._digest);
  }

  /** @returns {boolean} True when a signer and signature are present. */
  public get isSigned(): boolean {
    return this._signer !== null;
  }

  /** @returns {Uint8Array|null} Copy of the signer's compressed public key, or null for an anonymous stamp. */
  public get signer(): Uint8Array | null {
    return this._signer ? new Uint8Array(this._signer) : null;
  }

  /**
   * Payload without identity.
   *
   * @param {Uint8Array} digest 32-byte SHA-256 digest.
   * @returns {TimestampPayload} Anonymous payload.
   * @throws {TimestampPayloadError} If the digest is not 32 bytes.
   */
  public static anonymous(digest: Uint8Array): TimestampPayload {
    TimestampPayload.assertDigest(digest);
    return new TimestampPayload(digest, null, null);
  }

  /**
   * Strict decoder. Anything that is not exactly the documented layout is an error.
   *
   * @param {Uint8Array} bytes CBOR bytes.
   * @returns {TimestampPayload} Decoded payload.
   * @throws {TimestampPayloadError} On any structural problem.
   */
  public static fromCBOR(bytes: Uint8Array): TimestampPayload {
    let elements: Uint8Array[];
    let version: bigint;
    let digest: Uint8Array;
    let signer: Uint8Array | null;
    let signatureBytes: Uint8Array | null;
    try {
      elements = CborDeserializer.decodeArray(bytes, TimestampPayload.ELEMENT_COUNT);
      version = CborDeserializer.decodeUnsignedInteger(elements[0]);
      digest = CborDeserializer.decodeByteString(elements[1]);
      signer = CborDeserializer.decodeNullable(elements[2], CborDeserializer.decodeByteString);
      signatureBytes = CborDeserializer.decodeNullable(elements[3], CborDeserializer.decodeByteString);
    } catch (error) {
      throw new TimestampPayloadError(`Payload is not a CBOR array of ${TimestampPayload.ELEMENT_COUNT} elements.`, {
        cause: error,
      });
    }

    if (version !== PAYLOAD_VERSION) {
      throw new TimestampPayloadError(`Unsupported payload version ${version}; expected ${PAYLOAD_VERSION}.`);
    }
    TimestampPayload.assertDigest(digest);

    if (signer === null && signatureBytes === null) {
      return new TimestampPayload(digest, null, null);
    }
    if (signer === null || signatureBytes === null) {
      throw new TimestampPayloadError('Signer and signature must both be present or both be null.');
    }
    if (signer.length !== TimestampPayload.PUBLIC_KEY_LENGTH) {
      throw new TimestampPayloadError(
        `Signer must be a ${TimestampPayload.PUBLIC_KEY_LENGTH}-byte compressed public key, got ${signer.length} bytes.`,
      );
    }
    if (!SigningService.isPublicKeyValid(signer)) {
      throw new TimestampPayloadError('Signer is not a valid secp256k1 public key.');
    }
    if (signatureBytes.length !== TimestampPayload.SIGNATURE_LENGTH) {
      throw new TimestampPayloadError(
        `Signature must be ${TimestampPayload.SIGNATURE_LENGTH} bytes, got ${signatureBytes.length} bytes.`,
      );
    }

    let signature: Signature;
    try {
      signature = Signature.decode(signatureBytes);
    } catch (error) {
      throw new TimestampPayloadError('Signature is malformed.', { cause: error });
    }

    return new TimestampPayload(digest, signer, signature);
  }

  /**
   * Payload signed by the holder of a key. The signature covers the
   * domain-separated message of {@link signedMessage}, never the bare digest.
   *
   * @param {Uint8Array} digest 32-byte SHA-256 digest.
   * @param {SigningService} signingService Signer.
   * @returns {Promise<TimestampPayload>} Signed payload.
   * @throws {TimestampPayloadError} If the digest is not 32 bytes.
   */
  public static async sign(digest: Uint8Array, signingService: SigningService): Promise<TimestampPayload> {
    TimestampPayload.assertDigest(digest);
    const signature = await signingService.sign(await TimestampPayload.signedMessage(digest));
    return new TimestampPayload(digest, signingService.publicKey, signature);
  }

  /**
   * Message a signer signs: `SHA-256(CBOR["unicity-timestamp", 1, digest])`.
   * The tag and version stop the signature from doubling as a signature over
   * the raw digest in some other protocol.
   *
   * @param {Uint8Array} digest 32-byte SHA-256 digest.
   * @returns {Promise<DataHash>} Message hash.
   */
  public static signedMessage(digest: Uint8Array): Promise<DataHash> {
    return new DataHasher(HashAlgorithm.SHA256)
      .update(
        CborSerializer.encodeArray(
          CborSerializer.encodeTextString(TIMESTAMP_TAG),
          CborSerializer.encodeUnsignedInteger(PAYLOAD_VERSION),
          CborSerializer.encodeByteString(digest),
        ),
      )
      .digest();
  }

  private static assertDigest(digest: Uint8Array): void {
    if (digest.length !== TimestampPayload.DIGEST_LENGTH) {
      throw new TimestampPayloadError(
        `Digest must be ${TimestampPayload.DIGEST_LENGTH} bytes (SHA-256), got ${digest.length} bytes.`,
      );
    }
  }

  /**
   * @returns {Uint8Array} CBOR encoding of the payload.
   */
  public toCBOR(): Uint8Array {
    return CborSerializer.encodeArray(
      CborSerializer.encodeUnsignedInteger(PAYLOAD_VERSION),
      CborSerializer.encodeByteString(this._digest),
      CborSerializer.encodeNullable(this._signer, CborSerializer.encodeByteString),
      CborSerializer.encodeNullable(this.signature?.encode() ?? null, CborSerializer.encodeByteString),
    );
  }

  /**
   * Check the signature against the signer key. An anonymous payload has
   * nothing to check and verifies trivially.
   *
   * @returns {Promise<boolean>} True if anonymous, or if the signature verifies for the signer.
   */
  public async verifySignature(): Promise<boolean> {
    if (this._signer === null || this.signature === null) {
      return true;
    }
    return SigningService.verifyWithPublicKey(
      await TimestampPayload.signedMessage(this._digest),
      this.signature,
      this._signer,
    );
  }
}

/**
 * Decode a mint transaction's data field without throwing.
 *
 * @param {Uint8Array|null} data Data field of the mint transaction.
 * @returns {DecodedPayload} Payload, or the reason it could not be read.
 */
export function decodePayload(data: Uint8Array | null): DecodedPayload {
  if (data === null) {
    return { error: NO_PAYLOAD_MESSAGE, payload: null };
  }
  try {
    return { error: null, payload: TimestampPayload.fromCBOR(data) };
  } catch (error) {
    return { error: error instanceof Error ? error.message : String(error), payload: null };
  }
}
