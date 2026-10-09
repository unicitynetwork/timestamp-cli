import { SigningService } from '@unicitylabs/state-transition-sdk/lib/crypto/secp256k1/SigningService.js';
import { BurnPredicate } from '@unicitylabs/state-transition-sdk/lib/predicate/builtin/BurnPredicate.js';
import { SignaturePredicate } from '@unicitylabs/state-transition-sdk/lib/predicate/builtin/SignaturePredicate.js';
import { CborSerializer } from '@unicitylabs/state-transition-sdk/lib/serialization/cbor/CborSerializer.js';
import { HexConverter } from '@unicitylabs/state-transition-sdk/lib/util/HexConverter.js';
import { VerificationResult } from '@unicitylabs/state-transition-sdk/lib/verification/VerificationResult.js';
import { VerificationStatus } from '@unicitylabs/state-transition-sdk/lib/verification/VerificationStatus.js';

import { TIMESTAMP_TOKEN_TYPE } from '../../../src/lib/constants.js';
import { TimestampIssuanceVerifier } from '../../../src/lib/TimestampIssuanceVerifier.js';
import { TimestampPayload } from '../../../src/lib/TimestampPayload.js';
import { TEST_DIGEST } from '../../support/fixtures.js';
import { TestAggregatorClient } from '../../support/TestAggregatorClient.js';
import { certifyMint } from '../../support/TimestampFixtures.js';

function statusOf(result: VerificationResult<VerificationStatus>, rule: string): VerificationStatus | undefined {
  return result.results.find((child) => child.rule === rule)?.status as VerificationStatus | undefined;
}

describe('TimestampIssuanceVerifier', () => {
  const aggregator = TestAggregatorClient.create();
  const verifier = new TimestampIssuanceVerifier();
  const signer = SigningService.generate();
  const anonymousData = (): Uint8Array => TimestampPayload.anonymous(TEST_DIGEST).toCBOR();

  it('is registered for the timestamp token type', () => {
    expect(HexConverter.encode(verifier.tokenType.bytes)).toEqual(HexConverter.encode(TIMESTAMP_TOKEN_TYPE.bytes));
  });

  it('accepts a well-formed anonymous genesis with every rule passing', async () => {
    const result = await verifier.verify(await certifyMint(aggregator, undefined, { data: anonymousData() }));
    expect(result.status).toEqual(VerificationStatus.OK);
    expect(result.results.map((child) => child.rule)).toEqual([
      'RecipientIsTimestampBurn',
      'NoMintJustification',
      'PayloadPresent',
      'PayloadDecodes',
      'SignatureValid',
    ]);
    expect(result.results.every((child) => child.status === VerificationStatus.OK)).toBe(true);
  });

  it('accepts a well-formed signed genesis', async () => {
    const payload = await TimestampPayload.sign(TEST_DIGEST, signer);
    const result = await verifier.verify(await certifyMint(aggregator, undefined, { data: payload.toCBOR() }));
    expect(result.status).toEqual(VerificationStatus.OK);
  });

  it('rejects a signature predicate recipient but still runs the other rules', async () => {
    const genesis = await certifyMint(aggregator, SignaturePredicate.create(signer.publicKey), {
      data: anonymousData(),
    });
    const result = await verifier.verify(genesis);
    expect(result.status).toEqual(VerificationStatus.FAIL);
    expect(statusOf(result, 'RecipientIsTimestampBurn')).toEqual(VerificationStatus.FAIL);
    expect(result.message).toEqual('Recipient is not the timestamp burn predicate.');
    expect(statusOf(result, 'SignatureValid')).toEqual(VerificationStatus.OK);
  });

  it('rejects a burn predicate with a different reason', async () => {
    const genesis = await certifyMint(aggregator, BurnPredicate.create(new TextEncoder().encode('something else')), {
      data: anonymousData(),
    });
    expect(statusOf(await verifier.verify(genesis), 'RecipientIsTimestampBurn')).toEqual(VerificationStatus.FAIL);
  });

  it('rejects a mint justification', async () => {
    const genesis = await certifyMint(aggregator, undefined, {
      data: anonymousData(),
      justification: CborSerializer.encodeTag(1234n, CborSerializer.encodeNull()),
    });
    const result = await verifier.verify(genesis);
    expect(result.status).toEqual(VerificationStatus.FAIL);
    expect(statusOf(result, 'NoMintJustification')).toEqual(VerificationStatus.FAIL);
  });

  it('rejects a missing payload and stops there', async () => {
    const result = await verifier.verify(await certifyMint(aggregator));
    expect(result.status).toEqual(VerificationStatus.FAIL);
    expect(statusOf(result, 'PayloadPresent')).toEqual(VerificationStatus.FAIL);
    expect(result.results).toHaveLength(3);
    expect(result.message).toEqual('Mint transaction carries no data payload.');
  });

  it('rejects an undecodable payload with the decoder message', async () => {
    const genesis = await certifyMint(aggregator, undefined, {
      data: CborSerializer.encodeTextString('not a payload'),
    });
    const result = await verifier.verify(genesis);
    expect(result.status).toEqual(VerificationStatus.FAIL);
    expect(statusOf(result, 'PayloadDecodes')).toEqual(VerificationStatus.FAIL);
    expect(result.message).toEqual('Payload is not a CBOR array of 4 elements.');
    expect(result.results).toHaveLength(4);
  });

  it('rejects a tampered signature', async () => {
    const encoded = (await TimestampPayload.sign(TEST_DIGEST, signer)).toCBOR();
    encoded[encoded.length - 65] ^= 0x01;
    const result = await verifier.verify(await certifyMint(aggregator, undefined, { data: encoded }));
    expect(result.status).toEqual(VerificationStatus.FAIL);
    expect(statusOf(result, 'SignatureValid')).toEqual(VerificationStatus.FAIL);
    expect(result.message).toEqual('Payload signature does not verify for the signer.');
  });
});
