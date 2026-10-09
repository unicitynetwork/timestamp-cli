import { Token } from '@unicitylabs/state-transition-sdk/lib/transaction/Token.js';
import { TokenType } from '@unicitylabs/state-transition-sdk/lib/transaction/TokenType.js';
import { VerificationError } from '@unicitylabs/state-transition-sdk/lib/verification/VerificationError.js';
import { VerificationStatus } from '@unicitylabs/state-transition-sdk/lib/verification/VerificationStatus.js';

import { TimestampPayload } from '../../../src/lib/TimestampPayload.js';
import { createVerificationContext } from '../../../src/lib/verification.js';
import { TEST_DIGEST } from '../../support/fixtures.js';
import { TestAggregatorClient } from '../../support/TestAggregatorClient.js';
import { certifyMint } from '../../support/TimestampFixtures.js';

describe('createVerificationContext', () => {
  const aggregator = TestAggregatorClient.create();
  const context = createVerificationContext(aggregator.rootTrustBase);
  const data = TimestampPayload.anonymous(TEST_DIGEST).toCBOR();

  it('mints and verifies a timestamp token end to end against the in-memory aggregator', async () => {
    const genesis = await certifyMint(aggregator, undefined, { data });
    const token = await Token.mint(genesis, context);
    const roundTrip = await Token.fromCBOR(token.toCBOR());
    expect((await roundTrip.verify(context)).status).toEqual(VerificationStatus.OK);
    expect(roundTrip.genesis.referenceTime).toEqual(genesis.referenceTime);
  });

  it('rejects any other token type because the issuance registry is fail-closed', async () => {
    const genesis = await certifyMint(aggregator, undefined, { data, tokenType: TokenType.generate() });
    await expect(Token.mint(genesis, context)).rejects.toThrow(VerificationError);
  });

  it('rejects a timestamp token whose payload fails the issuance policy', async () => {
    await expect(Token.mint(await certifyMint(aggregator), context)).rejects.toThrow(VerificationError);
  });
});
