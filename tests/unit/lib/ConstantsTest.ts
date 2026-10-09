import { createHash } from 'node:crypto';

import { BurnPredicate } from '@unicitylabs/state-transition-sdk/lib/predicate/builtin/BurnPredicate.js';
import { HexConverter } from '@unicitylabs/state-transition-sdk/lib/util/HexConverter.js';

import {
  TIMESTAMP_BURN_REASON,
  TIMESTAMP_RECIPIENT,
  TIMESTAMP_RECIPIENT_ENCODED,
  TIMESTAMP_TAG,
  TIMESTAMP_TOKEN_TYPE,
  TIMESTAMP_TOKEN_TYPE_HEX,
} from '../../../src/lib/constants.js';

describe('constants', () => {
  it('derives the token type from the SHA-256 of the tag', () => {
    expect(createHash('sha256').update(TIMESTAMP_TAG, 'utf8').digest('hex')).toEqual(TIMESTAMP_TOKEN_TYPE_HEX);
    expect(HexConverter.encode(TIMESTAMP_TOKEN_TYPE.bytes)).toEqual(TIMESTAMP_TOKEN_TYPE_HEX);
    expect(TIMESTAMP_TOKEN_TYPE_HEX).toEqual('dd671898ac55e0a3a9e22f07120cef94943d25fdf1dd0485aab077b21ee16193');
  });

  it('uses the UTF-8 tag as the burn reason', () => {
    expect(HexConverter.encode(TIMESTAMP_BURN_REASON)).toEqual('756e69636974792d74696d657374616d70');
    expect(HexConverter.encode(TIMESTAMP_RECIPIENT.reason)).toEqual(HexConverter.encode(TIMESTAMP_BURN_REASON));
  });

  it('encodes the recipient predicate to the documented bytes', () => {
    expect(HexConverter.encode(TIMESTAMP_RECIPIENT_ENCODED.toCBOR())).toEqual(
      'd998788301410251756e69636974792d74696d657374616d70',
    );
  });

  it('round-trips the recipient through the SDK burn predicate decoder', () => {
    const decoded = BurnPredicate.fromPredicate(TIMESTAMP_RECIPIENT_ENCODED);
    expect(HexConverter.encode(decoded.reason)).toEqual(HexConverter.encode(TIMESTAMP_BURN_REASON));
  });
});
