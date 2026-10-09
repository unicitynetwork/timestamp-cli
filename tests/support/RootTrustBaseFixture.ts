import { RootTrustBase } from '@unicitylabs/state-transition-sdk/lib/api/bft/RootTrustBase.js';
import { NetworkId } from '@unicitylabs/state-transition-sdk/lib/api/NetworkId.js';
import { HexConverter } from '@unicitylabs/state-transition-sdk/lib/util/HexConverter.js';

/**
 * Single-node LOCAL trust base whose only root node signs with the given key.
 * Ported from the SDK's test utilities.
 */
export function createRootTrustBase(publicKey: Uint8Array): RootTrustBase {
  return RootTrustBase.fromJSON({
    changeRecordHash: null,
    epoch: '0',
    epochStartRound: '0',
    networkId: NetworkId.LOCAL.id,
    previousEntryHash: null,
    quorumThreshold: '1',
    rootNodes: [
      {
        nodeId: 'NODE',
        sigKey: HexConverter.encode(publicKey),
        stake: '1',
      },
    ],
    signatures: {},
    stateHash: '00',
    version: '1',
  });
}
