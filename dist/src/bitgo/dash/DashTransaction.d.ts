/// <reference types="node" />
import { UtxoTransaction } from '../UtxoTransaction';
import { Network } from '../../networks';
export declare class DashTransaction extends UtxoTransaction {
    static DASH_NORMAL: number;
    static DASH_PROVIDER_REGISTER: number;
    static DASH_PROVIDER_UPDATE_SERVICE: number;
    static DASH_PROVIDER_UPDATE_REGISTRAR: number;
    static DASH_PROVIDER_UPDATE_REVOKE: number;
    static DASH_COINBASE: number;
    static DASH_QUORUM_COMMITMENT: number;
    type: number;
    extraPayload?: Buffer;
    constructor(network: Network, tx?: UtxoTransaction | DashTransaction);
    static fromTransaction(tx: DashTransaction): DashTransaction;
    static fromBuffer(buffer: Buffer, noStrict: boolean, network: Network): DashTransaction;
    clone(): DashTransaction;
    byteLength(_ALLOW_WITNESS?: boolean): number;
    /**
     * Helper to override `__toBuffer()` of bitcoinjs.Transaction.
     * Since the method is private, we use a hack in the constructor to make it work.
     *
     * TODO: remove `private` modifier in bitcoinjs `__toBuffer()` or find some other solution
     *
     * @param buffer - optional target buffer
     * @param initialOffset - can only be undefined or 0. Other values are only used for serialization in blocks.
     * @param _ALLOW_WITNESS - ignored
     */
    private toBufferWithExtraPayload;
    getHash(forWitness?: boolean): Buffer;
    /**
     * Build a hash for all or none of the transaction inputs depending on the hashtype
     * @param hashType
     * @returns Buffer
     */
    getPrevoutHash(hashType: number): Buffer;
}
//# sourceMappingURL=DashTransaction.d.ts.map