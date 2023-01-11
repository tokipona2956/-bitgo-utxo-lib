/// <reference types="node" />
import { networks } from '../../networks';
import { UtxoTransaction } from '../UtxoTransaction';
export declare type ZcashNetwork = typeof networks.zcash | typeof networks.zcashTest;
export declare class UnsupportedTransactionError extends Error {
    constructor(message: string);
}
export declare function getDefaultVersionGroupIdForVersion(version: number): number;
export declare function getDefaultConsensusBranchIdForVersion(network: ZcashNetwork, version: number): number;
export declare class ZcashTransaction extends UtxoTransaction {
    network: ZcashNetwork;
    static VERSION_JOINSPLITS_SUPPORT: number;
    static VERSION_OVERWINTER: number;
    static VERSION_SAPLING: number;
    static VERSION4_BRANCH_CANOPY: number;
    static VERSION4_BRANCH_NU5: number;
    static VERSION5_BRANCH_NU5: number;
    overwintered: number;
    versionGroupId: number;
    expiryHeight: number;
    consensusBranchId: number;
    constructor(network: ZcashNetwork, tx?: ZcashTransaction);
    static fromBuffer(buffer: Buffer, __noStrict: boolean, network?: ZcashNetwork): ZcashTransaction;
    static fromBufferWithVersion(buf: Buffer, network: ZcashNetwork, version?: number): ZcashTransaction;
    byteLength(): number;
    isSaplingCompatible(): boolean;
    isOverwinterCompatible(): boolean;
    supportsJoinSplits(): boolean;
    /**
     * Build a hash for all or none of the transaction inputs depending on the hashtype
     * @param hashType
     * @returns Buffer - BLAKE2b hash or 256-bit zero if doesn't apply
     */
    getPrevoutHash(hashType: number): Buffer;
    /**
     * Build a hash for all or none of the transactions inputs sequence numbers depending on the hashtype
     * @param hashType
     * @returns Buffer BLAKE2b hash or 256-bit zero if doesn't apply
     */
    getSequenceHash(hashType: number): Buffer;
    /**
     * Build a hash for one, all or none of the transaction outputs depending on the hashtype
     * @param hashType
     * @param inIndex
     * @returns Buffer BLAKE2b hash or 256-bit zero if doesn't apply
     */
    getOutputsHash(hashType: number, inIndex: number): Buffer;
    /**
     * Hash transaction for signing a transparent transaction in Zcash. Protected transactions are not supported.
     * @param inIndex
     * @param prevOutScript
     * @param value
     * @param hashType
     * @returns Buffer BLAKE2b hash
     */
    hashForSignatureByNetwork(inIndex: number | undefined, prevOutScript: Buffer, value: number, hashType: number): Buffer;
    toBuffer(buffer?: Buffer, initialOffset?: number): Buffer;
    getHash(forWitness?: boolean): Buffer;
    clone(): ZcashTransaction;
}
//# sourceMappingURL=ZcashTransaction.d.ts.map