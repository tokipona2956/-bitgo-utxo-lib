/// <reference types="node" />
import * as bitcoinjs from 'bitcoinjs-lib';
import { Network } from '../networks';
export declare function varSliceSize(slice: Buffer): number;
export declare class UtxoTransaction extends bitcoinjs.Transaction {
    network: Network;
    static SIGHASH_FORKID: number;
    /** @deprecated use SIGHASH_FORKID */
    static SIGHASH_BITCOINCASHBIP143: number;
    constructor(network: Network, transaction?: bitcoinjs.Transaction);
    static fromBuffer(buf: Buffer, noStrict: boolean, network?: Network, prevOutput?: bitcoinjs.TxOutput[]): UtxoTransaction;
    addForkId(hashType: number): number;
    hashForWitnessV0(inIndex: number, prevOutScript: Buffer, value: number, hashType: number): Buffer;
    /**
     * Calculate the hash to verify the signature against
     */
    hashForSignatureByNetwork(inIndex: number, prevoutScript: Buffer, value: number | undefined, hashType: number): Buffer;
    hashForSignature(inIndex: number, prevOutScript: Buffer, hashType: number): Buffer;
    clone(): UtxoTransaction;
}
//# sourceMappingURL=UtxoTransaction.d.ts.map