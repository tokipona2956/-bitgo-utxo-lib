/// <reference types="node" />
/**
 * Implements hashing methods described in https://zips.z.cash/zip-0244.
 * Only supports full transparent transactions without shielded inputs or outputs.
 */
import { TxInput, TxOutput } from 'bitcoinjs-lib';
import { ZcashTransaction } from './ZcashTransaction';
declare type SignatureParams = {
    inIndex?: number;
    prevOutScript: Buffer;
    value: number;
    hashType: number;
};
/**
 * Blake2b hashing algorithm for Zcash
 * @param buffer
 * @param personalization
 * @returns 256-bit BLAKE2b hash
 */
export declare function getBlake2bHash(buffer: Buffer, personalization: string | Buffer): Buffer;
export declare function getPrevoutsDigest(ins: TxInput[], tag?: string, sigParams?: SignatureParams): Buffer;
export declare function getSequenceDigest(ins: TxInput[], tag?: string, sigParams?: SignatureParams): Buffer;
export declare function getOutputsDigest(outs: TxOutput[], tag?: string, sigParams?: SignatureParams): Buffer;
export declare function getTxidDigest(tx: ZcashTransaction): Buffer;
export declare function getSignatureDigest(tx: ZcashTransaction, inIndex: number | undefined, prevOutScript: Buffer, value: number, hashType: number): Buffer;
export {};
//# sourceMappingURL=hashZip0244.d.ts.map