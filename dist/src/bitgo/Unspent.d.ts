/// <reference types="node" />
import { TxOutput, Network } from '..';
import { UtxoTransactionBuilder } from './UtxoTransactionBuilder';
/**
 * Public unspent data in BitGo-specific representation.
 */
export interface Unspent {
    /**
     * Format: ${txid}:${vout}.
     * Use `parseOutputId(id)` to parse.
     */
    id: string;
    /**
     * The network-specific encoded address.
     * Use `toOutputScript(address, network)` to obtain scriptPubKey.
     */
    address: string;
    /**
     * The amount in satoshi.
     */
    value: number;
}
/**
 * @return TxOutput from Unspent
 */
export declare function toOutput(u: Unspent, network: Network): TxOutput;
/**
 * @param outputId
 * @return TxOutPoint
 */
export declare function parseOutputId(outputId: string): TxOutPoint;
/**
 * @param txid
 * @param vout
 * @return outputId
 */
export declare function formatOutputId({ txid, vout }: TxOutPoint): string;
export declare function getOutputIdForInput(i: {
    hash: Buffer;
    index: number;
}): TxOutPoint;
/**
 * Reference to output of an existing transaction
 */
export declare type TxOutPoint = {
    txid: string;
    vout: number;
};
/**
 * Output reference and script data.
 * Suitable for use for `txb.addInput()`
 */
export declare type PrevOutput = TxOutPoint & TxOutput;
/**
 * @return PrevOutput from Unspent
 */
export declare function toPrevOutput(u: Unspent, network: Network): PrevOutput;
/**
 * @param txb
 * @param u
 * @param sequence - sequenceId
 */
export declare function addToTransactionBuilder(txb: UtxoTransactionBuilder, u: Unspent, sequence?: number): void;
export declare function unspentSum(unspents: Unspent[]): number;
//# sourceMappingURL=Unspent.d.ts.map