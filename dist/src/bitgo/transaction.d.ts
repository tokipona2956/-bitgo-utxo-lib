/// <reference types="node" />
import { TxOutput } from 'bitcoinjs-lib';
import { Network } from '../networks';
import { UtxoTransaction } from './UtxoTransaction';
import { UtxoTransactionBuilder } from './UtxoTransactionBuilder';
export declare function createTransactionFromBuffer(buf: Buffer, network: Network, { version }?: {
    version?: number;
}): UtxoTransaction;
export declare function createTransactionFromHex(hex: string, network: Network): UtxoTransaction;
export declare function getDefaultTransactionVersion(network: Network): number;
export declare function setTransactionBuilderDefaults(txb: UtxoTransactionBuilder, network: Network, { version }?: {
    version?: number;
}): void;
export declare function createTransactionBuilderForNetwork(network: Network, { version }?: {
    version?: number;
}): UtxoTransactionBuilder;
export declare function createTransactionBuilderFromTransaction(tx: UtxoTransaction, prevOutputs?: TxOutput[]): UtxoTransactionBuilder;
//# sourceMappingURL=transaction.d.ts.map