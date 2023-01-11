/// <reference types="node" />
import { TxOutput, Transaction, TransactionBuilder } from 'bitcoinjs-lib';
import * as bitcoinjs from 'bitcoinjs-lib';
import { Network } from '..';
import { UtxoTransaction } from './UtxoTransaction';
export interface TxbSignArg {
    prevOutScriptType: string;
    vin: number;
    keyPair: bitcoinjs.ECPair.Signer;
    redeemScript?: Buffer;
    hashType?: number;
    witnessValue?: number;
    witnessScript?: Buffer;
    controlBlock?: Buffer;
}
export declare class UtxoTransactionBuilder<T extends UtxoTransaction = UtxoTransaction> extends TransactionBuilder {
    constructor(network: Network, txb?: TransactionBuilder, prevOutputs?: TxOutput[]);
    createInitialTransaction(network: Network, tx?: Transaction): UtxoTransaction;
    static fromTransaction(tx: UtxoTransaction, network?: bitcoinjs.Network, prevOutputs?: TxOutput[]): UtxoTransactionBuilder;
    get tx(): T;
    build(): T;
    buildIncomplete(): T;
    sign(signParams: number | TxbSignArg, keyPair?: bitcoinjs.ECPair.Signer, redeemScript?: Buffer, hashType?: number, witnessValue?: number, witnessScript?: Buffer): void;
}
//# sourceMappingURL=UtxoTransactionBuilder.d.ts.map