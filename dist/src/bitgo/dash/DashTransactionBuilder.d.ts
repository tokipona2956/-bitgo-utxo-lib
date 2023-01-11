/// <reference types="node" />
import * as bitcoinjs from 'bitcoinjs-lib';
import { Network } from '../../networks';
import { UtxoTransactionBuilder } from '../UtxoTransactionBuilder';
import { DashTransaction } from './DashTransaction';
export declare class DashTransactionBuilder extends UtxoTransactionBuilder<DashTransaction> {
    constructor(network: Network, txb?: UtxoTransactionBuilder);
    createInitialTransaction(network: Network, tx?: bitcoinjs.Transaction): DashTransaction;
    setType(type: number): void;
    setExtraPayload(extraPayload?: Buffer): void;
    static fromTransaction(tx: DashTransaction, network?: bitcoinjs.Network, prevOutput?: bitcoinjs.TxOutput[]): DashTransactionBuilder;
}
//# sourceMappingURL=DashTransactionBuilder.d.ts.map