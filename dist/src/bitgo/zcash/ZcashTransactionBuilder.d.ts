/// <reference types="node" />
import * as bitcoinjs from 'bitcoinjs-lib';
import { Network } from '../..';
import { ZcashNetwork, ZcashTransaction } from './ZcashTransaction';
import { UtxoTransactionBuilder } from '../UtxoTransactionBuilder';
export declare class ZcashTransactionBuilder extends UtxoTransactionBuilder<ZcashTransaction> {
    constructor(network: ZcashNetwork);
    createInitialTransaction(network: Network, tx?: bitcoinjs.Transaction): ZcashTransaction;
    static fromTransaction(transaction: ZcashTransaction, network?: bitcoinjs.Network, prevOutput?: bitcoinjs.TxOutput[]): ZcashTransactionBuilder;
    setVersion(version: number, overwinter?: boolean): void;
    setDefaultsForVersion(network: Network, version: number): void;
    private hasSignatures;
    private setPropertyCheckSignatures;
    setConsensusBranchId(consensusBranchId: number): void;
    setVersionGroupId(versionGroupId: number): void;
    setExpiryHeight(expiryHeight: number): void;
    build(): ZcashTransaction;
    buildIncomplete(): ZcashTransaction;
    addOutput(scriptPubKey: string | Buffer, value: number): number;
}
//# sourceMappingURL=ZcashTransactionBuilder.d.ts.map