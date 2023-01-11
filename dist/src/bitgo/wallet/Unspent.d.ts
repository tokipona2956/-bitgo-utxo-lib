import { UtxoTransactionBuilder } from '../UtxoTransactionBuilder';
import { WalletUnspentSigner } from './WalletUnspentSigner';
import { RootWalletKeys } from './WalletKeys';
import { UtxoTransaction } from '../UtxoTransaction';
import { Triple } from '../types';
import { Unspent } from '../Unspent';
import { ChainCode } from './chains';
export interface WalletUnspent extends Unspent {
    chain: ChainCode;
    index: number;
}
export declare function isWalletUnspent(u: Unspent): u is WalletUnspent;
export declare function signInputWithUnspent(txBuilder: UtxoTransactionBuilder, inputIndex: number, unspent: WalletUnspent, unspentSigner: WalletUnspentSigner<RootWalletKeys>): void;
/**
 * @param tx
 * @param inputIndex
 * @param unspents
 * @param walletKeys
 * @return triple of booleans indicating a valid signature for each pubkey
 */
export declare function verifySignatureWithUnspent(tx: UtxoTransaction, inputIndex: number, unspents: Unspent[], walletKeys: RootWalletKeys): Triple<boolean>;
/**
 * @deprecated
 * Used in certain legacy signing methods that do not derive signing data from index/chain
 */
export interface WalletUnspentLegacy extends WalletUnspent {
    /** @deprecated - obviated by signWithUnspent */
    redeemScript?: string;
    /** @deprecated - obviated by verifyWithUnspent */
    witnessScript?: string;
}
//# sourceMappingURL=Unspent.d.ts.map