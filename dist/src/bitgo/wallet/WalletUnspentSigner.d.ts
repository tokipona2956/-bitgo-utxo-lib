import * as bip32 from 'bip32';
import { DerivedWalletKeys, RootWalletKeys, WalletKeys } from './WalletKeys';
import { Triple } from '../types';
export declare class WalletUnspentSigner<T extends WalletKeys> {
    signer: bip32.BIP32Interface;
    cosigner: bip32.BIP32Interface;
    readonly walletKeys: T;
    static from(walletKeys: RootWalletKeys, signer: bip32.BIP32Interface, cosigner: bip32.BIP32Interface): WalletUnspentSigner<RootWalletKeys>;
    constructor(walletKeys: WalletKeys | Triple<bip32.BIP32Interface>, signer: bip32.BIP32Interface, cosigner: bip32.BIP32Interface);
    /**
     * @param chain
     * @param index
     * @return WalletUnspentSigner that contains keys for generating output scripts and signatures.
     */
    deriveForChainAndIndex(chain: number, index: number): WalletUnspentSigner<DerivedWalletKeys>;
}
//# sourceMappingURL=WalletUnspentSigner.d.ts.map