/**
 * @deprecated
 */
export declare const coins: {
    readonly BCH: "bch";
    readonly BSV: "bsv";
    readonly BTC: "btc";
    readonly BTG: "btg";
    readonly LTC: "ltc";
    readonly ZEC: "zec";
    readonly DASH: "dash";
};
/** @deprecated */
export declare type CoinKey = keyof typeof coins;
/** @deprecated */
export declare type Coin = typeof coins[CoinKey];
export declare type NetworkName = 'bitcoin' | 'testnet' | 'bitcoincash' | 'bitcoincashTestnet' | 'bitcoingold' | 'bitcoingoldTestnet' | 'bitcoinsv' | 'bitcoinsvTestnet' | 'dash' | 'dashTest' | 'litecoin' | 'litecoinTest' | 'zcash' | 'zcashTest';
export declare type Network = {
    messagePrefix: string;
    pubKeyHash: number;
    scriptHash: number;
    wif: number;
    bip32: {
        public: number;
        private: number;
    };
    bech32?: string;
    /**
     * @deprecated
     */
    coin: Coin;
    forkId?: number;
};
export declare type ZcashNetwork = Network & {
    consensusBranchId: Record<number, number>;
};
export declare type BitcoinCashNetwork = Network & {
    cashAddr: {
        prefix: string;
        pubKeyHash: number;
        scriptHash: number;
    };
};
//# sourceMappingURL=networkTypes.d.ts.map