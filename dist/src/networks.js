"use strict";
/*

The values for the various fork coins can be found in these files:

property       filename                  varname                           notes
------------------------------------------------------------------------------------------------------------------------
messagePrefix  src/validation.cpp        strMessageMagic                   Format `${CoinName} Signed Message`
bech32_hrp     src/chainparams.cpp       bech32_hrp                        Only for some networks
bip32.public   src/chainparams.cpp       base58Prefixes[EXT_PUBLIC_KEY]    Mainnets have same value, testnets have same value
bip32.private  src/chainparams.cpp       base58Prefixes[EXT_SECRET_KEY]    Mainnets have same value, testnets have same value
pubKeyHash     src/chainparams.cpp       base58Prefixes[PUBKEY_ADDRESS]
scriptHash     src/chainparams.cpp       base58Prefixes[SCRIPT_ADDRESS]
wif            src/chainparams.cpp       base58Prefixes[SECRET_KEY]        Testnets have same value
forkId         src/script/interpreter.h  FORKID_*

*/
Object.defineProperty(exports, "__esModule", { value: true });
exports.supportsTaproot = exports.supportsSegwit = exports.isValidNetwork = exports.isZcash = exports.isLitecoin = exports.isDash = exports.isBitcoinSV = exports.isBitcoinGold = exports.isBitcoinCash = exports.isBitcoin = exports.getTestnet = exports.isSameCoin = exports.isTestnet = exports.isMainnet = exports.getMainnet = exports.getNetworkName = exports.getNetworkList = exports.networks = void 0;
/**
 * @deprecated
 */
const coins = {
    BCH: 'bch',
    BSV: 'bsv',
    BTC: 'btc',
    BTG: 'btg',
    LTC: 'ltc',
    ZEC: 'zec',
    DASH: 'dash',
};
function getDefaultBip32Mainnet() {
    return {
        // base58 'xpub'
        public: 0x0488b21e,
        // base58 'xprv'
        private: 0x0488ade4,
    };
}
function getDefaultBip32Testnet() {
    return {
        // base58 'tpub'
        public: 0x043587cf,
        // base58 'tprv'
        private: 0x04358394,
    };
}
exports.networks = {
    // https://github.com/bitcoin/bitcoin/blob/master/src/validation.cpp
    // https://github.com/bitcoin/bitcoin/blob/master/src/chainparams.cpp
    bitcoin: {
        messagePrefix: '\x18Bitcoin Signed Message:\n',
        bech32: 'bc',
        bip32: getDefaultBip32Mainnet(),
        pubKeyHash: 0x00,
        scriptHash: 0x05,
        wif: 0x80,
        coin: coins.BTC,
    },
    testnet: {
        messagePrefix: '\x18Bitcoin Signed Message:\n',
        bech32: 'tb',
        bip32: getDefaultBip32Testnet(),
        pubKeyHash: 0x6f,
        scriptHash: 0xc4,
        wif: 0xef,
        coin: coins.BTC,
    },
    // https://github.com/Bitcoin-ABC/bitcoin-abc/blob/master/src/validation.cpp
    // https://github.com/Bitcoin-ABC/bitcoin-abc/blob/master/src/chainparams.cpp
    // https://github.com/bitcoincashorg/bitcoincash.org/blob/master/spec/cashaddr.md
    bitcoincash: {
        messagePrefix: '\x18Bitcoin Signed Message:\n',
        bip32: getDefaultBip32Mainnet(),
        pubKeyHash: 0x00,
        scriptHash: 0x05,
        wif: 0x80,
        coin: coins.BCH,
        forkId: 0x00,
        cashAddr: {
            prefix: 'bitcoincash',
            pubKeyHash: 0x00,
            scriptHash: 0x08,
        },
    },
    bitcoincashTestnet: {
        messagePrefix: '\x18Bitcoin Signed Message:\n',
        bip32: getDefaultBip32Testnet(),
        pubKeyHash: 0x6f,
        scriptHash: 0xc4,
        wif: 0xef,
        coin: coins.BCH,
        cashAddr: {
            prefix: 'bchtest',
            pubKeyHash: 0x00,
            scriptHash: 0x08,
        },
    },
    // https://github.com/BTCGPU/BTCGPU/blob/master/src/validation.cpp
    // https://github.com/BTCGPU/BTCGPU/blob/master/src/chainparams.cpp
    // https://github.com/BTCGPU/BTCGPU/blob/master/src/script/interpreter.h
    bitcoingold: {
        messagePrefix: '\x18Bitcoin Gold Signed Message:\n',
        bech32: 'btg',
        bip32: getDefaultBip32Mainnet(),
        pubKeyHash: 0x26,
        scriptHash: 0x17,
        wif: 0x80,
        forkId: 79,
        coin: coins.BTG,
    },
    bitcoingoldTestnet: {
        messagePrefix: '\x18Bitcoin Gold Signed Message:\n',
        bech32: 'tbtg',
        bip32: getDefaultBip32Testnet(),
        pubKeyHash: 111,
        scriptHash: 196,
        wif: 0xef,
        forkId: 79,
        coin: coins.BTG,
    },
    // https://github.com/bitcoin-sv/bitcoin-sv/blob/master/src/validation.cpp
    // https://github.com/bitcoin-sv/bitcoin-sv/blob/master/src/chainparams.cpp
    bitcoinsv: {
        messagePrefix: '\x18Bitcoin Signed Message:\n',
        bip32: getDefaultBip32Mainnet(),
        pubKeyHash: 0x00,
        scriptHash: 0x05,
        wif: 0x80,
        coin: coins.BSV,
        forkId: 0x00,
    },
    bitcoinsvTestnet: {
        messagePrefix: '\x18Bitcoin Signed Message:\n',
        bip32: getDefaultBip32Testnet(),
        pubKeyHash: 0x6f,
        scriptHash: 0xc4,
        wif: 0xef,
        coin: coins.BSV,
        forkId: 0x00,
    },
    // https://github.com/dashpay/dash/blob/master/src/validation.cpp
    // https://github.com/dashpay/dash/blob/master/src/chainparams.cpp
    dash: {
        messagePrefix: '\x19DarkCoin Signed Message:\n',
        bip32: getDefaultBip32Mainnet(),
        pubKeyHash: 0x4c,
        scriptHash: 0x10,
        wif: 0xcc,
        coin: coins.DASH,
    },
    dashTest: {
        messagePrefix: '\x19DarkCoin Signed Message:\n',
        bip32: getDefaultBip32Testnet(),
        pubKeyHash: 0x8c,
        scriptHash: 0x13,
        wif: 0xef,
        coin: coins.DASH,
    },
    // https://github.com/litecoin-project/litecoin/blob/master/src/validation.cpp
    // https://github.com/litecoin-project/litecoin/blob/master/src/chainparams.cpp
    litecoin: {
        messagePrefix: '\x19Litecoin Signed Message:\n',
        bech32: 'ltc',
        bip32: getDefaultBip32Mainnet(),
        pubKeyHash: 0x30,
        scriptHash: 0x32,
        wif: 0xb0,
        coin: coins.LTC,
    },
    litecoinTest: {
        messagePrefix: '\x19Litecoin Signed Message:\n',
        bech32: 'tltc',
        bip32: getDefaultBip32Testnet(),
        pubKeyHash: 0x6f,
        scriptHash: 0x3a,
        wif: 0xef,
        coin: coins.LTC,
    },
    // https://github.com/zcash/zcash/blob/master/src/validation.cpp
    // https://github.com/zcash/zcash/blob/master/src/chainparams.cpp
    zcash: {
        messagePrefix: '\x18ZCash Signed Message:\n',
        bip32: getDefaultBip32Mainnet(),
        pubKeyHash: 0x1cb8,
        scriptHash: 0x1cbd,
        wif: 0x80,
        coin: coins.ZEC,
    },
    zcashTest: {
        messagePrefix: '\x18ZCash Signed Message:\n',
        bip32: getDefaultBip32Testnet(),
        pubKeyHash: 0x1d25,
        scriptHash: 0x1cba,
        wif: 0xef,
        coin: coins.ZEC,
    },
};
/**
 * @returns {Network[]} all known networks as array
 */
function getNetworkList() {
    return Object.values(exports.networks);
}
exports.getNetworkList = getNetworkList;
/**
 * @param {Network} network
 * @returns {string} the name of the network. Returns undefined if network is not a value
 *                   of `networks`
 */
function getNetworkName(network) {
    return Object.keys(exports.networks).find((n) => exports.networks[n] === network);
}
exports.getNetworkName = getNetworkName;
/**
 * @param {Network} network
 * @returns {Object} the mainnet corresponding to a testnet
 */
function getMainnet(network) {
    switch (network) {
        case exports.networks.bitcoin:
        case exports.networks.testnet:
            return exports.networks.bitcoin;
        case exports.networks.bitcoincash:
        case exports.networks.bitcoincashTestnet:
            return exports.networks.bitcoincash;
        case exports.networks.bitcoingold:
        case exports.networks.bitcoingoldTestnet:
            return exports.networks.bitcoingold;
        case exports.networks.bitcoinsv:
        case exports.networks.bitcoinsvTestnet:
            return exports.networks.bitcoinsv;
        case exports.networks.dash:
        case exports.networks.dashTest:
            return exports.networks.dash;
        case exports.networks.litecoin:
        case exports.networks.litecoinTest:
            return exports.networks.litecoin;
        case exports.networks.zcash:
        case exports.networks.zcashTest:
            return exports.networks.zcash;
    }
    throw new TypeError(`invalid network`);
}
exports.getMainnet = getMainnet;
/**
 * @param {Network} network
 * @returns {boolean} true iff network is a mainnet
 */
function isMainnet(network) {
    return getMainnet(network) === network;
}
exports.isMainnet = isMainnet;
/**
 * @param {Network} network
 * @returns {boolean} true iff network is a testnet
 */
function isTestnet(network) {
    return getMainnet(network) !== network;
}
exports.isTestnet = isTestnet;
/**
 *
 * @param {Network} network
 * @param {Network} otherNetwork
 * @returns {boolean} true iff both networks are for the same coin
 */
function isSameCoin(network, otherNetwork) {
    return getMainnet(network) === getMainnet(otherNetwork);
}
exports.isSameCoin = isSameCoin;
const mainnets = getNetworkList().filter(isMainnet);
const testnets = getNetworkList().filter(isTestnet);
/**
 * Map where keys are mainnet networks and values are testnet networks
 * @type {Map<Network, Network[]>}
 */
const mainnetTestnetPairs = new Map(mainnets.map((m) => [m, testnets.filter((t) => getMainnet(t) === m)]));
/**
 * @param {Network} network
 * @returns {Network|undefined} - The testnet corresponding to a mainnet.
 *                               Returns undefined if a network has no testnet.
 */
function getTestnet(network) {
    if (isTestnet(network)) {
        return network;
    }
    const testnets = mainnetTestnetPairs.get(network);
    if (testnets === undefined) {
        throw new Error(`invalid argument`);
    }
    if (testnets.length === 0) {
        return;
    }
    if (testnets.length === 1) {
        return testnets[0];
    }
    throw new Error(`more than one testnet for ${getNetworkName(network)}`);
}
exports.getTestnet = getTestnet;
/**
 * @param {Network} network
 * @returns {boolean} true iff network bitcoin or testnet
 */
function isBitcoin(network) {
    return getMainnet(network) === exports.networks.bitcoin;
}
exports.isBitcoin = isBitcoin;
/**
 * @param {Network} network
 * @returns {boolean} true iff network is bitcoincash or bitcoincashTestnet
 */
function isBitcoinCash(network) {
    return getMainnet(network) === exports.networks.bitcoincash;
}
exports.isBitcoinCash = isBitcoinCash;
/**
 * @param {Network} network
 * @returns {boolean} true iff network is bitcoingold
 */
function isBitcoinGold(network) {
    return getMainnet(network) === exports.networks.bitcoingold;
}
exports.isBitcoinGold = isBitcoinGold;
/**
 * @param {Network} network
 * @returns {boolean} true iff network is bitcoinsv or bitcoinsvTestnet
 */
function isBitcoinSV(network) {
    return getMainnet(network) === exports.networks.bitcoinsv;
}
exports.isBitcoinSV = isBitcoinSV;
/**
 * @param {Network} network
 * @returns {boolean} true iff network is dash or dashTest
 */
function isDash(network) {
    return getMainnet(network) === exports.networks.dash;
}
exports.isDash = isDash;
/**
 * @param {Network} network
 * @returns {boolean} true iff network is litecoin or litecoinTest
 */
function isLitecoin(network) {
    return getMainnet(network) === exports.networks.litecoin;
}
exports.isLitecoin = isLitecoin;
/**
 * @param {Network} network
 * @returns {boolean} true iff network is zcash or zcashTest
 */
function isZcash(network) {
    return getMainnet(network) === exports.networks.zcash;
}
exports.isZcash = isZcash;
/**
 * @param {unknown} network
 * @returns {boolean} returns true iff network is any of the network stated in the argument
 */
function isValidNetwork(network) {
    return getNetworkList().includes(network);
}
exports.isValidNetwork = isValidNetwork;
function supportsSegwit(network) {
    return [exports.networks.bitcoin, exports.networks.litecoin, exports.networks.bitcoingold].includes(getMainnet(network));
}
exports.supportsSegwit = supportsSegwit;
function supportsTaproot(network) {
    return getMainnet(network) === exports.networks.bitcoin;
}
exports.supportsTaproot = supportsTaproot;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoibmV0d29ya3MuanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyIuLi8uLi9zcmMvbmV0d29ya3MudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6IjtBQUFBOzs7Ozs7Ozs7Ozs7Ozs7RUFlRTs7O0FBRUY7O0dBRUc7QUFDSCxNQUFNLEtBQUssR0FBRztJQUNaLEdBQUcsRUFBRSxLQUFLO0lBQ1YsR0FBRyxFQUFFLEtBQUs7SUFDVixHQUFHLEVBQUUsS0FBSztJQUNWLEdBQUcsRUFBRSxLQUFLO0lBQ1YsR0FBRyxFQUFFLEtBQUs7SUFDVixHQUFHLEVBQUUsS0FBSztJQUNWLElBQUksRUFBRSxNQUFNO0NBQ0osQ0FBQztBQXdDWCxTQUFTLHNCQUFzQjtJQUM3QixPQUFPO1FBQ0wsZ0JBQWdCO1FBQ2hCLE1BQU0sRUFBRSxVQUFVO1FBQ2xCLGdCQUFnQjtRQUNoQixPQUFPLEVBQUUsVUFBVTtLQUNwQixDQUFDO0FBQ0osQ0FBQztBQUVELFNBQVMsc0JBQXNCO0lBQzdCLE9BQU87UUFDTCxnQkFBZ0I7UUFDaEIsTUFBTSxFQUFFLFVBQVU7UUFDbEIsZ0JBQWdCO1FBQ2hCLE9BQU8sRUFBRSxVQUFVO0tBQ3BCLENBQUM7QUFDSixDQUFDO0FBRVksUUFBQSxRQUFRLEdBQWlDO0lBQ3BELG9FQUFvRTtJQUNwRSxxRUFBcUU7SUFDckUsT0FBTyxFQUFFO1FBQ1AsYUFBYSxFQUFFLCtCQUErQjtRQUM5QyxNQUFNLEVBQUUsSUFBSTtRQUNaLEtBQUssRUFBRSxzQkFBc0IsRUFBRTtRQUMvQixVQUFVLEVBQUUsSUFBSTtRQUNoQixVQUFVLEVBQUUsSUFBSTtRQUNoQixHQUFHLEVBQUUsSUFBSTtRQUNULElBQUksRUFBRSxLQUFLLENBQUMsR0FBRztLQUNoQjtJQUNELE9BQU8sRUFBRTtRQUNQLGFBQWEsRUFBRSwrQkFBK0I7UUFDOUMsTUFBTSxFQUFFLElBQUk7UUFDWixLQUFLLEVBQUUsc0JBQXNCLEVBQUU7UUFDL0IsVUFBVSxFQUFFLElBQUk7UUFDaEIsVUFBVSxF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QyxPQUFnQjtJQUN6QyxPQUFPLFVBQVUsQ0FBQyxPQUFPLENBQUMsS0FBSyxnQkFBUSxDQUFDLFFBQVEsQ0FBQztBQUNuRCxDQUFDO0FBRkQsZ0NBRUM7QUFFRDs7O0dBR0c7QUFDSCxTQUFnQixPQUFPLENBQUMsT0FBZ0I7SUFDdEMsT0FBTyxVQUFVLENBQUMsT0FBTyxDQUFDLEtBQUssZ0JBQVEsQ0FBQyxLQUFLLENBQUM7QUFDaEQsQ0FBQztBQUZELDBCQUVDO0FBRUQ7OztHQUdHO0FBQ0gsU0FBZ0IsY0FBYyxDQUFDLE9BQWdCO0lBQzdDLE9BQU8sY0FBYyxFQUFFLENBQUMsUUFBUSxDQUFDLE9BQWtCLENBQUMsQ0FBQztBQUN2RCxDQUFDO0FBRkQsd0NBRUM7QUFFRCxTQUFnQixjQUFjLENBQUMsT0FBZ0I7SUFDN0MsT0FBUSxDQUFDLGdCQUFRLENBQUMsT0FBTyxFQUFFLGdCQUFRLENBQUMsUUFBUSxFQUFFLGdCQUFRLENBQUMsV0FBVyxDQUFlLENBQUMsUUFBUSxDQUFDLFVBQVUsQ0FBQyxPQUFPLENBQUMsQ0FBQyxDQUFDO0FBQ2xILENBQUM7QUFGRCx3Q0FFQztBQUVELFNBQWdCLGVBQWUsQ0FBQyxPQUFnQjtJQUM5QyxPQUFPLFVBQVUsQ0FBQyxPQUFPLENBQUMsS0FBSyxnQkFBUSxDQUFDLE9BQU8sQ0FBQztBQUNsRCxDQUFDO0FBRkQsMENBRUMiLCJzb3VyY2VzQ29udGVudCI6WyIvKlxuXG5UaGUgdmFsdWVzIGZvciB0aGUgdmFyaW91cyBmb3JrIGNvaW5zIGNhbiBiZSBmb3VuZCBpbiB0aGVzZSBmaWxlczpcblxucHJvcGVydHkgICAgICAgZmlsZW5hbWUgICAgICAgICAgICAgICAgICB2YXJuYW1lICAgICAgICAgICAgICAgICAgICAgICAgICAgbm90ZXNcbi0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLVxubWVzc2FnZVByZWZpeCAgc3JjL3ZhbGlkYXRpb24uY3BwICAgICAgICBzdHJNZXNzYWdlTWFnaWMgICAgICAgICAgICAgICAgICAgRm9ybWF0IGAke0NvaW5OYW1lfSBTaWduZWQgTWVzc2FnZWBcbmJlY2gzMl9ocnAgICAgIHNyYy9jaGFpbnBhcmFtcy5jcHAgICAgICAgYmVjaDMyX2hycCAgICAgICAgICAgICAgICAgICAgICAgIE9ubHkgZm9yIHNvbWUgbmV0d29ya3NcbmJpcDMyLnB1YmxpYyAgIHNyYy9jaGFpbnBhcmFtcy5jcHAgICAgICAgYmFzZTU4UHJlZml4ZXNbRVhUX1BVQkxJQ19LRVldICAgIE1haW5uZXRzIGhhdmUgc2FtZSB2YWx1ZSwgdGVzdG5ldHMgaGF2ZSBzYW1lIHZhbHVlXG5iaXAzMi5wcml2YXRlICBzcmMvY2hhaW5wYXJhbXMuY3BwICAgICAgIGJhc2U1OFByZWZpeGVzW0VYVF9TRUNSRVRfS0VZXSAgICBNYWlubmV0cyBoYXZlIHNhbWUgdmFsdWUsIHRlc3RuZXRzIGhhdmUgc2FtZSB2YWx1ZVxucHViS2V5SGFzaCAgICAgc3JjL2NoYWlucGFyYW1zLmNwcCAgICAgICBiYXNlNThQcmVmaXhlc1tQVUJLRVlfQUREUkVTU11cbnNjcmlwdEhhc2ggICAgIHNyYy9jaGFpbnBhcmFtcy5jcHAgICAgICAgYmFzZTU4UHJlZml4ZXNbU0NSSVBUX0FERFJFU1NdXG53aWYgICAgICAgICAgICBzcmMvY2hhaW5wYXJhbXMuY3BwICAgICAgIGJhc2U1OFByZWZpeGVzW1NFQ1JFVF9LRVldICAgICAgICBUZXN0bmV0cyBoYXZlIHNhbWUgdmFsdWVcbmZvcmtJZCAgICAgICAgIHNyYy9zY3JpcHQvaW50ZXJwcmV0ZXIuaCAgRk9SS0lEXypcblxuKi9cblxuLyoqXG4gKiBAZGVwcmVjYXRlZFxuICovXG5jb25zdCBjb2lucyA9IHtcbiAgQkNIOiAnYmNoJyxcbiAgQlNWOiAnYnN2JyxcbiAgQlRDOiAnYnRjJyxcbiAgQlRHOiAnYnRnJyxcbiAgTFRDOiAnbHRjJyxcbiAgWkVDOiAnemVjJyxcbiAgREFTSDogJ2Rhc2gnLFxufSBhcyBjb25zdDtcblxuZXhwb3J0IHR5cGUgTmV0d29ya05hbWUgPVxuICB8ICdiaXRjb2luJ1xuICB8ICd0ZXN0bmV0J1xuICB8ICdiaXRjb2luY2FzaCdcbiAgfCAnYml0Y29pbmNhc2hUZXN0bmV0J1xuICB8ICdiaXRjb2luZ29sZCdcbiAgfCAnYml0Y29pbmdvbGRUZXN0bmV0J1xuICB8ICdiaXRjb2luc3YnXG4gIHwgJ2JpdGNvaW5zdlRlc3RuZXQnXG4gIHwgJ2Rhc2gnXG4gIHwgJ2Rhc2hUZXN0J1xuICB8ICdsaXRlY29pbidcbiAgfCAnbGl0ZWNvaW5UZXN0J1xuICB8ICd6Y2FzaCdcbiAgfCAnemNhc2hUZXN0JztcblxuZXhwb3J0IHR5cGUgTmV0d29yayA9IHtcbiAgbWVzc2FnZVByZWZpeDogc3RyaW5nO1xuICBwdWJLZXlIYXNoOiBudW1iZXI7XG4gIHNjcmlwdEhhc2g6IG51bWJlcjtcbiAgd2lmOiBudW1iZXI7XG4gIGJpcDMyOiB7XG4gICAgcHVibGljOiBudW1iZXI7XG4gICAgcHJpdmF0ZTogbnVtYmVyO1xuICB9O1xuICBjYXNoQWRkcj86IHtcbiAgICBwcmVmaXg6IHN0cmluZztcbiAgICBwdWJLZXlIYXNoOiBudW1iZXI7XG4gICAgc2NyaXB0SGFzaDogbnVtYmVyO1xuICB9O1xuICBiZWNoMzI/OiBzdHJpbmc7XG4gIGZvcmtJZD86IG51bWJlcjtcbiAgLyoqXG4gICAqIEBkZXByZWNhdGVkXG4gICAqL1xuICBjb2luOiBzdHJpbmc7XG59O1xuXG5mdW5jdGlvbiBnZXREZWZhdWx0QmlwMzJNYWlubmV0KCkge1xuICByZXR1cm4ge1xuICAgIC8vIGJhc2U1OCAneHB1YidcbiAgICBwdWJsaWM6IDB4MDQ4OGIyMWUsXG4gICAgLy8gYmFzZTU4ICd4cHJ2J1xuICAgIHByaXZhdGU6IDB4MDQ4OGFkZTQsXG4gIH07XG59XG5cbmZ1bmN0aW9uIGdldERlZmF1bHRCaXAzMlRlc3RuZXQoKSB7XG4gIHJldHVybiB7XG4gICAgLy8gYmFzZTU4ICd0cHViJ1xuICAgIHB1YmxpYzogMHgwNDM1ODdjZixcbiAgICAvLyBiYXNlNTggJ3RwcnYnXG4gICAgcHJpdmF0ZTogMHgwNDM1ODM5NCxcbiAgfTtcbn1cblxuZXhwb3J0IGNvbnN0IG5ldHdvcmtzOiBSZWNvcmQ8TmV0d29ya05hbWUsIE5ldHdvcms+ID0ge1xuICAvLyBodHRwczovL2dpdGh1Yi5jb20vYml0Y29pbi9iaXRjb2luL2Jsb2IvbWFzdGVyL3NyYy92YWxpZGF0aW9uLmNwcFxuICAvLyBodHRwczovL2dpdGh1Yi5jb20vYml0Y29pbi9iaXRjb2luL2Jsb2IvbWFzdGVyL3NyYy9jaGFpbnBhcmFtcy5jcHBcbiAgYml0Y29pbjoge1xuICAgIG1lc3NhZ2VQcmVmaXg6ICdcXHgxOEJpdGNvaW4gU2lnbmVkIE1lc3NhZ2U6XFxuJyxcbiAgICBiZWNoMzI6ICdiYycsXG4gICAgYmlwMzI6IGdldERlZmF1bHRCaXAzMk1haW5uZXQoKSxcbiAgICBwdWJLZXlIYXNoOiAweDAwLFxuICAgIHNjcmlwdEhhc2g6IDB4MDUsXG4gICAgd2lmOiAweDgwLFxuICAgIGNvaW46IGNvaW5zLkJUQyxcbiAgfSxcbiAgdGVzdG5ldDoge1xuICAgIG1lc3NhZ2VQcmVmaXg6ICdcXHgxOEJpdGNvaW4gU2lnbmVkIE1lc3NhZ2U6XFxuJyxcbiAgICBiZWNoMzI6ICd0YicsXG4gICAgYmlwMzI6IGdldERlZmF1bHRCaXAzMlRlc3RuZXQoKSxcbiAgICBwdWJLZXlIYXNoOiAweDZmLFxuICAgIHNjcmlwdEhhc2g6IDB4YzQsXG4gICAgd2lmOiAweGVmLFxuICAgIGNvaW46IGNvaW5zLkJUQyxcbiAgfSxcblxuICAvLyBodHRwczovL2dpdGh1Yi5jb20vQml0Y29pbi1BQkMvYml0Y29pbi1hYmMvYmxvYi9tYXN0ZXIvc3JjL3ZhbGlkYXRpb24uY3BwXG4gIC8vIGh0dHBzOi8vZ2l0aHViLmNvbS9CaXRjb2luLUFCQy9iaXRjb2luLWFiYy9ibG9iL21hc3Rlci9zcmMvY2hhaW5wYXJhbXMuY3BwXG4gIC8vIGh0dHBzOi8vZ2l0aHViLmNvbS9iaXRjb2luY2FzaG9yZy9iaXRjb2luY2FzaC5vcmcvYmxvYi9tYXN0ZXIvc3BlYy9jYXNoYWRkci5tZFxuICBiaXRjb2luY2FzaDoge1xuICAgIG1lc3NhZ2VQcmVmaXg6ICdcXHgxOEJpdGNvaW4gU2lnbmVkIE1lc3NhZ2U6XFxuJyxcbiAgICBiaXAzMjogZ2V0RGVmYXVsdEJpcDMyTWFpbm5ldCgpLFxuICAgIHB1YktleUhhc2g6IDB4MDAsXG4gICAgc2NyaXB0SGFzaDogMHgwNSxcbiAgICB3aWY6IDB4ODAsXG4gICAgY29pbjogY29pbnMuQkNILFxuICAgIGZvcmtJZDogMHgwMCxcbiAgICBjYXNoQWRkcjoge1xuICAgICAgcHJlZml4OiAnYml0Y29pbmNhc2gnLFxuICAgICAgcHViS2V5SGFzaDogMHgwMCxcbiAgICAgIHNjcmlwdEhhc2g6IDB4MDgsXG4gICAgfSxcbiAgfSxcbiAgYml0Y29pbmNhc2hUZXN0bmV0OiB7XG4gICAgbWVzc2FnZVByZWZpeDogJ1xceDE4Qml0Y29pbiBTaWduZWQgTWVzc2FnZTpcXG4nLFxuICAgIGJpcDMyOiBnZXREZWZhdWx0QmlwMzJUZXN0bmV0KCksXG4gICAgcHViS2V5SGFzaDogMHg2ZixcbiAgICBzY3JpcHRIYXNoOiAweGM0LFxuICAgIHdpZjogMHhlZixcbiAgICBjb2luOiBjb2lucy5CQ0gsXG4gICAgY2FzaEFkZHI6IHtcbiAgICAgIHByZWZpeDogJ2JjaHRlc3QnLFxuICAgICAgcHViS2V5SGFzaDogMHgwMCxcbiAgICAgIHNjcmlwdEhhc2g6IDB4MDgsXG4gICAgfSxcbiAgfSxcblxuICAvLyBodHRwczovL2dpdGh1Yi5jb20vQlRDR1BVL0JUQ0dQVS9ibG9iL21hc3Rlci9zcmMvdmFsaWRhdGlvbi5jcHBcbiAgLy8gaHR0cHM6Ly9naXRodWIuY29tL0JUQ0dQVS9CVENHUFUvYmxvYi9tYXN0ZXIvc3JjL2NoYWlucGFyYW1zLmNwcFxuICAvLyBodHRwczovL2dpdGh1Yi5jb20vQlRDR1BVL0JUQ0dQVS9ibG9iL21hc3Rlci9zcmMvc2NyaXB0L2ludGVycHJldGVyLmhcbiAgYml0Y29pbmdvbGQ6IHtcbiAgICBtZXNzYWdlUHJlZml4OiAnXFx4MThCaXRjb2luIEdvbGQgU2lnbmVkIE1lc3NhZ2U6XFxuJyxcbiAgICBiZWNoMzI6ICdidGcnLFxuICAgIGJpcDMyOiBnZXREZWZhdWx0QmlwMzJNYWlubmV0KCksXG4gICAgcHViS2V5SGFzaDogMHgyNixcbiAgICBzY3JpcHRIYXNoOiAweDE3LFxuICAgIHdpZjogMHg4MCxcbiAgICBmb3JrSWQ6IDc5LFxuICAgIGNvaW46IGNvaW5zLkJURyxcbiAgfSxcbiAgYml0Y29pbmdvbGRUZXN0bmV0OiB7XG4gICAgbWVzc2FnZVByZWZpeDogJ1xceDE4Qml0Y29pbiBHb2xkIFNpZ25lZCBNZXNzYWdlOlxcbicsXG4gICAgYmVjaDMyOiAndGJ0ZycsXG4gICAgYmlwMzI6IGdldERlZmF1bHRCaXAzMlRlc3RuZXQoKSxcbiAgICBwdWJLZXlIYXNoOiAxMTEsXG4gICAgc2NyaXB0SGFzaDogMTk2LFxuICAgIHdpZjogMHhlZixcbiAgICBmb3JrSWQ6IDc5LFxuICAgIGNvaW46IGNvaW5zLkJURyxcbiAgfSxcblxuICAvLyBodHRwczovL2dpdGh1Yi5jb20vYml0Y29pbi1zdi9iaXRjb2luLXN2L2Jsb2IvbWFzdGVyL3NyYy92YWxpZGF0aW9uLmNwcFxuICAvLyBodHRwczovL2dpdGh1Yi5jb20vYml0Y29pbi1zdi9iaXRjb2luLXN2L2Jsb2IvbWFzdGVyL3NyYy9jaGFpbnBhcmFtcy5jcHBcbiAgYml0Y29pbnN2OiB7XG4gICAgbWVzc2FnZVByZWZpeDogJ1xceDE4Qml0Y29pbiBTaWduZWQgTWVzc2FnZTpcXG4nLFxuICAgIGJpcDMyOiBnZXREZWZhdWx0QmlwMzJNYWlubmV0KCksXG4gICAgcHViS2V5SGFzaDogMHgwMCxcbiAgICBzY3JpcHRIYXNoOiAweDA1LFxuICAgIHdpZjogMHg4MCxcbiAgICBjb2luOiBjb2lucy5CU1YsXG4gICAgZm9ya0lkOiAweDAwLFxuICB9LFxuICBiaXRjb2luc3ZUZXN0bmV0OiB7XG4gICAgbWVzc2FnZVByZWZpeDogJ1xceDE4Qml0Y29pbiBTaWduZWQgTWVzc2FnZTpcXG4nLFxuICAgIGJpcDMyOiBnZXREZWZhdWx0QmlwMzJUZXN0bmV0KCksXG4gICAgcHViS2V5SGFzaDogMHg2ZixcbiAgICBzY3JpcHRIYXNoOiAweGM0LFxuICAgIHdpZjogMHhlZixcbiAgICBjb2luOiBjb2lucy5CU1YsXG4gICAgZm9ya0lkOiAweDAwLFxuICB9LFxuXG4gIC8vIGh0dHBzOi8vZ2l0aHViLmNvbS9kYXNocGF5L2Rhc2gvYmxvYi9tYXN0ZXIvc3JjL3ZhbGlkYXRpb24uY3BwXG4gIC8vIGh0dHBzOi8vZ2l0aHViLmNvbS9kYXNocGF5L2Rhc2gvYmxvYi9tYXN0ZXIvc3JjL2NoYWlucGFyYW1zLmNwcFxuICBkYXNoOiB7XG4gICAgbWVzc2FnZVByZWZpeDogJ1xceDE5RGFya0NvaW4gU2lnbmVkIE1lc3NhZ2U6XFxuJyxcbiAgICBiaXAzMjogZ2V0RGVmYXVsdEJpcDMyTWFpbm5ldCgpLFxuICAgIHB1YktleUhhc2g6IDB4NGMsXG4gICAgc2NyaXB0SGFzaDogMHgxMCxcbiAgICB3aWY6IDB4Y2MsXG4gICAgY29pbjogY29pbnMuREFTSCxcbiAgfSxcbiAgZGFzaFRlc3Q6IHtcbiAgICBtZXNzYWdlUHJlZml4OiAnXFx4MTlEYXJrQ29pbiBTaWduZWQgTWVzc2FnZTpcXG4nLFxuICAgIGJpcDMyOiBnZXREZWZhdWx0QmlwMzJUZXN0bmV0KCksXG4gICAgcHViS2V5SGFzaDogMHg4YyxcbiAgICBzY3JpcHRIYXNoOiAweDEzLFxuICAgIHdpZjogMHhlZixcbiAgICBjb2luOiBjb2lucy5EQVNILFxuICB9LFxuXG4gIC8vIGh0dHBzOi8vZ2l0aHViLmNvbS9saXRlY29pbi1wcm9qZWN0L2xpdGVjb2luL2Jsb2IvbWFzdGVyL3NyYy92YWxpZGF0aW9uLmNwcFxuICAvLyBodHRwczovL2dpdGh1Yi5jb20vbGl0ZWNvaW4tcHJvamVjdC9saXRlY29pbi9ibG9iL21hc3Rlci9zcmMvY2hhaW5wYXJhbXMuY3BwXG4gIGxpdGVjb2luOiB7XG4gICAgbWVzc2FnZVByZWZpeDogJ1xceDE5TGl0ZWNvaW4gU2lnbmVkIE1lc3NhZ2U6XFxuJyxcbiAgICBiZWNoMzI6ICdsdGMnLFxuICAgIGJpcDMyOiBnZXREZWZhdWx0QmlwMzJNYWlubmV0KCksXG4gICAgcHViS2V5SGFzaDogMHgzMCxcbiAgICBzY3JpcHRIYXNoOiAweDMyLFxuICAgIHdpZjogMHhiMCxcbiAgICBjb2luOiBjb2lucy5MVEMsXG4gIH0sXG4gIGxpdGVjb2luVGVzdDoge1xuICAgIG1lc3NhZ2VQcmVmaXg6ICdcXHgxOUxpdGVjb2luIFNpZ25lZCBNZXNzYWdlOlxcbicsXG4gICAgYmVjaDMyOiAndGx0YycsXG4gICAgYmlwMzI6IGdldERlZmF1bHRCaXAzMlRlc3RuZXQoKSxcbiAgICBwdWJLZXlIYXNoOiAweDZmLFxuICAgIHNjcmlwdEhhc2g6IDB4M2EsXG4gICAgd2lmOiAweGVmLFxuICAgIGNvaW46IGNvaW5zLkxUQyxcbiAgfSxcblxuICAvLyBodHRwczovL2dpdGh1Yi5jb20vemNhc2gvemNhc2gvYmxvYi9tYXN0ZXIvc3JjL3ZhbGlkYXRpb24uY3BwXG4gIC8vIGh0dHBzOi8vZ2l0aHViLmNvbS96Y2FzaC96Y2FzaC9ibG9iL21hc3Rlci9zcmMvY2hhaW5wYXJhbXMuY3BwXG4gIHpjYXNoOiB7XG4gICAgbWVzc2FnZVByZWZpeDogJ1xceDE4WkNhc2ggU2lnbmVkIE1lc3NhZ2U6XFxuJyxcbiAgICBiaXAzMjogZ2V0RGVmYXVsdEJpcDMyTWFpbm5ldCgpLFxuICAgIHB1YktleUhhc2g6IDB4MWNiOCxcbiAgICBzY3JpcHRIYXNoOiAweDFjYmQsXG4gICAgd2lmOiAweDgwLFxuICAgIGNvaW46IGNvaW5zLlpFQyxcbiAgfSxcbiAgemNhc2hUZXN0OiB7XG4gICAgbWVzc2FnZVByZWZpeDogJ1xceDE4WkNhc2ggU2lnbmVkIE1lc3NhZ2U6XFxuJyxcbiAgICBiaXAzMjogZ2V0RGVmYXVsdEJpcDMyVGVzdG5ldCgpLFxuICAgIHB1YktleUhhc2g6IDB4MWQyNSxcbiAgICBzY3JpcHRIYXNoOiAweDFjYmEsXG4gICAgd2lmOiAweGVmLFxuICAgIGNvaW46IGNvaW5zLlpFQyxcbiAgfSxcbn07XG5cbi8qKlxuICogQHJldHVybnMge05ldHdvcmtbXX0gYWxsIGtub3duIG5ldHdvcmtzIGFzIGFycmF5XG4gKi9cbmV4cG9ydCBmdW5jdGlvbiBnZXROZXR3b3JrTGlzdCgpOiBOZXR3b3JrW10ge1xuICByZXR1cm4gT2JqZWN0LnZhbHVlcyhuZXR3b3Jrcyk7XG59XG5cbi8qKlxuICogQHBhcmFtIHtOZXR3b3JrfSBuZXR3b3JrXG4gKiBAcmV0dXJucyB7c3RyaW5nfSB0aGUgbmFtZSBvZiB0aGUgbmV0d29yay4gUmV0dXJucyB1bmRlZmluZWQgaWYgbmV0d29yayBpcyBub3QgYSB2YWx1ZVxuICogICAgICAgICAgICAgICAgICAgb2YgYG5ldHdvcmtzYFxuICovXG5leHBvcnQgZnVuY3Rpb24gZ2V0TmV0d29ya05hbWUobmV0d29yazogTmV0d29yayk6IHN0cmluZyB8IHVuZGVmaW5lZCB7XG4gIHJldHVybiBPYmplY3Qua2V5cyhuZXR3b3JrcykuZmluZCgobikgPT4gKG5ldHdvcmtzIGFzIFJlY29yZDxzdHJpbmcsIE5ldHdvcms+KVtuXSA9PT0gbmV0d29yayk7XG59XG5cbi8qKlxuICogQHBhcmFtIHtOZXR3b3JrfSBuZXR3b3JrXG4gKiBAcmV0dXJucyB7T2JqZWN0fSB0aGUgbWFpbm5ldCBjb3JyZXNwb25kaW5nIHRvIGEgdGVzdG5ldFxuICovXG5leHBvcnQgZnVuY3Rpb24gZ2V0TWFpbm5ldChuZXR3b3JrOiBOZXR3b3JrKTogTmV0d29yayB7XG4gIHN3aXRjaCAobmV0d29yaykge1xuICAgIGNhc2UgbmV0d29ya3MuYml0Y29pbjpcbiAgICBjYXNlIG5ldHdvcmtzLnRlc3RuZXQ6XG4gICAgICByZXR1cm4gbmV0d29ya3MuYml0Y29pbjtcblxuICAgIGNhc2UgbmV0d29ya3MuYml0Y29pbmNhc2g6XG4gICAgY2FzZSBuZXR3b3Jrcy5iaXRjb2luY2FzaFRlc3RuZXQ6XG4gICAgICByZXR1cm4gbmV0d29ya3MuYml0Y29pbmNhc2g7XG5cbiAgICBjYXNlIG5ldHdvcmtzLmJpdGNvaW5nb2xkOlxuICAgIGNhc2UgbmV0d29ya3MuYml0Y29pbmdvbGRUZXN0bmV0OlxuICAgICAgcmV0dXJuIG5ldHdvcmtzLmJpdGNvaW5nb2xkO1xuXG4gICAgY2FzZSBuZXR3b3Jrcy5iaXRjb2luc3Y6XG4gICAgY2FzZSBuZXR3b3Jrcy5iaXRjb2luc3ZUZXN0bmV0OlxuICAgICAgcmV0dXJuIG5ldHdvcmtzLmJpdGNvaW5zdjtcblxuICAgIGNhc2UgbmV0d29ya3MuZGFzaDpcbiAgICBjYXNlIG5ldHdvcmtzLmRhc2hUZXN0OlxuICAgICAgcmV0dXJuIG5ldHdvcmtzLmRhc2g7XG5cbiAgICBjYXNlIG5ldHdvcmtzLmxpdGVjb2luOlxuICAgIGNhc2UgbmV0d29ya3MubGl0ZWNvaW5UZXN0OlxuICAgICAgcmV0dXJuIG5ldHdvcmtzLmxpdGVjb2luO1xuXG4gICAgY2FzZSBuZXR3b3Jrcy56Y2FzaDpcbiAgICBjYXNlIG5ldHdvcmtzLnpjYXNoVGVzdDpcbiAgICAgIHJldHVybiBuZXR3b3Jrcy56Y2FzaDtcbiAgfVxuICB0aHJvdyBuZXcgVHlwZUVycm9yKGBpbnZhbGlkIG5ldHdvcmtgKTtcbn1cblxuLyoqXG4gKiBAcGFyYW0ge05ldHdvcmt9IG5ldHdvcmtcbiAqIEByZXR1cm5zIHtib29sZWFufSB0cnVlIGlmZiBuZXR3b3JrIGlzIGEgbWFpbm5ldFxuICovXG5leHBvcnQgZnVuY3Rpb24gaXNNYWlubmV0KG5ldHdvcms6IE5ldHdvcmspOiBib29sZWFuIHtcbiAgcmV0dXJuIGdldE1haW5uZXQobmV0d29yaykgPT09IG5ldHdvcms7XG59XG5cbi8qKlxuICogQHBhcmFtIHtOZXR3b3JrfSBuZXR3b3JrXG4gKiBAcmV0dXJucyB7Ym9vbGVhbn0gdHJ1ZSBpZmYgbmV0d29yayBpcyBhIHRlc3RuZXRcbiAqL1xuZXhwb3J0IGZ1bmN0aW9uIGlzVGVzdG5ldChuZXR3b3JrOiBOZXR3b3JrKTogYm9vbGVhbiB7XG4gIHJldHVybiBnZXRNYWlubmV0KG5ldHdvcmspICE9PSBuZXR3b3JrO1xufVxuXG4vKipcbiAqXG4gKiBAcGFyYW0ge05ldHdvcmt9IG5ldHdvcmtcbiAqIEBwYXJhbSB7TmV0d29ya30gb3RoZXJOZXR3b3JrXG4gKiBAcmV0dXJucyB7Ym9vbGVhbn0gdHJ1ZSBpZmYgYm90aCBuZXR3b3JrcyBhcmUgZm9yIHRoZSBzYW1lIGNvaW5cbiAqL1xuZXhwb3J0IGZ1bmN0aW9uIGlzU2FtZUNvaW4obmV0d29yazogTmV0d29yaywgb3RoZXJOZXR3b3JrOiBOZXR3b3JrKTogYm9vbGVhbiB7XG4gIHJldHVybiBnZXRNYWlubmV0KG5ldHdvcmspID09PSBnZXRNYWlubmV0KG90aGVyTmV0d29yayk7XG59XG5cbmNvbnN0IG1haW5uZXRzID0gZ2V0TmV0d29ya0xpc3QoKS5maWx0ZXIoaXNNYWlubmV0KTtcbmNvbnN0IHRlc3RuZXRzID0gZ2V0TmV0d29ya0xpc3QoKS5maWx0ZXIoaXNUZXN0bmV0KTtcblxuLyoqXG4gKiBNYXAgd2hlcmUga2V5cyBhcmUgbWFpbm5ldCBuZXR3b3JrcyBhbmQgdmFsdWVzIGFyZSB0ZXN0bmV0IG5ldHdvcmtzXG4gKiBAdHlwZSB7TWFwPE5ldHdvcmssIE5ldHdvcmtbXT59XG4gKi9cbmNvbnN0IG1haW5uZXRUZXN0bmV0UGFpcnMgPSBuZXcgTWFwKG1haW5uZXRzLm1hcCgobSkgPT4gW20sIHRlc3RuZXRzLmZpbHRlcigodCkgPT4gZ2V0TWFpbm5ldCh0KSA9PT0gbSldKSk7XG5cbi8qKlxuICogQHBhcmFtIHtOZXR3b3JrfSBuZXR3b3JrXG4gKiBAcmV0dXJucyB7TmV0d29ya3x1bmRlZmluZWR9IC0gVGhlIHRlc3RuZXQgY29ycmVzcG9uZGluZyB0byBhIG1haW5uZXQuXG4gKiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBSZXR1cm5zIHVuZGVmaW5lZCBpZiBhIG5ldHdvcmsgaGFzIG5vIHRlc3RuZXQuXG4gKi9cbmV4cG9ydCBmdW5jdGlvbiBnZXRUZXN0bmV0KG5ldHdvcms6IE5ldHdvcmspOiBOZXR3b3JrIHwgdW5kZWZpbmVkIHtcbiAgaWYgKGlzVGVzdG5ldChuZXR3b3JrKSkge1xuICAgIHJldHVybiBuZXR3b3JrO1xuICB9XG4gIGNvbnN0IHRlc3RuZXRzID0gbWFpbm5ldFRlc3RuZXRQYWlycy5nZXQobmV0d29yayk7XG4gIGlmICh0ZXN0bmV0cyA9PT0gdW5kZWZpbmVkKSB7XG4gICAgdGhyb3cgbmV3IEVycm9yKGBpbnZhbGlkIGFyZ3VtZW50YCk7XG4gIH1cbiAgaWYgKHRlc3RuZXRzLmxlbmd0aCA9PT0gMCkge1xuICAgIHJldHVybjtcbiAgfVxuICBpZiAodGVzdG5ldHMubGVuZ3RoID09PSAxKSB7XG4gICAgcmV0dXJuIHRlc3RuZXRzWzBdO1xuICB9XG4gIHRocm93IG5ldyBFcnJvcihgbW9yZSB0aGFuIG9uZSB0ZXN0bmV0IGZvciAke2dldE5ldHdvcmtOYW1lKG5ldHdvcmspfWApO1xufVxuXG4vKipcbiAqIEBwYXJhbSB7TmV0d29ya30gbmV0d29ya1xuICogQHJldHVybnMge2Jvb2xlYW59IHRydWUgaWZmIG5ldHdvcmsgYml0Y29pbiBvciB0ZXN0bmV0XG4gKi9cbmV4cG9ydCBmdW5jdGlvbiBpc0JpdGNvaW4obmV0d29yazogTmV0d29yayk6IGJvb2xlYW4ge1xuICByZXR1cm4gZ2V0TWFpbm5ldChuZXR3b3JrKSA9PT0gbmV0d29ya3MuYml0Y29pbjtcbn1cblxuLyoqXG4gKiBAcGFyYW0ge05ldHdvcmt9IG5ldHdvcmtcbiAqIEByZXR1cm5zIHtib29sZWFufSB0cnVlIGlmZiBuZXR3b3JrIGlzIGJpdGNvaW5jYXNoIG9yIGJpdGNvaW5jYXNoVGVzdG5ldFxuICovXG5leHBvcnQgZnVuY3Rpb24gaXNCaXRjb2luQ2FzaChuZXR3b3JrOiBOZXR3b3JrKTogYm9vbGVhbiB7XG4gIHJldHVybiBnZXRNYWlubmV0KG5ldHdvcmspID09PSBuZXR3b3Jrcy5iaXRjb2luY2FzaDtcbn1cblxuLyoqXG4gKiBAcGFyYW0ge05ldHdvcmt9IG5ldHdvcmtcbiAqIEByZXR1cm5zIHtib29sZWFufSB0cnVlIGlmZiBuZXR3b3JrIGlzIGJpdGNvaW5nb2xkXG4gKi9cbmV4cG9ydCBmdW5jdGlvbiBpc0JpdGNvaW5Hb2xkKG5ldHdvcms6IE5ldHdvcmspOiBib29sZWFuIHtcbiAgcmV0dXJuIGdldE1haW5uZXQobmV0d29yaykgPT09IG5ldHdvcmtzLmJpdGNvaW5nb2xkO1xufVxuXG4vKipcbiAqIEBwYXJhbSB7TmV0d29ya30gbmV0d29ya1xuICogQHJldHVybnMge2Jvb2xlYW59IHRydWUgaWZmIG5ldHdvcmsgaXMgYml0Y29pbnN2IG9yIGJpdGNvaW5zdlRlc3RuZXRcbiAqL1xuZXhwb3J0IGZ1bmN0aW9uIGlzQml0Y29pblNWKG5ldHdvcms6IE5ldHdvcmspOiBib29sZWFuIHtcbiAgcmV0dXJuIGdldE1haW5uZXQobmV0d29yaykgPT09IG5ldHdvcmtzLmJpdGNvaW5zdjtcbn1cblxuLyoqXG4gKiBAcGFyYW0ge05ldHdvcmt9IG5ldHdvcmtcbiAqIEByZXR1cm5zIHtib29sZWFufSB0cnVlIGlmZiBuZXR3b3JrIGlzIGRhc2ggb3IgZGFzaFRlc3RcbiAqL1xuZXhwb3J0IGZ1bmN0aW9uIGlzRGFzaChuZXR3b3JrOiBOZXR3b3JrKTogYm9vbGVhbiB7XG4gIHJldHVybiBnZXRNYWlubmV0KG5ldHdvcmspID09PSBuZXR3b3Jrcy5kYXNoO1xufVxuXG4vKipcbiAqIEBwYXJhbSB7TmV0d29ya30gbmV0d29ya1xuICogQHJldHVybnMge2Jvb2xlYW59IHRydWUgaWZmIG5ldHdvcmsgaXMgbGl0ZWNvaW4gb3IgbGl0ZWNvaW5UZXN0XG4gKi9cbmV4cG9ydCBmdW5jdGlvbiBpc0xpdGVjb2luKG5ldHdvcms6IE5ldHdvcmspOiBib29sZWFuIHtcbiAgcmV0dXJuIGdldE1haW5uZXQobmV0d29yaykgPT09IG5ldHdvcmtzLmxpdGVjb2luO1xufVxuXG4vKipcbiAqIEBwYXJhbSB7TmV0d29ya30gbmV0d29ya1xuICogQHJldHVybnMge2Jvb2xlYW59IHRydWUgaWZmIG5ldHdvcmsgaXMgemNhc2ggb3IgemNhc2hUZXN0XG4gKi9cbmV4cG9ydCBmdW5jdGlvbiBpc1pjYXNoKG5ldHdvcms6IE5ldHdvcmspOiBib29sZWFuIHtcbiAgcmV0dXJuIGdldE1haW5uZXQobmV0d29yaykgPT09IG5ldHdvcmtzLnpjYXNoO1xufVxuXG4vKipcbiAqIEBwYXJhbSB7dW5rbm93bn0gbmV0d29ya1xuICogQHJldHVybnMge2Jvb2xlYW59IHJldHVybnMgdHJ1ZSBpZmYgbmV0d29yayBpcyBhbnkgb2YgdGhlIG5ldHdvcmsgc3RhdGVkIGluIHRoZSBhcmd1bWVudFxuICovXG5leHBvcnQgZnVuY3Rpb24gaXNWYWxpZE5ldHdvcmsobmV0d29yazogdW5rbm93bik6IG5ldHdvcmsgaXMgTmV0d29yayB7XG4gIHJldHVybiBnZXROZXR3b3JrTGlzdCgpLmluY2x1ZGVzKG5ldHdvcmsgYXMgTmV0d29yayk7XG59XG5cbmV4cG9ydCBmdW5jdGlvbiBzdXBwb3J0c1NlZ3dpdChuZXR3b3JrOiBOZXR3b3JrKTogYm9vbGVhbiB7XG4gIHJldHVybiAoW25ldHdvcmtzLmJpdGNvaW4sIG5ldHdvcmtzLmxpdGVjb2luLCBuZXR3b3Jrcy5iaXRjb2luZ29sZF0gYXMgTmV0d29ya1tdKS5pbmNsdWRlcyhnZXRNYWlubmV0KG5ldHdvcmspKTtcbn1cblxuZXhwb3J0IGZ1bmN0aW9uIHN1cHBvcnRzVGFwcm9vdChuZXR3b3JrOiBOZXR3b3JrKTogYm9vbGVhbiB7XG4gIHJldHVybiBnZXRNYWlubmV0KG5ldHdvcmspID09PSBuZXR3b3Jrcy5iaXRjb2luO1xufVxuIl19