"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ZEC = exports.LTC = exports.DASH = exports.BTG = exports.BTC = exports.BSV = exports.BCH = exports.isValidNetwork = exports.isZcash = exports.isLitecoin = exports.isDash = exports.isBitcoinSV = exports.isBitcoinGold = exports.isBitcoinCash = exports.isBitcoin = exports.getTestnet = exports.isSameCoin = exports.isTestnet = exports.isMainnet = exports.getMainnet = exports.getNetworkName = exports.getNetworkList = void 0;
const networks = require("./networks");
const networkTypes_1 = require("./networkTypes");
/**
 * @returns {Network[]} all known networks as array
 */
function getNetworkList() {
    return Object.values(networks);
}
exports.getNetworkList = getNetworkList;
/**
 * @param {Network} network
 * @returns {string} the name of the network. Returns undefined if network is not a value
 *                   of `networks`
 */
function getNetworkName(network) {
    return Object.keys(networks).find((n) => networks[n] === network);
}
exports.getNetworkName = getNetworkName;
/**
 * @param {Network} network
 * @returns {Object} the mainnet corresponding to a testnet
 */
function getMainnet(network) {
    switch (network) {
        case networks.bitcoin:
        case networks.testnet:
            return networks.bitcoin;
        case networks.bitcoincash:
        case networks.bitcoincashTestnet:
            return networks.bitcoincash;
        case networks.bitcoingold:
        case networks.bitcoingoldTestnet:
            return networks.bitcoingold;
        case networks.bitcoinsv:
        case networks.bitcoinsvTestnet:
            return networks.bitcoinsv;
        case networks.dash:
        case networks.dashTest:
            return networks.dash;
        case networks.litecoin:
        case networks.litecoinTest:
            return networks.litecoin;
        case networks.zcash:
        case networks.zcashTest:
            return networks.zcash;
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
    return getMainnet(network) === networks.bitcoin;
}
exports.isBitcoin = isBitcoin;
/**
 * @param {Network} network
 * @returns {boolean} true iff network is bitcoincash or bitcoincashTestnet
 */
function isBitcoinCash(network) {
    return getMainnet(network) === networks.bitcoincash;
}
exports.isBitcoinCash = isBitcoinCash;
/**
 * @param {Network} network
 * @returns {boolean} true iff network is bitcoingold
 */
function isBitcoinGold(network) {
    return getMainnet(network) === networks.bitcoingold;
}
exports.isBitcoinGold = isBitcoinGold;
/**
 * @param {Network} network
 * @returns {boolean} true iff network is bitcoinsv or bitcoinsvTestnet
 */
function isBitcoinSV(network) {
    return getMainnet(network) === networks.bitcoinsv;
}
exports.isBitcoinSV = isBitcoinSV;
/**
 * @param {Network} network
 * @returns {boolean} true iff network is dash or dashTest
 */
function isDash(network) {
    return getMainnet(network) === networks.dash;
}
exports.isDash = isDash;
/**
 * @param {Network} network
 * @returns {boolean} true iff network is litecoin or litecoinTest
 */
function isLitecoin(network) {
    return getMainnet(network) === networks.litecoin;
}
exports.isLitecoin = isLitecoin;
/**
 * @param {Network} network
 * @returns {boolean} true iff network is zcash or zcashTest
 */
function isZcash(network) {
    return getMainnet(network) === networks.zcash;
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
/** @deprecated */
exports.BCH = networkTypes_1.coins.BCH;
/** @deprecated */
exports.BSV = networkTypes_1.coins.BSV;
/** @deprecated */
exports.BTC = networkTypes_1.coins.BTC;
/** @deprecated */
exports.BTG = networkTypes_1.coins.BTG;
/** @deprecated */
exports.DASH = networkTypes_1.coins.DASH;
/** @deprecated */
exports.LTC = networkTypes_1.coins.LTC;
/** @deprecated */
exports.ZEC = networkTypes_1.coins.ZEC;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiY29pbnMuanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyIuLi8uLi9zcmMvY29pbnMudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6Ijs7O0FBQUEsdUNBQXVDO0FBQ3ZDLGlEQUE2RDtBQUU3RDs7R0FFRztBQUNILFNBQWdCLGNBQWM7SUFDNUIsT0FBTyxNQUFNLENBQUMsTUFBTSxDQUFDLFFBQVEsQ0FBQyxDQUFDO0FBQ2pDLENBQUM7QUFGRCx3Q0FFQztBQUVEOzs7O0dBSUc7QUFDSCxTQUFnQixjQUFjLENBQUMsT0FBZ0I7SUFDN0MsT0FBTyxNQUFNLENBQUMsSUFBSSxDQUFDLFFBQVEsQ0FBQyxDQUFDLElBQUksQ0FBQyxDQUFDLENBQUMsRUFBRSxFQUFFLENBQUMsUUFBUSxDQUFDLENBQWdCLENBQUMsS0FBSyxPQUFPLENBQUMsQ0FBQztBQUNuRixDQUFDO0FBRkQsd0NBRUM7QUFFRDs7O0dBR0c7QUFDSCxTQUFnQixVQUFVLENBQUMsT0FBZ0I7SUFDekMsUUFBUSxPQUFPLEVBQUU7UUFDZixLQUFLLFFBQVEsQ0FBQyxPQUFPLENBQUM7UUFDdEIsS0FBSyxRQUFRLENBQUMsT0FBTztZQUNuQixPQUFPLFFBQVEsQ0FBQyxPQUFPLENBQUM7UUFFMUIsS0FBSyxRQUFRLENBQUMsV0FBVyxDQUFDO1FBQzFCLEtBQUssUUFBUSxDQUFDLGtCQUFrQjtZQUM5QixPQUFPLFFBQVEsQ0FBQyxXQUFXLENBQUM7UUFFOUIsS0FBSyxRQUFRLENBQUMsV0FBVyxDQUFDO1FBQzFCLEtBQUssUUFBUSxDQUFDLGtCQUFrQjtZQUM5QixPQUFPLFFBQVEsQ0FBQyxXQUFXLENBQUM7UUFFOUIsS0FBSyxRQUFRLENBQUMsU0FBUyxDQUFDO1FBQ3hCLEtBQUssUUFBUSxDQUFDLGdCQUFnQjtZQUM1QixPQUFPLFFBQVEsQ0FBQyxTQUFTLENBQUM7UUFFNUIsS0FBSyxRQUFRLENBQUMsSUFBSSxDQUFDO1FBQ25CLEtBQUssUUFBUSxDQUFDLFFBQVE7WUFDcEIsT0FBTyxRQUFR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b0JBQUssQ0FBQyxHQUFHLENBQUMiLCJzb3VyY2VzQ29udGVudCI6WyJpbXBvcnQgKiBhcyBuZXR3b3JrcyBmcm9tICcuL25ldHdvcmtzJztcbmltcG9ydCB7IGNvaW5zLCBOZXR3b3JrLCBOZXR3b3JrTmFtZSB9IGZyb20gJy4vbmV0d29ya1R5cGVzJztcblxuLyoqXG4gKiBAcmV0dXJucyB7TmV0d29ya1tdfSBhbGwga25vd24gbmV0d29ya3MgYXMgYXJyYXlcbiAqL1xuZXhwb3J0IGZ1bmN0aW9uIGdldE5ldHdvcmtMaXN0KCk6IE5ldHdvcmtbXSB7XG4gIHJldHVybiBPYmplY3QudmFsdWVzKG5ldHdvcmtzKTtcbn1cblxuLyoqXG4gKiBAcGFyYW0ge05ldHdvcmt9IG5ldHdvcmtcbiAqIEByZXR1cm5zIHtzdHJpbmd9IHRoZSBuYW1lIG9mIHRoZSBuZXR3b3JrLiBSZXR1cm5zIHVuZGVmaW5lZCBpZiBuZXR3b3JrIGlzIG5vdCBhIHZhbHVlXG4gKiAgICAgICAgICAgICAgICAgICBvZiBgbmV0d29ya3NgXG4gKi9cbmV4cG9ydCBmdW5jdGlvbiBnZXROZXR3b3JrTmFtZShuZXR3b3JrOiBOZXR3b3JrKTogc3RyaW5nIHwgdW5kZWZpbmVkIHtcbiAgcmV0dXJuIE9iamVjdC5rZXlzKG5ldHdvcmtzKS5maW5kKChuKSA9PiBuZXR3b3Jrc1tuIGFzIE5ldHdvcmtOYW1lXSA9PT0gbmV0d29yayk7XG59XG5cbi8qKlxuICogQHBhcmFtIHtOZXR3b3JrfSBuZXR3b3JrXG4gKiBAcmV0dXJucyB7T2JqZWN0fSB0aGUgbWFpbm5ldCBjb3JyZXNwb25kaW5nIHRvIGEgdGVzdG5ldFxuICovXG5leHBvcnQgZnVuY3Rpb24gZ2V0TWFpbm5ldChuZXR3b3JrOiBOZXR3b3JrKTogTmV0d29yayB7XG4gIHN3aXRjaCAobmV0d29yaykge1xuICAgIGNhc2UgbmV0d29ya3MuYml0Y29pbjpcbiAgICBjYXNlIG5ldHdvcmtzLnRlc3RuZXQ6XG4gICAgICByZXR1cm4gbmV0d29ya3MuYml0Y29pbjtcblxuICAgIGNhc2UgbmV0d29ya3MuYml0Y29pbmNhc2g6XG4gICAgY2FzZSBuZXR3b3Jrcy5iaXRjb2luY2FzaFRlc3RuZXQ6XG4gICAgICByZXR1cm4gbmV0d29ya3MuYml0Y29pbmNhc2g7XG5cbiAgICBjYXNlIG5ldHdvcmtzLmJpdGNvaW5nb2xkOlxuICAgIGNhc2UgbmV0d29ya3MuYml0Y29pbmdvbGRUZXN0bmV0OlxuICAgICAgcmV0dXJuIG5ldHdvcmtzLmJpdGNvaW5nb2xkO1xuXG4gICAgY2FzZSBuZXR3b3Jrcy5iaXRjb2luc3Y6XG4gICAgY2FzZSBuZXR3b3Jrcy5iaXRjb2luc3ZUZXN0bmV0OlxuICAgICAgcmV0dXJuIG5ldHdvcmtzLmJpdGNvaW5zdjtcblxuICAgIGNhc2UgbmV0d29ya3MuZGFzaDpcbiAgICBjYXNlIG5ldHdvcmtzLmRhc2hUZXN0OlxuICAgICAgcmV0dXJuIG5ldHdvcmtzLmRhc2g7XG5cbiAgICBjYXNlIG5ldHdvcmtzLmxpdGVjb2luOlxuICAgIGNhc2UgbmV0d29ya3MubGl0ZWNvaW5UZXN0OlxuICAgICAgcmV0dXJuIG5ldHdvcmtzLmxpdGVjb2luO1xuXG4gICAgY2FzZSBuZXR3b3Jrcy56Y2FzaDpcbiAgICBjYXNlIG5ldHdvcmtzLnpjYXNoVGVzdDpcbiAgICAgIHJldHVybiBuZXR3b3Jrcy56Y2FzaDtcbiAgfVxuICB0aHJvdyBuZXcgVHlwZUVycm9yKGBpbnZhbGlkIG5ldHdvcmtgKTtcbn1cblxuLyoqXG4gKiBAcGFyYW0ge05ldHdvcmt9IG5ldHdvcmtcbiAqIEByZXR1cm5zIHtib29sZWFufSB0cnVlIGlmZiBuZXR3b3JrIGlzIGEgbWFpbm5ldFxuICovXG5leHBvcnQgZnVuY3Rpb24gaXNNYWlubmV0KG5ldHdvcms6IE5ldHdvcmspOiBib29sZWFuIHtcbiAgcmV0dXJuIGdldE1haW5uZXQobmV0d29yaykgPT09IG5ldHdvcms7XG59XG5cbi8qKlxuICogQHBhcmFtIHtOZXR3b3JrfSBuZXR3b3JrXG4gKiBAcmV0dXJucyB7Ym9vbGVhbn0gdHJ1ZSBpZmYgbmV0d29yayBpcyBhIHRlc3RuZXRcbiAqL1xuZXhwb3J0IGZ1bmN0aW9uIGlzVGVzdG5ldChuZXR3b3JrOiBOZXR3b3JrKTogYm9vbGVhbiB7XG4gIHJldHVybiBnZXRNYWlubmV0KG5ldHdvcmspICE9PSBuZXR3b3JrO1xufVxuXG4vKipcbiAqXG4gKiBAcGFyYW0ge05ldHdvcmt9IG5ldHdvcmtcbiAqIEBwYXJhbSB7TmV0d29ya30gb3RoZXJOZXR3b3JrXG4gKiBAcmV0dXJucyB7Ym9vbGVhbn0gdHJ1ZSBpZmYgYm90aCBuZXR3b3JrcyBhcmUgZm9yIHRoZSBzYW1lIGNvaW5cbiAqL1xuZXhwb3J0IGZ1bmN0aW9uIGlzU2FtZUNvaW4obmV0d29yazogTmV0d29yaywgb3RoZXJOZXR3b3JrOiBOZXR3b3JrKTogYm9vbGVhbiB7XG4gIHJldHVybiBnZXRNYWlubmV0KG5ldHdvcmspID09PSBnZXRNYWlubmV0KG90aGVyTmV0d29yayk7XG59XG5cbmNvbnN0IG1haW5uZXRzID0gZ2V0TmV0d29ya0xpc3QoKS5maWx0ZXIoaXNNYWlubmV0KTtcbmNvbnN0IHRlc3RuZXRzID0gZ2V0TmV0d29ya0xpc3QoKS5maWx0ZXIoaXNUZXN0bmV0KTtcblxuLyoqXG4gKiBNYXAgd2hlcmUga2V5cyBhcmUgbWFpbm5ldCBuZXR3b3JrcyBhbmQgdmFsdWVzIGFyZSB0ZXN0bmV0IG5ldHdvcmtzXG4gKiBAdHlwZSB7TWFwPE5ldHdvcmssIE5ldHdvcmtbXT59XG4gKi9cbmNvbnN0IG1haW5uZXRUZXN0bmV0UGFpcnMgPSBuZXcgTWFwKG1haW5uZXRzLm1hcCgobSkgPT4gW20sIHRlc3RuZXRzLmZpbHRlcigodCkgPT4gZ2V0TWFpbm5ldCh0KSA9PT0gbSldKSk7XG5cbi8qKlxuICogQHBhcmFtIHtOZXR3b3JrfSBuZXR3b3JrXG4gKiBAcmV0dXJucyB7TmV0d29ya3x1bmRlZmluZWR9IC0gVGhlIHRlc3RuZXQgY29ycmVzcG9uZGluZyB0byBhIG1haW5uZXQuXG4gKiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBSZXR1cm5zIHVuZGVmaW5lZCBpZiBhIG5ldHdvcmsgaGFzIG5vIHRlc3RuZXQuXG4gKi9cbmV4cG9ydCBmdW5jdGlvbiBnZXRUZXN0bmV0KG5ldHdvcms6IE5ldHdvcmspOiBOZXR3b3JrIHwgdW5kZWZpbmVkIHtcbiAgaWYgKGlzVGVzdG5ldChuZXR3b3JrKSkge1xuICAgIHJldHVybiBuZXR3b3JrO1xuICB9XG4gIGNvbnN0IHRlc3RuZXRzID0gbWFpbm5ldFRlc3RuZXRQYWlycy5nZXQobmV0d29yayk7XG4gIGlmICh0ZXN0bmV0cyA9PT0gdW5kZWZpbmVkKSB7XG4gICAgdGhyb3cgbmV3IEVycm9yKGBpbnZhbGlkIGFyZ3VtZW50YCk7XG4gIH1cbiAgaWYgKHRlc3RuZXRzLmxlbmd0aCA9PT0gMCkge1xuICAgIHJldHVybjtcbiAgfVxuICBpZiAodGVzdG5ldHMubGVuZ3RoID09PSAxKSB7XG4gICAgcmV0dXJuIHRlc3RuZXRzWzBdO1xuICB9XG4gIHRocm93IG5ldyBFcnJvcihgbW9yZSB0aGFuIG9uZSB0ZXN0bmV0IGZvciAke2dldE5ldHdvcmtOYW1lKG5ldHdvcmspfWApO1xufVxuXG4vKipcbiAqIEBwYXJhbSB7TmV0d29ya30gbmV0d29ya1xuICogQHJldHVybnMge2Jvb2xlYW59IHRydWUgaWZmIG5ldHdvcmsgYml0Y29pbiBvciB0ZXN0bmV0XG4gKi9cbmV4cG9ydCBmdW5jdGlvbiBpc0JpdGNvaW4obmV0d29yazogTmV0d29yayk6IGJvb2xlYW4ge1xuICByZXR1cm4gZ2V0TWFpbm5ldChuZXR3b3JrKSA9PT0gbmV0d29ya3MuYml0Y29pbjtcbn1cblxuLyoqXG4gKiBAcGFyYW0ge05ldHdvcmt9IG5ldHdvcmtcbiAqIEByZXR1cm5zIHtib29sZWFufSB0cnVlIGlmZiBuZXR3b3JrIGlzIGJpdGNvaW5jYXNoIG9yIGJpdGNvaW5jYXNoVGVzdG5ldFxuICovXG5leHBvcnQgZnVuY3Rpb24gaXNCaXRjb2luQ2FzaChuZXR3b3JrOiBOZXR3b3JrKTogYm9vbGVhbiB7XG4gIHJldHVybiBnZXRNYWlubmV0KG5ldHdvcmspID09PSBuZXR3b3Jrcy5iaXRjb2luY2FzaDtcbn1cblxuLyoqXG4gKiBAcGFyYW0ge05ldHdvcmt9IG5ldHdvcmtcbiAqIEByZXR1cm5zIHtib29sZWFufSB0cnVlIGlmZiBuZXR3b3JrIGlzIGJpdGNvaW5nb2xkXG4gKi9cbmV4cG9ydCBmdW5jdGlvbiBpc0JpdGNvaW5Hb2xkKG5ldHdvcms6IE5ldHdvcmspOiBib29sZWFuIHtcbiAgcmV0dXJuIGdldE1haW5uZXQobmV0d29yaykgPT09IG5ldHdvcmtzLmJpdGNvaW5nb2xkO1xufVxuXG4vKipcbiAqIEBwYXJhbSB7TmV0d29ya30gbmV0d29ya1xuICogQHJldHVybnMge2Jvb2xlYW59IHRydWUgaWZmIG5ldHdvcmsgaXMgYml0Y29pbnN2IG9yIGJpdGNvaW5zdlRlc3RuZXRcbiAqL1xuZXhwb3J0IGZ1bmN0aW9uIGlzQml0Y29pblNWKG5ldHdvcms6IE5ldHdvcmspOiBib29sZWFuIHtcbiAgcmV0dXJuIGdldE1haW5uZXQobmV0d29yaykgPT09IG5ldHdvcmtzLmJpdGNvaW5zdjtcbn1cblxuLyoqXG4gKiBAcGFyYW0ge05ldHdvcmt9IG5ldHdvcmtcbiAqIEByZXR1cm5zIHtib29sZWFufSB0cnVlIGlmZiBuZXR3b3JrIGlzIGRhc2ggb3IgZGFzaFRlc3RcbiAqL1xuZXhwb3J0IGZ1bmN0aW9uIGlzRGFzaChuZXR3b3JrOiBOZXR3b3JrKTogYm9vbGVhbiB7XG4gIHJldHVybiBnZXRNYWlubmV0KG5ldHdvcmspID09PSBuZXR3b3Jrcy5kYXNoO1xufVxuXG4vKipcbiAqIEBwYXJhbSB7TmV0d29ya30gbmV0d29ya1xuICogQHJldHVybnMge2Jvb2xlYW59IHRydWUgaWZmIG5ldHdvcmsgaXMgbGl0ZWNvaW4gb3IgbGl0ZWNvaW5UZXN0XG4gKi9cbmV4cG9ydCBmdW5jdGlvbiBpc0xpdGVjb2luKG5ldHdvcms6IE5ldHdvcmspOiBib29sZWFuIHtcbiAgcmV0dXJuIGdldE1haW5uZXQobmV0d29yaykgPT09IG5ldHdvcmtzLmxpdGVjb2luO1xufVxuXG4vKipcbiAqIEBwYXJhbSB7TmV0d29ya30gbmV0d29ya1xuICogQHJldHVybnMge2Jvb2xlYW59IHRydWUgaWZmIG5ldHdvcmsgaXMgemNhc2ggb3IgemNhc2hUZXN0XG4gKi9cbmV4cG9ydCBmdW5jdGlvbiBpc1pjYXNoKG5ldHdvcms6IE5ldHdvcmspOiBib29sZWFuIHtcbiAgcmV0dXJuIGdldE1haW5uZXQobmV0d29yaykgPT09IG5ldHdvcmtzLnpjYXNoO1xufVxuXG4vKipcbiAqIEBwYXJhbSB7dW5rbm93bn0gbmV0d29ya1xuICogQHJldHVybnMge2Jvb2xlYW59IHJldHVybnMgdHJ1ZSBpZmYgbmV0d29yayBpcyBhbnkgb2YgdGhlIG5ldHdvcmsgc3RhdGVkIGluIHRoZSBhcmd1bWVudFxuICovXG5leHBvcnQgZnVuY3Rpb24gaXNWYWxpZE5ldHdvcmsobmV0d29yazogdW5rbm93bik6IG5ldHdvcmsgaXMgTmV0d29yayB7XG4gIHJldHVybiBnZXROZXR3b3JrTGlzdCgpLmluY2x1ZGVzKG5ldHdvcmsgYXMgTmV0d29yayk7XG59XG5cbi8qKiBAZGVwcmVjYXRlZCAqL1xuZXhwb3J0IGNvbnN0IEJDSCA9IGNvaW5zLkJDSDtcbi8qKiBAZGVwcmVjYXRlZCAqL1xuZXhwb3J0IGNvbnN0IEJTViA9IGNvaW5zLkJTVjtcbi8qKiBAZGVwcmVjYXRlZCAqL1xuZXhwb3J0IGNvbnN0IEJUQyA9IGNvaW5zLkJUQztcbi8qKiBAZGVwcmVjYXRlZCAqL1xuZXhwb3J0IGNvbnN0IEJURyA9IGNvaW5zLkJURztcbi8qKiBAZGVwcmVjYXRlZCAqL1xuZXhwb3J0IGNvbnN0IERBU0ggPSBjb2lucy5EQVNIO1xuLyoqIEBkZXByZWNhdGVkICovXG5leHBvcnQgY29uc3QgTFRDID0gY29pbnMuTFRDO1xuLyoqIEBkZXByZWNhdGVkICovXG5leHBvcnQgY29uc3QgWkVDID0gY29pbnMuWkVDO1xuIl19