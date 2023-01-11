"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.toOutputScriptWithFormat = exports.fromOutputScriptWithFormat = exports.toOutputScriptFromCashAddress = exports.fromOutputScriptToCashAddress = exports.getPrefix = void 0;
/**
 * Wrapper around `cashaddress` library.
 *
 * Performs some address sanitation:
 * - add prefix if missing
 * - normalize to lower-case
 * - reject mixed-case
 *
 * Based on these documents
 *
 * - https://github.com/bitcoincashorg/bitcoincash.org/blob/master/spec/cashaddr.md
 * - https://www.bitcoinabc.org/cashaddr/
 */
const cashaddress = require("cashaddress");
const bitcoinjs = require("bitcoinjs-lib");
const networks_1 = require("../../networks");
/**
 * @param name
 * @param output
 * @return the encoded pubkeyhash or scripthash
 */
function getHashFromOutputScript(name, output) {
    const func = bitcoinjs.payments[name];
    if (!func) {
        throw new Error(`no payment with name ${name}`);
    }
    try {
        return func({ output }).hash;
    }
    catch (e) {
        return undefined;
    }
}
/**
 * @param network
 * @return network-specific cashaddr prefix
 */
function getPrefix(network) {
    switch (network) {
        case networks_1.networks.bitcoincash:
            return 'bitcoincash';
        case networks_1.networks.bitcoincashTestnet:
            return 'bchtest';
        default:
            throw new Error(`unsupported prefix for ${networks_1.getNetworkName(network)}`);
    }
}
exports.getPrefix = getPrefix;
/**
 * @param outputScript
 * @param network
 * @return outputScript encoded as cashaddr (prefixed, lowercase)
 */
function fromOutputScriptToCashAddress(outputScript, network) {
    if (!networks_1.isBitcoinCash(network)) {
        throw new Error(`invalid network`);
    }
    for (const [paymentName, scriptType] of [
        ['p2pkh', 'pubkeyhash'],
        ['p2sh', 'scripthash'],
    ]) {
        const hash = getHashFromOutputScript(paymentName, outputScript);
        if (hash) {
            return cashaddress.encode(getPrefix(network), scriptType, hash);
        }
    }
    throw new Error(`could not determine hash for outputScript`);
}
exports.fromOutputScriptToCashAddress = fromOutputScriptToCashAddress;
/**
 * @param address - Accepts addresses with and without prefix. Accepts all-lowercase and all-uppercase addresses. Rejects mixed-case addresses.
 * @param network
 * @return decoded output script
 */
function toOutputScriptFromCashAddress(address, network) {
    if (!networks_1.isBitcoinCash(network)) {
        throw new Error(`invalid network`);
    }
    if (address === address.toUpperCase()) {
        address = address.toLowerCase();
    }
    if (address !== address.toLowerCase()) {
        throw new Error(`mixed-case addresses not allowed`);
    }
    if (!address.startsWith(getPrefix(network) + ':')) {
        address = `${getPrefix(network)}:${address}`;
    }
    const decoded = cashaddress.decode(address);
    let outputScript;
    switch (decoded.version) {
        case 'scripthash':
            outputScript = bitcoinjs.payments.p2sh({ hash: decoded.hash }).output;
            break;
        case 'pubkeyhash':
            outputScript = bitcoinjs.payments.p2pkh({ hash: decoded.hash }).output;
            break;
        default:
            throw new Error(`unknown version ${decoded.version}`);
    }
    if (!outputScript) {
        throw new Error(`could not determine output script`);
    }
    return outputScript;
}
exports.toOutputScriptFromCashAddress = toOutputScriptFromCashAddress;
/**
 * @param outputScript
 * @param format
 * @param network
 * @return address in specified format
 */
function fromOutputScriptWithFormat(outputScript, format, network) {
    if (!networks_1.isBitcoinCash(network)) {
        throw new Error(`invalid network`);
    }
    if (format === 'cashaddr') {
        return fromOutputScriptToCashAddress(outputScript, network);
    }
    if (format === 'default') {
        return bitcoinjs.address.fromOutputScript(outputScript, network);
    }
    throw new Error(`invalid format`);
}
exports.fromOutputScriptWithFormat = fromOutputScriptWithFormat;
/**
 * @param address
 * @param format
 * @param network
 * @return output script from address in specified format
 */
function toOutputScriptWithFormat(address, format, network) {
    if (!networks_1.isBitcoinCash(network)) {
        throw new Error(`invalid network`);
    }
    if (format === 'cashaddr') {
        return toOutputScriptFromCashAddress(address, network);
    }
    if (format === 'default') {
        return bitcoinjs.address.toOutputScript(address, network);
    }
    throw new Error(`invalid format`);
}
exports.toOutputScriptWithFormat = toOutputScriptWithFormat;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiYWRkcmVzcy5qcyIsInNvdXJjZVJvb3QiOiIiLCJzb3VyY2VzIjpbIi4uLy4uLy4uLy4uL3NyYy9iaXRnby9iaXRjb2luY2FzaC9hZGRyZXNzLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7OztBQUFBOzs7Ozs7Ozs7Ozs7R0FZRztBQUNILDJDQUEyQztBQUMzQywyQ0FBMkM7QUFDM0MsNkNBQWtGO0FBR2xGOzs7O0dBSUc7QUFDSCxTQUFTLHVCQUF1QixDQUFDLElBQVksRUFBRSxNQUFjO0lBRTNELE1BQU0sSUFBSSxHQUFJLFNBQVMsQ0FBQyxRQUF3QyxDQUFDLElBQUksQ0FBQyxDQUFDO0lBQ3ZFLElBQUksQ0FBQyxJQUFJLEVBQUU7UUFDVCxNQUFNLElBQUksS0FBSyxDQUFDLHdCQUF3QixJQUFJLEVBQUUsQ0FBQyxDQUFDO0tBQ2pEO0lBQ0QsSUFBSTtRQUNGLE9BQU8sSUFBSSxDQUFDLEVBQUUsTUFBTSxFQUFFLENBQUMsQ0FBQyxJQUFJLENBQUM7S0FDOUI7SUFBQyxPQUFPLENBQUMsRUFBRTtRQUNWLE9BQU8sU0FBUyxDQUFDO0tBQ2xCO0FBQ0gsQ0FBQztBQUVEOzs7R0FHRztBQUNILFNBQWdCLFNBQVMsQ0FBQyxPQUFnQjtJQUN4QyxRQUFRLE9BQU8sRUFBRTtRQUNmLEtBQUssbUJBQVEsQ0FBQyxXQUFXO1lBQ3ZCLE9BQU8sYUFBYSxDQUFDO1FBQ3ZCLEtBQUssbUJBQVEsQ0FBQyxrQkFBa0I7WUFDOUIsT0FBTyxTQUFTLENBQUM7UUFDbkI7WUFDRSxNQUFNLElBQUksS0FBSyxDQUFDLDBCQUEwQix5QkFBYyxDQUFDLE9BQU8sQ0FBQyxFQUFFLENBQUMsQ0FBQztLQUN4RTtBQUNILENBQUM7QUFURCw4QkFTQztBQUVEOzs7O0dBSUc7QUFDSCxTQUFnQiw2QkFBNkIsQ0FBQyxZQUFvQixFQUFFLE9BQWdCO0lBQ2xGLElBQUksQ0FBQyx3QkFBYSxDQUFDLE9BQU8sQ0FBQyxFQUFFO1FBQzNCLE1BQU0sSUFBSSxLQUFLLENBQUMsaUJBQWlCLENB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RUQ7Ozs7O0dBS0c7QUFDSCxTQUFnQix3QkFBd0IsQ0FBQyxPQUFlLEVBQUUsTUFBcUIsRUFBRSxPQUFnQjtJQUMvRixJQUFJLENBQUMsd0JBQWEsQ0FBQyxPQUFPLENBQUMsRUFBRTtRQUMzQixNQUFNLElBQUksS0FBSyxDQUFDLGlCQUFpQixDQUFDLENBQUM7S0FDcEM7SUFFRCxJQUFJLE1BQU0sS0FBSyxVQUFVLEVBQUU7UUFDekIsT0FBTyw2QkFBNkIsQ0FBQyxPQUFPLEVBQUUsT0FBTyxDQUFDLENBQUM7S0FDeEQ7SUFFRCxJQUFJLE1BQU0sS0FBSyxTQUFTLEVBQUU7UUFDeEIsT0FBTyxTQUFTLENBQUMsT0FBTyxDQUFDLGNBQWMsQ0FBQyxPQUFPLEVBQUUsT0FBNEIsQ0FBQyxDQUFDO0tBQ2hGO0lBRUQsTUFBTSxJQUFJLEtBQUssQ0FBQyxnQkFBZ0IsQ0FBQyxDQUFDO0FBQ3BDLENBQUM7QUFkRCw0REFjQyIsInNvdXJjZXNDb250ZW50IjpbIi8qKlxuICogV3JhcHBlciBhcm91bmQgYGNhc2hhZGRyZXNzYCBsaWJyYXJ5LlxuICpcbiAqIFBlcmZvcm1zIHNvbWUgYWRkcmVzcyBzYW5pdGF0aW9uOlxuICogLSBhZGQgcHJlZml4IGlmIG1pc3NpbmdcbiAqIC0gbm9ybWFsaXplIHRvIGxvd2VyLWNhc2VcbiAqIC0gcmVqZWN0IG1peGVkLWNhc2VcbiAqXG4gKiBCYXNlZCBvbiB0aGVzZSBkb2N1bWVudHNcbiAqXG4gKiAtIGh0dHBzOi8vZ2l0aHViLmNvbS9iaXRjb2luY2FzaG9yZy9iaXRjb2luY2FzaC5vcmcvYmxvYi9tYXN0ZXIvc3BlYy9jYXNoYWRkci5tZFxuICogLSBodHRwczovL3d3dy5iaXRjb2luYWJjLm9yZy9jYXNoYWRkci9cbiAqL1xuaW1wb3J0ICogYXMgY2FzaGFkZHJlc3MgZnJvbSAnY2FzaGFkZHJlc3MnO1xuaW1wb3J0ICogYXMgYml0Y29pbmpzIGZyb20gJ2JpdGNvaW5qcy1saWInO1xuaW1wb3J0IHsgZ2V0TmV0d29ya05hbWUsIGlzQml0Y29pbkNhc2gsIE5ldHdvcmssIG5ldHdvcmtzIH0gZnJvbSAnLi4vLi4vbmV0d29ya3MnO1xuaW1wb3J0IHsgQWRkcmVzc0Zvcm1hdCB9IGZyb20gJy4uLy4uL2FkZHJlc3NGb3JtYXQnO1xuXG4vKipcbiAqIEBwYXJhbSBuYW1lXG4gKiBAcGFyYW0gb3V0cHV0XG4gKiBAcmV0dXJuIHRoZSBlbmNvZGVkIHB1YmtleWhhc2ggb3Igc2NyaXB0aGFzaFxuICovXG5mdW5jdGlvbiBnZXRIYXNoRnJvbU91dHB1dFNjcmlwdChuYW1lOiBzdHJpbmcsIG91dHB1dDogQnVmZmVyKTogQnVmZmVyIHwgdW5kZWZpbmVkIHtcbiAgdHlwZSBQYXltZW50RnVuYyA9ICh7IG91dHB1dCB9OiB7IG91dHB1dDogQnVmZmVyIH0pID0+IGJpdGNvaW5qcy5QYXltZW50O1xuICBjb25zdCBmdW5jID0gKGJpdGNvaW5qcy5wYXltZW50cyBhcyBSZWNvcmQ8c3RyaW5nLCBQYXltZW50RnVuYz4pW25hbWVdO1xuICBpZiAoIWZ1bmMpIHtcbiAgICB0aHJvdyBuZXcgRXJyb3IoYG5vIHBheW1lbnQgd2l0aCBuYW1lICR7bmFtZX1gKTtcbiAgfVxuICB0cnkge1xuICAgIHJldHVybiBmdW5jKHsgb3V0cHV0IH0pLmhhc2g7XG4gIH0gY2F0Y2ggKGUpIHtcbiAgICByZXR1cm4gdW5kZWZpbmVkO1xuICB9XG59XG5cbi8qKlxuICogQHBhcmFtIG5ldHdvcmtcbiAqIEByZXR1cm4gbmV0d29yay1zcGVjaWZpYyBjYXNoYWRkciBwcmVmaXhcbiAqL1xuZXhwb3J0IGZ1bmN0aW9uIGdldFByZWZpeChuZXR3b3JrOiBOZXR3b3JrKTogc3RyaW5nIHtcbiAgc3dpdGNoIChuZXR3b3JrKSB7XG4gICAgY2FzZSBuZXR3b3Jrcy5iaXRjb2luY2FzaDpcbiAgICAgIHJldHVybiAnYml0Y29pbmNhc2gnO1xuICAgIGNhc2UgbmV0d29ya3MuYml0Y29pbmNhc2hUZXN0bmV0OlxuICAgICAgcmV0dXJuICdiY2h0ZXN0JztcbiAgICBkZWZhdWx0OlxuICAgICAgdGhyb3cgbmV3IEVycm9yKGB1bnN1cHBvcnRlZCBwcmVmaXggZm9yICR7Z2V0TmV0d29ya05hbWUobmV0d29yayl9YCk7XG4gIH1cbn1cblxuLyoqXG4gKiBAcGFyYW0gb3V0cHV0U2NyaXB0XG4gKiBAcGFyYW0gbmV0d29ya1xuICogQHJldHVybiBvdXRwdXRTY3JpcHQgZW5jb2RlZCBhcyBjYXNoYWRkciAocHJlZml4ZWQsIGxvd2VyY2FzZSlcbiAqL1xuZXhwb3J0IGZ1bmN0aW9uIGZyb21PdXRwdXRTY3JpcHRUb0Nhc2hBZGRyZXNzKG91dHB1dFNjcmlwdDogQnVmZmVyLCBuZXR3b3JrOiBOZXR3b3JrKTogc3RyaW5nIHtcbiAgaWYgKCFpc0JpdGNvaW5DYXNoKG5ldHdvcmspKSB7XG4gICAgdGhyb3cgbmV3IEVycm9yKGBpbnZhbGlkIG5ldHdvcmtgKTtcbiAgfVxuICBmb3IgKGNvbnN0IFtwYXltZW50TmFtZSwgc2NyaXB0VHlwZV0gb2YgW1xuICAgIFsncDJwa2gnLCAncHVia2V5aGFzaCddLFxuICAgIFsncDJzaCcsICdzY3JpcHRoYXNoJ10sXG4gIF0pIHtcbiAgICBjb25zdCBoYXNoID0gZ2V0SGFzaEZyb21PdXRwdXRTY3JpcHQocGF5bWVudE5hbWUsIG91dHB1dFNjcmlwdCk7XG4gICAgaWYgKGhhc2gpIHtcbiAgICAgIHJldHVybiBjYXNoYWRkcmVzcy5lbmNvZGUoZ2V0UHJlZml4KG5ldHdvcmspLCBzY3JpcHRUeXBlIGFzIGNhc2hhZGRyZXNzLlNjcmlwdFR5cGUsIGhhc2gpO1xuICAgIH1cbiAgfVxuICB0aHJvdyBuZXcgRXJyb3IoYGNvdWxkIG5vdCBkZXRlcm1pbmUgaGFzaCBmb3Igb3V0cHV0U2NyaXB0YCk7XG59XG5cbi8qKlxuICogQHBhcmFtIGFkZHJlc3MgLSBBY2NlcHRzIGFkZHJlc3NlcyB3aXRoIGFuZCB3aXRob3V0IHByZWZpeC4gQWNjZXB0cyBhbGwtbG93ZXJjYXNlIGFuZCBhbGwtdXBwZXJjYXNlIGFkZHJlc3Nlcy4gUmVqZWN0cyBtaXhlZC1jYXNlIGFkZHJlc3Nlcy5cbiAqIEBwYXJhbSBuZXR3b3JrXG4gKiBAcmV0dXJuIGRlY29kZWQgb3V0cHV0IHNjcmlwdFxuICovXG5leHBvcnQgZnVuY3Rpb24gdG9PdXRwdXRTY3JpcHRGcm9tQ2FzaEFkZHJlc3MoYWRkcmVzczogc3RyaW5nLCBuZXR3b3JrOiBOZXR3b3JrKTogQnVmZmVyIHtcbiAgaWYgKCFpc0JpdGNvaW5DYXNoKG5ldHdvcmspKSB7XG4gICAgdGhyb3cgbmV3IEVycm9yKGBpbnZhbGlkIG5ldHdvcmtgKTtcbiAgfVxuICBpZiAoYWRkcmVzcyA9PT0gYWRkcmVzcy50b1VwcGVyQ2FzZSgpKSB7XG4gICAgYWRkcmVzcyA9IGFkZHJlc3MudG9Mb3dlckNhc2UoKTtcbiAgfVxuICBpZiAoYWRkcmVzcyAhPT0gYWRkcmVzcy50b0xvd2VyQ2FzZSgpKSB7XG4gICAgdGhyb3cgbmV3IEVycm9yKGBtaXhlZC1jYXNlIGFkZHJlc3NlcyBub3QgYWxsb3dlZGApO1xuICB9XG4gIGlmICghYWRkcmVzcy5zdGFydHNXaXRoKGdldFByZWZpeChuZXR3b3JrKSArICc6JykpIHtcbiAgICBhZGRyZXNzID0gYCR7Z2V0UHJlZml4KG5ldHdvcmspfToke2FkZHJlc3N9YDtcbiAgfVxuICBjb25zdCBkZWNvZGVkID0gY2FzaGFkZHJlc3MuZGVjb2RlKGFkZHJlc3MpO1xuICBsZXQgb3V0cHV0U2NyaXB0OiBCdWZmZXIgfCB1bmRlZmluZWQ7XG4gIHN3aXRjaCAoZGVjb2RlZC52ZXJzaW9uKSB7XG4gICAgY2FzZSAnc2NyaXB0aGFzaCc6XG4gICAgICBvdXRwdXRTY3JpcHQgPSBiaXRjb2luanMucGF5bWVudHMucDJzaCh7IGhhc2g6IGRlY29kZWQuaGFzaCB9KS5vdXRwdXQ7XG4gICAgICBicmVhaztcbiAgICBjYXNlICdwdWJrZXloYXNoJzpcbiAgICAgIG91dHB1dFNjcmlwdCA9IGJpdGNvaW5qcy5wYXltZW50cy5wMnBraCh7IGhhc2g6IGRlY29kZWQuaGFzaCB9KS5vdXRwdXQ7XG4gICAgICBicmVhaztcbiAgICBkZWZhdWx0OlxuICAgICAgdGhyb3cgbmV3IEVycm9yKGB1bmtub3duIHZlcnNpb24gJHtkZWNvZGVkLnZlcnNpb259YCk7XG4gIH1cbiAgaWYgKCFvdXRwdXRTY3JpcHQpIHtcbiAgICB0aHJvdyBuZXcgRXJyb3IoYGNvdWxkIG5vdCBkZXRlcm1pbmUgb3V0cHV0IHNjcmlwdGApO1xuICB9XG4gIHJldHVybiBvdXRwdXRTY3JpcHQ7XG59XG5cbi8qKlxuICogQHBhcmFtIG91dHB1dFNjcmlwdFxuICogQHBhcmFtIGZvcm1hdFxuICogQHBhcmFtIG5ldHdvcmtcbiAqIEByZXR1cm4gYWRkcmVzcyBpbiBzcGVjaWZpZWQgZm9ybWF0XG4gKi9cbmV4cG9ydCBmdW5jdGlvbiBmcm9tT3V0cHV0U2NyaXB0V2l0aEZvcm1hdChvdXRwdXRTY3JpcHQ6IEJ1ZmZlciwgZm9ybWF0OiBBZGRyZXNzRm9ybWF0LCBuZXR3b3JrOiBOZXR3b3JrKTogc3RyaW5nIHtcbiAgaWYgKCFpc0JpdGNvaW5DYXNoKG5ldHdvcmspKSB7XG4gICAgdGhyb3cgbmV3IEVycm9yKGBpbnZhbGlkIG5ldHdvcmtgKTtcbiAgfVxuXG4gIGlmIChmb3JtYXQgPT09ICdjYXNoYWRkcicpIHtcbiAgICByZXR1cm4gZnJvbU91dHB1dFNjcmlwdFRvQ2FzaEFkZHJlc3Mob3V0cHV0U2NyaXB0LCBuZXR3b3JrKTtcbiAgfVxuXG4gIGlmIChmb3JtYXQgPT09ICdkZWZhdWx0Jykge1xuICAgIHJldHVybiBiaXRjb2luanMuYWRkcmVzcy5mcm9tT3V0cHV0U2NyaXB0KG91dHB1dFNjcmlwdCwgbmV0d29yayBhcyBiaXRjb2luanMuTmV0d29yayk7XG4gIH1cblxuICB0aHJvdyBuZXcgRXJyb3IoYGludmFsaWQgZm9ybWF0YCk7XG59XG5cbi8qKlxuICogQHBhcmFtIGFkZHJlc3NcbiAqIEBwYXJhbSBmb3JtYXRcbiAqIEBwYXJhbSBuZXR3b3JrXG4gKiBAcmV0dXJuIG91dHB1dCBzY3JpcHQgZnJvbSBhZGRyZXNzIGluIHNwZWNpZmllZCBmb3JtYXRcbiAqL1xuZXhwb3J0IGZ1bmN0aW9uIHRvT3V0cHV0U2NyaXB0V2l0aEZvcm1hdChhZGRyZXNzOiBzdHJpbmcsIGZvcm1hdDogQWRkcmVzc0Zvcm1hdCwgbmV0d29yazogTmV0d29yayk6IEJ1ZmZlciB7XG4gIGlmICghaXNCaXRjb2luQ2FzaChuZXR3b3JrKSkge1xuICAgIHRocm93IG5ldyBFcnJvcihgaW52YWxpZCBuZXR3b3JrYCk7XG4gIH1cblxuICBpZiAoZm9ybWF0ID09PSAnY2FzaGFkZHInKSB7XG4gICAgcmV0dXJuIHRvT3V0cHV0U2NyaXB0RnJvbUNhc2hBZGRyZXNzKGFkZHJlc3MsIG5ldHdvcmspO1xuICB9XG5cbiAgaWYgKGZvcm1hdCA9PT0gJ2RlZmF1bHQnKSB7XG4gICAgcmV0dXJuIGJpdGNvaW5qcy5hZGRyZXNzLnRvT3V0cHV0U2NyaXB0KGFkZHJlc3MsIG5ldHdvcmsgYXMgYml0Y29pbmpzLk5ldHdvcmspO1xuICB9XG5cbiAgdGhyb3cgbmV3IEVycm9yKGBpbnZhbGlkIGZvcm1hdGApO1xufVxuIl19