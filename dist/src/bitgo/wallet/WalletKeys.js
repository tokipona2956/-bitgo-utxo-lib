"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.RootWalletKeys = exports.DerivedWalletKeys = exports.WalletKeys = exports.eqPublicKey = void 0;
function eqPublicKey(a, b) {
    return a.publicKey.equals(b.publicKey);
}
exports.eqPublicKey = eqPublicKey;
/**
 * Base class for RootWalletKeys and DerivedWalletKeys.
 * Keys can be either public keys or private keys.
 */
class WalletKeys {
    /**
     * @param triple - bip32 key triple
     */
    constructor(triple) {
        this.triple = triple;
        triple.forEach((a, i) => {
            triple.forEach((b, j) => {
                if (eqPublicKey(a, b) && i !== j) {
                    throw new Error(`wallet keys must be distinct`);
                }
            });
        });
        this.publicKeys = this.triple.map((k) => k.publicKey);
    }
    get user() {
        return this.triple[0];
    }
    get backup() {
        return this.triple[1];
    }
    get bitgo() {
        return this.triple[2];
    }
}
exports.WalletKeys = WalletKeys;
/**
 * Set of WalletKeys derived from RootWalletKeys. Suitable for signing transaction inputs.
 * Contains reference to the RootWalletKeys this was derived from as well as the paths used
 * for derivation.
 */
class DerivedWalletKeys extends WalletKeys {
    /**
     * @param parent - wallet keys to derive from
     * @param paths - paths to derive with
     */
    constructor(parent, paths) {
        super(parent.triple.map((k, i) => k.derivePath(paths[i])));
        this.parent = parent;
        this.paths = paths;
    }
}
exports.DerivedWalletKeys = DerivedWalletKeys;
/**
 * Set of root wallet keys, typically instantiated using the wallet xpub triple.
 */
class RootWalletKeys extends WalletKeys {
    /**
     * @param triple - bip32 key triple
     * @param derivationPrefixes - Certain v1 wallets or their migrated v2 counterparts
     *                             can have a nonstandard prefix.
     */
    constructor(triple, derivationPrefixes = [
        RootWalletKeys.defaultPrefix,
        RootWalletKeys.defaultPrefix,
        RootWalletKeys.defaultPrefix,
    ]) {
        super(triple);
        this.derivationPrefixes = derivationPrefixes;
        derivationPrefixes.forEach((p) => {
            if (p.startsWith('/') || p.endsWith('/')) {
                throw new Error(`derivation prefix must not start or end with a slash`);
            }
        });
    }
    /**
     * @param key
     * @param chain
     * @param index
     * @return full derivation path for key, including key-specific prefix
     */
    getDerivationPath(key, chain, index) {
        if (!this.derivationPrefixes) {
            throw new Error(`no derivation prefixes`);
        }
        const prefix = this.derivationPrefixes.find((prefix, i) => eqPublicKey(key, this.triple[i]));
        if (prefix === undefined) {
            throw new Error(`key not in walletKeys`);
        }
        return `${prefix}/${chain}/${index}`;
    }
    /**
     * @param chain
     * @param index
     * @return walletKeys for a particular address identified by (chain, index)
     */
    deriveForChainAndIndex(chain, index) {
        return new DerivedWalletKeys(this, this.triple.map((k) => this.getDerivationPath(k, chain, index)));
    }
}
exports.RootWalletKeys = RootWalletKeys;
RootWalletKeys.defaultPrefix = '0/0';
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiV2FsbGV0S2V5cy5qcyIsInNvdXJjZVJvb3QiOiIiLCJzb3VyY2VzIjpbIi4uLy4uLy4uLy4uL3NyYy9iaXRnby93YWxsZXQvV2FsbGV0S2V5cy50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOzs7QUFlQSxTQUFnQixXQUFXLENBQUMsQ0FBdUIsRUFBRSxDQUF1QjtJQUMxRSxPQUFPLENBQUMsQ0FBQyxTQUFTLENBQUMsTUFBTSxDQUFDLENBQUMsQ0FBQyxTQUFTLENBQUMsQ0FBQztBQUN6QyxDQUFDO0FBRkQsa0NBRUM7QUFFRDs7O0dBR0c7QUFDSCxNQUFhLFVBQVU7SUFHckI7O09BRUc7SUFDSCxZQUE0QixNQUFvQztRQUFwQyxXQUFNLEdBQU4sTUFBTSxDQUE4QjtRQUM5RCxNQUFNLENBQUMsT0FBTyxDQUFDLENBQUMsQ0FBQyxFQUFFLENBQUMsRUFBRSxFQUFFO1lBQ3RCLE1BQU0sQ0FBQyxPQUFPLENBQUMsQ0FBQyxDQUFDLEVBQUUsQ0FBQyxFQUFFLEVBQUU7Z0JBQ3RCLElBQUksV0FBVyxDQUFDLENBQUMsRUFBRSxDQUFDLENBQUMsSUFBSSxDQUFDLEtBQUssQ0FBQyxFQUFFO29CQUNoQyxNQUFNLElBQUksS0FBSyxDQUFDLDhCQUE4QixDQUFDLENBQUM7aUJBQ2pEO1lBQ0gsQ0FBQyxDQUFDLENBQUM7UUFDTCxDQUFDLENBQUMsQ0FBQztRQUVILElBQUksQ0FBQyxVQUFVLEdBQUcsSUFBSSxDQUFDLE1BQU0sQ0FBQyxHQUFHLENBQUMsQ0FBQyxDQUFDLEVBQUUsRUFBRSxDQUFDLENBQUMsQ0FBQyxTQUFTLENBQW1CLENBQUM7SUFDMUUsQ0FBQztJQUVELElBQUksSUFBSTtRQUNOLE9BQU8sSUFBSSxDQUFDLE1BQU0sQ0FBQyxDQUFDLENBQUMsQ0FBQztJQUN4QixDQUFDO0lBRUQsSUFBSSxNQUFNO1FBQ1IsT0FBTyxJQUFJLENBQUMsTUFBTSxDQUFDLENBQUMsQ0FBQyxDQUFDO0lBQ3hCLENBQUM7SUFFRCxJQUFJLEtBQUs7UUFDUCxPQUFPLElBQUksQ0FBQyxNQUFNLENBQUMsQ0FBQyxDQUFDLENBQUM7SUFDeEIsQ0FBQztDQUNGO0FBN0JELGdDQTZCQztBQUVEOzs7O0dBSUc7QUFDSCxNQUFhLGlCQUFrQixTQUFRLFVBQVU7SUFDL0M7OztPQUdHO0lBQ0gsWUFBbUIsTUFBc0IsRUFBUyxLQUFxQjtRQUNyRSxLQUFLLENBQUMsTUFBTSxDQUFDLE1BQU0sQ0FBQyxHQUFHLENBQUMsQ0FBQyxDQUFDLEVBQUUsQ0FBQyxFQUFFLEVBQUUsQ0FBQyxDQUFDLENBQUMsVUFBVSxDQUFDLEtBQUssQ0FBQyxDQUFDLENBQUMsQ0FBQyxDQUFpQyxDQUFDLENBQUM7UUFEMUUsV0FBTSxHQUFOLE1BQU0sQ0FBZ0I7UUFBUyxVQUFLLEdBQUwsS0FBSyxDQUFnQjtJQUV2RSxDQUFDO0NBQ0Y7QUFSRCw4Q0FRQztBQUVEOztHQUVHO0FBQ0gsTUFBYSxjQUFlLFNBQVEsVUFBVTtJQUc1Qzs7OztPQUlHO0lBQ0gsWUFDRSxNQUFvQyxFQUNwQixxQkFBcUM7UUFDbkQsY0FBYyxDQUFDLGFBQWE7UUFDNUIsY0FBYyxDQUFDLGFBQWE7UUFDNUIsY0FBYyxDQUFDLGFBQWE7S0FDN0I7UUFFRCxLQUFLLENBQUMsTUFBTSxDQUFDLENBQUM7UUFORSx1QkFBa0IsR0FBbEIsa0JBQWtCLENBSWpDO1FBSUQsa0JBQWtCLENBQUMsT0FBTyxDQUFDLENBQUMsQ0FBQyxFQUFFLEVBQUU7WUFDL0IsSUFBSSxDQUFDLENBQUMsVUFBVSxDQUFDLEdBQUcsQ0FBQyxJQUFJLENBQUMsQ0FBQyxRQUFRLENBQUMsR0FBRyxDQUFDLEVBQUU7Z0JBQ3hDLE1BQU0sSUFBSSxLQUFLLENBQUMsc0RBQXNELENBQUMsQ0FBQzthQUN6RTtRQUNILENBQUMsQ0FBQyxDQUFDO0lBQ0wsQ0FBQztJQUVEOzs7OztPQUtHO0lBQ0gsaUJBQWlCLENBQUMsR0FBeUIsRUFBRSxLQUFhLEVBQUUsS0FBYTtRQUN2RSxJQUFJLENBQUMsSUFBSSxDQUFDLGtCQUFrQixFQUFFO1lBQzVCLE1BQU0sSUFBSSxLQUFLLENBQUMsd0JBQXdCLENBQUMsQ0FBQztTQUMzQztRQUNELE1BQU0sTUFBTSxHQUFHLElBQUksQ0FBQyxrQkFBa0IsQ0FBQyxJQUFJLENBQUMsQ0FBQyxNQUFNLEVBQUUsQ0FBQyxFQUFFLEVBQUUsQ0FBQyxXQUFXLENBQUMsR0FBRyxFQUFFLElBQUksQ0FBQyxNQUFNLENBQUMsQ0FBQyxDQUFDLENBQUMsQ0FBQyxDQUFDO1FBQzdGLElBQUksTUFBTSxLQUFLLFNBQVMsRUFBRTtZQUN4QixNQUFNLElBQUksS0FBSyxDQUFDLHVCQUF1QixDQUFDLENBQUM7U0FDMUM7UUFDRCxPQUFPLEdBQUcsTUFBTSxJQUFJLEtBQUssSUFBSSxLQUFLLEVBQUUsQ0FBQztJQUN2QyxDQUFDO0lBRUQ7Ozs7T0FJRztJQUNILHNCQUFzQixDQUFDLEtBQWEsRUFBRSxLQUFhO1FBQ2pELE9BQU8sSUFBSSxpQkFBaUIsQ0FDMUIsSUFBSSxFQUNKLElBQUksQ0FBQyxNQUFNLENBQUMsR0FBRyxDQUFDLENBQUMsQ0FBQyxFQUFFLEVBQUUsQ0FBQyxJQUFJLENBQUMsaUJBQWlCLENBQUMsQ0FBQyxFQUFFLEtBQUssRUFBRSxLQUFLLENBQUMsQ0FBbUIsQ0FDbEYsQ0FBQztJQUNKLENBQUM7O0FBcERILHdDQXFEQztBQXBEaUIsNEJBQWEsR0FBRyxLQUFLLENBQUMiLCJzb3VyY2VzQ29udGVudCI6WyIvKipcbiAqIENsYXNzZXMgZm9yIGRlcml2aW5nIGtleSB0cmlwbGVzIGZvciB3YWxsZXQgYWRkcmVzc2VzLlxuICpcbiAqIEJ5IGRlZmF1bHQsIEJpdEdvIHdhbGxldHMgY29uc2lzdCBvZiBhIHRyaXBsZSBvZiBiaXAzMiBleHRlbmQga2V5cGFpcnMuXG4gKiBFdmVyeSB3YWxsZXQgYWRkcmVzcyBjYW4gYmUgaWRlbnRpZmllZCBieSBfKGNoYWluOiBudW1iZXIsIGluZGV4OiBudW1iZXIpXy5cbiAqIFRoZSBrZXkgc2V0IGZvciBhIHBhcnRpY3VsYXIgYWRkcmVzcyBjYW4gYmUgb2J0YWluZWQgYnkgZGVyaXZpbmcgd2l0aCB0aGUgcGF0aFxuICogYDAvMC8ke2NoYWlufS8ke2luZGV4fWAuIChJbiByYXJlIGNhc2VzIHRoZSBwcmVmaXggMC8wIGNhbiBiZSBkaWZmZXJlbnQpXG4gKlxuICogU2luY2Ugd2UgbmV2ZXIgdXNlIG90aGVyIGRlcml2YXRpb25zIGZvciB1dHhvIGFkZHJlc3Mgc2NyaXB0cywgdGhlIGNsYXNzZXMgZGVmaW5lZCBoZXJlIG9ubHlcbiAqIGFsbG93IGV4YWN0bHkgb25lIGxldmVsIG9mIGRlcml2YXRpb24uXG4gKi9cbmltcG9ydCAqIGFzIGJpcDMyIGZyb20gJ2JpcDMyJztcblxuaW1wb3J0IHsgVHJpcGxlIH0gZnJvbSAnLi4vdHlwZXMnO1xuXG5leHBvcnQgZnVuY3Rpb24gZXFQdWJsaWNLZXkoYTogYmlwMzIuQklQMzJJbnRlcmZhY2UsIGI6IGJpcDMyLkJJUDMySW50ZXJmYWNlKTogYm9vbGVhbiB7XG4gIHJldHVybiBhLnB1YmxpY0tleS5lcXVhbHMoYi5wdWJsaWNLZXkpO1xufVxuXG4vKipcbiAqIEJhc2UgY2xhc3MgZm9yIFJvb3RXYWxsZXRLZXlzIGFuZCBEZXJpdmVkV2FsbGV0S2V5cy5cbiAqIEtleXMgY2FuIGJlIGVpdGhlciBwdWJsaWMga2V5cyBvciBwcml2YXRlIGtleXMuXG4gKi9cbmV4cG9ydCBjbGFzcyBXYWxsZXRLZXlzIHtcbiAgcHVibGljIHJlYWRvbmx5IHB1YmxpY0tleXM6IFRyaXBsZTxCdWZmZXI+O1xuXG4gIC8qKlxuICAgKiBAcGFyYW0gdHJpcGxlIC0gYmlwMzIga2V5IHRyaXBsZVxuICAgKi9cbiAgY29uc3RydWN0b3IocHVibGljIHJlYWRvbmx5IHRyaXBsZTogVHJpcGxlPGJpcDMyLkJJUDMySW50ZXJmYWNlPikge1xuICAgIHRyaXBsZS5mb3JFYWNoKChhLCBpKSA9PiB7XG4gICAgICB0cmlwbGUuZm9yRWFjaCgoYiwgaikgPT4ge1xuICAgICAgICBpZiAoZXFQdWJsaWNLZXkoYSwgYikgJiYgaSAhPT0gaikge1xuICAgICAgICAgIHRocm93IG5ldyBFcnJvcihgd2FsbGV0IGtleXMgbXVzdCBiZSBkaXN0aW5jdGApO1xuICAgICAgICB9XG4gICAgICB9KTtcbiAgICB9KTtcblxuICAgIHRoaXMucHVibGljS2V5cyA9IHRoaXMudHJpcGxlLm1hcCgoaykgPT4gay5wdWJsaWNLZXkpIGFzIFRyaXBsZTxCdWZmZXI+O1xuICB9XG5cbiAgZ2V0IHVzZXIoKTogYmlwMzIuQklQMzJJbnRlcmZhY2Uge1xuICAgIHJldHVybiB0aGlzLnRyaXBsZVswXTtcbiAgfVxuXG4gIGdldCBiYWNrdXAoKTogYmlwMzIuQklQMzJJbnRlcmZhY2Uge1xuICAgIHJldHVybiB0aGlzLnRyaXBsZVsxXTtcbiAgfVxuXG4gIGdldCBiaXRnbygpOiBiaXAzMi5CSVAzMkludGVyZmFjZSB7XG4gICAgcmV0dXJuIHRoaXMudHJpcGxlWzJdO1xuICB9XG59XG5cbi8qKlxuICogU2V0IG9mIFdhbGxldEtleXMgZGVyaXZlZCBmcm9tIFJvb3RXYWxsZXRLZXlzLiBTdWl0YWJsZSBmb3Igc2lnbmluZyB0cmFuc2FjdGlvbiBpbnB1dHMuXG4gKiBDb250YWlucyByZWZlcmVuY2UgdG8gdGhlIFJvb3RXYWxsZXRLZXlzIHRoaXMgd2FzIGRlcml2ZWQgZnJvbSBhcyB3ZWxsIGFzIHRoZSBwYXRocyB1c2VkXG4gKiBmb3IgZGVyaXZhdGlvbi5cbiAqL1xuZXhwb3J0IGNsYXNzIERlcml2ZWRXYWxsZXRLZXlzIGV4dGVuZHMgV2FsbGV0S2V5cyB7XG4gIC8qKlxuICAgKiBAcGFyYW0gcGFyZW50IC0gd2FsbGV0IGtleXMgdG8gZGVyaXZlIGZyb21cbiAgICogQHBhcmFtIHBhdGhzIC0gcGF0aHMgdG8gZGVyaXZlIHdpdGhcbiAgICovXG4gIGNvbnN0cnVjdG9yKHB1YmxpYyBwYXJlbnQ6IFJvb3RXYWxsZXRLZXlzLCBwdWJsaWMgcGF0aHM6IFRyaXBsZTxzdHJpbmc+KSB7XG4gICAgc3VwZXIocGFyZW50LnRyaXBsZS5tYXAoKGssIGkpID0+IGsuZGVyaXZlUGF0aChwYXRoc1tpXSkpIGFzIFRyaXBsZTxiaXAzMi5CSVAzMkludGVyZmFjZT4pO1xuICB9XG59XG5cbi8qKlxuICogU2V0IG9mIHJvb3Qgd2FsbGV0IGtleXMsIHR5cGljYWxseSBpbnN0YW50aWF0ZWQgdXNpbmcgdGhlIHdhbGxldCB4cHViIHRyaXBsZS5cbiAqL1xuZXhwb3J0IGNsYXNzIFJvb3RXYWxsZXRLZXlzIGV4dGVuZHMgV2FsbGV0S2V5cyB7XG4gIHN0YXRpYyByZWFkb25seSBkZWZhdWx0UHJlZml4ID0gJzAvMCc7XG5cbiAgLyoqXG4gICAqIEBwYXJhbSB0cmlwbGUgLSBiaXAzMiBrZXkgdHJpcGxlXG4gICAqIEBwYXJhbSBkZXJpdmF0aW9uUHJlZml4ZXMgLSBDZXJ0YWluIHYxIHdhbGxldHMgb3IgdGhlaXIgbWlncmF0ZWQgdjIgY291bnRlcnBhcnRzXG4gICAqICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjYW4gaGF2ZSBhIG5vbnN0YW5kYXJkIHByZWZpeC5cbiAgICovXG4gIGNvbnN0cnVjdG9yKFxuICAgIHRyaXBsZTogVHJpcGxlPGJpcDMyLkJJUDMySW50ZXJmYWNlPixcbiAgICBwdWJsaWMgcmVhZG9ubHkgZGVyaXZhdGlvblByZWZpeGVzOiBUcmlwbGU8c3RyaW5nPiA9IFtcbiAgICAgIFJvb3RXYWxsZXRLZXlzLmRlZmF1bHRQcmVmaXgsXG4gICAgICBSb290V2FsbGV0S2V5cy5kZWZhdWx0UHJlZml4LFxuICAgICAgUm9vdFdhbGxldEtleXMuZGVmYXVsdFByZWZpeCxcbiAgICBdXG4gICkge1xuICAgIHN1cGVyKHRyaXBsZSk7XG5cbiAgICBkZXJpdmF0aW9uUHJlZml4ZXMuZm9yRWFjaCgocCkgPT4ge1xuICAgICAgaWYgKHAuc3RhcnRzV2l0aCgnLycpIHx8IHAuZW5kc1dpdGgoJy8nKSkge1xuICAgICAgICB0aHJvdyBuZXcgRXJyb3IoYGRlcml2YXRpb24gcHJlZml4IG11c3Qgbm90IHN0YXJ0IG9yIGVuZCB3aXRoIGEgc2xhc2hgKTtcbiAgICAgIH1cbiAgICB9KTtcbiAgfVxuXG4gIC8qKlxuICAgKiBAcGFyYW0ga2V5XG4gICAqIEBwYXJhbSBjaGFpblxuICAgKiBAcGFyYW0gaW5kZXhcbiAgICogQHJldHVybiBmdWxsIGRlcml2YXRpb24gcGF0aCBmb3Iga2V5LCBpbmNsdWRpbmcga2V5LXNwZWNpZmljIHByZWZpeFxuICAgKi9cbiAgZ2V0RGVyaXZhdGlvblBhdGgoa2V5OiBiaXAzMi5CSVAzMkludGVyZmFjZSwgY2hhaW46IG51bWJlciwgaW5kZXg6IG51bWJlcik6IHN0cmluZyB7XG4gICAgaWYgKCF0aGlzLmRlcml2YXRpb25QcmVmaXhlcykge1xuICAgICAgdGhyb3cgbmV3IEVycm9yKGBubyBkZXJpdmF0aW9uIHByZWZpeGVzYCk7XG4gICAgfVxuICAgIGNvbnN0IHByZWZpeCA9IHRoaXMuZGVyaXZhdGlvblByZWZpeGVzLmZpbmQoKHByZWZpeCwgaSkgPT4gZXFQdWJsaWNLZXkoa2V5LCB0aGlzLnRyaXBsZVtpXSkpO1xuICAgIGlmIChwcmVmaXggPT09IHVuZGVmaW5lZCkge1xuICAgICAgdGhyb3cgbmV3IEVycm9yKGBrZXkgbm90IGluIHdhbGxldEtleXNgKTtcbiAgICB9XG4gICAgcmV0dXJuIGAke3ByZWZpeH0vJHtjaGFpbn0vJHtpbmRleH1gO1xuICB9XG5cbiAgLyoqXG4gICAqIEBwYXJhbSBjaGFpblxuICAgKiBAcGFyYW0gaW5kZXhcbiAgICogQHJldHVybiB3YWxsZXRLZXlzIGZvciBhIHBhcnRpY3VsYXIgYWRkcmVzcyBpZGVudGlmaWVkIGJ5IChjaGFpbiwgaW5kZXgpXG4gICAqL1xuICBkZXJpdmVGb3JDaGFpbkFuZEluZGV4KGNoYWluOiBudW1iZXIsIGluZGV4OiBudW1iZXIpOiBEZXJpdmVkV2FsbGV0S2V5cyB7XG4gICAgcmV0dXJuIG5ldyBEZXJpdmVkV2FsbGV0S2V5cyhcbiAgICAgIHRoaXMsXG4gICAgICB0aGlzLnRyaXBsZS5tYXAoKGspID0+IHRoaXMuZ2V0RGVyaXZhdGlvblBhdGgoaywgY2hhaW4sIGluZGV4KSkgYXMgVHJpcGxlPHN0cmluZz5cbiAgICApO1xuICB9XG59XG4iXX0=