"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.UtxoTransaction = exports.varSliceSize = void 0;
const bitcoinjs = require("bitcoinjs-lib");
const varuint = require("varuint-bitcoin");
const networks_1 = require("../networks");
function varSliceSize(slice) {
    const length = slice.length;
    return varuint.encodingLength(length) + length;
}
exports.varSliceSize = varSliceSize;
class UtxoTransaction extends bitcoinjs.Transaction {
    constructor(network, transaction = new bitcoinjs.Transaction()) {
        super();
        this.network = network;
        this.version = transaction.version;
        this.locktime = transaction.locktime;
        this.ins = transaction.ins.map((v) => ({ ...v }));
        this.outs = transaction.outs.map((v) => ({ ...v }));
    }
    static fromBuffer(buf, noStrict, network, prevOutput) {
        if (!network) {
            throw new Error(`must provide network`);
        }
        return new UtxoTransaction(network, bitcoinjs.Transaction.fromBuffer(buf, noStrict));
    }
    addForkId(hashType) {
        if (hashType & UtxoTransaction.SIGHASH_FORKID) {
            const forkId = networks_1.isBitcoinGold(this.network) ? 79 : 0;
            return (hashType | (forkId << 8)) >>> 0;
        }
        return hashType;
    }
    hashForWitnessV0(inIndex, prevOutScript, value, hashType) {
        return super.hashForWitnessV0(inIndex, prevOutScript, value, this.addForkId(hashType));
    }
    /**
     * Calculate the hash to verify the signature against
     */
    hashForSignatureByNetwork(inIndex, prevoutScript, value, hashType) {
        switch (networks_1.getMainnet(this.network)) {
            case networks_1.networks.zcash:
                throw new Error(`illegal state`);
            case networks_1.networks.bitcoincash:
            case networks_1.networks.bitcoinsv:
            case networks_1.networks.bitcoingold:
                /*
                  Bitcoin Cash supports a FORKID flag. When set, we hash using hashing algorithm
                   that is used for segregated witness transactions (defined in BIP143).
        
                  The flag is also used by BitcoinSV and BitcoinGold
        
                  https://github.com/bitcoincashorg/bitcoincash.org/blob/master/spec/replay-protected-sighash.md
                 */
                const addForkId = (hashType & UtxoTransaction.SIGHASH_FORKID) > 0;
                if (addForkId) {
                    /*
                      ``The sighash type is altered to include a 24-bit fork id in its most significant bits.''
                      We also use unsigned right shift operator `>>>` to cast to UInt32
                      https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Operators/Unsigned_right_shift
                     */
                    if (value === undefined) {
                        throw new Error(`must provide value`);
                    }
                    return super.hashForWitnessV0(inIndex, prevoutScript, value, this.addForkId(hashType));
                }
        }
        return super.hashForSignature(inIndex, prevoutScript, hashType);
    }
    hashForSignature(inIndex, prevOutScript, hashType) {
        return this.hashForSignatureByNetwork(inIndex, prevOutScript, this.ins[inIndex].value, hashType);
    }
    clone() {
        return new UtxoTransaction(this.network, super.clone());
    }
}
exports.UtxoTransaction = UtxoTransaction;
UtxoTransaction.SIGHASH_FORKID = 0x40;
/** @deprecated use SIGHASH_FORKID */
UtxoTransaction.SIGHASH_BITCOINCASHBIP143 = UtxoTransaction.SIGHASH_FORKID;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiVXR4b1RyYW5zYWN0aW9uLmpzIiwic291cmNlUm9vdCI6IiIsInNvdXJjZXMiOlsiLi4vLi4vLi4vc3JjL2JpdGdvL1V0eG9UcmFuc2FjdGlvbi50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOzs7QUFBQSwyQ0FBMkM7QUFDM0MsMkNBQTJDO0FBRTNDLDBDQUEyRTtBQUUzRSxTQUFnQixZQUFZLENBQUMsS0FBYTtJQUN4QyxNQUFNLE1BQU0sR0FBRyxLQUFLLENBQUMsTUFBTSxDQUFDO0lBQzVCLE9BQU8sT0FBTyxDQUFDLGNBQWMsQ0FBQyxNQUFNLENBQUMsR0FBRyxNQUFNLENBQUM7QUFDakQsQ0FBQztBQUhELG9DQUdDO0FBRUQsTUFBYSxlQUFnQixTQUFRLFNBQVMsQ0FBQyxXQUFXO0lBS3hELFlBQW1CLE9BQWdCLEVBQUUsY0FBcUMsSUFBSSxTQUFTLENBQUMsV0FBVyxFQUFFO1FBQ25HLEtBQUssRUFBRSxDQUFDO1FBRFMsWUFBTyxHQUFQLE9BQU8sQ0FBUztRQUVqQyxJQUFJLENBQUMsT0FBTyxHQUFHLFdBQVcsQ0FBQyxPQUFPLENBQUM7UUFDbkMsSUFBSSxDQUFDLFFBQVEsR0FBRyxXQUFXLENBQUMsUUFBUSxDQUFDO1FBQ3JDLElBQUksQ0FBQyxHQUFHLEdBQUcsV0FBVyxDQUFDLEdBQUcsQ0FBQyxHQUFHLENBQUMsQ0FBQyxDQUFDLEVBQUUsRUFBRSxDQUFDLENBQUMsRUFBRSxHQUFHLENBQUMsRUFBRSxDQUFDLENBQUMsQ0FBQztRQUNsRCxJQUFJLENBQUMsSUFBSSxHQUFHLFdBQVcsQ0FBQyxJQUFJLENBQUMsR0FBRyxDQUFDLENBQUMsQ0FBQyxFQUFFLEVBQUUsQ0FBQyxDQUFDLEVBQUUsR0FBRyxDQUFDLEVBQUUsQ0FBQyxDQUFDLENBQUM7SUFDdEQsQ0FBQztJQUVELE1BQU0sQ0FBQyxVQUFVLENBQ2YsR0FBVyxFQUNYLFFBQWlCLEVBQ2pCLE9BQWlCLEVBQ2pCLFVBQWlDO1FBRWpDLElBQUksQ0FBQyxPQUFPLEVBQUU7WUFDWixNQUFNLElBQUksS0FBSyxDQUFDLHNCQUFzQixDQUFDLENBQUM7U0FDekM7UUFDRCxPQUFPLElBQUksZUFBZSxDQUFDLE9BQU8sRUFBRSxTQUFTLENBQUMsV0FBVyxDQUFDLFVBQVUsQ0FBQyxHQUFHLEVBQUUsUUFBUSxDQUFDLENBQUMsQ0FBQztJQUN2RixDQUFDO0lBRUQsU0FBUyxDQUFDLFFBQWdCO1FBQ3hCLElBQUksUUFBUSxHQUFHLGVBQWUsQ0FBQyxjQUFjLEVBQUU7WUFDN0MsTUFBTSxNQUFNLEdBQUcsd0JBQWEsQ0FBQyxJQUFJLENBQUMsT0FBTyxDQUFDLENBQUMsQ0FBQyxDQUFDLEVBQUUsQ0FBQyxDQUFDLENBQUMsQ0FBQyxDQUFDO1lBQ3BELE9BQU8sQ0FBQyxRQUFRLEdBQUcsQ0FBQyxNQUFNLElBQUksQ0FBQyxDQUFDLENBQUMsS0FBSyxDQUFDLENBQUM7U0FDekM7UUFFRCxPQUFPLFFBQVEsQ0FBQztJQUNsQixDQUFDO0lBRUQsZ0JBQWdCLENBQUMsT0FBZSxFQUFFLGFBQXFCLEVBQUUsS0FBYSxFQUFFLFFBQWdCO1FBQ3RGLE9BQU8sS0FBSyxDQUFDLGdCQUFnQixDQUFDLE9BQU8sRUFBRSxhQUFhLEVBQUUsS0FBSyxFQUFFLElBQUksQ0FBQyxTQUFTLENBQUMsUUFBUSxDQUFDLENBQUMsQ0FBQztJQUN6RixDQUFDO0lBRUQ7O09BRUc7SUFDSCx5QkFBeUIsQ0FDdkIsT0FBZSxFQUNmLGFBQXFCLEVBQ3JCLEtBQXlCLEVBQ3pCLFFBQWdCO1FBRWhCLFFBQVEscUJBQVUsQ0FBQyxJQUFJLENBQUMsT0FBTyxDQUFDLEVBQUU7WUFDaEMsS0FBSyxtQkFBUSxDQUFDLEtBQUs7Z0JBQ2pCLE1BQU0sSUFBSSxLQUFLLENBQUMsZUFBZSxDQUFDLENBQUM7WUFDbkMsS0FBSyxtQkFBUSxDQUFDLFdBQVcsQ0FBQztZQUMxQixLQUFLLG1CQUFRLENBQUMsU0FBUyxDQUFDO1lBQ3hCLEtBQUssbUJBQVEsQ0FBQyxXQUFXO2dCQUN2Qjs7Ozs7OzttQkFPRztnQkFDSCxNQUFNLFNBQVMsR0FBRyxDQUFDLFFBQVEsR0FBRyxlQUFlLENBQUMsY0FBYyxDQUFDLEdBQUcsQ0FBQyxDQUFDO2dCQUVsRSxJQUFJLFNBQVMsRUFBRTtvQkFDYjs7Ozt1QkFJRztvQkFDSCxJQUFJLEtBQUssS0FBSyxTQUFTLEVBQUU7d0JBQ3ZCLE1BQU0sSUFBSSxLQUFLLENBQUMsb0JBQW9CLENBQUMsQ0FBQztxQkFDdkM7b0JBQ0QsT0FBTyxLQUFLLENBQUMsZ0JBQWdCLENBQUMsT0FBTyxFQUFFLGFBQWEsRUFBRSxLQUFLLEVBQUUsSUFBSSxDQUFDLFNBQVMsQ0FBQyxRQUFRLENBQUMsQ0FBQyxDQUFDO2lCQUN4RjtTQUNKO1FBRUQsT0FBTyxLQUFLLENBQUMsZ0JBQWdCLENBQUMsT0FBTyxFQUFFLGFBQWEsRUFBRSxRQUFRLENBQUMsQ0FBQztJQUNsRSxDQUFDO0lBRUQsZ0JBQWdCLENBQUMsT0FBZSxFQUFFLGFBQXFCLEVBQUUsUUFBZ0I7UUFDdkUsT0FBTyxJQUFJLENBQUMseUJBQXlCLENBQUMsT0FBTyxFQUFFLGFBQWEsRUFBRyxJQUFJLENBQUMsR0FBRyxDQUFDLE9BQU8sQ0FBUyxDQUFDLEtBQUssRUFBRSxRQUFRLENBQUMsQ0FBQztJQUM1RyxDQUFDO0lBRUQsS0FBSztRQUNILE9BQU8sSUFBSSxlQUFlLENBQUMsSUFBSSxDQUFDLE9BQU8sRUFBRSxLQUFLLENBQUMsS0FBSyxFQUFFLENBQUMsQ0FBQztJQUMxRCxDQUFDOztBQXJGSCwwQ0FzRkM7QUFyRlEsOEJBQWMsR0FBRyxJQUFJLENBQUM7QUFDN0IscUNBQXFDO0FBQzlCLHlDQUF5QixHQUFHLGVBQWUsQ0FBQyxjQUFjLENBQUMiLCJzb3VyY2VzQ29udGVudCI6WyJpbXBvcnQgKiBhcyBiaXRjb2luanMgZnJvbSAnYml0Y29pbmpzLWxpYic7XG5pbXBvcnQgKiBhcyB2YXJ1aW50IGZyb20gJ3ZhcnVpbnQtYml0Y29pbic7XG5cbmltcG9ydCB7IG5ldHdvcmtzLCBOZXR3b3JrLCBnZXRNYWlubmV0LCBpc0JpdGNvaW5Hb2xkIH0gZnJvbSAnLi4vbmV0d29ya3MnO1xuXG5leHBvcnQgZnVuY3Rpb24gdmFyU2xpY2VTaXplKHNsaWNlOiBCdWZmZXIpOiBudW1iZXIge1xuICBjb25zdCBsZW5ndGggPSBzbGljZS5sZW5ndGg7XG4gIHJldHVybiB2YXJ1aW50LmVuY29kaW5nTGVuZ3RoKGxlbmd0aCkgKyBsZW5ndGg7XG59XG5cbmV4cG9ydCBjbGFzcyBVdHhvVHJhbnNhY3Rpb24gZXh0ZW5kcyBiaXRjb2luanMuVHJhbnNhY3Rpb24ge1xuICBzdGF0aWMgU0lHSEFTSF9GT1JLSUQgPSAweDQwO1xuICAvKiogQGRlcHJlY2F0ZWQgdXNlIFNJR0hBU0hfRk9SS0lEICovXG4gIHN0YXRpYyBTSUdIQVNIX0JJVENPSU5DQVNIQklQMTQzID0gVXR4b1RyYW5zYWN0aW9uLlNJR0hBU0hfRk9SS0lEO1xuXG4gIGNvbnN0cnVjdG9yKHB1YmxpYyBuZXR3b3JrOiBOZXR3b3JrLCB0cmFuc2FjdGlvbjogYml0Y29pbmpzLlRyYW5zYWN0aW9uID0gbmV3IGJpdGNvaW5qcy5UcmFuc2FjdGlvbigpKSB7XG4gICAgc3VwZXIoKTtcbiAgICB0aGlzLnZlcnNpb24gPSB0cmFuc2FjdGlvbi52ZXJzaW9uO1xuICAgIHRoaXMubG9ja3RpbWUgPSB0cmFuc2FjdGlvbi5sb2NrdGltZTtcbiAgICB0aGlzLmlucyA9IHRyYW5zYWN0aW9uLmlucy5tYXAoKHYpID0+ICh7IC4uLnYgfSkpO1xuICAgIHRoaXMub3V0cyA9IHRyYW5zYWN0aW9uLm91dHMubWFwKCh2KSA9PiAoeyAuLi52IH0pKTtcbiAgfVxuXG4gIHN0YXRpYyBmcm9tQnVmZmVyKFxuICAgIGJ1ZjogQnVmZmVyLFxuICAgIG5vU3RyaWN0OiBib29sZWFuLFxuICAgIG5ldHdvcms/OiBOZXR3b3JrLFxuICAgIHByZXZPdXRwdXQ/OiBiaXRjb2luanMuVHhPdXRwdXRbXVxuICApOiBVdHhvVHJhbnNhY3Rpb24ge1xuICAgIGlmICghbmV0d29yaykge1xuICAgICAgdGhyb3cgbmV3IEVycm9yKGBtdXN0IHByb3ZpZGUgbmV0d29ya2ApO1xuICAgIH1cbiAgICByZXR1cm4gbmV3IFV0eG9UcmFuc2FjdGlvbihuZXR3b3JrLCBiaXRjb2luanMuVHJhbnNhY3Rpb24uZnJvbUJ1ZmZlcihidWYsIG5vU3RyaWN0KSk7XG4gIH1cblxuICBhZGRGb3JrSWQoaGFzaFR5cGU6IG51bWJlcik6IG51bWJlciB7XG4gICAgaWYgKGhhc2hUeXBlICYgVXR4b1RyYW5zYWN0aW9uLlNJR0hBU0hfRk9SS0lEKSB7XG4gICAgICBjb25zdCBmb3JrSWQgPSBpc0JpdGNvaW5Hb2xkKHRoaXMubmV0d29yaykgPyA3OSA6IDA7XG4gICAgICByZXR1cm4gKGhhc2hUeXBlIHwgKGZvcmtJZCA8PCA4KSkgPj4+IDA7XG4gICAgfVxuXG4gICAgcmV0dXJuIGhhc2hUeXBlO1xuICB9XG5cbiAgaGFzaEZvcldpdG5lc3NWMChpbkluZGV4OiBudW1iZXIsIHByZXZPdXRTY3JpcHQ6IEJ1ZmZlciwgdmFsdWU6IG51bWJlciwgaGFzaFR5cGU6IG51bWJlcik6IEJ1ZmZlciB7XG4gICAgcmV0dXJuIHN1cGVyLmhhc2hGb3JXaXRuZXNzVjAoaW5JbmRleCwgcHJldk91dFNjcmlwdCwgdmFsdWUsIHRoaXMuYWRkRm9ya0lkKGhhc2hUeXBlKSk7XG4gIH1cblxuICAvKipcbiAgICogQ2FsY3VsYXRlIHRoZSBoYXNoIHRvIHZlcmlmeSB0aGUgc2lnbmF0dXJlIGFnYWluc3RcbiAgICovXG4gIGhhc2hGb3JTaWduYXR1cmVCeU5ldHdvcmsoXG4gICAgaW5JbmRleDogbnVtYmVyLFxuICAgIHByZXZvdXRTY3JpcHQ6IEJ1ZmZlcixcbiAgICB2YWx1ZTogbnVtYmVyIHwgdW5kZWZpbmVkLFxuICAgIGhhc2hUeXBlOiBudW1iZXJcbiAgKTogQnVmZmVyIHtcbiAgICBzd2l0Y2ggKGdldE1haW5uZXQodGhpcy5uZXR3b3JrKSkge1xuICAgICAgY2FzZSBuZXR3b3Jrcy56Y2FzaDpcbiAgICAgICAgdGhyb3cgbmV3IEVycm9yKGBpbGxlZ2FsIHN0YXRlYCk7XG4gICAgICBjYXNlIG5ldHdvcmtzLmJpdGNvaW5jYXNoOlxuICAgICAgY2FzZSBuZXR3b3Jrcy5iaXRjb2luc3Y6XG4gICAgICBjYXNlIG5ldHdvcmtzLmJpdGNvaW5nb2xkOlxuICAgICAgICAvKlxuICAgICAgICAgIEJpdGNvaW4gQ2FzaCBzdXBwb3J0cyBhIEZPUktJRCBmbGFnLiBXaGVuIHNldCwgd2UgaGFzaCB1c2luZyBoYXNoaW5nIGFsZ29yaXRobVxuICAgICAgICAgICB0aGF0IGlzIHVzZWQgZm9yIHNlZ3JlZ2F0ZWQgd2l0bmVzcyB0cmFuc2FjdGlvbnMgKGRlZmluZWQgaW4gQklQMTQzKS5cblxuICAgICAgICAgIFRoZSBmbGFnIGlzIGFsc28gdXNlZCBieSBCaXRjb2luU1YgYW5kIEJpdGNvaW5Hb2xkXG5cbiAgICAgICAgICBodHRwczovL2dpdGh1Yi5jb20vYml0Y29pbmNhc2hvcmcvYml0Y29pbmNhc2gub3JnL2Jsb2IvbWFzdGVyL3NwZWMvcmVwbGF5LXByb3RlY3RlZC1zaWdoYXNoLm1kXG4gICAgICAgICAqL1xuICAgICAgICBjb25zdCBhZGRGb3JrSWQgPSAoaGFzaFR5cGUgJiBVdHhvVHJhbnNhY3Rpb24uU0lHSEFTSF9GT1JLSUQpID4gMDtcblxuICAgICAgICBpZiAoYWRkRm9ya0lkKSB7XG4gICAgICAgICAgLypcbiAgICAgICAgICAgIGBgVGhlIHNpZ2hhc2ggdHlwZSBpcyBhbHRlcmVkIHRvIGluY2x1ZGUgYSAyNC1iaXQgZm9yayBpZCBpbiBpdHMgbW9zdCBzaWduaWZpY2FudCBiaXRzLicnXG4gICAgICAgICAgICBXZSBhbHNvIHVzZSB1bnNpZ25lZCByaWdodCBzaGlmdCBvcGVyYXRvciBgPj4+YCB0byBjYXN0IHRvIFVJbnQzMlxuICAgICAgICAgICAgaHR0cHM6Ly9kZXZlbG9wZXIubW96aWxsYS5vcmcvZW4tVVMvZG9jcy9XZWIvSmF2YVNjcmlwdC9SZWZlcmVuY2UvT3BlcmF0b3JzL1Vuc2lnbmVkX3JpZ2h0X3NoaWZ0XG4gICAgICAgICAgICovXG4gICAgICAgICAgaWYgKHZhbHVlID09PSB1bmRlZmluZWQpIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBFcnJvcihgbXVzdCBwcm92aWRlIHZhbHVlYCk7XG4gICAgICAgICAgfVxuICAgICAgICAgIHJldHVybiBzdXBlci5oYXNoRm9yV2l0bmVzc1YwKGluSW5kZXgsIHByZXZvdXRTY3JpcHQsIHZhbHVlLCB0aGlzLmFkZEZvcmtJZChoYXNoVHlwZSkpO1xuICAgICAgICB9XG4gICAgfVxuXG4gICAgcmV0dXJuIHN1cGVyLmhhc2hGb3JTaWduYXR1cmUoaW5JbmRleCwgcHJldm91dFNjcmlwdCwgaGFzaFR5cGUpO1xuICB9XG5cbiAgaGFzaEZvclNpZ25hdHVyZShpbkluZGV4OiBudW1iZXIsIHByZXZPdXRTY3JpcHQ6IEJ1ZmZlciwgaGFzaFR5cGU6IG51bWJlcik6IEJ1ZmZlciB7XG4gICAgcmV0dXJuIHRoaXMuaGFzaEZvclNpZ25hdHVyZUJ5TmV0d29yayhpbkluZGV4LCBwcmV2T3V0U2NyaXB0LCAodGhpcy5pbnNbaW5JbmRleF0gYXMgYW55KS52YWx1ZSwgaGFzaFR5cGUpO1xuICB9XG5cbiAgY2xvbmUoKTogVXR4b1RyYW5zYWN0aW9uIHtcbiAgICByZXR1cm4gbmV3IFV0eG9UcmFuc2FjdGlvbih0aGlzLm5ldHdvcmssIHN1cGVyLmNsb25lKCkpO1xuICB9XG59XG4iXX0=