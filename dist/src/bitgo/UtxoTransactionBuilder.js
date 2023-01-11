"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.UtxoTransactionBuilder = void 0;
const bitcoinjs_lib_1 = require("bitcoinjs-lib");
const UtxoTransaction_1 = require("./UtxoTransaction");
class UtxoTransactionBuilder extends bitcoinjs_lib_1.TransactionBuilder {
    constructor(network, txb, prevOutputs) {
        var _a;
        super();
        this.network = network;
        this.__TX = this.createInitialTransaction(network, (_a = txb) === null || _a === void 0 ? void 0 : _a.__TX);
        if (txb) {
            this.__INPUTS = txb.__INPUTS;
        }
        if (prevOutputs) {
            const txbInputs = this.__INPUTS;
            if (prevOutputs.length !== txbInputs.length) {
                throw new Error(`prevOuts must match txbInput length`);
            }
            prevOutputs.forEach((o, i) => {
                txbInputs[i].value = o.value;
                txbInputs[i].prevOutScript = o.script;
            });
        }
    }
    createInitialTransaction(network, tx) {
        return new UtxoTransaction_1.UtxoTransaction(network, tx);
    }
    static fromTransaction(tx, network, prevOutputs) {
        return new UtxoTransactionBuilder(tx.network, bitcoinjs_lib_1.TransactionBuilder.fromTransaction(tx), prevOutputs);
    }
    get tx() {
        return this.__TX;
    }
    build() {
        return super.build();
    }
    buildIncomplete() {
        return super.buildIncomplete();
    }
    sign(signParams, keyPair, redeemScript, hashType, witnessValue, witnessScript) {
        // Regular bitcoin p2sh-p2ms inputs do not include the input amount (value) in the signature and
        // thus do not require the parameter `value` to be set.
        // For bitcoincash and bitcoinsv p2sh-p2ms inputs, the value parameter *is* required however.
        // Since the `value` parameter is not passed to the legacy hashing method, we must store it
        // on the transaction input object.
        if (typeof signParams === 'number') {
            if (typeof witnessValue === 'number') {
                this.tx.ins[signParams].value = witnessValue;
            }
            return super.sign(signParams, keyPair, redeemScript, hashType, witnessValue, witnessScript);
        }
        if (signParams.witnessValue !== undefined) {
            this.tx.ins[signParams.vin].value = signParams.witnessValue;
        }
        // When calling the sign method via TxbSignArg, the `value` parameter is actually not permitted
        // to be set for p2sh-p2ms transactions.
        if (signParams.prevOutScriptType === 'p2sh-p2ms') {
            delete signParams.witnessValue;
        }
        return super.sign(signParams);
    }
}
exports.UtxoTransactionBuilder = UtxoTransactionBuilder;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiVXR4b1RyYW5zYWN0aW9uQnVpbGRlci5qcyIsInNvdXJjZVJvb3QiOiIiLCJzb3VyY2VzIjpbIi4uLy4uLy4uL3NyYy9iaXRnby9VdHhvVHJhbnNhY3Rpb25CdWlsZGVyLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7OztBQUFBLGlEQUEwRTtBQUkxRSx1REFBb0Q7QUFhcEQsTUFBYSxzQkFBb0UsU0FBUSxrQ0FBa0I7SUFDekcsWUFBWSxPQUFnQixFQUFFLEdBQXdCLEVBQUUsV0FBd0I7O1FBQzlFLEtBQUssRUFBRSxDQUFDO1FBQ1IsSUFBSSxDQUFDLE9BQU8sR0FBRyxPQUE0QixDQUFDO1FBRTNDLElBQVksQ0FBQyxJQUFJLEdBQUcsSUFBSSxDQUFDLHdCQUF3QixDQUFDLE9BQU8sRUFBRSxNQUFDLEdBQVcsMENBQUUsSUFBSSxDQUFDLENBQUM7UUFFaEYsSUFBSSxHQUFHLEVBQUU7WUFDTixJQUFZLENBQUMsUUFBUSxHQUFJLEdBQVcsQ0FBQyxRQUFRLENBQUM7U0FDaEQ7UUFFRCxJQUFJLFdBQVcsRUFBRTtZQUNmLE1BQU0sU0FBUyxHQUFJLElBQVksQ0FBQyxRQUFRLENBQUM7WUFDekMsSUFBSSxXQUFXLENBQUMsTUFBTSxLQUFLLFNBQVMsQ0FBQyxNQUFNLEVBQUU7Z0JBQzNDLE1BQU0sSUFBSSxLQUFLLENBQUMscUNBQXFDLENBQUMsQ0FBQzthQUN4RDtZQUNELFdBQVcsQ0FBQyxPQUFPLENBQUMsQ0FBQyxDQUFDLEVBQUUsQ0FBQyxFQUFFLEVBQUU7Z0JBQzNCLFNBQVMsQ0FBQyxDQUFDLENBQUMsQ0FBQyxLQUFLLEdBQUcsQ0FBQyxDQUFDLEtBQUssQ0FBQztnQkFDN0IsU0FBUyxDQUFDLENBQUMsQ0FBQyxDQUFDLGFBQWEsR0FBRyxDQUFDLENBQUMsTUFBTSxDQUFDO1lBQ3hDLENBQUMsQ0FBQyxDQUFDO1NBQ0o7SUFDSCxDQUFDO0lBRUQsd0JBQXdCLENBQUMsT0FBZ0IsRUFBRSxFQUFnQjtRQUN6RCxPQUFPLElBQUksaUNBQWUsQ0FBQyxPQUFPLEVBQUUsRUFBRSxDQUFDLENBQUM7SUFDMUMsQ0FBQztJQUVELE1BQU0sQ0FBQyxlQUFlLENBQ3BCLEVBQW1CLEVBQ25CLE9BQTJCLEVBQzNCLFdBQXdCO1FBRXhCLE9BQU8sSUFBSSxzQkFBc0IsQ0FBQyxFQUFFLENBQUMsT0FBTyxFQUFFLGtDQUFrQixDQUFDLGVBQWUsQ0FBQyxFQUFFLENBQUMsRUFBRSxXQUFXLENBQUMsQ0FBQztJQUNyRyxDQUFDO0lBRUQsSUFBSSxFQUFFO1FBQ0osT0FBUSxJQUFZLENBQUMsSUFBSSxDQUFDO0lBQzVCLENBQUM7SUFFRCxLQUFLO1FBQ0gsT0FBTyxLQUFLLENBQUMsS0FBSyxFQUFPLENBQUM7SUFDNUIsQ0FBQztJQUVELGVBQWU7UUFDYixPQUFPLEtBQUssQ0FBQyxlQUFlLEVBQU8sQ0FBQztJQUN0QyxDQUFDO0lBRUQsSUFBSSxDQUNGLFVBQStCLEVBQy9CLE9BQWlDLEVBQ2pDLFlBQXFCLEVBQ3JCLFFBQWlCLEVBQ2pCLFlBQXFCLEVBQ3JCLGFBQXNCO1FBRXRCLGdHQUFnRztRQUNoRyx1REFBdUQ7UUFDdkQsNkZBQTZGO1FBQzdGLDJGQUEyRjtRQUMzRixtQ0FBbUM7UUFFbkMsSUFBSSxPQUFPLFVBQVUsS0FBSyxRQUFRLEVBQUU7WUFDbEMsSUFBSSxPQUFPLFlBQVksS0FBSyxRQUFRLEVBQUU7Z0JBQ25DLElBQUksQ0FBQyxFQUFFLENBQUMsR0FBRyxDQUFDLFVBQVUsQ0FBUyxDQUFDLEtBQUssR0FBRyxZQUFZLENBQUM7YUFDdkQ7WUFFRCxPQUFPLEtBQUssQ0FBQyxJQUFJLENBQUMsVUFBVSxFQUFFLE9BQU8sRUFBRSxZQUFZLEVBQUUsUUFBUSxFQUFFLFlBQVksRUFBRSxhQUFhLENBQUMsQ0FBQztTQUM3RjtRQUVELElBQUksVUFBVSxDQUFDLFlBQVksS0FBSyxTQUFTLEVBQUU7WUFDeEMsSUFBSSxDQUFDLEVBQUUsQ0FBQyxHQUFHLENBQUMsVUFBVSxDQUFDLEdBQUcsQ0FBUyxDQUFDLEtBQUssR0FBRyxVQUFVLENBQUMsWUFBWSxDQUFDO1NBQ3RFO1FBQ0QsK0ZBQStGO1FBQy9GLHdDQUF3QztRQUN4QyxJQUFJLFVBQVUsQ0FBQyxpQkFBaUIsS0FBSyxXQUFXLEVBQUU7WUFDaEQsT0FBTyxVQUFVLENBQUMsWUFBWSxDQUFDO1NBQ2hDO1FBQ0QsT0FBTyxLQUFLLENBQUMsSUFBSSxDQUFDLFVBQVUsQ0FBQyxDQUFDO0lBQ2hDLENBQUM7Q0FDRjtBQS9FRCx3REErRUMiLCJzb3VyY2VzQ29udGVudCI6WyJpbXBvcnQgeyBUeE91dHB1dCwgVHJhbnNhY3Rpb24sIFRyYW5zYWN0aW9uQnVpbGRlciB9IGZyb20gJ2JpdGNvaW5qcy1saWInO1xuLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lXG5pbXBvcnQgKiBhcyBiaXRjb2luanMgZnJvbSAnYml0Y29pbmpzLWxpYic7XG5pbXBvcnQgeyBOZXR3b3JrIH0gZnJvbSAnLi4nO1xuaW1wb3J0IHsgVXR4b1RyYW5zYWN0aW9uIH0gZnJvbSAnLi9VdHhvVHJhbnNhY3Rpb24nO1xuXG5leHBvcnQgaW50ZXJmYWNlIFR4YlNpZ25Bcmcge1xuICBwcmV2T3V0U2NyaXB0VHlwZTogc3RyaW5nO1xuICB2aW46IG51bWJlcjtcbiAga2V5UGFpcjogYml0Y29pbmpzLkVDUGFpci5TaWduZXI7XG4gIHJlZGVlbVNjcmlwdD86IEJ1ZmZlcjtcbiAgaGFzaFR5cGU/OiBudW1iZXI7XG4gIHdpdG5lc3NWYWx1ZT86IG51bWJlcjtcbiAgd2l0bmVzc1NjcmlwdD86IEJ1ZmZlcjtcbiAgY29udHJvbEJsb2NrPzogQnVmZmVyO1xufVxuXG5leHBvcnQgY2xhc3MgVXR4b1RyYW5zYWN0aW9uQnVpbGRlcjxUIGV4dGVuZHMgVXR4b1RyYW5zYWN0aW9uID0gVXR4b1RyYW5zYWN0aW9uPiBleHRlbmRzIFRyYW5zYWN0aW9uQnVpbGRlciB7XG4gIGNvbnN0cnVjdG9yKG5ldHdvcms6IE5ldHdvcmssIHR4Yj86IFRyYW5zYWN0aW9uQnVpbGRlciwgcHJldk91dHB1dHM/OiBUeE91dHB1dFtdKSB7XG4gICAgc3VwZXIoKTtcbiAgICB0aGlzLm5ldHdvcmsgPSBuZXR3b3JrIGFzIGJpdGNvaW5qcy5OZXR3b3JrO1xuXG4gICAgKHRoaXMgYXMgYW55KS5fX1RYID0gdGhpcy5jcmVhdGVJbml0aWFsVHJhbnNhY3Rpb24obmV0d29yaywgKHR4YiBhcyBhbnkpPy5fX1RYKTtcblxuICAgIGlmICh0eGIpIHtcbiAgICAgICh0aGlzIGFzIGFueSkuX19JTlBVVFMgPSAodHhiIGFzIGFueSkuX19JTlBVVFM7XG4gICAgfVxuXG4gICAgaWYgKHByZXZPdXRwdXRzKSB7XG4gICAgICBjb25zdCB0eGJJbnB1dHMgPSAodGhpcyBhcyBhbnkpLl9fSU5QVVRTO1xuICAgICAgaWYgKHByZXZPdXRwdXRzLmxlbmd0aCAhPT0gdHhiSW5wdXRzLmxlbmd0aCkge1xuICAgICAgICB0aHJvdyBuZXcgRXJyb3IoYHByZXZPdXRzIG11c3QgbWF0Y2ggdHhiSW5wdXQgbGVuZ3RoYCk7XG4gICAgICB9XG4gICAgICBwcmV2T3V0cHV0cy5mb3JFYWNoKChvLCBpKSA9PiB7XG4gICAgICAgIHR4YklucHV0c1tpXS52YWx1ZSA9IG8udmFsdWU7XG4gICAgICAgIHR4YklucHV0c1tpXS5wcmV2T3V0U2NyaXB0ID0gby5zY3JpcHQ7XG4gICAgICB9KTtcbiAgICB9XG4gIH1cblxuICBjcmVhdGVJbml0aWFsVHJhbnNhY3Rpb24obmV0d29yazogTmV0d29yaywgdHg/OiBUcmFuc2FjdGlvbik6IFV0eG9UcmFuc2FjdGlvbiB7XG4gICAgcmV0dXJuIG5ldyBVdHhvVHJhbnNhY3Rpb24obmV0d29yaywgdHgpO1xuICB9XG5cbiAgc3RhdGljIGZyb21UcmFuc2FjdGlvbihcbiAgICB0eDogVXR4b1RyYW5zYWN0aW9uLFxuICAgIG5ldHdvcms/OiBiaXRjb2luanMuTmV0d29yayxcbiAgICBwcmV2T3V0cHV0cz86IFR4T3V0cHV0W11cbiAgKTogVXR4b1RyYW5zYWN0aW9uQnVpbGRlciB7XG4gICAgcmV0dXJuIG5ldyBVdHhvVHJhbnNhY3Rpb25CdWlsZGVyKHR4Lm5ldHdvcmssIFRyYW5zYWN0aW9uQnVpbGRlci5mcm9tVHJhbnNhY3Rpb24odHgpLCBwcmV2T3V0cHV0cyk7XG4gIH1cblxuICBnZXQgdHgoKTogVCB7XG4gICAgcmV0dXJuICh0aGlzIGFzIGFueSkuX19UWDtcbiAgfVxuXG4gIGJ1aWxkKCk6IFQge1xuICAgIHJldHVybiBzdXBlci5idWlsZCgpIGFzIFQ7XG4gIH1cblxuICBidWlsZEluY29tcGxldGUoKTogVCB7XG4gICAgcmV0dXJuIHN1cGVyLmJ1aWxkSW5jb21wbGV0ZSgpIGFzIFQ7XG4gIH1cblxuICBzaWduKFxuICAgIHNpZ25QYXJhbXM6IG51bWJlciB8IFR4YlNpZ25BcmcsXG4gICAga2V5UGFpcj86IGJpdGNvaW5qcy5FQ1BhaXIuU2lnbmVyLFxuICAgIHJlZGVlbVNjcmlwdD86IEJ1ZmZlcixcbiAgICBoYXNoVHlwZT86IG51bWJlcixcbiAgICB3aXRuZXNzVmFsdWU/OiBudW1iZXIsXG4gICAgd2l0bmVzc1NjcmlwdD86IEJ1ZmZlclxuICApOiB2b2lkIHtcbiAgICAvLyBSZWd1bGFyIGJpdGNvaW4gcDJzaC1wMm1zIGlucHV0cyBkbyBub3QgaW5jbHVkZSB0aGUgaW5wdXQgYW1vdW50ICh2YWx1ZSkgaW4gdGhlIHNpZ25hdHVyZSBhbmRcbiAgICAvLyB0aHVzIGRvIG5vdCByZXF1aXJlIHRoZSBwYXJhbWV0ZXIgYHZhbHVlYCB0byBiZSBzZXQuXG4gICAgLy8gRm9yIGJpdGNvaW5jYXNoIGFuZCBiaXRjb2luc3YgcDJzaC1wMm1zIGlucHV0cywgdGhlIHZhbHVlIHBhcmFtZXRlciAqaXMqIHJlcXVpcmVkIGhvd2V2ZXIuXG4gICAgLy8gU2luY2UgdGhlIGB2YWx1ZWAgcGFyYW1ldGVyIGlzIG5vdCBwYXNzZWQgdG8gdGhlIGxlZ2FjeSBoYXNoaW5nIG1ldGhvZCwgd2UgbXVzdCBzdG9yZSBpdFxuICAgIC8vIG9uIHRoZSB0cmFuc2FjdGlvbiBpbnB1dCBvYmplY3QuXG5cbiAgICBpZiAodHlwZW9mIHNpZ25QYXJhbXMgPT09ICdudW1iZXInKSB7XG4gICAgICBpZiAodHlwZW9mIHdpdG5lc3NWYWx1ZSA9PT0gJ251bWJlcicpIHtcbiAgICAgICAgKHRoaXMudHguaW5zW3NpZ25QYXJhbXNdIGFzIGFueSkudmFsdWUgPSB3aXRuZXNzVmFsdWU7XG4gICAgICB9XG5cbiAgICAgIHJldHVybiBzdXBlci5zaWduKHNpZ25QYXJhbXMsIGtleVBhaXIsIHJlZGVlbVNjcmlwdCwgaGFzaFR5cGUsIHdpdG5lc3NWYWx1ZSwgd2l0bmVzc1NjcmlwdCk7XG4gICAgfVxuXG4gICAgaWYgKHNpZ25QYXJhbXMud2l0bmVzc1ZhbHVlICE9PSB1bmRlZmluZWQpIHtcbiAgICAgICh0aGlzLnR4Lmluc1tzaWduUGFyYW1zLnZpbl0gYXMgYW55KS52YWx1ZSA9IHNpZ25QYXJhbXMud2l0bmVzc1ZhbHVlO1xuICAgIH1cbiAgICAvLyBXaGVuIGNhbGxpbmcgdGhlIHNpZ24gbWV0aG9kIHZpYSBUeGJTaWduQXJnLCB0aGUgYHZhbHVlYCBwYXJhbWV0ZXIgaXMgYWN0dWFsbHkgbm90IHBlcm1pdHRlZFxuICAgIC8vIHRvIGJlIHNldCBmb3IgcDJzaC1wMm1zIHRyYW5zYWN0aW9ucy5cbiAgICBpZiAoc2lnblBhcmFtcy5wcmV2T3V0U2NyaXB0VHlwZSA9PT0gJ3Ayc2gtcDJtcycpIHtcbiAgICAgIGRlbGV0ZSBzaWduUGFyYW1zLndpdG5lc3NWYWx1ZTtcbiAgICB9XG4gICAgcmV0dXJuIHN1cGVyLnNpZ24oc2lnblBhcmFtcyk7XG4gIH1cbn1cbiJdfQ==