"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.DashTransaction = void 0;
const bufferutils_1 = require("bitcoinjs-lib/src/bufferutils");
const bitcoinjs_lib_1 = require("bitcoinjs-lib");
const UtxoTransaction_1 = require("../UtxoTransaction");
const networks_1 = require("../../networks");
class DashTransaction extends UtxoTransaction_1.UtxoTransaction {
    constructor(network, tx) {
        super(network, tx);
        this.type = 0;
        if (!networks_1.isDash(network)) {
            throw new Error(`invalid network`);
        }
        if (tx) {
            this.version = tx.version;
            if (tx instanceof DashTransaction) {
                this.type = tx.type;
                this.extraPayload = tx.extraPayload;
            }
        }
        // since `__toBuffer` is private we have to do a little hack here
        this.__toBuffer = this.toBufferWithExtraPayload;
    }
    static fromTransaction(tx) {
        return new DashTransaction(tx.network, tx);
    }
    static fromBuffer(buffer, noStrict, network) {
        const baseTx = UtxoTransaction_1.UtxoTransaction.fromBuffer(buffer, true, network);
        const tx = new DashTransaction(network, baseTx);
        tx.version = baseTx.version & 0xffff;
        tx.type = baseTx.version >> 16;
        if (baseTx.byteLength() !== buffer.length) {
            const bufferReader = new bufferutils_1.BufferReader(buffer, baseTx.byteLength());
            tx.extraPayload = bufferReader.readVarSlice();
        }
        return tx;
    }
    clone() {
        return new DashTransaction(this.network, this);
    }
    byteLength(_ALLOW_WITNESS) {
        return super.byteLength(_ALLOW_WITNESS) + (this.extraPayload ? UtxoTransaction_1.varSliceSize(this.extraPayload) : 0);
    }
    /**
     * Helper to override `__toBuffer()` of bitcoinjs.Transaction.
     * Since the method is private, we use a hack in the constructor to make it work.
     *
     * TODO: remove `private` modifier in bitcoinjs `__toBuffer()` or find some other solution
     *
     * @param buffer - optional target buffer
     * @param initialOffset - can only be undefined or 0. Other values are only used for serialization in blocks.
     * @param _ALLOW_WITNESS - ignored
     */
    toBufferWithExtraPayload(buffer, initialOffset, _ALLOW_WITNESS = false) {
        // We can ignore the `_ALLOW_WITNESS` parameter here since it has no effect.
        if (!buffer) {
            buffer = Buffer.allocUnsafe(this.byteLength(false));
        }
        if (initialOffset !== undefined && initialOffset !== 0) {
            throw new Error(`not supported`);
        }
        // Start out with regular bitcoin byte sequence.
        // This buffer will have excess size because it uses `byteLength()` to allocate.
        const baseBuffer = bitcoinjs_lib_1.Transaction.prototype.__toBuffer.call(this);
        baseBuffer.copy(buffer);
        // overwrite leading version bytes (uint16 version, uint16 type)
        const bufferWriter = new bufferutils_1.BufferWriter(buffer, 0);
        bufferWriter.writeUInt32((this.version & 0xffff) | (this.type << 16));
        // Seek to end of original byte sequence and add extraPayload.
        // We must use the byteLength as calculated by the bitcoinjs implementation since
        // `baseBuffer` has an excess size.
        if (this.extraPayload) {
            bufferWriter.offset = bitcoinjs_lib_1.Transaction.prototype.byteLength.call(this);
            bufferWriter.writeVarSlice(this.extraPayload);
        }
        return buffer;
    }
    getHash(forWitness) {
        if (forWitness) {
            throw new Error(`invalid argument`);
        }
        return bitcoinjs_lib_1.crypto.hash256(this.toBuffer());
    }
    /**
     * Build a hash for all or none of the transaction inputs depending on the hashtype
     * @param hashType
     * @returns Buffer
     */
    getPrevoutHash(hashType) {
        if (!(hashType & UtxoTransaction_1.UtxoTransaction.SIGHASH_ANYONECANPAY)) {
            const bufferWriter = new bufferutils_1.BufferWriter(Buffer.allocUnsafe(36 * this.ins.length));
            this.ins.forEach(function (txIn) {
                bufferWriter.writeSlice(txIn.hash);
                bufferWriter.writeUInt32(txIn.index);
            });
            return bitcoinjs_lib_1.crypto.hash256(bufferWriter.buffer);
        }
        return Buffer.alloc(32, 0);
    }
}
exports.DashTransaction = DashTransaction;
DashTransaction.DASH_NORMAL = 0;
DashTransaction.DASH_PROVIDER_REGISTER = 1;
DashTransaction.DASH_PROVIDER_UPDATE_SERVICE = 2;
DashTransaction.DASH_PROVIDER_UPDATE_REGISTRAR = 3;
DashTransaction.DASH_PROVIDER_UPDATE_REVOKE = 4;
DashTransaction.DASH_COINBASE = 5;
DashTransaction.DASH_QUORUM_COMMITMENT = 6;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiRGFzaFRyYW5zYWN0aW9uLmpzIiwic291cmNlUm9vdCI6IiIsInNvdXJjZXMiOlsiLi4vLi4vLi4vLi4vc3JjL2JpdGdvL2Rhc2gvRGFzaFRyYW5zYWN0aW9uLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7OztBQUFBLCtEQUEyRTtBQUMzRSxpREFBK0Q7QUFFL0Qsd0RBQW1FO0FBQ25FLDZDQUFpRDtBQUVqRCxNQUFhLGVBQWdCLFNBQVEsaUNBQWU7SUFZbEQsWUFBWSxPQUFnQixFQUFFLEVBQXNDO1FBQ2xFLEtBQUssQ0FBQyxPQUFPLEVBQUUsRUFBRSxDQUFDLENBQUM7UUFKZCxTQUFJLEdBQUcsQ0FBQyxDQUFDO1FBTWQsSUFBSSxDQUFDLGlCQUFNLENBQUMsT0FBTyxDQUFDLEVBQUU7WUFDcEIsTUFBTSxJQUFJLEtBQUssQ0FBQyxpQkFBaUIsQ0FBQyxDQUFDO1NBQ3BDO1FBRUQsSUFBSSxFQUFFLEVBQUU7WUFDTixJQUFJLENBQUMsT0FBTyxHQUFHLEVBQUUsQ0FBQyxPQUFPLENBQUM7WUFFMUIsSUFBSSxFQUFFLFlBQVksZUFBZSxFQUFFO2dCQUNqQyxJQUFJLENBQUMsSUFBSSxHQUFHLEVBQUUsQ0FBQyxJQUFJLENBQUM7Z0JBQ3BCLElBQUksQ0FBQyxZQUFZLEdBQUcsRUFBRSxDQUFDLFlBQVksQ0FBQzthQUNyQztTQUNGO1FBRUQsaUVBQWlFO1FBQ2hFLElBQVksQ0FBQyxVQUFVLEdBQUcsSUFBSSxDQUFDLHdCQUF3QixDQUFDO0lBQzNELENBQUM7SUFFRCxNQUFNLENBQUMsZUFBZSxDQUFDLEVBQW1CO1FBQ3hDLE9BQU8sSUFBSSxlQUFlLENBQUMsRUFBRSxDQUFDLE9BQU8sRUFBRSxFQUFFLENBQUMsQ0FBQztJQUM3QyxDQUFDO0lBRUQsTUFBTSxDQUFDLFVBQVUsQ0FBQyxNQUFjLEVBQUUsUUFBaUIsRUFBRSxPQUFnQjtRQUNuRSxNQUFNLE1BQU0sR0FBRyxpQ0FBZSxDQUFDLFVBQVUsQ0FBQyxNQUFNLEVBQUUsSUFBSSxFQUFFLE9BQU8s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QVksQ0FBQyxNQUFNLENBQUMsV0FBVyxDQUFDLEVBQUUsR0FBRyxJQUFJLENBQUMsR0FBRyxDQUFDLE1BQU0sQ0FBQyxDQUFDLENBQUM7WUFFaEYsSUFBSSxDQUFDLEdBQUcsQ0FBQyxPQUFPLENBQUMsVUFBVSxJQUFJO2dCQUM3QixZQUFZLENBQUMsVUFBVSxDQUFDLElBQUksQ0FBQyxJQUFJLENBQUMsQ0FBQztnQkFDbkMsWUFBWSxDQUFDLFdBQVcsQ0FBQyxJQUFJLENBQUMsS0FBSyxDQUFDLENBQUM7WUFDdkMsQ0FBQyxDQUFDLENBQUM7WUFFSCxPQUFPLHNCQUFPLENBQUMsT0FBTyxDQUFDLFlBQVksQ0FBQyxNQUFNLENBQUMsQ0FBQztTQUM3QztRQUVELE9BQU8sTUFBTSxDQUFDLEtBQUssQ0FBQyxFQUFFLEVBQUUsQ0FBQyxDQUFDLENBQUM7SUFDN0IsQ0FBQzs7QUF6SEgsMENBMEhDO0FBekhRLDJCQUFXLEdBQUcsQ0FBQyxDQUFDO0FBQ2hCLHNDQUFzQixHQUFHLENBQUMsQ0FBQztBQUMzQiw0Q0FBNEIsR0FBRyxDQUFDLENBQUM7QUFDakMsOENBQThCLEdBQUcsQ0FBQyxDQUFDO0FBQ25DLDJDQUEyQixHQUFHLENBQUMsQ0FBQztBQUNoQyw2QkFBYSxHQUFHLENBQUMsQ0FBQztBQUNsQixzQ0FBc0IsR0FBRyxDQUFDLENBQUMiLCJzb3VyY2VzQ29udGVudCI6WyJpbXBvcnQgeyBCdWZmZXJSZWFkZXIsIEJ1ZmZlcldyaXRlciB9IGZyb20gJ2JpdGNvaW5qcy1saWIvc3JjL2J1ZmZlcnV0aWxzJztcbmltcG9ydCB7IGNyeXB0byBhcyBiY3J5cHRvLCBUcmFuc2FjdGlvbiB9IGZyb20gJ2JpdGNvaW5qcy1saWInO1xuXG5pbXBvcnQgeyBVdHhvVHJhbnNhY3Rpb24sIHZhclNsaWNlU2l6ZSB9IGZyb20gJy4uL1V0eG9UcmFuc2FjdGlvbic7XG5pbXBvcnQgeyBpc0Rhc2gsIE5ldHdvcmsgfSBmcm9tICcuLi8uLi9uZXR3b3Jrcyc7XG5cbmV4cG9ydCBjbGFzcyBEYXNoVHJhbnNhY3Rpb24gZXh0ZW5kcyBVdHhvVHJhbnNhY3Rpb24ge1xuICBzdGF0aWMgREFTSF9OT1JNQUwgPSAwO1xuICBzdGF0aWMgREFTSF9QUk9WSURFUl9SRUdJU1RFUiA9IDE7XG4gIHN0YXRpYyBEQVNIX1BST1ZJREVSX1VQREFURV9TRVJWSUNFID0gMjtcbiAgc3RhdGljIERBU0hfUFJPVklERVJfVVBEQVRFX1JFR0lTVFJBUiA9IDM7XG4gIHN0YXRpYyBEQVNIX1BST1ZJREVSX1VQREFURV9SRVZPS0UgPSA0O1xuICBzdGF0aWMgREFTSF9DT0lOQkFTRSA9IDU7XG4gIHN0YXRpYyBEQVNIX1FVT1JVTV9DT01NSVRNRU5UID0gNjtcblxuICBwdWJsaWMgdHlwZSA9IDA7XG4gIHB1YmxpYyBleHRyYVBheWxvYWQ/OiBCdWZmZXI7XG5cbiAgY29uc3RydWN0b3IobmV0d29yazogTmV0d29yaywgdHg/OiBVdHhvVHJhbnNhY3Rpb24gfCBEYXNoVHJhbnNhY3Rpb24pIHtcbiAgICBzdXBlcihuZXR3b3JrLCB0eCk7XG5cbiAgICBpZiAoIWlzRGFzaChuZXR3b3JrKSkge1xuICAgICAgdGhyb3cgbmV3IEVycm9yKGBpbnZhbGlkIG5ldHdvcmtgKTtcbiAgICB9XG5cbiAgICBpZiAodHgpIHtcbiAgICAgIHRoaXMudmVyc2lvbiA9IHR4LnZlcnNpb247XG5cbiAgICAgIGlmICh0eCBpbnN0YW5jZW9mIERhc2hUcmFuc2FjdGlvbikge1xuICAgICAgICB0aGlzLnR5cGUgPSB0eC50eXBlO1xuICAgICAgICB0aGlzLmV4dHJhUGF5bG9hZCA9IHR4LmV4dHJhUGF5bG9hZDtcbiAgICAgIH1cbiAgICB9XG5cbiAgICAvLyBzaW5jZSBgX190b0J1ZmZlcmAgaXMgcHJpdmF0ZSB3ZSBoYXZlIHRvIGRvIGEgbGl0dGxlIGhhY2sgaGVyZVxuICAgICh0aGlzIGFzIGFueSkuX190b0J1ZmZlciA9IHRoaXMudG9CdWZmZXJXaXRoRXh0cmFQYXlsb2FkO1xuICB9XG5cbiAgc3RhdGljIGZyb21UcmFuc2FjdGlvbih0eDogRGFzaFRyYW5zYWN0aW9uKTogRGFzaFRyYW5zYWN0aW9uIHtcbiAgICByZXR1cm4gbmV3IERhc2hUcmFuc2FjdGlvbih0eC5uZXR3b3JrLCB0eCk7XG4gIH1cblxuICBzdGF0aWMgZnJvbUJ1ZmZlcihidWZmZXI6IEJ1ZmZlciwgbm9TdHJpY3Q6IGJvb2xlYW4sIG5ldHdvcms6IE5ldHdvcmspOiBEYXNoVHJhbnNhY3Rpb24ge1xuICAgIGNvbnN0IGJhc2VUeCA9IFV0eG9UcmFuc2FjdGlvbi5mcm9tQnVmZmVyKGJ1ZmZlciwgdHJ1ZSwgbmV0d29yayk7XG4gICAgY29uc3QgdHggPSBuZXcgRGFzaFRyYW5zYWN0aW9uKG5ldHdvcmssIGJhc2VUeCk7XG4gICAgdHgudmVyc2lvbiA9IGJhc2VUeC52ZXJzaW9uICYgMHhmZmZmO1xuICAgIHR4LnR5cGUgPSBiYXNlVHgudmVyc2lvbiA+PiAxNjtcbiAgICBpZiAoYmFzZVR4LmJ5dGVMZW5ndGgoKSAhPT0gYnVmZmVyLmxlbmd0aCkge1xuICAgICAgY29uc3QgYnVmZmVyUmVhZGVyID0gbmV3IEJ1ZmZlclJlYWRlcihidWZmZXIsIGJhc2VUeC5ieXRlTGVuZ3RoKCkpO1xuICAgICAgdHguZXh0cmFQYXlsb2FkID0gYnVmZmVyUmVhZGVyLnJlYWRWYXJTbGljZSgpO1xuICAgIH1cbiAgICByZXR1cm4gdHg7XG4gIH1cblxuICBjbG9uZSgpOiBEYXNoVHJhbnNhY3Rpb24ge1xuICAgIHJldHVybiBuZXcgRGFzaFRyYW5zYWN0aW9uKHRoaXMubmV0d29yaywgdGhpcyk7XG4gIH1cblxuICBieXRlTGVuZ3RoKF9BTExPV19XSVRORVNTPzogYm9vbGVhbik6IG51bWJlciB7XG4gICAgcmV0dXJuIHN1cGVyLmJ5dGVMZW5ndGgoX0FMTE9XX1dJVE5FU1MpICsgKHRoaXMuZXh0cmFQYXlsb2FkID8gdmFyU2xpY2VTaXplKHRoaXMuZXh0cmFQYXlsb2FkKSA6IDApO1xuICB9XG5cbiAgLyoqXG4gICAqIEhlbHBlciB0byBvdmVycmlkZSBgX190b0J1ZmZlcigpYCBvZiBiaXRjb2luanMuVHJhbnNhY3Rpb24uXG4gICAqIFNpbmNlIHRoZSBtZXRob2QgaXMgcHJpdmF0ZSwgd2UgdXNlIGEgaGFjayBpbiB0aGUgY29uc3RydWN0b3IgdG8gbWFrZSBpdCB3b3JrLlxuICAgKlxuICAgKiBUT0RPOiByZW1vdmUgYHByaXZhdGVgIG1vZGlmaWVyIGluIGJpdGNvaW5qcyBgX190b0J1ZmZlcigpYCBvciBmaW5kIHNvbWUgb3RoZXIgc29sdXRpb25cbiAgICpcbiAgICogQHBhcmFtIGJ1ZmZlciAtIG9wdGlvbmFsIHRhcmdldCBidWZmZXJcbiAgICogQHBhcmFtIGluaXRpYWxPZmZzZXQgLSBjYW4gb25seSBiZSB1bmRlZmluZWQgb3IgMC4gT3RoZXIgdmFsdWVzIGFyZSBvbmx5IHVzZWQgZm9yIHNlcmlhbGl6YXRpb24gaW4gYmxvY2tzLlxuICAgKiBAcGFyYW0gX0FMTE9XX1dJVE5FU1MgLSBpZ25vcmVkXG4gICAqL1xuICBwcml2YXRlIHRvQnVmZmVyV2l0aEV4dHJhUGF5bG9hZChidWZmZXI/OiBCdWZmZXIsIGluaXRpYWxPZmZzZXQ/OiBudW1iZXIsIF9BTExPV19XSVRORVNTID0gZmFsc2UpOiBCdWZmZXIge1xuICAgIC8vIFdlIGNhbiBpZ25vcmUgdGhlIGBfQUxMT1dfV0lUTkVTU2AgcGFyYW1ldGVyIGhlcmUgc2luY2UgaXQgaGFzIG5vIGVmZmVjdC5cbiAgICBpZiAoIWJ1ZmZlcikge1xuICAgICAgYnVmZmVyID0gQnVmZmVyLmFsbG9jVW5zYWZlKHRoaXMuYnl0ZUxlbmd0aChmYWxzZSkpO1xuICAgIH1cblxuICAgIGlmIChpbml0aWFsT2Zmc2V0ICE9PSB1bmRlZmluZWQgJiYgaW5pdGlhbE9mZnNldCAhPT0gMCkge1xuICAgICAgdGhyb3cgbmV3IEVycm9yKGBub3Qgc3VwcG9ydGVkYCk7XG4gICAgfVxuXG4gICAgLy8gU3RhcnQgb3V0IHdpdGggcmVndWxhciBiaXRjb2luIGJ5dGUgc2VxdWVuY2UuXG4gICAgLy8gVGhpcyBidWZmZXIgd2lsbCBoYXZlIGV4Y2VzcyBzaXplIGJlY2F1c2UgaXQgdXNlcyBgYnl0ZUxlbmd0aCgpYCB0byBhbGxvY2F0ZS5cbiAgICBjb25zdCBiYXNlQnVmZmVyID0gKFRyYW5zYWN0aW9uLnByb3RvdHlwZSBhcyBhbnkpLl9fdG9CdWZmZXIuY2FsbCh0aGlzKTtcbiAgICBiYXNlQnVmZmVyLmNvcHkoYnVmZmVyKTtcblxuICAgIC8vIG92ZXJ3cml0ZSBsZWFkaW5nIHZlcnNpb24gYnl0ZXMgKHVpbnQxNiB2ZXJzaW9uLCB1aW50MTYgdHlwZSlcbiAgICBjb25zdCBidWZmZXJXcml0ZXIgPSBuZXcgQnVmZmVyV3JpdGVyKGJ1ZmZlciwgMCk7XG4gICAgYnVmZmVyV3JpdGVyLndyaXRlVUludDMyKCh0aGlzLnZlcnNpb24gJiAweGZmZmYpIHwgKHRoaXMudHlwZSA8PCAxNikpO1xuXG4gICAgLy8gU2VlayB0byBlbmQgb2Ygb3JpZ2luYWwgYnl0ZSBzZXF1ZW5jZSBhbmQgYWRkIGV4dHJhUGF5bG9hZC5cbiAgICAvLyBXZSBtdXN0IHVzZSB0aGUgYnl0ZUxlbmd0aCBhcyBjYWxjdWxhdGVkIGJ5IHRoZSBiaXRjb2luanMgaW1wbGVtZW50YXRpb24gc2luY2VcbiAgICAvLyBgYmFzZUJ1ZmZlcmAgaGFzIGFuIGV4Y2VzcyBzaXplLlxuICAgIGlmICh0aGlzLmV4dHJhUGF5bG9hZCkge1xuICAgICAgYnVmZmVyV3JpdGVyLm9mZnNldCA9IFRyYW5zYWN0aW9uLnByb3RvdHlwZS5ieXRlTGVuZ3RoLmNhbGwodGhpcyk7XG4gICAgICBidWZmZXJXcml0ZXIud3JpdGVWYXJTbGljZSh0aGlzLmV4dHJhUGF5bG9hZCk7XG4gICAgfVxuXG4gICAgcmV0dXJuIGJ1ZmZlcjtcbiAgfVxuXG4gIGdldEhhc2goZm9yV2l0bmVzcz86IGJvb2xlYW4pOiBCdWZmZXIge1xuICAgIGlmIChmb3JXaXRuZXNzKSB7XG4gICAgICB0aHJvdyBuZXcgRXJyb3IoYGludmFsaWQgYXJndW1lbnRgKTtcbiAgICB9XG4gICAgcmV0dXJuIGJjcnlwdG8uaGFzaDI1Nih0aGlzLnRvQnVmZmVyKCkpO1xuICB9XG5cbiAgLyoqXG4gICAqIEJ1aWxkIGEgaGFzaCBmb3IgYWxsIG9yIG5vbmUgb2YgdGhlIHRyYW5zYWN0aW9uIGlucHV0cyBkZXBlbmRpbmcgb24gdGhlIGhhc2h0eXBlXG4gICAqIEBwYXJhbSBoYXNoVHlwZVxuICAgKiBAcmV0dXJucyBCdWZmZXJcbiAgICovXG4gIGdldFByZXZvdXRIYXNoKGhhc2hUeXBlOiBudW1iZXIpOiBCdWZmZXIge1xuICAgIGlmICghKGhhc2hUeXBlICYgVXR4b1RyYW5zYWN0aW9uLlNJR0hBU0hfQU5ZT05FQ0FOUEFZKSkge1xuICAgICAgY29uc3QgYnVmZmVyV3JpdGVyID0gbmV3IEJ1ZmZlcldyaXRlcihCdWZmZXIuYWxsb2NVbnNhZmUoMzYgKiB0aGlzLmlucy5sZW5ndGgpKTtcblxuICAgICAgdGhpcy5pbnMuZm9yRWFjaChmdW5jdGlvbiAodHhJbikge1xuICAgICAgICBidWZmZXJXcml0ZXIud3JpdGVTbGljZSh0eEluLmhhc2gpO1xuICAgICAgICBidWZmZXJXcml0ZXIud3JpdGVVSW50MzIodHhJbi5pbmRleCk7XG4gICAgICB9KTtcblxuICAgICAgcmV0dXJuIGJjcnlwdG8uaGFzaDI1NihidWZmZXJXcml0ZXIuYnVmZmVyKTtcbiAgICB9XG5cbiAgICByZXR1cm4gQnVmZmVyLmFsbG9jKDMyLCAwKTtcbiAgfVxufVxuIl19