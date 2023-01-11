"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ZcashTransactionBuilder = void 0;
const types = require("bitcoinjs-lib/src/types");
const typeforce = require('typeforce');
const ZcashTransaction_1 = require("./ZcashTransaction");
const UtxoTransactionBuilder_1 = require("../UtxoTransactionBuilder");
const address_1 = require("./address");
class ZcashTransactionBuilder extends UtxoTransactionBuilder_1.UtxoTransactionBuilder {
    constructor(network) {
        super(network);
    }
    createInitialTransaction(network, tx) {
        return new ZcashTransaction_1.ZcashTransaction(network, tx);
    }
    static fromTransaction(transaction, network, prevOutput) {
        const txb = new ZcashTransactionBuilder(transaction.network);
        // Copy transaction fields
        txb.setVersion(transaction.version, !!transaction.overwintered);
        txb.setLockTime(transaction.locktime);
        // Copy Zcash overwinter fields. Omitted if the transaction builder is not for Zcash.
        if (txb.tx.isOverwinterCompatible()) {
            txb.setVersionGroupId(transaction.versionGroupId);
            txb.setExpiryHeight(transaction.expiryHeight);
        }
        txb.setConsensusBranchId(transaction.consensusBranchId);
        // Copy outputs (done first to avoid signature invalidation)
        transaction.outs.forEach(function (txOut) {
            txb.addOutput(txOut.script, txOut.value);
        });
        // Copy inputs
        transaction.ins.forEach(function (txIn) {
            txb.__addInputUnsafe(txIn.hash, txIn.index, {
                sequence: txIn.sequence,
                script: txIn.script,
                witness: txIn.witness,
                value: txIn.value,
            });
        });
        return txb;
    }
    setVersion(version, overwinter = true) {
        typeforce(types.UInt32, version);
        this.tx.overwintered = overwinter ? 1 : 0;
        this.tx.version = version;
    }
    setDefaultsForVersion(network, version) {
        switch (version) {
            case 4:
            case ZcashTransaction_1.ZcashTransaction.VERSION4_BRANCH_CANOPY:
            case ZcashTransaction_1.ZcashTransaction.VERSION4_BRANCH_NU5:
                this.setVersion(4);
                break;
            case 5:
            case ZcashTransaction_1.ZcashTransaction.VERSION5_BRANCH_NU5:
                this.setVersion(5);
                break;
            default:
                throw new Error(`invalid version ${version}`);
        }
        this.tx.versionGroupId = ZcashTransaction_1.getDefaultVersionGroupIdForVersion(version);
        this.tx.consensusBranchId = ZcashTransaction_1.getDefaultConsensusBranchIdForVersion(network, version);
    }
    hasSignatures() {
        return this.__INPUTS.some(function (input) {
            return input.signatures !== undefined;
        });
    }
    setPropertyCheckSignatures(propName, value) {
        if (this.tx[propName] === value) {
            return;
        }
        if (this.hasSignatures()) {
            throw new Error(`Changing property ${propName} for a partially signed transaction would invalidate signatures`);
        }
        this.tx[propName] = value;
    }
    setConsensusBranchId(consensusBranchId) {
        typeforce(types.UInt32, consensusBranchId);
        this.setPropertyCheckSignatures('consensusBranchId', consensusBranchId);
    }
    setVersionGroupId(versionGroupId) {
        typeforce(types.UInt32, versionGroupId);
        this.setPropertyCheckSignatures('versionGroupId', versionGroupId);
    }
    setExpiryHeight(expiryHeight) {
        typeforce(types.UInt32, expiryHeight);
        this.setPropertyCheckSignatures('expiryHeight', expiryHeight);
    }
    build() {
        return super.build();
    }
    buildIncomplete() {
        return super.buildIncomplete();
    }
    addOutput(scriptPubKey, value) {
        // Attempt to get a script if it's a base58 or bech32 address string
        if (typeof scriptPubKey === 'string') {
            scriptPubKey = address_1.toOutputScript(scriptPubKey, this.network);
        }
        return super.addOutput(scriptPubKey, value);
    }
}
exports.ZcashTransactionBuilder = ZcashTransactionBuilder;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiWmNhc2hUcmFuc2FjdGlvbkJ1aWxkZXIuanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyIuLi8uLi8uLi8uLi9zcmMvYml0Z28vemNhc2gvWmNhc2hUcmFuc2FjdGlvbkJ1aWxkZXIudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6Ijs7O0FBQ0EsaURBQWlEO0FBQ2pELE1BQU0sU0FBUyxHQUFHLE9BQU8sQ0FBQyxXQUFXLENBQUMsQ0FBQztBQUd2Qyx5REFLNEI7QUFDNUIsc0VBQW1FO0FBQ25FLHVDQUEyQztBQUUzQyxNQUFhLHVCQUF3QixTQUFRLCtDQUF3QztJQUNuRixZQUFZLE9BQXFCO1FBQy9CLEtBQUssQ0FBQyxPQUFPLENBQUMsQ0FBQztJQUNqQixDQUFDO0lBRUQsd0JBQXdCLENBQUMsT0FBZ0IsRUFBRSxFQUEwQjtRQUNuRSxPQUFPLElBQUksbUNBQWdCLENBQUMsT0FBdUIsRUFBRSxFQUFzQixDQUFDLENBQUM7SUFDL0UsQ0FBQztJQUVELE1BQU0sQ0FBQyxlQUFlLENBQ3BCLFdBQTZCLEVBQzdCLE9BQTJCLEVBQzNCLFVBQWlDO1FBRWpDLE1BQU0sR0FBRyxHQUFHLElBQUksdUJBQXVCLENBQUMsV0FBVyxDQUFDLE9BQU8sQ0FBQyxDQUFDO1FBRTdELDBCQUEwQjtRQUMxQixHQUFHLENBQUMsVUFBVSxDQUFDLFdBQVcsQ0FBQyxPQUFPLEVBQUUsQ0FBQyxDQUFDLFdBQVcsQ0FBQyxZQUFZLENBQUMsQ0FBQztRQUNoRSxHQUFHLENBQUMsV0FBVyxDQUFDLFdBQVcsQ0FBQyxRQUFRLENBQUMsQ0FBQztRQUV0QyxxRkFBcUY7UUFDckYsSUFBSSxHQUFHLENBQUMsRUFBRSxDQUFDLHNCQUFzQixFQUFFLEVBQUU7WUFDbkMsR0FBRyxDQUFDLGlCQUFpQixDQUFDLFdBQVcsQ0FBQyxjQUFjLENBQUMsQ0FBQztZQUNsRCxHQUFHLENBQUMsZUFBZSxDQUFDLFdBQVcsQ0FBQyxZQUFZLENBQUMsQ0FBQztTQUMvQztRQUVELEdBQUcsQ0FBQyxvQkFB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QyxjQUFzQjtRQUN0QyxTQUFTLENBQUMsS0FBSyxDQUFDLE1BQU0sRUFBRSxjQUFjLENBQUMsQ0FBQztRQUN4QyxJQUFJLENBQUMsMEJBQTBCLENBQUMsZ0JBQWdCLEVBQUUsY0FBYyxDQUFDLENBQUM7SUFDcEUsQ0FBQztJQUVELGVBQWUsQ0FBQyxZQUFvQjtRQUNsQyxTQUFTLENBQUMsS0FBSyxDQUFDLE1BQU0sRUFBRSxZQUFZLENBQUMsQ0FBQztRQUN0QyxJQUFJLENBQUMsMEJBQTBCLENBQUMsY0FBYyxFQUFFLFlBQVksQ0FBQyxDQUFDO0lBQ2hFLENBQUM7SUFFRCxLQUFLO1FBQ0gsT0FBTyxLQUFLLENBQUMsS0FBSyxFQUFzQixDQUFDO0lBQzNDLENBQUM7SUFFRCxlQUFlO1FBQ2IsT0FBTyxLQUFLLENBQUMsZUFBZSxFQUFzQixDQUFDO0lBQ3JELENBQUM7SUFFRCxTQUFTLENBQUMsWUFBNkIsRUFBRSxLQUFhO1FBQ3BELG9FQUFvRTtRQUNwRSxJQUFJLE9BQU8sWUFBWSxLQUFLLFFBQVEsRUFBRTtZQUNwQyxZQUFZLEdBQUcsd0JBQWMsQ0FBQyxZQUFZLEVBQUUsSUFBSSxDQUFDLE9BQWtCLENBQUMsQ0FBQztTQUN0RTtRQUVELE9BQU8sS0FBSyxDQUFDLFNBQVMsQ0FBQyxZQUFZLEVBQUUsS0FBSyxDQUFDLENBQUM7SUFDOUMsQ0FBQztDQUNGO0FBdEhELDBEQXNIQyIsInNvdXJjZXNDb250ZW50IjpbImltcG9ydCAqIGFzIGJpdGNvaW5qcyBmcm9tICdiaXRjb2luanMtbGliJztcbmltcG9ydCAqIGFzIHR5cGVzIGZyb20gJ2JpdGNvaW5qcy1saWIvc3JjL3R5cGVzJztcbmNvbnN0IHR5cGVmb3JjZSA9IHJlcXVpcmUoJ3R5cGVmb3JjZScpO1xuXG5pbXBvcnQgeyBOZXR3b3JrIH0gZnJvbSAnLi4vLi4nO1xuaW1wb3J0IHtcbiAgZ2V0RGVmYXVsdENvbnNlbnN1c0JyYW5jaElkRm9yVmVyc2lvbixcbiAgZ2V0RGVmYXVsdFZlcnNpb25Hcm91cElkRm9yVmVyc2lvbixcbiAgWmNhc2hOZXR3b3JrLFxuICBaY2FzaFRyYW5zYWN0aW9uLFxufSBmcm9tICcuL1pjYXNoVHJhbnNhY3Rpb24nO1xuaW1wb3J0IHsgVXR4b1RyYW5zYWN0aW9uQnVpbGRlciB9IGZyb20gJy4uL1V0eG9UcmFuc2FjdGlvbkJ1aWxkZXInO1xuaW1wb3J0IHsgdG9PdXRwdXRTY3JpcHQgfSBmcm9tICcuL2FkZHJlc3MnO1xuXG5leHBvcnQgY2xhc3MgWmNhc2hUcmFuc2FjdGlvbkJ1aWxkZXIgZXh0ZW5kcyBVdHhvVHJhbnNhY3Rpb25CdWlsZGVyPFpjYXNoVHJhbnNhY3Rpb24+IHtcbiAgY29uc3RydWN0b3IobmV0d29yazogWmNhc2hOZXR3b3JrKSB7XG4gICAgc3VwZXIobmV0d29yayk7XG4gIH1cblxuICBjcmVhdGVJbml0aWFsVHJhbnNhY3Rpb24obmV0d29yazogTmV0d29yaywgdHg/OiBiaXRjb2luanMuVHJhbnNhY3Rpb24pOiBaY2FzaFRyYW5zYWN0aW9uIHtcbiAgICByZXR1cm4gbmV3IFpjYXNoVHJhbnNhY3Rpb24obmV0d29yayBhcyBaY2FzaE5ldHdvcmssIHR4IGFzIFpjYXNoVHJhbnNhY3Rpb24pO1xuICB9XG5cbiAgc3RhdGljIGZyb21UcmFuc2FjdGlvbihcbiAgICB0cmFuc2FjdGlvbjogWmNhc2hUcmFuc2FjdGlvbixcbiAgICBuZXR3b3JrPzogYml0Y29pbmpzLk5ldHdvcmssXG4gICAgcHJldk91dHB1dD86IGJpdGNvaW5qcy5UeE91dHB1dFtdXG4gICk6IFpjYXNoVHJhbnNhY3Rpb25CdWlsZGVyIHtcbiAgICBjb25zdCB0eGIgPSBuZXcgWmNhc2hUcmFuc2FjdGlvbkJ1aWxkZXIodHJhbnNhY3Rpb24ubmV0d29yayk7XG5cbiAgICAvLyBDb3B5IHRyYW5zYWN0aW9uIGZpZWxkc1xuICAgIHR4Yi5zZXRWZXJzaW9uKHRyYW5zYWN0aW9uLnZlcnNpb24sICEhdHJhbnNhY3Rpb24ub3ZlcndpbnRlcmVkKTtcbiAgICB0eGIuc2V0TG9ja1RpbWUodHJhbnNhY3Rpb24ubG9ja3RpbWUpO1xuXG4gICAgLy8gQ29weSBaY2FzaCBvdmVyd2ludGVyIGZpZWxkcy4gT21pdHRlZCBpZiB0aGUgdHJhbnNhY3Rpb24gYnVpbGRlciBpcyBub3QgZm9yIFpjYXNoLlxuICAgIGlmICh0eGIudHguaXNPdmVyd2ludGVyQ29tcGF0aWJsZSgpKSB7XG4gICAgICB0eGIuc2V0VmVyc2lvbkdyb3VwSWQodHJhbnNhY3Rpb24udmVyc2lvbkdyb3VwSWQpO1xuICAgICAgdHhiLnNldEV4cGlyeUhlaWdodCh0cmFuc2FjdGlvbi5leHBpcnlIZWlnaHQpO1xuICAgIH1cblxuICAgIHR4Yi5zZXRDb25zZW5zdXNCcmFuY2hJZCh0cmFuc2FjdGlvbi5jb25zZW5zdXNCcmFuY2hJZCk7XG5cbiAgICAvLyBDb3B5IG91dHB1dHMgKGRvbmUgZmlyc3QgdG8gYXZvaWQgc2lnbmF0dXJlIGludmFsaWRhdGlvbilcbiAgICB0cmFuc2FjdGlvbi5vdXRzLmZvckVhY2goZnVuY3Rpb24gKHR4T3V0KSB7XG4gICAgICB0eGIuYWRkT3V0cHV0KHR4T3V0LnNjcmlwdCwgdHhPdXQudmFsdWUpO1xuICAgIH0pO1xuXG4gICAgLy8gQ29weSBpbnB1dHNcbiAgICB0cmFuc2FjdGlvbi5pbnMuZm9yRWFjaChmdW5jdGlvbiAodHhJbikge1xuICAgICAgKHR4YiBhcyBhbnkpLl9fYWRkSW5wdXRVbnNhZmUodHhJbi5oYXNoLCB0eEluLmluZGV4LCB7XG4gICAgICAgIHNlcXVlbmNlOiB0eEluLnNlcXVlbmNlLFxuICAgICAgICBzY3JpcHQ6IHR4SW4uc2NyaXB0LFxuICAgICAgICB3aXRuZXNzOiB0eEluLndpdG5lc3MsXG4gICAgICAgIHZhbHVlOiAodHhJbiBhcyBhbnkpLnZhbHVlLFxuICAgICAgfSk7XG4gICAgfSk7XG5cbiAgICByZXR1cm4gdHhiO1xuICB9XG5cbiAgc2V0VmVyc2lvbih2ZXJzaW9uOiBudW1iZXIsIG92ZXJ3aW50ZXIgPSB0cnVlKTogdm9pZCB7XG4gICAgdHlwZWZvcmNlKHR5cGVzLlVJbnQzMiwgdmVyc2lvbik7XG4gICAgdGhpcy50eC5vdmVyd2ludGVyZWQgPSBvdmVyd2ludGVyID8gMSA6IDA7XG4gICAgdGhpcy50eC52ZXJzaW9uID0gdmVyc2lvbjtcbiAgfVxuXG4gIHNldERlZmF1bHRzRm9yVmVyc2lvbihuZXR3b3JrOiBOZXR3b3JrLCB2ZXJzaW9uOiBudW1iZXIpOiB2b2lkIHtcbiAgICBzd2l0Y2ggKHZlcnNpb24pIHtcbiAgICAgIGNhc2UgNDpcbiAgICAgIGNhc2UgWmNhc2hUcmFuc2FjdGlvbi5WRVJTSU9ONF9CUkFOQ0hfQ0FOT1BZOlxuICAgICAgY2FzZSBaY2FzaFRyYW5zYWN0aW9uLlZFUlNJT040X0JSQU5DSF9OVTU6XG4gICAgICAgIHRoaXMuc2V0VmVyc2lvbig0KTtcbiAgICAgICAgYnJlYWs7XG4gICAgICBjYXNlIDU6XG4gICAgICBjYXNlIFpjYXNoVHJhbnNhY3Rpb24uVkVSU0lPTjVfQlJBTkNIX05VNTpcbiAgICAgICAgdGhpcy5zZXRWZXJzaW9uKDUpO1xuICAgICAgICBicmVhaztcbiAgICAgIGRlZmF1bHQ6XG4gICAgICAgIHRocm93IG5ldyBFcnJvcihgaW52YWxpZCB2ZXJzaW9uICR7dmVyc2lvbn1gKTtcbiAgICB9XG5cbiAgICB0aGlzLnR4LnZlcnNpb25Hcm91cElkID0gZ2V0RGVmYXVsdFZlcnNpb25Hcm91cElkRm9yVmVyc2lvbih2ZXJzaW9uKTtcbiAgICB0aGlzLnR4LmNvbnNlbnN1c0JyYW5jaElkID0gZ2V0RGVmYXVsdENvbnNlbnN1c0JyYW5jaElkRm9yVmVyc2lvbihuZXR3b3JrLCB2ZXJzaW9uKTtcbiAgfVxuXG4gIHByaXZhdGUgaGFzU2lnbmF0dXJlcygpOiBib29sZWFuIHtcbiAgICByZXR1cm4gKHRoaXMgYXMgYW55KS5fX0lOUFVUUy5zb21lKGZ1bmN0aW9uIChpbnB1dDogeyBzaWduYXR1cmVzOiB1bmtub3duIH0pIHtcbiAgICAgIHJldHVybiBpbnB1dC5zaWduYXR1cmVzICE9PSB1bmRlZmluZWQ7XG4gICAgfSk7XG4gIH1cblxuICBwcml2YXRlIHNldFByb3BlcnR5Q2hlY2tTaWduYXR1cmVzKHByb3BOYW1lOiBrZXlvZiBaY2FzaFRyYW5zYWN0aW9uLCB2YWx1ZTogdW5rbm93bikge1xuICAgIGlmICh0aGlzLnR4W3Byb3BOYW1lXSA9PT0gdmFsdWUpIHtcbiAgICAgIHJldHVybjtcbiAgICB9XG4gICAgaWYgKHRoaXMuaGFzU2lnbmF0dXJlcygpKSB7XG4gICAgICB0aHJvdyBuZXcgRXJyb3IoYENoYW5naW5nIHByb3BlcnR5ICR7cHJvcE5hbWV9IGZvciBhIHBhcnRpYWxseSBzaWduZWQgdHJhbnNhY3Rpb24gd291bGQgaW52YWxpZGF0ZSBzaWduYXR1cmVzYCk7XG4gICAgfVxuICAgIHRoaXMudHhbcHJvcE5hbWVdID0gdmFsdWUgYXMgYW55O1xuICB9XG5cbiAgc2V0Q29uc2Vuc3VzQnJhbmNoSWQoY29uc2Vuc3VzQnJhbmNoSWQ6IG51bWJlcik6IHZvaWQge1xuICAgIHR5cGVmb3JjZSh0eXBlcy5VSW50MzIsIGNvbnNlbnN1c0JyYW5jaElkKTtcbiAgICB0aGlzLnNldFByb3BlcnR5Q2hlY2tTaWduYXR1cmVzKCdjb25zZW5zdXNCcmFuY2hJZCcsIGNvbnNlbnN1c0JyYW5jaElkKTtcbiAgfVxuXG4gIHNldFZlcnNpb25Hcm91cElkKHZlcnNpb25Hcm91cElkOiBudW1iZXIpOiB2b2lkIHtcbiAgICB0eXBlZm9yY2UodHlwZXMuVUludDMyLCB2ZXJzaW9uR3JvdXBJZCk7XG4gICAgdGhpcy5zZXRQcm9wZXJ0eUNoZWNrU2lnbmF0dXJlcygndmVyc2lvbkdyb3VwSWQnLCB2ZXJzaW9uR3JvdXBJZCk7XG4gIH1cblxuICBzZXRFeHBpcnlIZWlnaHQoZXhwaXJ5SGVpZ2h0OiBudW1iZXIpOiB2b2lkIHtcbiAgICB0eXBlZm9yY2UodHlwZXMuVUludDMyLCBleHBpcnlIZWlnaHQpO1xuICAgIHRoaXMuc2V0UHJvcGVydHlDaGVja1NpZ25hdHVyZXMoJ2V4cGlyeUhlaWdodCcsIGV4cGlyeUhlaWdodCk7XG4gIH1cblxuICBidWlsZCgpOiBaY2FzaFRyYW5zYWN0aW9uIHtcbiAgICByZXR1cm4gc3VwZXIuYnVpbGQoKSBhcyBaY2FzaFRyYW5zYWN0aW9uO1xuICB9XG5cbiAgYnVpbGRJbmNvbXBsZXRlKCk6IFpjYXNoVHJhbnNhY3Rpb24ge1xuICAgIHJldHVybiBzdXBlci5idWlsZEluY29tcGxldGUoKSBhcyBaY2FzaFRyYW5zYWN0aW9uO1xuICB9XG5cbiAgYWRkT3V0cHV0KHNjcmlwdFB1YktleTogc3RyaW5nIHwgQnVmZmVyLCB2YWx1ZTogbnVtYmVyKTogbnVtYmVyIHtcbiAgICAvLyBBdHRlbXB0IHRvIGdldCBhIHNjcmlwdCBpZiBpdCdzIGEgYmFzZTU4IG9yIGJlY2gzMiBhZGRyZXNzIHN0cmluZ1xuICAgIGlmICh0eXBlb2Ygc2NyaXB0UHViS2V5ID09PSAnc3RyaW5nJykge1xuICAgICAgc2NyaXB0UHViS2V5ID0gdG9PdXRwdXRTY3JpcHQoc2NyaXB0UHViS2V5LCB0aGlzLm5ldHdvcmsgYXMgTmV0d29yayk7XG4gICAgfVxuXG4gICAgcmV0dXJuIHN1cGVyLmFkZE91dHB1dChzY3JpcHRQdWJLZXksIHZhbHVlKTtcbiAgfVxufVxuIl19