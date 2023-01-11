"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.toOutputScript = exports.fromOutputScript = exports.toBase58Check = exports.fromBase58Check = void 0;
const assert = require("assert");
const bitcoinjs_lib_1 = require("bitcoinjs-lib");
const types = require("bitcoinjs-lib/src/types");
const networks_1 = require("../../networks");
const bs58check = require('bs58check');
const typeforce = require('typeforce');
function fromBase58Check(address) {
    const payload = bs58check.decode(address);
    const version = payload.readUInt16BE(0);
    const hash = payload.slice(2);
    return { version, hash };
}
exports.fromBase58Check = fromBase58Check;
function toBase58Check(hash, version) {
    typeforce(types.tuple(types.Hash160bit, types.Number), arguments);
    const payload = Buffer.allocUnsafe(22);
    payload.writeUInt16BE(version, 0);
    hash.copy(payload, 2);
    return bs58check.encode(payload);
}
exports.toBase58Check = toBase58Check;
function fromOutputScript(outputScript, network) {
    assert(networks_1.isZcash(network));
    let o;
    let prefix;
    try {
        o = bitcoinjs_lib_1.payments.p2pkh({ output: outputScript });
        prefix = network.pubKeyHash;
    }
    catch (e) { }
    try {
        o = bitcoinjs_lib_1.payments.p2sh({ output: outputScript });
        prefix = network.scriptHash;
    }
    catch (e) { }
    if (!o || !o.hash || prefix === undefined) {
        throw new Error(`unsupported outputScript`);
    }
    return toBase58Check(o.hash, prefix);
}
exports.fromOutputScript = fromOutputScript;
function toOutputScript(address, network) {
    assert(networks_1.isZcash(network));
    const { version, hash } = fromBase58Check(address);
    if (version === network.pubKeyHash) {
        return bitcoinjs_lib_1.payments.p2pkh({ hash }).output;
    }
    if (version === network.scriptHash) {
        return bitcoinjs_lib_1.payments.p2sh({ hash }).output;
    }
    throw new Error(address + ' has no matching Script');
}
exports.toOutputScript = toOutputScript;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiYWRkcmVzcy5qcyIsInNvdXJjZVJvb3QiOiIiLCJzb3VyY2VzIjpbIi4uLy4uLy4uLy4uL3NyYy9iaXRnby96Y2FzaC9hZGRyZXNzLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7OztBQUFBLGlDQUFpQztBQUNqQyxpREFBeUM7QUFDekMsaURBQWlEO0FBRWpELDZDQUFrRDtBQUNsRCxNQUFNLFNBQVMsR0FBRyxPQUFPLENBQUMsV0FBVyxDQUFDLENBQUM7QUFDdkMsTUFBTSxTQUFTLEdBQUcsT0FBTyxDQUFDLFdBQVcsQ0FBQyxDQUFDO0FBRXZDLFNBQWdCLGVBQWUsQ0FBQyxPQUFlO0lBQzdDLE1BQU0sT0FBTyxHQUFHLFNBQVMsQ0FBQyxNQUFNLENBQUMsT0FBTyxDQUFDLENBQUM7SUFDMUMsTUFBTSxPQUFPLEdBQUcsT0FBTyxDQUFDLFlBQVksQ0FBQyxDQUFDLENBQUMsQ0FBQztJQUN4QyxNQUFNLElBQUksR0FBRyxPQUFPLENBQUMsS0FBSyxDQUFDLENBQUMsQ0FBQyxDQUFDO0lBQzlCLE9BQU8sRUFBRSxPQUFPLEVBQUUsSUFBSSxFQUFFLENBQUM7QUFDM0IsQ0FBQztBQUxELDBDQUtDO0FBRUQsU0FBZ0IsYUFBYSxDQUFDLElBQVksRUFBRSxPQUFlO0lBQ3pELFNBQVMsQ0FBQyxLQUFLLENBQUMsS0FBSyxDQUFDLEtBQUssQ0FBQyxVQUFVLEVBQUUsS0FBSyxDQUFDLE1BQU0sQ0FBQyxFQUFFLFNBQVMsQ0FBQyxDQUFDO0lBRWxFLE1BQU0sT0FBTyxHQUFHLE1BQU0sQ0FBQyxXQUFXLENBQUMsRUFBRSxDQUFDLENBQUM7SUFDdkMsT0FBTyxDQUFDLGFBQWEsQ0FBQyxPQUFPLEVBQUUsQ0FBQyxDQUFDLENBQUM7SUFDbEMsSUFBSSxDQUFDLElBQUksQ0FBQyxPQUFPLEVBQUUsQ0FBQyxDQUFDLENBQUM7SUFDdEIsT0FBTyxTQUFTLENBQUMsTUFBTSxDQUFDLE9BQU8sQ0FBQyxDQUFDO0FBQ25DLENBQUM7QUFQRCxzQ0FPQztBQUVELFNBQWdCLGdCQUFnQixDQUFDLFlBQW9CLEVBQUUsT0FBZ0I7SUFDckUsTUFBTSxDQUFDLGtCQUFPLENBQUMsT0FBTyxDQUFDLENBQUMsQ0FBQztJQUN6QixJQUFJLENBQUMsQ0FBQztJQUNOLElBQUksTUFBTSxDQUFDO0lBQ1gsSUFBSTtRQUNGLENBQUMsR0FBRyx3QkFBUSxDQUFDLEtBQUssQ0FBQyxFQUFFLE1BQU0sRUFBRSxZQUFZLEVBQUUsQ0FBQyxDQUFDO1FBQzdDLE1BQU0sR0FBRyxPQUFPLENBQUMsVUFBVSxDQUFDO0tBQzdCO0lBQUMsT0FBTyxDQUFDLEVBQUUsR0FBRTtJQUNkLElBQUk7UUFDRixDQUFDLEdBQUcsd0JBQVEsQ0FBQyxJQUFJLENBQUMsRUFBRSxNQUFNLEVBQUUsWUFBWSxFQUFFLENBQUMsQ0FBQztRQUM1QyxNQUFNLEdBQUcsT0FBTyxDQUFDLFVBQVUsQ0FBQztLQUM3QjtJQUFDLE9BQU8sQ0FBQyxFQUFFLEdBQUU7SUFDZCxJQUFJLENBQUMsQ0FBQyxJQUFJLENBQUMsQ0FBQyxDQUFDLElBQUksSUFBSSxNQUFNLEtBQUssU0FBUyxFQUFFO1FBQ3pDLE1BQU0sSUFBSSxLQUFLLENBQUMsMEJBQTBCLENBQUMsQ0FBQztLQUM3QztJQUNELE9BQU8sYUFBYSxDQUFDLENBQUMsQ0FBQyxJQUFJLEVBQUUsTUFBTSxDQUFDLENBQUM7QUFDdkMsQ0FBQztBQWhCRCw0Q0FnQkM7QUFFRCxTQUFnQixjQUFjLENBQUMsT0FBZSxFQUFFLE9BQWdCO0lBQzlELE1BQU0sQ0FBQyxrQkFBTyxDQUFDLE9BQU8sQ0FBQyxDQUFDLENBQUM7SUFDekIsTUFBTSxFQUFFLE9BQU8sRUFBRSxJQUFJLEVBQUUsR0FBRyxlQUFlLENBQUMsT0FBTyxDQUFDLENBQUM7SUFDbkQsSUFBSSxPQUFPLEtBQUssT0FBTyxDQUFDLFVBQVUsRUFBRTtRQUNsQyxPQUFPLHdCQUFRLENBQUMsS0FBSyxDQUFDLEVBQUUsSUFBSSxFQUFFLENBQUMsQ0FBQyxNQUFnQixDQUFDO0tBQ2xEO0lBQ0QsSUFBSSxPQUFPLEtBQUssT0FBTyxDQUFDLFVBQVUsRUFBRTtRQUNsQyxPQUFPLHdCQUFRLENBQUMsSUFBSSxDQUFDLEVBQUUsSUFBSSxFQUFFLENBQUMsQ0FBQyxNQUFnQixDQUFDO0tBQ2pEO0lBQ0QsTUFBTSxJQUFJLEtBQUssQ0FBQyxPQUFPLEdBQUcseUJBQXlCLENBQUMsQ0FBQztBQUN2RCxDQUFDO0FBVkQsd0NBVUMiLCJzb3VyY2VzQ29udGVudCI6WyJpbXBvcnQgKiBhcyBhc3NlcnQgZnJvbSAnYXNzZXJ0JztcbmltcG9ydCB7IHBheW1lbnRzIH0gZnJvbSAnYml0Y29pbmpzLWxpYic7XG5pbXBvcnQgKiBhcyB0eXBlcyBmcm9tICdiaXRjb2luanMtbGliL3NyYy90eXBlcyc7XG5pbXBvcnQgeyBCYXNlNThDaGVja1Jlc3VsdCB9IGZyb20gJ2JpdGNvaW5qcy1saWIvdHlwZXMvYWRkcmVzcyc7XG5pbXBvcnQgeyBpc1pjYXNoLCBOZXR3b3JrIH0gZnJvbSAnLi4vLi4vbmV0d29ya3MnO1xuY29uc3QgYnM1OGNoZWNrID0gcmVxdWlyZSgnYnM1OGNoZWNrJyk7XG5jb25zdCB0eXBlZm9yY2UgPSByZXF1aXJlKCd0eXBlZm9yY2UnKTtcblxuZXhwb3J0IGZ1bmN0aW9uIGZyb21CYXNlNThDaGVjayhhZGRyZXNzOiBzdHJpbmcpOiBCYXNlNThDaGVja1Jlc3VsdCB7XG4gIGNvbnN0IHBheWxvYWQgPSBiczU4Y2hlY2suZGVjb2RlKGFkZHJlc3MpO1xuICBjb25zdCB2ZXJzaW9uID0gcGF5bG9hZC5yZWFkVUludDE2QkUoMCk7XG4gIGNvbnN0IGhhc2ggPSBwYXlsb2FkLnNsaWNlKDIpO1xuICByZXR1cm4geyB2ZXJzaW9uLCBoYXNoIH07XG59XG5cbmV4cG9ydCBmdW5jdGlvbiB0b0Jhc2U1OENoZWNrKGhhc2g6IEJ1ZmZlciwgdmVyc2lvbjogbnVtYmVyKTogc3RyaW5nIHtcbiAgdHlwZWZvcmNlKHR5cGVzLnR1cGxlKHR5cGVzLkhhc2gxNjBiaXQsIHR5cGVzLk51bWJlciksIGFyZ3VtZW50cyk7XG5cbiAgY29uc3QgcGF5bG9hZCA9IEJ1ZmZlci5hbGxvY1Vuc2FmZSgyMik7XG4gIHBheWxvYWQud3JpdGVVSW50MTZCRSh2ZXJzaW9uLCAwKTtcbiAgaGFzaC5jb3B5KHBheWxvYWQsIDIpO1xuICByZXR1cm4gYnM1OGNoZWNrLmVuY29kZShwYXlsb2FkKTtcbn1cblxuZXhwb3J0IGZ1bmN0aW9uIGZyb21PdXRwdXRTY3JpcHQob3V0cHV0U2NyaXB0OiBCdWZmZXIsIG5ldHdvcms6IE5ldHdvcmspOiBzdHJpbmcge1xuICBhc3NlcnQoaXNaY2FzaChuZXR3b3JrKSk7XG4gIGxldCBvO1xuICBsZXQgcHJlZml4O1xuICB0cnkge1xuICAgIG8gPSBwYXltZW50cy5wMnBraCh7IG91dHB1dDogb3V0cHV0U2NyaXB0IH0pO1xuICAgIHByZWZpeCA9IG5ldHdvcmsucHViS2V5SGFzaDtcbiAgfSBjYXRjaCAoZSkge31cbiAgdHJ5IHtcbiAgICBvID0gcGF5bWVudHMucDJzaCh7IG91dHB1dDogb3V0cHV0U2NyaXB0IH0pO1xuICAgIHByZWZpeCA9IG5ldHdvcmsuc2NyaXB0SGFzaDtcbiAgfSBjYXRjaCAoZSkge31cbiAgaWYgKCFvIHx8ICFvLmhhc2ggfHwgcHJlZml4ID09PSB1bmRlZmluZWQpIHtcbiAgICB0aHJvdyBuZXcgRXJyb3IoYHVuc3VwcG9ydGVkIG91dHB1dFNjcmlwdGApO1xuICB9XG4gIHJldHVybiB0b0Jhc2U1OENoZWNrKG8uaGFzaCwgcHJlZml4KTtcbn1cblxuZXhwb3J0IGZ1bmN0aW9uIHRvT3V0cHV0U2NyaXB0KGFkZHJlc3M6IHN0cmluZywgbmV0d29yazogTmV0d29yayk6IEJ1ZmZlciB7XG4gIGFzc2VydChpc1pjYXNoKG5ldHdvcmspKTtcbiAgY29uc3QgeyB2ZXJzaW9uLCBoYXNoIH0gPSBmcm9tQmFzZTU4Q2hlY2soYWRkcmVzcyk7XG4gIGlmICh2ZXJzaW9uID09PSBuZXR3b3JrLnB1YktleUhhc2gpIHtcbiAgICByZXR1cm4gcGF5bWVudHMucDJwa2goeyBoYXNoIH0pLm91dHB1dCBhcyBCdWZmZXI7XG4gIH1cbiAgaWYgKHZlcnNpb24gPT09IG5ldHdvcmsuc2NyaXB0SGFzaCkge1xuICAgIHJldHVybiBwYXltZW50cy5wMnNoKHsgaGFzaCB9KS5vdXRwdXQgYXMgQnVmZmVyO1xuICB9XG4gIHRocm93IG5ldyBFcnJvcihhZGRyZXNzICsgJyBoYXMgbm8gbWF0Y2hpbmcgU2NyaXB0Jyk7XG59XG4iXX0=