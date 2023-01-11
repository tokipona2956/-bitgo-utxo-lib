var baddress = require('./address');
var bcrypto = require('./crypto');
var ecdsa = require('./ecdsa');
var randomBytes = require('randombytes');
var typeforce = require('typeforce');
var types = require('./types');
var wif = require('wif');
var NETWORKS = require('./networks');
var BigInteger = require('bigi');
var ecurve = require('ecurve');
var curve = ecurve.getCurveByName('secp256k1');
var secp256k1 = ecdsa.__curve;
var fastcurve = require('./fastcurve');
function ECPair(d, Q, options) {
    if (options) {
        typeforce({
            compressed: types.maybe(types.Boolean),
            network: types.maybe(types.Network)
        }, options);
    }
    options = options || {};
    if (d) {
        if (d.signum() <= 0)
            throw new Error('Private key must be greater than 0');
        if (d.compareTo(secp256k1.n) >= 0)
            throw new Error('Private key must be less than the curve order');
        if (Q)
            throw new TypeError('Unexpected publicKey parameter');
        this.d = d;
    }
    else {
        typeforce(types.ECPoint, Q);
        this.__Q = Q;
    }
    this.compressed = options.compressed === undefined ? true : options.compressed;
    this.network = options.network || NETWORKS.bitcoin;
}
Object.defineProperty(ECPair.prototype, 'Q', {
    get: function () {
        if (!this.__Q && this.d) {
            const qBuf = fastcurve.publicKeyCreate(this.d.toBuffer(32), false);
            this.__Q = qBuf ? ecurve.Point.decodeFrom(curve, qBuf) : secp256k1.G.multiply(this.d);
        }
        return this.__Q;
    }
});
ECPair.fromPublicKeyBuffer = function (buffer, network) {
    var Q = ecurve.Point.decodeFrom(secp256k1, buffer);
    return new ECPair(null, Q, {
        compressed: Q.compressed,
        network: network
    });
};
ECPair.fromWIF = function (string, network) {
    var decoded = wif.decode(string);
    var version = decoded.version;
    // list of networks?
    if (types.Array(network)) {
        network = network.filter(function (x) {
            return version === x.wif;
        }).pop();
        if (!network)
            throw new Error('Unknown network version');
        // otherwise, assume a network object (or default to bitcoin)
    }
    else {
        network = network || NETWORKS.bitcoin;
        if (version !== network.wif)
            throw new Error('Invalid network version');
    }
    var d = BigInteger.fromBuffer(decoded.privateKey);
    return new ECPair(d, null, {
        compressed: decoded.compressed,
        network: network
    });
};
ECPair.makeRandom = function (options) {
    options = options || {};
    var rng = options.rng || randomBytes;
    var d;
    do {
        var buffer = rng(32);
        typeforce(types.Buffer256bit, buffer);
        d = BigInteger.fromBuffer(buffer);
    } while (d.signum() <= 0 || d.compareTo(secp256k1.n) >= 0);
    return new ECPair(d, null, options);
};
ECPair.prototype.getAddress = function () {
    return baddress.toBase58Check(bcrypto.hash160(this.getPublicKeyBuffer()), this.getNetwork().pubKeyHash);
};
ECPair.prototype.getNetwork = function () {
    return this.network;
};
ECPair.prototype.getPublicKeyBuffer = function () {
    return this.Q.getEncoded(this.compressed);
};
ECPair.prototype.sign = function (hash) {
    if (!this.d)
        throw new Error('Missing private key');
    var sig = fastcurve.sign(hash, this.d);
    if (sig !== undefined)
        return sig;
    return ecdsa.sign(hash, this.d);
};
ECPair.prototype.toWIF = function () {
    if (!this.d)
        throw new Error('Missing private key');
    return wif.encode(this.network.wif, this.d.toBuffer(32), this.compressed);
};
ECPair.prototype.verify = function (hash, signature) {
    var fastsig = fastcurve.verify(hash, signature, this.getPublicKeyBuffer());
    if (fastsig !== undefined)
        return fastsig;
    return ecdsa.verify(hash, signature, this.Q);
};
/**
 * @deprecated
 * Use {@see keyutil.privateKeyBufferToECPair} instead
 * Will be removed in next major version (BLOCK-267)
 */
ECPair.fromPrivateKeyBuffer = function (buffer, network) {
    // toplevel import unavailable due to circular dependency
    var keyutil = require('./bitgo/keyutil');
    return keyutil.privateKeyBufferToECPair(buffer, network);
};
/**
 * @deprecated
 * Use {@see keyutil.privateKeyBufferFromECPair} instead
 * Will be removed in next major version (BLOCK-267)
 */
ECPair.prototype.getPrivateKeyBuffer = function () {
    // toplevel import unavailable due to circular dependency
    var keyutil = require('./bitgo/keyutil');
    return keyutil.privateKeyBufferFromECPair(this);
};
module.exports = ECPair;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiZWNwYWlyLmpzIiwic291cmNlUm9vdCI6IiIsInNvdXJjZXMiOlsiLi4vLi4vc3JjL2VjcGFpci5qcyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiQUFBQSxJQUFJLFFBQVEsR0FBRyxPQUFPLENBQUMsV0FBVyxDQUFDLENBQUE7QUFDbkMsSUFBSSxPQUFPLEdBQUcsT0FBTyxDQUFDLFVBQVUsQ0FBQyxDQUFBO0FBQ2pDLElBQUksS0FBSyxHQUFHLE9BQU8sQ0FBQyxTQUFTLENBQUMsQ0FBQTtBQUM5QixJQUFJLFdBQVcsR0FBRyxPQUFPLENBQUMsYUFBYSxDQUFDLENBQUE7QUFDeEMsSUFBSSxTQUFTLEdBQUcsT0FBTyxDQUFDLFdBQVcsQ0FBQyxDQUFBO0FBQ3BDLElBQUksS0FBSyxHQUFHLE9BQU8sQ0FBQyxTQUFTLENBQUMsQ0FBQTtBQUM5QixJQUFJLEdBQUcsR0FBRyxPQUFPLENBQUMsS0FBSyxDQUFDLENBQUE7QUFFeEIsSUFBSSxRQUFRLEdBQUcsT0FBTyxDQUFDLFlBQVksQ0FBQyxDQUFBO0FBQ3BDLElBQUksVUFBVSxHQUFHLE9BQU8sQ0FBQyxNQUFNLENBQUMsQ0FBQTtBQUVoQyxJQUFJLE1BQU0sR0FBRyxPQUFPLENBQUMsUUFBUSxDQUFDLENBQUE7QUFDOUIsSUFBSSxLQUFLLEdBQUcsTUFBTSxDQUFDLGNBQWMsQ0FBQyxXQUFXLENBQUMsQ0FBQTtBQUM5QyxJQUFJLFNBQVMsR0FBRyxLQUFLLENBQUMsT0FBTyxDQUFBO0FBRTdCLElBQUksU0FBUyxHQUFHLE9BQU8sQ0FBQyxhQUFhLENBQUMsQ0FBQTtBQUV0QyxTQUFTLE1BQU0sQ0FBRSxDQUFDLEVBQUUsQ0FBQyxFQUFFLE9BQU87SUFDNUIsSUFBSSxPQUFPLEVBQUU7UUFDWCxTQUFTLENBQUM7WUFDUixVQUFVLEVBQUUsS0FBSyxDQUFDLEtBQUssQ0FBQyxLQUFLLENBQUMsT0FBTyxDQUFDO1lBQ3RDLE9BQU8sRUFBRSxLQUFLLENBQUMsS0FBSyxDQUFDLEtBQUssQ0FBQyxPQUFPLENBQUM7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Q0FBQyxNQUFNLENBQUMsSUFBSSxFQUFFLFNBQVMsRUFBRSxJQUFJLENBQUMsa0JBQWtCLEVBQUUsQ0FBQyxDQUFBO0lBQzFFLElBQUksT0FBTyxLQUFLLFNBQVM7UUFBRSxPQUFPLE9BQU8sQ0FBQTtJQUN6QyxPQUFPLEtBQUssQ0FBQyxNQUFNLENBQUMsSUFBSSxFQUFFLFNBQVMsRUFBRSxJQUFJLENBQUMsQ0FBQyxDQUFDLENBQUE7QUFDOUMsQ0FBQyxDQUFBO0FBRUQ7Ozs7R0FJRztBQUNILE1BQU0sQ0FBQyxvQkFBb0IsR0FBRyxVQUFVLE1BQU0sRUFBRSxPQUFPO0lBQ3JELHlEQUF5RDtJQUN6RCxJQUFJLE9BQU8sR0FBRyxPQUFPLENBQUMsaUJBQWlCLENBQUMsQ0FBQTtJQUN4QyxPQUFPLE9BQU8sQ0FBQyx3QkFBd0IsQ0FBQyxNQUFNLEVBQUUsT0FBTyxDQUFDLENBQUE7QUFDMUQsQ0FBQyxDQUFBO0FBRUQ7Ozs7R0FJRztBQUNILE1BQU0sQ0FBQyxTQUFTLENBQUMsbUJBQW1CLEdBQUc7SUFDckMseURBQXlEO0lBQ3pELElBQUksT0FBTyxHQUFHLE9BQU8sQ0FBQyxpQkFBaUIsQ0FBQyxDQUFBO0lBQ3hDLE9BQU8sT0FBTyxDQUFDLDBCQUEwQixDQUFDLElBQUksQ0FBQyxDQUFBO0FBQ2pELENBQUMsQ0FBQTtBQUVELE1BQU0sQ0FBQyxPQUFPLEdBQUcsTUFBTSxDQUFBIiwic291cmNlc0NvbnRlbnQiOlsidmFyIGJhZGRyZXNzID0gcmVxdWlyZSgnLi9hZGRyZXNzJylcbnZhciBiY3J5cHRvID0gcmVxdWlyZSgnLi9jcnlwdG8nKVxudmFyIGVjZHNhID0gcmVxdWlyZSgnLi9lY2RzYScpXG52YXIgcmFuZG9tQnl0ZXMgPSByZXF1aXJlKCdyYW5kb21ieXRlcycpXG52YXIgdHlwZWZvcmNlID0gcmVxdWlyZSgndHlwZWZvcmNlJylcbnZhciB0eXBlcyA9IHJlcXVpcmUoJy4vdHlwZXMnKVxudmFyIHdpZiA9IHJlcXVpcmUoJ3dpZicpXG5cbnZhciBORVRXT1JLUyA9IHJlcXVpcmUoJy4vbmV0d29ya3MnKVxudmFyIEJpZ0ludGVnZXIgPSByZXF1aXJlKCdiaWdpJylcblxudmFyIGVjdXJ2ZSA9IHJlcXVpcmUoJ2VjdXJ2ZScpXG52YXIgY3VydmUgPSBlY3VydmUuZ2V0Q3VydmVCeU5hbWUoJ3NlY3AyNTZrMScpXG52YXIgc2VjcDI1NmsxID0gZWNkc2EuX19jdXJ2ZVxuXG52YXIgZmFzdGN1cnZlID0gcmVxdWlyZSgnLi9mYXN0Y3VydmUnKVxuXG5mdW5jdGlvbiBFQ1BhaXIgKGQsIFEsIG9wdGlvbnMpIHtcbiAgaWYgKG9wdGlvbnMpIHtcbiAgICB0eXBlZm9yY2Uoe1xuICAgICAgY29tcHJlc3NlZDogdHlwZXMubWF5YmUodHlwZXMuQm9vbGVhbiksXG4gICAgICBuZXR3b3JrOiB0eXBlcy5tYXliZSh0eXBlcy5OZXR3b3JrKVxuICAgIH0sIG9wdGlvbnMpXG4gIH1cblxuICBvcHRpb25zID0gb3B0aW9ucyB8fCB7fVxuXG4gIGlmIChkKSB7XG4gICAgaWYgKGQuc2lnbnVtKCkgPD0gMCkgdGhyb3cgbmV3IEVycm9yKCdQcml2YXRlIGtleSBtdXN0IGJlIGdyZWF0ZXIgdGhhbiAwJylcbiAgICBpZiAoZC5jb21wYXJlVG8oc2VjcDI1NmsxLm4pID49IDApIHRocm93IG5ldyBFcnJvcignUHJpdmF0ZSBrZXkgbXVzdCBiZSBsZXNzIHRoYW4gdGhlIGN1cnZlIG9yZGVyJylcbiAgICBpZiAoUSkgdGhyb3cgbmV3IFR5cGVFcnJvcignVW5leHBlY3RlZCBwdWJsaWNLZXkgcGFyYW1ldGVyJylcblxuICAgIHRoaXMuZCA9IGRcbiAgfSBlbHNlIHtcbiAgICB0eXBlZm9yY2UodHlwZXMuRUNQb2ludCwgUSlcblxuICAgIHRoaXMuX19RID0gUVxuICB9XG5cbiAgdGhpcy5jb21wcmVzc2VkID0gb3B0aW9ucy5jb21wcmVzc2VkID09PSB1bmRlZmluZWQgPyB0cnVlIDogb3B0aW9ucy5jb21wcmVzc2VkXG4gIHRoaXMubmV0d29yayA9IG9wdGlvbnMubmV0d29yayB8fCBORVRXT1JLUy5iaXRjb2luXG59XG5cbk9iamVjdC5kZWZpbmVQcm9wZXJ0eShFQ1BhaXIucHJvdG90eXBlLCAnUScsIHtcbiAgZ2V0OiBmdW5jdGlvbiAoKSB7XG4gICAgaWYgKCF0aGlzLl9fUSAmJiB0aGlzLmQpIHtcbiAgICAgIGNvbnN0IHFCdWYgPSBmYXN0Y3VydmUucHVibGljS2V5Q3JlYXRlKHRoaXMuZC50b0J1ZmZlcigzMiksIGZhbHNlKVxuICAgICAgdGhpcy5fX1EgPSBxQnVmID8gZWN1cnZlLlBvaW50LmRlY29kZUZyb20oY3VydmUsIHFCdWYpIDogc2VjcDI1NmsxLkcubXVsdGlwbHkodGhpcy5kKVxuICAgIH1cblxuICAgIHJldHVybiB0aGlzLl9fUVxuICB9XG59KVxuXG5FQ1BhaXIuZnJvbVB1YmxpY0tleUJ1ZmZlciA9IGZ1bmN0aW9uIChidWZmZXIsIG5ldHdvcmspIHtcbiAgdmFyIFEgPSBlY3VydmUuUG9pbnQuZGVjb2RlRnJvbShzZWNwMjU2azEsIGJ1ZmZlcilcblxuICByZXR1cm4gbmV3IEVDUGFpcihudWxsLCBRLCB7XG4gICAgY29tcHJlc3NlZDogUS5jb21wcmVzc2VkLFxuICAgIG5ldHdvcms6IG5ldHdvcmtcbiAgfSlcbn1cbkVDUGFpci5mcm9tV0lGID0gZnVuY3Rpb24gKHN0cmluZywgbmV0d29yaykge1xuICB2YXIgZGVjb2RlZCA9IHdpZi5kZWNvZGUoc3RyaW5nKVxuICB2YXIgdmVyc2lvbiA9IGRlY29kZWQudmVyc2lvblxuXG4gIC8vIGxpc3Qgb2YgbmV0d29ya3M/XG4gIGlmICh0eXBlcy5BcnJheShuZXR3b3JrKSkge1xuICAgIG5ldHdvcmsgPSBuZXR3b3JrLmZpbHRlcihmdW5jdGlvbiAoeCkge1xuICAgICAgcmV0dXJuIHZlcnNpb24gPT09IHgud2lmXG4gICAgfSkucG9wKClcblxuICAgIGlmICghbmV0d29yaykgdGhyb3cgbmV3IEVycm9yKCdVbmtub3duIG5ldHdvcmsgdmVyc2lvbicpXG5cbiAgLy8gb3RoZXJ3aXNlLCBhc3N1bWUgYSBuZXR3b3JrIG9iamVjdCAob3IgZGVmYXVsdCB0byBiaXRjb2luKVxuICB9IGVsc2Uge1xuICAgIG5ldHdvcmsgPSBuZXR3b3JrIHx8IE5FVFdPUktTLmJpdGNvaW5cblxuICAgIGlmICh2ZXJzaW9uICE9PSBuZXR3b3JrLndpZikgdGhyb3cgbmV3IEVycm9yKCdJbnZhbGlkIG5ldHdvcmsgdmVyc2lvbicpXG4gIH1cblxuICB2YXIgZCA9IEJpZ0ludGVnZXIuZnJvbUJ1ZmZlcihkZWNvZGVkLnByaXZhdGVLZXkpXG5cbiAgcmV0dXJuIG5ldyBFQ1BhaXIoZCwgbnVsbCwge1xuICAgIGNvbXByZXNzZWQ6IGRlY29kZWQuY29tcHJlc3NlZCxcbiAgICBuZXR3b3JrOiBuZXR3b3JrXG4gIH0pXG59XG5cbkVDUGFpci5tYWtlUmFuZG9tID0gZnVuY3Rpb24gKG9wdGlvbnMpIHtcbiAgb3B0aW9ucyA9IG9wdGlvbnMgfHwge31cblxuICB2YXIgcm5nID0gb3B0aW9ucy5ybmcgfHwgcmFuZG9tQnl0ZXNcblxuICB2YXIgZFxuICBkbyB7XG4gICAgdmFyIGJ1ZmZlciA9IHJuZygzMilcbiAgICB0eXBlZm9yY2UodHlwZXMuQnVmZmVyMjU2Yml0LCBidWZmZXIpXG5cbiAgICBkID0gQmlnSW50ZWdlci5mcm9tQnVmZmVyKGJ1ZmZlcilcbiAgfSB3aGlsZSAoZC5zaWdudW0oKSA8PSAwIHx8IGQuY29tcGFyZVRvKHNlY3AyNTZrMS5uKSA+PSAwKVxuXG4gIHJldHVybiBuZXcgRUNQYWlyKGQsIG51bGwsIG9wdGlvbnMpXG59XG5cbkVDUGFpci5wcm90b3R5cGUuZ2V0QWRkcmVzcyA9IGZ1bmN0aW9uICgpIHtcbiAgcmV0dXJuIGJhZGRyZXNzLnRvQmFzZTU4Q2hlY2soYmNyeXB0by5oYXNoMTYwKHRoaXMuZ2V0UHVibGljS2V5QnVmZmVyKCkpLCB0aGlzLmdldE5ldHdvcmsoKS5wdWJLZXlIYXNoKVxufVxuXG5FQ1BhaXIucHJvdG90eXBlLmdldE5ldHdvcmsgPSBmdW5jdGlvbiAoKSB7XG4gIHJldHVybiB0aGlzLm5ldHdvcmtcbn1cblxuRUNQYWlyLnByb3RvdHlwZS5nZXRQdWJsaWNLZXlCdWZmZXIgPSBmdW5jdGlvbiAoKSB7XG4gIHJldHVybiB0aGlzLlEuZ2V0RW5jb2RlZCh0aGlzLmNvbXByZXNzZWQpXG59XG5cbkVDUGFpci5wcm90b3R5cGUuc2lnbiA9IGZ1bmN0aW9uIChoYXNoKSB7XG4gIGlmICghdGhpcy5kKSB0aHJvdyBuZXcgRXJyb3IoJ01pc3NpbmcgcHJpdmF0ZSBrZXknKVxuXG4gIHZhciBzaWcgPSBmYXN0Y3VydmUuc2lnbihoYXNoLCB0aGlzLmQpXG4gIGlmIChzaWcgIT09IHVuZGVmaW5lZCkgcmV0dXJuIHNpZ1xuICByZXR1cm4gZWNkc2Euc2lnbihoYXNoLCB0aGlzLmQpXG59XG5cbkVDUGFpci5wcm90b3R5cGUudG9XSUYgPSBmdW5jdGlvbiAoKSB7XG4gIGlmICghdGhpcy5kKSB0aHJvdyBuZXcgRXJyb3IoJ01pc3NpbmcgcHJpdmF0ZSBrZXknKVxuXG4gIHJldHVybiB3aWYuZW5jb2RlKHRoaXMubmV0d29yay53aWYsIHRoaXMuZC50b0J1ZmZlcigzMiksIHRoaXMuY29tcHJlc3NlZClcbn1cblxuRUNQYWlyLnByb3RvdHlwZS52ZXJpZnkgPSBmdW5jdGlvbiAoaGFzaCwgc2lnbmF0dXJlKSB7XG4gIHZhciBmYXN0c2lnID0gZmFzdGN1cnZlLnZlcmlmeShoYXNoLCBzaWduYXR1cmUsIHRoaXMuZ2V0UHVibGljS2V5QnVmZmVyKCkpXG4gIGlmIChmYXN0c2lnICE9PSB1bmRlZmluZWQpIHJldHVybiBmYXN0c2lnXG4gIHJldHVybiBlY2RzYS52ZXJpZnkoaGFzaCwgc2lnbmF0dXJlLCB0aGlzLlEpXG59XG5cbi8qKlxuICogQGRlcHJlY2F0ZWRcbiAqIFVzZSB7QHNlZSBrZXl1dGlsLnByaXZhdGVLZXlCdWZmZXJUb0VDUGFpcn0gaW5zdGVhZFxuICogV2lsbCBiZSByZW1vdmVkIGluIG5leHQgbWFqb3IgdmVyc2lvbiAoQkxPQ0stMjY3KVxuICovXG5FQ1BhaXIuZnJvbVByaXZhdGVLZXlCdWZmZXIgPSBmdW5jdGlvbiAoYnVmZmVyLCBuZXR3b3JrKSB7XG4gIC8vIHRvcGxldmVsIGltcG9ydCB1bmF2YWlsYWJsZSBkdWUgdG8gY2lyY3VsYXIgZGVwZW5kZW5jeVxuICB2YXIga2V5dXRpbCA9IHJlcXVpcmUoJy4vYml0Z28va2V5dXRpbCcpXG4gIHJldHVybiBrZXl1dGlsLnByaXZhdGVLZXlCdWZmZXJUb0VDUGFpcihidWZmZXIsIG5ldHdvcmspXG59XG5cbi8qKlxuICogQGRlcHJlY2F0ZWRcbiAqIFVzZSB7QHNlZSBrZXl1dGlsLnByaXZhdGVLZXlCdWZmZXJGcm9tRUNQYWlyfSBpbnN0ZWFkXG4gKiBXaWxsIGJlIHJlbW92ZWQgaW4gbmV4dCBtYWpvciB2ZXJzaW9uIChCTE9DSy0yNjcpXG4gKi9cbkVDUGFpci5wcm90b3R5cGUuZ2V0UHJpdmF0ZUtleUJ1ZmZlciA9IGZ1bmN0aW9uICgpIHtcbiAgLy8gdG9wbGV2ZWwgaW1wb3J0IHVuYXZhaWxhYmxlIGR1ZSB0byBjaXJjdWxhciBkZXBlbmRlbmN5XG4gIHZhciBrZXl1dGlsID0gcmVxdWlyZSgnLi9iaXRnby9rZXl1dGlsJylcbiAgcmV0dXJuIGtleXV0aWwucHJpdmF0ZUtleUJ1ZmZlckZyb21FQ1BhaXIodGhpcylcbn1cblxubW9kdWxlLmV4cG9ydHMgPSBFQ1BhaXJcbiJdfQ==