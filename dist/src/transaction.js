var Buffer = require('safe-buffer').Buffer;
var bcrypto = require('./crypto');
var bscript = require('./script');
var { BufferReader, BufferWriter } = require('./bufferutils');
var coins = require('./coins');
var opcodes = require('bitcoin-ops');
var networks = require('./networks');
var typeforce = require('typeforce');
var types = require('./types');
var varuint = require('varuint-bitcoin');
var blake2b = require('@bitgo/blake2b');
var zcashVersion = require('./forks/zcash/version');
function varSliceSize(someScript) {
    var length = someScript.length;
    return varuint.encodingLength(length) + length;
}
function vectorSize(someVector) {
    var length = someVector.length;
    return varuint.encodingLength(length) + someVector.reduce(function (sum, witness) {
        return sum + varSliceSize(witness);
    }, 0);
}
// By default, assume is a bitcoin transaction
function Transaction(network = networks.bitcoin) {
    this.version = 1;
    this.locktime = 0;
    this.ins = [];
    this.outs = [];
    this.network = network;
    if (coins.isZcash(network)) {
        // ZCash version >= 3
        this.overwintered = 0; // 1 if the transaction is post overwinter upgrade, 0 otherwise
        this.versionGroupId = 0; // 0x03C48270 (63210096) for overwinter and 0x892F2085 (2301567109) for sapling
        this.expiryHeight = 0; // Block height after which this transactions will expire, or 0 to disable expiry
        // Must be updated along with version
        this.consensusBranchId = network.consensusBranchId[this.version];
    }
    if (coins.isDash(network)) {
        // Dash version = 3
        this.type = 0;
        this.extraPayload = Buffer.alloc(0);
    }
}
Transaction.DEFAULT_SEQUENCE = 0xffffffff;
Transaction.SIGHASH_ALL = 0x01;
Transaction.SIGHASH_NONE = 0x02;
Transaction.SIGHASH_SINGLE = 0x03;
Transaction.SIGHASH_ANYONECANPAY = 0x80;
/**
 * Enable BIP143 hashing with custom forkID
 * https://github.com/bitcoincashorg/bitcoincash.org/blob/master/spec/replay-protected-sighash.md
 */
Transaction.SIGHASH_FORKID = 0x40;
/** @deprecated use SIGHASH_FORKID */
Transaction.SIGHASH_BITCOINCASHBIP143 = Transaction.SIGHASH_FORKID;
Transaction.ADVANCED_TRANSACTION_MARKER = 0x00;
Transaction.ADVANCED_TRANSACTION_FLAG = 0x01;
var EMPTY_SCRIPT = Buffer.allocUnsafe(0);
var EMPTY_WITNESS = [];
var ZERO = Buffer.from('0000000000000000000000000000000000000000000000000000000000000000', 'hex');
var ONE = Buffer.from('0000000000000000000000000000000000000000000000000000000000000001', 'hex');
// Used to represent the absence of a value
var VALUE_UINT64_MAX = Buffer.from('ffffffffffffffff', 'hex');
var VALUE_INT64_ZERO = Buffer.from('0000000000000000', 'hex');
var BLANK_OUTPUT = {
    script: EMPTY_SCRIPT,
    valueBuffer: VALUE_UINT64_MAX
};
Transaction.DASH_NORMAL = 0;
Transaction.DASH_PROVIDER_REGISTER = 1;
Transaction.DASH_PROVIDER_UPDATE_SERVICE = 2;
Transaction.DASH_PROVIDER_UPDATE_REGISTRAR = 3;
Transaction.DASH_PROVIDER_UPDATE_REVOKE = 4;
Transaction.DASH_COINBASE = 5;
Transaction.DASH_QUORUM_COMMITMENT = 6;
Transaction.fromBuffer = function (buffer, network = networks.bitcoin, __noStrict) {
    let bufferReader = new BufferReader(buffer);
    let tx = new Transaction(network);
    tx.version = bufferReader.readInt32();
    if (coins.isZcash(network)) {
        // Split the header into fOverwintered and nVersion
        tx.overwintered = tx.version >>> 31; // Must be 1 for version 3 and up
        tx.version = tx.version & 0x07FFFFFFF; // 3 for overwinter
        if (tx.overwintered && !network.consensusBranchId.hasOwnProperty(tx.version)) {
            throw new Error('Unsupported Zcash transaction');
        }
        tx.consensusBranchId = network.consensusBranchId[tx.version];
    }
    if (coins.isDash(network)) {
        tx.type = tx.version >> 16;
        tx.version = tx.version & 0xffff;
        if (tx.version === 3 && (tx.type < Transaction.DASH_NORMAL || tx.type > Transaction.DASH_QUORUM_COMMITMENT)) {
            throw new Error('Unsupported Dash transaction type');
        }
    }
    var marker = bufferReader.readUInt8();
    var flag = bufferReader.readUInt8();
    var hasWitnesses = false;
    if (marker === Transaction.ADVANCED_TRANSACTION_MARKER &&
        flag === Transaction.ADVANCED_TRANSACTION_FLAG &&
        !coins.isZcash(network)) {
        hasWitnesses = true;
    }
    else {
        bufferReader.offset -= 2;
    }
    if (tx.isOverwinterCompatible()) {
        tx.versionGroupId = bufferReader.readUInt32();
    }
    var vinLen = bufferReader.readVarInt();
    for (var i = 0; i < vinLen; ++i) {
        tx.ins.push({
            hash: bufferReader.readSlice(32),
            index: bufferReader.readUInt32(),
            script: bufferReader.readVarSlice(),
            sequence: bufferReader.readUInt32(),
            witness: EMPTY_WITNESS
        });
    }
    var voutLen = bufferReader.readVarInt();
    for (i = 0; i < voutLen; ++i) {
        tx.outs.push({
            value: bufferReader.readUInt64(),
            script: bufferReader.readVarSlice()
        });
    }
    if (hasWitnesses) {
        for (i = 0; i < vinLen; ++i) {
            tx.ins[i].witness = bufferReader.readVector();
        }
        // was this pointless?
        if (!tx.hasWitnesses())
            throw new Error('Transaction has superfluous witness data');
    }
    tx.locktime = bufferReader.readUInt32();
    if (coins.isZcash(network)) {
        if (tx.isOverwinterCompatible()) {
            tx.expiryHeight = bufferReader.readUInt32();
        }
        if (tx.isSaplingCompatible()) {
            tx.valueBalance = bufferReader.readSlice(8);
            if (!tx.valueBalance.equals(VALUE_INT64_ZERO)) {
                /* istanbul ignore next */
                throw new Error(`unsupported valueBalance`);
            }
            var nShieldedSpend = bufferReader.readVarInt();
            if (nShieldedSpend !== 0) {
                /* istanbul ignore next */
                throw new Error(`shielded spend not supported`);
            }
            var nShieldedOutput = bufferReader.readVarInt();
            if (nShieldedOutput !== 0) {
                /* istanbul ignore next */
                throw new Error(`shielded output not supported`);
            }
        }
        if (tx.supportsJoinSplits()) {
            var joinSplitsLen = bufferReader.readVarInt();
            if (joinSplitsLen !== 0) {
                /* istanbul ignore next */
                throw new Error(`joinSplits not supported`);
            }
        }
    }
    if (tx.isDashSpecialTransaction()) {
        tx.extraPayload = bufferReader.readVarSlice();
    }
    tx.network = network;
    if (__noStrict)
        return tx;
    if (bufferReader.offset !== buffer.length)
        throw new Error('Transaction has unexpected data');
    return tx;
};
Transaction.fromHex = function (hex, network) {
    return Transaction.fromBuffer(Buffer.from(hex, 'hex'), network);
};
Transaction.isCoinbaseHash = function (buffer) {
    typeforce(types.Hash256bit, buffer);
    for (var i = 0; i < 32; ++i) {
        if (buffer[i] !== 0)
            return false;
    }
    return true;
};
Transaction.prototype.isSaplingCompatible = function () {
    return coins.isZcash(this.network) && this.overwintered && this.version >= zcashVersion.SAPLING;
};
Transaction.prototype.isOverwinterCompatible = function () {
    return coins.isZcash(this.network) && this.overwintered && this.version >= zcashVersion.OVERWINTER;
};
Transaction.prototype.supportsJoinSplits = function () {
    return coins.isZcash(this.network) && this.overwintered && this.version >= zcashVersion.JOINSPLITS_SUPPORT;
};
Transaction.prototype.versionSupportsDashSpecialTransactions = function () {
    return coins.isDash(this.network) && this.version >= 3;
};
Transaction.prototype.isDashSpecialTransaction = function () {
    return this.versionSupportsDashSpecialTransactions() && this.type !== Transaction.DASH_NORMAL;
};
Transaction.prototype.isCoinbase = function () {
    return this.ins.length === 1 && Transaction.isCoinbaseHash(this.ins[0].hash);
};
Transaction.prototype.addInput = function (hash, index, sequence, scriptSig) {
    typeforce(types.tuple(types.Hash256bit, types.UInt32, types.maybe(types.UInt32), types.maybe(types.Buffer)), arguments);
    if (types.Null(sequence)) {
        sequence = Transaction.DEFAULT_SEQUENCE;
    }
    // Add the input and return the input's index
    return (this.ins.push({
        hash: hash,
        index: index,
        script: scriptSig || EMPTY_SCRIPT,
        sequence: sequence,
        witness: EMPTY_WITNESS
    }) - 1);
};
Transaction.prototype.addOutput = function (scriptPubKey, value) {
    typeforce(types.tuple(types.Buffer, types.Satoshi), arguments);
    // Add the output and return the output's index
    return (this.outs.push({
        script: scriptPubKey,
        value: value
    }) - 1);
};
Transaction.prototype.hasWitnesses = function () {
    return this.ins.some(function (x) {
        return x.witness.length !== 0;
    });
};
Transaction.prototype.weight = function () {
    var base = this.__byteLength(false);
    var total = this.__byteLength(true);
    return base * 3 + total;
};
Transaction.prototype.virtualSize = function () {
    return Math.ceil(this.weight() / 4);
};
Transaction.prototype.byteLength = function () {
    return this.__byteLength(true);
};
Transaction.prototype.zcashTransactionByteLength = function () {
    if (!coins.isZcash(this.network)) {
        /* istanbul ignore next */
        throw new Error('zcashTransactionByteLength can only be called when using Zcash network');
    }
    var byteLength = 0;
    byteLength += 4; // Header
    if (this.isOverwinterCompatible()) {
        byteLength += 4; // nVersionGroupId
    }
    byteLength += varuint.encodingLength(this.ins.length); // tx_in_count
    byteLength += this.ins.reduce(function (sum, input) { return sum + 40 + varSliceSize(input.script); }, 0); // tx_in
    byteLength += varuint.encodingLength(this.outs.length); // tx_out_count
    byteLength += this.outs.reduce(function (sum, output) { return sum + 8 + varSliceSize(output.script); }, 0); // tx_out
    byteLength += 4; // lock_time
    if (this.isOverwinterCompatible()) {
        byteLength += 4; // nExpiryHeight
    }
    if (this.isSaplingCompatible()) {
        byteLength += 8; // valueBalance
        byteLength += varuint.encodingLength(0); // inputs
        byteLength += varuint.encodingLength(0); // outputs
    }
    if (this.supportsJoinSplits()) {
        byteLength += varuint.encodingLength(0); // joinsplits
    }
    return byteLength;
};
Transaction.prototype.__byteLength = function (__allowWitness) {
    var hasWitnesses = __allowWitness && this.hasWitnesses();
    if (coins.isZcash(this.network)) {
        return this.zcashTransactionByteLength();
    }
    return ((hasWitnesses ? 10 : 8) +
        varuint.encodingLength(this.ins.length) +
        varuint.encodingLength(this.outs.length) +
        this.ins.reduce(function (sum, input) { return sum + 40 + varSliceSize(input.script); }, 0) +
        this.outs.reduce(function (sum, output) { return sum + 8 + varSliceSize(output.script); }, 0) +
        (this.isDashSpecialTransaction() ? varSliceSize(this.extraPayload) : 0) +
        (hasWitnesses ? this.ins.reduce(function (sum, input) { return sum + vectorSize(input.witness); }, 0) : 0));
};
Transaction.prototype.clone = function () {
    var newTx = new Transaction(this.network);
    newTx.version = this.version;
    newTx.locktime = this.locktime;
    newTx.network = this.network;
    if (coins.isDash(this.network)) {
        newTx.type = this.type;
        newTx.extraPayload = this.extraPayload;
    }
    if (coins.isZcash(this.network)) {
        newTx.consensusBranchId = this.consensusBranchId;
    }
    if (this.isOverwinterCompatible()) {
        newTx.overwintered = this.overwintered;
        newTx.versionGroupId = this.versionGroupId;
        newTx.expiryHeight = this.expiryHeight;
    }
    if (this.isSaplingCompatible()) {
        newTx.valueBalance = this.valueBalance;
    }
    newTx.ins = this.ins.map(function (txIn) {
        return {
            hash: txIn.hash,
            index: txIn.index,
            script: txIn.script,
            sequence: txIn.sequence,
            witness: txIn.witness
        };
    });
    newTx.outs = this.outs.map(function (txOut) {
        return {
            script: txOut.script,
            value: txOut.value
        };
    });
    return newTx;
};
/**
 * Get Zcash header or version
 * @returns {number}
 */
Transaction.prototype.getHeader = function () {
    var mask = (this.overwintered ? 1 : 0);
    var header = this.version | (mask << 31);
    return header;
};
/**
 * Hash transaction for signing a specific input.
 *
 * Bitcoin uses a different hash for each signed transaction input.
 * This method copies the transaction, makes the necessary changes based on the
 * hashType, and then hashes the result.
 * This hash can then be used to sign the provided transaction input.
 */
Transaction.prototype.hashForSignature = function (inIndex, prevOutScript, hashType) {
    typeforce(types.tuple(types.UInt32, types.Buffer, /* types.UInt8 */ types.Number), arguments);
    // https://github.com/bitcoin/bitcoin/blob/master/src/test/sighash_tests.cpp#L29
    if (inIndex >= this.ins.length)
        return ONE;
    // ignore OP_CODESEPARATOR
    var ourScript = bscript.compile(bscript.decompile(prevOutScript).filter(function (x) {
        return x !== opcodes.OP_CODESEPARATOR;
    }));
    var txTmp = this.clone();
    // SIGHASH_NONE: ignore all outputs? (wildcard payee)
    if ((hashType & 0x1f) === Transaction.SIGHASH_NONE) {
        txTmp.outs = [];
        // ignore sequence numbers (except at inIndex)
        txTmp.ins.forEach(function (input, i) {
            if (i === inIndex)
                return;
            input.sequence = 0;
        });
        // SIGHASH_SINGLE: ignore all outputs, except at the same index?
    }
    else if ((hashType & 0x1f) === Transaction.SIGHASH_SINGLE) {
        // https://github.com/bitcoin/bitcoin/blob/master/src/test/sighash_tests.cpp#L60
        if (inIndex >= this.outs.length)
            return ONE;
        // truncate outputs after
        txTmp.outs.length = inIndex + 1;
        // "blank" outputs before
        for (var i = 0; i < inIndex; i++) {
            txTmp.outs[i] = BLANK_OUTPUT;
        }
        // ignore sequence numbers (except at inIndex)
        txTmp.ins.forEach(function (input, y) {
            if (y === inIndex)
                return;
            input.sequence = 0;
        });
    }
    // SIGHASH_ANYONECANPAY: ignore inputs entirely?
    if (hashType & Transaction.SIGHASH_ANYONECANPAY) {
        txTmp.ins = [txTmp.ins[inIndex]];
        txTmp.ins[0].script = ourScript;
        // SIGHASH_ALL: only ignore input scripts
    }
    else {
        // "blank" others input scripts
        txTmp.ins.forEach(function (input) { input.script = EMPTY_SCRIPT; });
        txTmp.ins[inIndex].script = ourScript;
    }
    // serialize and hash
    var buffer = Buffer.allocUnsafe(txTmp.__byteLength(false) + 4);
    buffer.writeInt32LE(hashType, buffer.length - 4);
    txTmp.__toBuffer(buffer, 0, false);
    return bcrypto.hash256(buffer);
};
/**
 * Calculate the hash to verify the signature against
 * @param inIndex
 * @param prevoutScript
 * @param value - The previous output's amount
 * @param hashType
 * @param isSegwit
 * @returns {*}
 */
Transaction.prototype.hashForSignatureByNetwork = function (inIndex, prevoutScript, value, hashType, isSegwit) {
    switch (coins.getMainnet(this.network)) {
        case networks.zcash:
            return this.hashForZcashSignature(inIndex, prevoutScript, value, hashType);
        case networks.bitcoincash:
        case networks.bitcoinsv:
        case networks.bitcoingold:
            /*
              Bitcoin Cash supports a FORKID flag. When set, we hash using hashing algorithm
               that is used for segregated witness transactions (defined in BIP143).
      
              The flag is also used by BitcoinSV and BitcoinGold
      
              https://github.com/bitcoincashorg/bitcoincash.org/blob/master/spec/replay-protected-sighash.md
             */
            var addForkId = hashType & Transaction.SIGHASH_FORKID > 0;
            if (addForkId) {
                /*
                  ``The sighash type is altered to include a 24-bit fork id in its most significant bits.''
                  We also use unsigned right shift operator `>>>` to cast to UInt32
                  https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Operators/Unsigned_right_shift
                 */
                hashType = (hashType | this.network.forkId << 8) >>> 0;
                return this.hashForWitnessV0(inIndex, prevoutScript, value, hashType);
            }
    }
    if (isSegwit) {
        return this.hashForWitnessV0(inIndex, prevoutScript, value, hashType);
    }
    else {
        return this.hashForSignature(inIndex, prevoutScript, hashType);
    }
};
/** @deprecated use hashForSignatureByNetwork */
/* istanbul ignore next */
Transaction.prototype.hashForCashSignature = function (...args) {
    if (coins.getMainnet(this.network) !== networks.bitcoincash &&
        coins.getMainnet(this.network) !== networks.bitcoinsv) {
        throw new Error(`called hashForCashSignature on transaction with network ${coins.getNetworkName(this.network)}`);
    }
    return this.hashForSignatureByNetwork(...args);
};
/** @deprecated use hashForSignatureByNetwork */
/* istanbul ignore next */
Transaction.prototype.hashForGoldSignature = function (...args) {
    if (coins.getMainnet(this.network) !== networks.bitcoingold) {
        throw new Error(`called hashForGoldSignature on transaction with network ${coins.getNetworkName(this.network)}`);
    }
    return this.hashForSignatureByNetwork(...args);
};
/**
 * Blake2b hashing algorithm for Zcash
 * @param bufferToHash
 * @param personalization
 * @returns 256-bit BLAKE2b hash
 */
Transaction.prototype.getBlake2bHash = function (bufferToHash, personalization) {
    var out = Buffer.allocUnsafe(32);
    return blake2b(out.length, null, null, Buffer.from(personalization)).update(bufferToHash).digest(out);
};
/**
 * Build a hash for all or none of the transaction inputs depending on the hashtype
 * @param hashType
 * @returns double SHA-256, 256-bit BLAKE2b hash or 256-bit zero if doesn't apply
 */
Transaction.prototype.getPrevoutHash = function (hashType) {
    if (!(hashType & Transaction.SIGHASH_ANYONECANPAY)) {
        var bufferWriter = new BufferWriter(Buffer.allocUnsafe(36 * this.ins.length));
        this.ins.forEach(function (txIn) {
            bufferWriter.writeSlice(txIn.hash);
            bufferWriter.writeUInt32(txIn.index);
        });
        if (coins.isZcash(this.network)) {
            return this.getBlake2bHash(bufferWriter.buffer, 'ZcashPrevoutHash');
        }
        return bcrypto.hash256(bufferWriter.buffer);
    }
    return ZERO;
};
/**
 * Build a hash for all or none of the transactions inputs sequence numbers depending on the hashtype
 * @param hashType
 * @returns double SHA-256, 256-bit BLAKE2b hash or 256-bit zero if doesn't apply
 */
Transaction.prototype.getSequenceHash = function (hashType) {
    if (!(hashType & Transaction.SIGHASH_ANYONECANPAY) &&
        (hashType & 0x1f) !== Transaction.SIGHASH_SINGLE &&
        (hashType & 0x1f) !== Transaction.SIGHASH_NONE) {
        var bufferWriter = new BufferWriter(Buffer.allocUnsafe(4 * this.ins.length));
        this.ins.forEach(function (txIn) {
            bufferWriter.writeUInt32(txIn.sequence);
        });
        if (coins.isZcash(this.network)) {
            return this.getBlake2bHash(bufferWriter.buffer, 'ZcashSequencHash');
        }
        return bcrypto.hash256(bufferWriter.buffer);
    }
    return ZERO;
};
/**
 * Build a hash for one, all or none of the transaction outputs depending on the hashtype
 * @param hashType
 * @param inIndex
 * @returns double SHA-256, 256-bit BLAKE2b hash or 256-bit zero if doesn't apply
 */
Transaction.prototype.getOutputsHash = function (hashType, inIndex) {
    var bufferWriter;
    if ((hashType & 0x1f) !== Transaction.SIGHASH_SINGLE && (hashType & 0x1f) !== Transaction.SIGHASH_NONE) {
        // Find out the size of the outputs and write them
        var txOutsSize = this.outs.reduce(function (sum, output) {
            return sum + 8 + varSliceSize(output.script);
        }, 0);
        bufferWriter = new BufferWriter(Buffer.allocUnsafe(txOutsSize));
        this.outs.forEach(function (out) {
            bufferWriter.writeUInt64(out.value);
            bufferWriter.writeVarSlice(out.script);
        });
        if (coins.isZcash(this.network)) {
            return this.getBlake2bHash(bufferWriter.buffer, 'ZcashOutputsHash');
        }
        return bcrypto.hash256(bufferWriter.buffer);
    }
    else if ((hashType & 0x1f) === Transaction.SIGHASH_SINGLE && inIndex < this.outs.length) {
        // Write only the output specified in inIndex
        var output = this.outs[inIndex];
        bufferWriter = new BufferWriter(Buffer.allocUnsafe(8 + varSliceSize(output.script)));
        bufferWriter.writeUInt64(output.value);
        bufferWriter.writeVarSlice(output.script);
        if (coins.isZcash(this.network)) {
            return this.getBlake2bHash(bufferWriter.buffer, 'ZcashOutputsHash');
        }
        return bcrypto.hash256(bufferWriter.buffer);
    }
    return ZERO;
};
/**
 * Hash transaction for signing a transparent transaction in Zcash. Protected transactions are not supported.
 * @param inIndex
 * @param prevOutScript
 * @param value
 * @param hashType
 * @returns double SHA-256 or 256-bit BLAKE2b hash
 */
Transaction.prototype.hashForZcashSignature = function (inIndex, prevOutScript, value, hashType) {
    typeforce(types.tuple(types.UInt32, types.Buffer, types.Satoshi, types.UInt32), arguments);
    if (!coins.isZcash(this.network)) {
        /* istanbul ignore next */
        throw new Error('hashForZcashSignature can only be called when using Zcash network');
    }
    if (inIndex >= this.ins.length && inIndex !== VALUE_UINT64_MAX) {
        /* istanbul ignore next */
        throw new Error('Input index is out of range');
    }
    if (this.isOverwinterCompatible()) {
        var hashPrevouts = this.getPrevoutHash(hashType);
        var hashSequence = this.getSequenceHash(hashType);
        var hashOutputs = this.getOutputsHash(hashType, inIndex);
        var hashJoinSplits = ZERO;
        var hashShieldedSpends = ZERO;
        var hashShieldedOutputs = ZERO;
        var bufferWriter;
        var baseBufferSize = 0;
        baseBufferSize += 4 * 5; // header, nVersionGroupId, lock_time, nExpiryHeight, hashType
        baseBufferSize += 32 * 4; // 256 hashes: hashPrevouts, hashSequence, hashOutputs, hashJoinSplits
        if (inIndex !== VALUE_UINT64_MAX) {
            // If this hash is for a transparent input signature (i.e. not for txTo.joinSplitSig), we need extra space
            baseBufferSize += 4 * 2; // input.index, input.sequence
            baseBufferSize += 8; // value
            baseBufferSize += 32; // input.hash
            baseBufferSize += varSliceSize(prevOutScript); // prevOutScript
        }
        if (this.isSaplingCompatible()) {
            baseBufferSize += 32 * 2; // hashShieldedSpends and hashShieldedOutputs
            baseBufferSize += 8; // valueBalance
        }
        bufferWriter = new BufferWriter(Buffer.alloc(baseBufferSize));
        bufferWriter.writeInt32(this.getHeader());
        bufferWriter.writeUInt32(this.versionGroupId);
        bufferWriter.writeSlice(hashPrevouts);
        bufferWriter.writeSlice(hashSequence);
        bufferWriter.writeSlice(hashOutputs);
        bufferWriter.writeSlice(hashJoinSplits);
        if (this.isSaplingCompatible()) {
            bufferWriter.writeSlice(hashShieldedSpends);
            bufferWriter.writeSlice(hashShieldedOutputs);
        }
        bufferWriter.writeUInt32(this.locktime);
        bufferWriter.writeUInt32(this.expiryHeight);
        if (this.isSaplingCompatible()) {
            bufferWriter.writeSlice(VALUE_INT64_ZERO);
        }
        bufferWriter.writeUInt32(hashType);
        // If this hash is for a transparent input signature (i.e. not for txTo.joinSplitSig):
        if (inIndex !== VALUE_UINT64_MAX) {
            // The input being signed (replacing the scriptSig with scriptCode + amount)
            // The prevout may already be contained in hashPrevout, and the nSequence
            // may already be contained in hashSequence.
            var input = this.ins[inIndex];
            bufferWriter.writeSlice(input.hash);
            bufferWriter.writeUInt32(input.index);
            bufferWriter.writeVarSlice(prevOutScript);
            bufferWriter.writeUInt64(value);
            bufferWriter.writeUInt32(input.sequence);
        }
        var personalization = Buffer.alloc(16);
        var prefix = 'ZcashSigHash';
        personalization.write(prefix);
        personalization.writeUInt32LE(this.consensusBranchId, prefix.length);
        return this.getBlake2bHash(bufferWriter.buffer, personalization);
    }
    /* istanbul ignore next */
    throw new Error(`unsupported version`);
};
Transaction.prototype.hashForWitnessV0 = function (inIndex, prevOutScript, value, hashType) {
    typeforce(types.tuple(types.UInt32, types.Buffer, types.Satoshi, types.UInt32), arguments);
    var hashPrevouts = this.getPrevoutHash(hashType);
    var hashSequence = this.getSequenceHash(hashType);
    var hashOutputs = this.getOutputsHash(hashType, inIndex);
    var bufferWriter = new BufferWriter(Buffer.allocUnsafe(156 + varSliceSize(prevOutScript)));
    var input = this.ins[inIndex];
    bufferWriter.writeUInt32(this.version);
    bufferWriter.writeSlice(hashPrevouts);
    bufferWriter.writeSlice(hashSequence);
    bufferWriter.writeSlice(input.hash);
    bufferWriter.writeUInt32(input.index);
    bufferWriter.writeVarSlice(prevOutScript);
    bufferWriter.writeUInt64(value);
    bufferWriter.writeUInt32(input.sequence);
    bufferWriter.writeSlice(hashOutputs);
    bufferWriter.writeUInt32(this.locktime);
    bufferWriter.writeUInt32(hashType);
    return bcrypto.hash256(bufferWriter.buffer);
};
Transaction.prototype.getHash = function () {
    return bcrypto.hash256(this.__toBuffer(undefined, undefined, false));
};
Transaction.prototype.getId = function () {
    // transaction hash's are displayed in reverse order
    return this.getHash().reverse().toString('hex');
};
Transaction.prototype.toBuffer = function (buffer, initialOffset) {
    return this.__toBuffer(buffer, initialOffset, true);
};
Transaction.prototype.__toBuffer = function (buffer, initialOffset, __allowWitness) {
    if (!buffer)
        buffer = Buffer.allocUnsafe(this.__byteLength(__allowWitness));
    const bufferWriter = new BufferWriter(buffer, initialOffset || 0);
    function writeUInt16(i) {
        bufferWriter.offset = bufferWriter.buffer.writeUInt16LE(i, bufferWriter.offset);
    }
    if (this.isOverwinterCompatible()) {
        var mask = (this.overwintered ? 1 : 0);
        bufferWriter.writeInt32(this.version | (mask << 31)); // Set overwinter bit
        bufferWriter.writeUInt32(this.versionGroupId);
    }
    else if (this.isDashSpecialTransaction()) {
        writeUInt16(this.version);
        writeUInt16(this.type);
    }
    else {
        bufferWriter.writeInt32(this.version);
    }
    var hasWitnesses = __allowWitness && this.hasWitnesses();
    if (hasWitnesses) {
        bufferWriter.writeUInt8(Transaction.ADVANCED_TRANSACTION_MARKER);
        bufferWriter.writeUInt8(Transaction.ADVANCED_TRANSACTION_FLAG);
    }
    bufferWriter.writeVarInt(this.ins.length);
    this.ins.forEach(function (txIn) {
        bufferWriter.writeSlice(txIn.hash);
        bufferWriter.writeUInt32(txIn.index);
        bufferWriter.writeVarSlice(txIn.script);
        bufferWriter.writeUInt32(txIn.sequence);
    });
    bufferWriter.writeVarInt(this.outs.length);
    this.outs.forEach(function (txOut) {
        if (!txOut.valueBuffer) {
            bufferWriter.writeUInt64(txOut.value);
        }
        else {
            bufferWriter.writeSlice(txOut.valueBuffer);
        }
        bufferWriter.writeVarSlice(txOut.script);
    });
    if (hasWitnesses) {
        this.ins.forEach(function (input) {
            bufferWriter.writeVector(input.witness);
        });
    }
    bufferWriter.writeUInt32(this.locktime);
    if (this.isOverwinterCompatible()) {
        bufferWriter.writeUInt32(this.expiryHeight);
    }
    if (this.isSaplingCompatible()) {
        bufferWriter.writeSlice(VALUE_INT64_ZERO);
        bufferWriter.writeVarInt(0); // vShieldedSpendLength
        bufferWriter.writeVarInt(0); // vShieldedOutputLength
    }
    if (this.supportsJoinSplits()) {
        bufferWriter.writeVarInt(0); // joinsSplits length
    }
    if (this.isDashSpecialTransaction()) {
        bufferWriter.writeVarSlice(this.extraPayload);
    }
    if (initialOffset !== undefined)
        return buffer.slice(initialOffset, bufferWriter.offset);
    // avoid slicing unless necessary
    // TODO (https://github.com/BitGo/bitgo-utxo-lib/issues/11): we shouldn't have to slice the final buffer
    return buffer.slice(0, bufferWriter.offset);
};
Transaction.prototype.toHex = function () {
    return this.toBuffer().toString('hex');
};
Transaction.prototype.setInputScript = function (index, scriptSig) {
    typeforce(types.tuple(types.Number, types.Buffer), arguments);
    this.ins[index].script = scriptSig;
};
Transaction.prototype.setWitness = function (index, witness) {
    typeforce(types.tuple(types.Number, [types.Buffer]), arguments);
    this.ins[index].witness = witness;
};
module.exports = Transaction;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoidHJhbnNhY3Rpb24uanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyIuLi8uLi9zcmMvdHJhbnNhY3Rpb24uanMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6IkFBQUEsSUFBSSxNQUFNLEdBQUcsT0FBTyxDQUFDLGFBQWEsQ0FBQyxDQUFDLE1BQU0sQ0FBQTtBQUMxQyxJQUFJLE9BQU8sR0FBRyxPQUFPLENBQUMsVUFBVSxDQUFDLENBQUE7QUFDakMsSUFBSSxPQUFPLEdBQUcsT0FBTyxDQUFDLFVBQVUsQ0FBQyxDQUFBO0FBQ2pDLElBQUksRUFBRSxZQUFZLEVBQUUsWUFBWSxFQUFFLEdBQUcsT0FBTyxDQUFDLGVBQWUsQ0FBQyxDQUFBO0FBQzdELElBQUksS0FBSyxHQUFHLE9BQU8sQ0FBQyxTQUFTLENBQUMsQ0FBQTtBQUM5QixJQUFJLE9BQU8sR0FBRyxPQUFPLENBQUMsYUFBYSxDQUFDLENBQUE7QUFDcEMsSUFBSSxRQUFRLEdBQUcsT0FBTyxDQUFDLFlBQVksQ0FBQyxDQUFBO0FBQ3BDLElBQUksU0FBUyxHQUFHLE9BQU8sQ0FBQyxXQUFXLENBQUMsQ0FBQTtBQUNwQyxJQUFJLEtBQUssR0FBRyxPQUFPLENBQUMsU0FBUyxDQUFDLENBQUE7QUFDOUIsSUFBSSxPQUFPLEdBQUcsT0FBTyxDQUFDLGlCQUFpQixDQUFDLENBQUE7QUFDeEMsSUFBSSxPQUFPLEdBQUcsT0FBTyxDQUFDLGdCQUFnQixDQUFDLENBQUE7QUFFdkMsSUFBSSxZQUFZLEdBQUcsT0FBTyxDQUFDLHVCQUF1QixDQUFDLENBQUE7QUFFbkQsU0FBUyxZQUFZLENBQUUsVUFBVTtJQUMvQixJQUFJLE1BQU0sR0FBRyxVQUFVLENBQUMsTUFBTSxDQUFBO0lBRTlCLE9BQU8sT0FBTyxDQUFDLGNBQWMsQ0FBQyxNQUFNLENBQUMsR0FBRyxNQUFNLENBQUE7QUFDaEQsQ0FBQztBQUVELFNBQVMsVUFBVSxDQUFFLFVBQVU7SUFDN0IsSUFBSSxNQUFNLEdBQUcsVUFBVSxDQUFDLE1BQU0sQ0FB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QXdHO0lBQ3hHLE9BQU8sTUFBTSxDQUFDLEtBQUssQ0FBQyxDQUFDLEVBQUUsWUFBWSxDQUFDLE1BQU0sQ0FBQyxDQUFBO0FBQzdDLENBQUMsQ0FBQTtBQUVELFdBQVcsQ0FBQyxTQUFTLENBQUMsS0FBSyxHQUFHO0lBQzVCLE9BQU8sSUFBSSxDQUFDLFFBQVEsRUFBRSxDQUFDLFFBQVEsQ0FBQyxLQUFLLENBQUMsQ0FBQTtBQUN4QyxDQUFDLENBQUE7QUFFRCxXQUFXLENBQUMsU0FBUyxDQUFDLGNBQWMsR0FBRyxVQUFVLEtBQUssRUFBRSxTQUFTO0lBQy9ELFNBQVMsQ0FBQyxLQUFLLENBQUMsS0FBSyxDQUFDLEtBQUssQ0FBQyxNQUFNLEVBQUUsS0FBSyxDQUFDLE1BQU0sQ0FBQyxFQUFFLFNBQVMsQ0FBQyxDQUFBO0lBRTdELElBQUksQ0FBQyxHQUFHLENBQUMsS0FBSyxDQUFDLENBQUMsTUFBTSxHQUFHLFNBQVMsQ0FBQTtBQUNwQyxDQUFDLENBQUE7QUFFRCxXQUFXLENBQUMsU0FBUyxDQUFDLFVBQVUsR0FBRyxVQUFVLEtBQUssRUFBRSxPQUFPO0lBQ3pELFNBQVMsQ0FBQyxLQUFLLENBQUMsS0FBSyxDQUFDLEtBQUssQ0FBQyxNQUFNLEVBQUUsQ0FBQyxLQUFLLENBQUMsTUFBTSxDQUFDLENBQUMsRUFBRSxTQUFTLENBQUMsQ0FBQTtJQUUvRCxJQUFJLENBQUMsR0FBRyxDQUFDLEtBQUssQ0FBQyxDQUFDLE9BQU8sR0FBRyxPQUFPLENBQUE7QUFDbkMsQ0FBQyxDQUFBO0FBRUQsTUFBTSxDQUFDLE9BQU8sR0FBRyxXQUFXLENBQUEiLCJzb3VyY2VzQ29udGVudCI6WyJ2YXIgQnVmZmVyID0gcmVxdWlyZSgnc2FmZS1idWZmZXInKS5CdWZmZXJcbnZhciBiY3J5cHRvID0gcmVxdWlyZSgnLi9jcnlwdG8nKVxudmFyIGJzY3JpcHQgPSByZXF1aXJlKCcuL3NjcmlwdCcpXG52YXIgeyBCdWZmZXJSZWFkZXIsIEJ1ZmZlcldyaXRlciB9ID0gcmVxdWlyZSgnLi9idWZmZXJ1dGlscycpXG52YXIgY29pbnMgPSByZXF1aXJlKCcuL2NvaW5zJylcbnZhciBvcGNvZGVzID0gcmVxdWlyZSgnYml0Y29pbi1vcHMnKVxudmFyIG5ldHdvcmtzID0gcmVxdWlyZSgnLi9uZXR3b3JrcycpXG52YXIgdHlwZWZvcmNlID0gcmVxdWlyZSgndHlwZWZvcmNlJylcbnZhciB0eXBlcyA9IHJlcXVpcmUoJy4vdHlwZXMnKVxudmFyIHZhcnVpbnQgPSByZXF1aXJlKCd2YXJ1aW50LWJpdGNvaW4nKVxudmFyIGJsYWtlMmIgPSByZXF1aXJlKCdAYml0Z28vYmxha2UyYicpXG5cbnZhciB6Y2FzaFZlcnNpb24gPSByZXF1aXJlKCcuL2ZvcmtzL3pjYXNoL3ZlcnNpb24nKVxuXG5mdW5jdGlvbiB2YXJTbGljZVNpemUgKHNvbWVTY3JpcHQpIHtcbiAgdmFyIGxlbmd0aCA9IHNvbWVTY3JpcHQubGVuZ3RoXG5cbiAgcmV0dXJuIHZhcnVpbnQuZW5jb2RpbmdMZW5ndGgobGVuZ3RoKSArIGxlbmd0aFxufVxuXG5mdW5jdGlvbiB2ZWN0b3JTaXplIChzb21lVmVjdG9yKSB7XG4gIHZhciBsZW5ndGggPSBzb21lVmVjdG9yLmxlbmd0aFxuXG4gIHJldHVybiB2YXJ1aW50LmVuY29kaW5nTGVuZ3RoKGxlbmd0aCkgKyBzb21lVmVjdG9yLnJlZHVjZShmdW5jdGlvbiAoc3VtLCB3aXRuZXNzKSB7XG4gICAgcmV0dXJuIHN1bSArIHZhclNsaWNlU2l6ZSh3aXRuZXNzKVxuICB9LCAwKVxufVxuXG4vLyBCeSBkZWZhdWx0LCBhc3N1bWUgaXMgYSBiaXRjb2luIHRyYW5zYWN0aW9uXG5mdW5jdGlvbiBUcmFuc2FjdGlvbiAobmV0d29yayA9IG5ldHdvcmtzLmJpdGNvaW4pIHtcbiAgdGhpcy52ZXJzaW9uID0gMVxuICB0aGlzLmxvY2t0aW1lID0gMFxuICB0aGlzLmlucyA9IFtdXG4gIHRoaXMub3V0cyA9IFtdXG4gIHRoaXMubmV0d29yayA9IG5ldHdvcmtcbiAgaWYgKGNvaW5zLmlzWmNhc2gobmV0d29yaykpIHtcbiAgICAvLyBaQ2FzaCB2ZXJzaW9uID49IDNcbiAgICB0aGlzLm92ZXJ3aW50ZXJlZCA9IDAgIC8vIDEgaWYgdGhlIHRyYW5zYWN0aW9uIGlzIHBvc3Qgb3ZlcndpbnRlciB1cGdyYWRlLCAwIG90aGVyd2lzZVxuICAgIHRoaXMudmVyc2lvbkdyb3VwSWQgPSAwICAvLyAweDAzQzQ4MjcwICg2MzIxMDA5NikgZm9yIG92ZXJ3aW50ZXIgYW5kIDB4ODkyRjIwODUgKDIzMDE1NjcxMDkpIGZvciBzYXBsaW5nXG4gICAgdGhpcy5leHBpcnlIZWlnaHQgPSAwICAvLyBCbG9jayBoZWlnaHQgYWZ0ZXIgd2hpY2ggdGhpcyB0cmFuc2FjdGlvbnMgd2lsbCBleHBpcmUsIG9yIDAgdG8gZGlzYWJsZSBleHBpcnlcbiAgICAvLyBNdXN0IGJlIHVwZGF0ZWQgYWxvbmcgd2l0aCB2ZXJzaW9uXG4gICAgdGhpcy5jb25zZW5zdXNCcmFuY2hJZCA9IG5ldHdvcmsuY29uc2Vuc3VzQnJhbmNoSWRbdGhpcy52ZXJzaW9uXVxuICB9XG4gIGlmIChjb2lucy5pc0Rhc2gobmV0d29yaykpIHtcbiAgICAvLyBEYXNoIHZlcnNpb24gPSAzXG4gICAgdGhpcy50eXBlID0gMFxuICAgIHRoaXMuZXh0cmFQYXlsb2FkID0gQnVmZmVyLmFsbG9jKDApXG4gIH1cbn1cblxuVHJhbnNhY3Rpb24uREVGQVVMVF9TRVFVRU5DRSA9IDB4ZmZmZmZmZmZcblRyYW5zYWN0aW9uLlNJR0hBU0hfQUxMID0gMHgwMVxuVHJhbnNhY3Rpb24uU0lHSEFTSF9OT05FID0gMHgwMlxuVHJhbnNhY3Rpb24uU0lHSEFTSF9TSU5HTEUgPSAweDAzXG5UcmFuc2FjdGlvbi5TSUdIQVNIX0FOWU9ORUNBTlBBWSA9IDB4ODBcbi8qKlxuICogRW5hYmxlIEJJUDE0MyBoYXNoaW5nIHdpdGggY3VzdG9tIGZvcmtJRFxuICogaHR0cHM6Ly9naXRodWIuY29tL2JpdGNvaW5jYXNob3JnL2JpdGNvaW5jYXNoLm9yZy9ibG9iL21hc3Rlci9zcGVjL3JlcGxheS1wcm90ZWN0ZWQtc2lnaGFzaC5tZFxuICovXG5UcmFuc2FjdGlvbi5TSUdIQVNIX0ZPUktJRCA9IDB4NDBcbi8qKiBAZGVwcmVjYXRlZCB1c2UgU0lHSEFTSF9GT1JLSUQgKi9cblRyYW5zYWN0aW9uLlNJR0hBU0hfQklUQ09JTkNBU0hCSVAxNDMgPSBUcmFuc2FjdGlvbi5TSUdIQVNIX0ZPUktJRFxuVHJhbnNhY3Rpb24uQURWQU5DRURfVFJBTlNBQ1RJT05fTUFSS0VSID0gMHgwMFxuVHJhbnNhY3Rpb24uQURWQU5DRURfVFJBTlNBQ1RJT05fRkxBRyA9IDB4MDFcblxudmFyIEVNUFRZX1NDUklQVCA9IEJ1ZmZlci5hbGxvY1Vuc2FmZSgwKVxudmFyIEVNUFRZX1dJVE5FU1MgPSBbXVxudmFyIFpFUk8gPSBCdWZmZXIuZnJvbSgnMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMCcsICdoZXgnKVxudmFyIE9ORSA9IEJ1ZmZlci5mcm9tKCcwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAxJywgJ2hleCcpXG4vLyBVc2VkIHRvIHJlcHJlc2VudCB0aGUgYWJzZW5jZSBvZiBhIHZhbHVlXG52YXIgVkFMVUVfVUlOVDY0X01BWCA9IEJ1ZmZlci5mcm9tKCdmZmZmZmZmZmZmZmZmZmZmJywgJ2hleCcpXG52YXIgVkFMVUVfSU5UNjRfWkVSTyA9IEJ1ZmZlci5mcm9tKCcwMDAwMDAwMDAwMDAwMDAwJywgJ2hleCcpXG52YXIgQkxBTktfT1VUUFVUID0ge1xuICBzY3JpcHQ6IEVNUFRZX1NDUklQVCxcbiAgdmFsdWVCdWZmZXI6IFZBTFVFX1VJTlQ2NF9NQVhcbn1cblxuVHJhbnNhY3Rpb24uREFTSF9OT1JNQUwgPSAwXG5UcmFuc2FjdGlvbi5EQVNIX1BST1ZJREVSX1JFR0lTVEVSID0gMVxuVHJhbnNhY3Rpb24uREFTSF9QUk9WSURFUl9VUERBVEVfU0VSVklDRSA9IDJcblRyYW5zYWN0aW9uLkRBU0hfUFJPVklERVJfVVBEQVRFX1JFR0lTVFJBUiA9IDNcblRyYW5zYWN0aW9uLkRBU0hfUFJPVklERVJfVVBEQVRFX1JFVk9LRSA9IDRcblRyYW5zYWN0aW9uLkRBU0hfQ09JTkJBU0UgPSA1XG5UcmFuc2FjdGlvbi5EQVNIX1FVT1JVTV9DT01NSVRNRU5UID0gNlxuXG5UcmFuc2FjdGlvbi5mcm9tQnVmZmVyID0gZnVuY3Rpb24gKGJ1ZmZlciwgbmV0d29yayA9IG5ldHdvcmtzLmJpdGNvaW4sIF9fbm9TdHJpY3QpIHtcbiAgbGV0IGJ1ZmZlclJlYWRlciA9IG5ldyBCdWZmZXJSZWFkZXIoYnVmZmVyKVxuXG4gIGxldCB0eCA9IG5ldyBUcmFuc2FjdGlvbihuZXR3b3JrKVxuICB0eC52ZXJzaW9uID0gYnVmZmVyUmVhZGVyLnJlYWRJbnQzMigpXG5cbiAgaWYgKGNvaW5zLmlzWmNhc2gobmV0d29yaykpIHtcbiAgICAvLyBTcGxpdCB0aGUgaGVhZGVyIGludG8gZk92ZXJ3aW50ZXJlZCBhbmQgblZlcnNpb25cbiAgICB0eC5vdmVyd2ludGVyZWQgPSB0eC52ZXJzaW9uID4+PiAzMSAgLy8gTXVzdCBiZSAxIGZvciB2ZXJzaW9uIDMgYW5kIHVwXG4gICAgdHgudmVyc2lvbiA9IHR4LnZlcnNpb24gJiAweDA3RkZGRkZGRiAgLy8gMyBmb3Igb3ZlcndpbnRlclxuICAgIGlmICh0eC5vdmVyd2ludGVyZWQgJiYgIW5ldHdvcmsuY29uc2Vuc3VzQnJhbmNoSWQuaGFzT3duUHJvcGVydHkodHgudmVyc2lvbikpIHtcbiAgICAgIHRocm93IG5ldyBFcnJvcignVW5zdXBwb3J0ZWQgWmNhc2ggdHJhbnNhY3Rpb24nKVxuICAgIH1cbiAgICB0eC5jb25zZW5zdXNCcmFuY2hJZCA9IG5ldHdvcmsuY29uc2Vuc3VzQnJhbmNoSWRbdHgudmVyc2lvbl1cbiAgfVxuXG4gIGlmIChjb2lucy5pc0Rhc2gobmV0d29yaykpIHtcbiAgICB0eC50eXBlID0gdHgudmVyc2lvbiA+PiAxNlxuICAgIHR4LnZlcnNpb24gPSB0eC52ZXJzaW9uICYgMHhmZmZmXG4gICAgaWYgKHR4LnZlcnNpb24gPT09IDMgJiYgKHR4LnR5cGUgPCBUcmFuc2FjdGlvbi5EQVNIX05PUk1BTCB8fCB0eC50eXBlID4gVHJhbnNhY3Rpb24uREFTSF9RVU9SVU1fQ09NTUlUTUVOVCkpIHtcbiAgICAgIHRocm93IG5ldyBFcnJvcignVW5zdXBwb3J0ZWQgRGFzaCB0cmFuc2FjdGlvbiB0eXBlJylcbiAgICB9XG4gIH1cblxuICB2YXIgbWFya2VyID0gYnVmZmVyUmVhZGVyLnJlYWRVSW50OCgpXG4gIHZhciBmbGFnID0gYnVmZmVyUmVhZGVyLnJlYWRVSW50OCgpXG5cbiAgdmFyIGhhc1dpdG5lc3NlcyA9IGZhbHNlXG4gIGlmIChtYXJrZXIgPT09IFRyYW5zYWN0aW9uLkFEVkFOQ0VEX1RSQU5TQUNUSU9OX01BUktFUiAmJlxuICAgICAgZmxhZyA9PT0gVHJhbnNhY3Rpb24uQURWQU5DRURfVFJBTlNBQ1RJT05fRkxBRyAmJlxuICAgICAgIWNvaW5zLmlzWmNhc2gobmV0d29yaykpIHtcbiAgICBoYXNXaXRuZXNzZXMgPSB0cnVlXG4gIH0gZWxzZSB7XG4gICAgYnVmZmVyUmVhZGVyLm9mZnNldCAtPSAyXG4gIH1cblxuICBpZiAodHguaXNPdmVyd2ludGVyQ29tcGF0aWJsZSgpKSB7XG4gICAgdHgudmVyc2lvbkdyb3VwSWQgPSBidWZmZXJSZWFkZXIucmVhZFVJbnQzMigpXG4gIH1cblxuICB2YXIgdmluTGVuID0gYnVmZmVyUmVhZGVyLnJlYWRWYXJJbnQoKVxuICBmb3IgKHZhciBpID0gMDsgaSA8IHZpbkxlbjsgKytpKSB7XG4gICAgdHguaW5zLnB1c2goe1xuICAgICAgaGFzaDogYnVmZmVyUmVhZGVyLnJlYWRTbGljZSgzMiksXG4gICAgICBpbmRleDogYnVmZmVyUmVhZGVyLnJlYWRVSW50MzIoKSxcbiAgICAgIHNjcmlwdDogYnVmZmVyUmVhZGVyLnJlYWRWYXJTbGljZSgpLFxuICAgICAgc2VxdWVuY2U6IGJ1ZmZlclJlYWRlci5yZWFkVUludDMyKCksXG4gICAgICB3aXRuZXNzOiBFTVBUWV9XSVRORVNTXG4gICAgfSlcbiAgfVxuXG4gIHZhciB2b3V0TGVuID0gYnVmZmVyUmVhZGVyLnJlYWRWYXJJbnQoKVxuICBmb3IgKGkgPSAwOyBpIDwgdm91dExlbjsgKytpKSB7XG4gICAgdHgub3V0cy5wdXNoKHtcbiAgICAgIHZhbHVlOiBidWZmZXJSZWFkZXIucmVhZFVJbnQ2NCgpLFxuICAgICAgc2NyaXB0OiBidWZmZXJSZWFkZXIucmVhZFZhclNsaWNlKClcbiAgICB9KVxuICB9XG5cbiAgaWYgKGhhc1dpdG5lc3Nlcykge1xuICAgIGZvciAoaSA9IDA7IGkgPCB2aW5MZW47ICsraSkge1xuICAgICAgdHguaW5zW2ldLndpdG5lc3MgPSBidWZmZXJSZWFkZXIucmVhZFZlY3RvcigpXG4gICAgfVxuXG4gICAgLy8gd2FzIHRoaXMgcG9pbnRsZXNzP1xuICAgIGlmICghdHguaGFzV2l0bmVzc2VzKCkpIHRocm93IG5ldyBFcnJvcignVHJhbnNhY3Rpb24gaGFzIHN1cGVyZmx1b3VzIHdpdG5lc3MgZGF0YScpXG4gIH1cblxuICB0eC5sb2NrdGltZSA9IGJ1ZmZlclJlYWRlci5yZWFkVUludDMyKClcblxuICBpZiAoY29pbnMuaXNaY2FzaChuZXR3b3JrKSkge1xuICAgIGlmICh0eC5pc092ZXJ3aW50ZXJDb21wYXRpYmxlKCkpIHtcbiAgICAgIHR4LmV4cGlyeUhlaWdodCA9IGJ1ZmZlclJlYWRlci5yZWFkVUludDMyKClcbiAgICB9XG5cbiAgICBpZiAodHguaXNTYXBsaW5nQ29tcGF0aWJsZSgpKSB7XG4gICAgICB0eC52YWx1ZUJhbGFuY2UgPSBidWZmZXJSZWFkZXIucmVhZFNsaWNlKDgpXG4gICAgICBpZiAoIXR4LnZhbHVlQmFsYW5jZS5lcXVhbHMoVkFMVUVfSU5UNjRfWkVSTykpIHtcbiAgICAgICAgLyogaXN0YW5idWwgaWdub3JlIG5leHQgKi9cbiAgICAgICAgdGhyb3cgbmV3IEVycm9yKGB1bnN1cHBvcnRlZCB2YWx1ZUJhbGFuY2VgKVxuICAgICAgfVxuXG4gICAgICB2YXIgblNoaWVsZGVkU3BlbmQgPSBidWZmZXJSZWFkZXIucmVhZFZhckludCgpXG4gICAgICBpZiAoblNoaWVsZGVkU3BlbmQgIT09IDApIHtcbiAgICAgICAgLyogaXN0YW5idWwgaWdub3JlIG5leHQgKi9cbiAgICAgICAgdGhyb3cgbmV3IEVycm9yKGBzaGllbGRlZCBzcGVuZCBub3Qgc3VwcG9ydGVkYClcbiAgICAgIH1cblxuICAgICAgdmFyIG5TaGllbGRlZE91dHB1dCA9IGJ1ZmZlclJlYWRlci5yZWFkVmFySW50KClcbiAgICAgIGlmIChuU2hpZWxkZWRPdXRwdXQgIT09IDApIHtcbiAgICAgICAgLyogaXN0YW5idWwgaWdub3JlIG5leHQgKi9cbiAgICAgICAgdGhyb3cgbmV3IEVycm9yKGBzaGllbGRlZCBvdXRwdXQgbm90IHN1cHBvcnRlZGApXG4gICAgICB9XG4gICAgfVxuXG4gICAgaWYgKHR4LnN1cHBvcnRzSm9pblNwbGl0cygpKSB7XG4gICAgICB2YXIgam9pblNwbGl0c0xlbiA9IGJ1ZmZlclJlYWRlci5yZWFkVmFySW50KClcbiAgICAgIGlmIChqb2luU3BsaXRzTGVuICE9PSAwKSB7XG4gICAgICAgIC8qIGlzdGFuYnVsIGlnbm9yZSBuZXh0ICovXG4gICAgICAgIHRocm93IG5ldyBFcnJvcihgam9pblNwbGl0cyBub3Qgc3VwcG9ydGVkYClcbiAgICAgIH1cbiAgICB9XG4gIH1cblxuICBpZiAodHguaXNEYXNoU3BlY2lhbFRyYW5zYWN0aW9uKCkpIHtcbiAgICB0eC5leHRyYVBheWxvYWQgPSBidWZmZXJSZWFkZXIucmVhZFZhclNsaWNlKClcbiAgfVxuXG4gIHR4Lm5ldHdvcmsgPSBuZXR3b3JrXG5cbiAgaWYgKF9fbm9TdHJpY3QpIHJldHVybiB0eFxuICBpZiAoYnVmZmVyUmVhZGVyLm9mZnNldCAhPT0gYnVmZmVyLmxlbmd0aCkgdGhyb3cgbmV3IEVycm9yKCdUcmFuc2FjdGlvbiBoYXMgdW5leHBlY3RlZCBkYXRhJylcblxuICByZXR1cm4gdHhcbn1cblxuVHJhbnNhY3Rpb24uZnJvbUhleCA9IGZ1bmN0aW9uIChoZXgsIG5ldHdvcmspIHtcbiAgcmV0dXJuIFRyYW5zYWN0aW9uLmZyb21CdWZmZXIoQnVmZmVyLmZyb20oaGV4LCAnaGV4JyksIG5ldHdvcmspXG59XG5cblRyYW5zYWN0aW9uLmlzQ29pbmJhc2VIYXNoID0gZnVuY3Rpb24gKGJ1ZmZlcikge1xuICB0eXBlZm9yY2UodHlwZXMuSGFzaDI1NmJpdCwgYnVmZmVyKVxuICBmb3IgKHZhciBpID0gMDsgaSA8IDMyOyArK2kpIHtcbiAgICBpZiAoYnVmZmVyW2ldICE9PSAwKSByZXR1cm4gZmFsc2VcbiAgfVxuICByZXR1cm4gdHJ1ZVxufVxuXG5UcmFuc2FjdGlvbi5wcm90b3R5cGUuaXNTYXBsaW5nQ29tcGF0aWJsZSA9IGZ1bmN0aW9uICgpIHtcbiAgcmV0dXJuIGNvaW5zLmlzWmNhc2godGhpcy5uZXR3b3JrKSAmJiB0aGlzLm92ZXJ3aW50ZXJlZCAmJiB0aGlzLnZlcnNpb24gPj0gemNhc2hWZXJzaW9uLlNBUExJTkdcbn1cblxuVHJhbnNhY3Rpb24ucHJvdG90eXBlLmlzT3ZlcndpbnRlckNvbXBhdGlibGUgPSBmdW5jdGlvbiAoKSB7XG4gIHJldHVybiBjb2lucy5pc1pjYXNoKHRoaXMubmV0d29yaykgJiYgdGhpcy5vdmVyd2ludGVyZWQgJiYgdGhpcy52ZXJzaW9uID49IHpjYXNoVmVyc2lvbi5PVkVSV0lOVEVSXG59XG5cblRyYW5zYWN0aW9uLnByb3RvdHlwZS5zdXBwb3J0c0pvaW5TcGxpdHMgPSBmdW5jdGlvbiAoKSB7XG4gIHJldHVybiBjb2lucy5pc1pjYXNoKHRoaXMubmV0d29yaykgJiYgdGhpcy5vdmVyd2ludGVyZWQgJiYgdGhpcy52ZXJzaW9uID49IHpjYXNoVmVyc2lvbi5KT0lOU1BMSVRTX1NVUFBPUlRcbn1cblxuVHJhbnNhY3Rpb24ucHJvdG90eXBlLnZlcnNpb25TdXBwb3J0c0Rhc2hTcGVjaWFsVHJhbnNhY3Rpb25zID0gZnVuY3Rpb24gKCkge1xuICByZXR1cm4gY29pbnMuaXNEYXNoKHRoaXMubmV0d29yaykgJiYgdGhpcy52ZXJzaW9uID49IDNcbn1cblxuVHJhbnNhY3Rpb24ucHJvdG90eXBlLmlzRGFzaFNwZWNpYWxUcmFuc2FjdGlvbiA9IGZ1bmN0aW9uICgpIHtcbiAgcmV0dXJuIHRoaXMudmVyc2lvblN1cHBvcnRzRGFzaFNwZWNpYWxUcmFuc2FjdGlvbnMoKSAmJiB0aGlzLnR5cGUgIT09IFRyYW5zYWN0aW9uLkRBU0hfTk9STUFMXG59XG5cblRyYW5zYWN0aW9uLnByb3RvdHlwZS5pc0NvaW5iYXNlID0gZnVuY3Rpb24gKCkge1xuICByZXR1cm4gdGhpcy5pbnMubGVuZ3RoID09PSAxICYmIFRyYW5zYWN0aW9uLmlzQ29pbmJhc2VIYXNoKHRoaXMuaW5zWzBdLmhhc2gpXG59XG5cblRyYW5zYWN0aW9uLnByb3RvdHlwZS5hZGRJbnB1dCA9IGZ1bmN0aW9uIChoYXNoLCBpbmRleCwgc2VxdWVuY2UsIHNjcmlwdFNpZykge1xuICB0eXBlZm9yY2UodHlwZXMudHVwbGUoXG4gICAgdHlwZXMuSGFzaDI1NmJpdCxcbiAgICB0eXBlcy5VSW50MzIsXG4gICAgdHlwZXMubWF5YmUodHlwZXMuVUludDMyKSxcbiAgICB0eXBlcy5tYXliZSh0eXBlcy5CdWZmZXIpXG4gICksIGFyZ3VtZW50cylcblxuICBpZiAodHlwZXMuTnVsbChzZXF1ZW5jZSkpIHtcbiAgICBzZXF1ZW5jZSA9IFRyYW5zYWN0aW9uLkRFRkFVTFRfU0VRVUVOQ0VcbiAgfVxuXG4gIC8vIEFkZCB0aGUgaW5wdXQgYW5kIHJldHVybiB0aGUgaW5wdXQncyBpbmRleFxuICByZXR1cm4gKHRoaXMuaW5zLnB1c2goe1xuICAgIGhhc2g6IGhhc2gsXG4gICAgaW5kZXg6IGluZGV4LFxuICAgIHNjcmlwdDogc2NyaXB0U2lnIHx8IEVNUFRZX1NDUklQVCxcbiAgICBzZXF1ZW5jZTogc2VxdWVuY2UsXG4gICAgd2l0bmVzczogRU1QVFlfV0lUTkVTU1xuICB9KSAtIDEpXG59XG5cblRyYW5zYWN0aW9uLnByb3RvdHlwZS5hZGRPdXRwdXQgPSBmdW5jdGlvbiAoc2NyaXB0UHViS2V5LCB2YWx1ZSkge1xuICB0eXBlZm9yY2UodHlwZXMudHVwbGUodHlwZXMuQnVmZmVyLCB0eXBlcy5TYXRvc2hpKSwgYXJndW1lbnRzKVxuXG4gIC8vIEFkZCB0aGUgb3V0cHV0IGFuZCByZXR1cm4gdGhlIG91dHB1dCdzIGluZGV4XG4gIHJldHVybiAodGhpcy5vdXRzLnB1c2goe1xuICAgIHNjcmlwdDogc2NyaXB0UHViS2V5LFxuICAgIHZhbHVlOiB2YWx1ZVxuICB9KSAtIDEpXG59XG5cblRyYW5zYWN0aW9uLnByb3RvdHlwZS5oYXNXaXRuZXNzZXMgPSBmdW5jdGlvbiAoKSB7XG4gIHJldHVybiB0aGlzLmlucy5zb21lKGZ1bmN0aW9uICh4KSB7XG4gICAgcmV0dXJuIHgud2l0bmVzcy5sZW5ndGggIT09IDBcbiAgfSlcbn1cblxuVHJhbnNhY3Rpb24ucHJvdG90eXBlLndlaWdodCA9IGZ1bmN0aW9uICgpIHtcbiAgdmFyIGJhc2UgPSB0aGlzLl9fYnl0ZUxlbmd0aChmYWxzZSlcbiAgdmFyIHRvdGFsID0gdGhpcy5fX2J5dGVMZW5ndGgodHJ1ZSlcbiAgcmV0dXJuIGJhc2UgKiAzICsgdG90YWxcbn1cblxuVHJhbnNhY3Rpb24ucHJvdG90eXBlLnZpcnR1YWxTaXplID0gZnVuY3Rpb24gKCkge1xuICByZXR1cm4gTWF0aC5jZWlsKHRoaXMud2VpZ2h0KCkgLyA0KVxufVxuXG5UcmFuc2FjdGlvbi5wcm90b3R5cGUuYnl0ZUxlbmd0aCA9IGZ1bmN0aW9uICgpIHtcbiAgcmV0dXJuIHRoaXMuX19ieXRlTGVuZ3RoKHRydWUpXG59XG5cblRyYW5zYWN0aW9uLnByb3RvdHlwZS56Y2FzaFRyYW5zYWN0aW9uQnl0ZUxlbmd0aCA9IGZ1bmN0aW9uICgpIHtcbiAgaWYgKCFjb2lucy5pc1pjYXNoKHRoaXMubmV0d29yaykpIHtcbiAgICAvKiBpc3RhbmJ1bCBpZ25vcmUgbmV4dCAqL1xuICAgIHRocm93IG5ldyBFcnJvcignemNhc2hUcmFuc2FjdGlvbkJ5dGVMZW5ndGggY2FuIG9ubHkgYmUgY2FsbGVkIHdoZW4gdXNpbmcgWmNhc2ggbmV0d29yaycpXG4gIH1cbiAgdmFyIGJ5dGVMZW5ndGggPSAwXG4gIGJ5dGVMZW5ndGggKz0gNCAgLy8gSGVhZGVyXG4gIGlmICh0aGlzLmlzT3ZlcndpbnRlckNvbXBhdGlibGUoKSkge1xuICAgIGJ5dGVMZW5ndGggKz0gNCAgLy8gblZlcnNpb25Hcm91cElkXG4gIH1cbiAgYnl0ZUxlbmd0aCArPSB2YXJ1aW50LmVuY29kaW5nTGVuZ3RoKHRoaXMuaW5zLmxlbmd0aCkgIC8vIHR4X2luX2NvdW50XG4gIGJ5dGVMZW5ndGggKz0gdGhpcy5pbnMucmVkdWNlKGZ1bmN0aW9uIChzdW0sIGlucHV0KSB7IHJldHVybiBzdW0gKyA0MCArIHZhclNsaWNlU2l6ZShpbnB1dC5zY3JpcHQpIH0sIDApICAvLyB0eF9pblxuICBieXRlTGVuZ3RoICs9IHZhcnVpbnQuZW5jb2RpbmdMZW5ndGgodGhpcy5vdXRzLmxlbmd0aCkgIC8vIHR4X291dF9jb3VudFxuICBieXRlTGVuZ3RoICs9IHRoaXMub3V0cy5yZWR1Y2UoZnVuY3Rpb24gKHN1bSwgb3V0cHV0KSB7IHJldHVybiBzdW0gKyA4ICsgdmFyU2xpY2VTaXplKG91dHB1dC5zY3JpcHQpIH0sIDApICAvLyB0eF9vdXRcbiAgYnl0ZUxlbmd0aCArPSA0ICAvLyBsb2NrX3RpbWVcbiAgaWYgKHRoaXMuaXNPdmVyd2ludGVyQ29tcGF0aWJsZSgpKSB7XG4gICAgYnl0ZUxlbmd0aCArPSA0ICAvLyBuRXhwaXJ5SGVpZ2h0XG4gIH1cbiAgaWYgKHRoaXMuaXNTYXBsaW5nQ29tcGF0aWJsZSgpKSB7XG4gICAgYnl0ZUxlbmd0aCArPSA4ICAvLyB2YWx1ZUJhbGFuY2VcbiAgICBieXRlTGVuZ3RoICs9IHZhcnVpbnQuZW5jb2RpbmdMZW5ndGgoMCkgLy8gaW5wdXRzXG4gICAgYnl0ZUxlbmd0aCArPSB2YXJ1aW50LmVuY29kaW5nTGVuZ3RoKDApIC8vIG91dHB1dHNcbiAgfVxuICBpZiAodGhpcy5zdXBwb3J0c0pvaW5TcGxpdHMoKSkge1xuICAgIGJ5dGVMZW5ndGggKz0gdmFydWludC5lbmNvZGluZ0xlbmd0aCgwKSAvLyBqb2luc3BsaXRzXG4gIH1cbiAgcmV0dXJuIGJ5dGVMZW5ndGhcbn1cblxuVHJhbnNhY3Rpb24ucHJvdG90eXBlLl9fYnl0ZUxlbmd0aCA9IGZ1bmN0aW9uIChfX2FsbG93V2l0bmVzcykge1xuICB2YXIgaGFzV2l0bmVzc2VzID0gX19hbGxvd1dpdG5lc3MgJiYgdGhpcy5oYXNXaXRuZXNzZXMoKVxuXG4gIGlmIChjb2lucy5pc1pjYXNoKHRoaXMubmV0d29yaykpIHtcbiAgICByZXR1cm4gdGhpcy56Y2FzaFRyYW5zYWN0aW9uQnl0ZUxlbmd0aCgpXG4gIH1cblxuICByZXR1cm4gKFxuICAgIChoYXNXaXRuZXNzZXMgPyAxMCA6IDgpICtcbiAgICB2YXJ1aW50LmVuY29kaW5nTGVuZ3RoKHRoaXMuaW5zLmxlbmd0aCkgK1xuICAgIHZhcnVpbnQuZW5jb2RpbmdMZW5ndGgodGhpcy5vdXRzLmxlbmd0aCkgK1xuICAgIHRoaXMuaW5zLnJlZHVjZShmdW5jdGlvbiAoc3VtLCBpbnB1dCkgeyByZXR1cm4gc3VtICsgNDAgKyB2YXJTbGljZVNpemUoaW5wdXQuc2NyaXB0KSB9LCAwKSArXG4gICAgdGhpcy5vdXRzLnJlZHVjZShmdW5jdGlvbiAoc3VtLCBvdXRwdXQpIHsgcmV0dXJuIHN1bSArIDggKyB2YXJTbGljZVNpemUob3V0cHV0LnNjcmlwdCkgfSwgMCkgK1xuICAgICh0aGlzLmlzRGFzaFNwZWNpYWxUcmFuc2FjdGlvbigpID8gdmFyU2xpY2VTaXplKHRoaXMuZXh0cmFQYXlsb2FkKSA6IDApICtcbiAgICAoaGFzV2l0bmVzc2VzID8gdGhpcy5pbnMucmVkdWNlKGZ1bmN0aW9uIChzdW0sIGlucHV0KSB7IHJldHVybiBzdW0gKyB2ZWN0b3JTaXplKGlucHV0LndpdG5lc3MpIH0sIDApIDogMClcbiAgKVxufVxuXG5UcmFuc2FjdGlvbi5wcm90b3R5cGUuY2xvbmUgPSBmdW5jdGlvbiAoKSB7XG4gIHZhciBuZXdUeCA9IG5ldyBUcmFuc2FjdGlvbih0aGlzLm5ldHdvcmspXG4gIG5ld1R4LnZlcnNpb24gPSB0aGlzLnZlcnNpb25cbiAgbmV3VHgubG9ja3RpbWUgPSB0aGlzLmxvY2t0aW1lXG4gIG5ld1R4Lm5ldHdvcmsgPSB0aGlzLm5ldHdvcmtcblxuICBpZiAoY29pbnMuaXNEYXNoKHRoaXMubmV0d29yaykpIHtcbiAgICBuZXdUeC50eXBlID0gdGhpcy50eXBlXG4gICAgbmV3VHguZXh0cmFQYXlsb2FkID0gdGhpcy5leHRyYVBheWxvYWRcbiAgfVxuXG4gIGlmIChjb2lucy5pc1pjYXNoKHRoaXMubmV0d29yaykpIHtcbiAgICBuZXdUeC5jb25zZW5zdXNCcmFuY2hJZCA9IHRoaXMuY29uc2Vuc3VzQnJhbmNoSWRcbiAgfVxuICBpZiAodGhpcy5pc092ZXJ3aW50ZXJDb21wYXRpYmxlKCkpIHtcbiAgICBuZXdUeC5vdmVyd2ludGVyZWQgPSB0aGlzLm92ZXJ3aW50ZXJlZFxuICAgIG5ld1R4LnZlcnNpb25Hcm91cElkID0gdGhpcy52ZXJzaW9uR3JvdXBJZFxuICAgIG5ld1R4LmV4cGlyeUhlaWdodCA9IHRoaXMuZXhwaXJ5SGVpZ2h0XG4gIH1cbiAgaWYgKHRoaXMuaXNTYXBsaW5nQ29tcGF0aWJsZSgpKSB7XG4gICAgbmV3VHgudmFsdWVCYWxhbmNlID0gdGhpcy52YWx1ZUJhbGFuY2VcbiAgfVxuXG4gIG5ld1R4LmlucyA9IHRoaXMuaW5zLm1hcChmdW5jdGlvbiAodHhJbikge1xuICAgIHJldHVybiB7XG4gICAgICBoYXNoOiB0eEluLmhhc2gsXG4gICAgICBpbmRleDogdHhJbi5pbmRleCxcbiAgICAgIHNjcmlwdDogdHhJbi5zY3JpcHQsXG4gICAgICBzZXF1ZW5jZTogdHhJbi5zZXF1ZW5jZSxcbiAgICAgIHdpdG5lc3M6IHR4SW4ud2l0bmVzc1xuICAgIH1cbiAgfSlcblxuICBuZXdUeC5vdXRzID0gdGhpcy5vdXRzLm1hcChmdW5jdGlvbiAodHhPdXQpIHtcbiAgICByZXR1cm4ge1xuICAgICAgc2NyaXB0OiB0eE91dC5zY3JpcHQsXG4gICAgICB2YWx1ZTogdHhPdXQudmFsdWVcbiAgICB9XG4gIH0pXG5cbiAgcmV0dXJuIG5ld1R4XG59XG5cbi8qKlxuICogR2V0IFpjYXNoIGhlYWRlciBvciB2ZXJzaW9uXG4gKiBAcmV0dXJucyB7bnVtYmVyfVxuICovXG5UcmFuc2FjdGlvbi5wcm90b3R5cGUuZ2V0SGVhZGVyID0gZnVuY3Rpb24gKCkge1xuICB2YXIgbWFzayA9ICh0aGlzLm92ZXJ3aW50ZXJlZCA/IDEgOiAwKVxuICB2YXIgaGVhZGVyID0gdGhpcy52ZXJzaW9uIHwgKG1hc2sgPDwgMzEpXG4gIHJldHVybiBoZWFkZXJcbn1cblxuLyoqXG4gKiBIYXNoIHRyYW5zYWN0aW9uIGZvciBzaWduaW5nIGEgc3BlY2lmaWMgaW5wdXQuXG4gKlxuICogQml0Y29pbiB1c2VzIGEgZGlmZmVyZW50IGhhc2ggZm9yIGVhY2ggc2lnbmVkIHRyYW5zYWN0aW9uIGlucHV0LlxuICogVGhpcyBtZXRob2QgY29waWVzIHRoZSB0cmFuc2FjdGlvbiwgbWFrZXMgdGhlIG5lY2Vzc2FyeSBjaGFuZ2VzIGJhc2VkIG9uIHRoZVxuICogaGFzaFR5cGUsIGFuZCB0aGVuIGhhc2hlcyB0aGUgcmVzdWx0LlxuICogVGhpcyBoYXNoIGNhbiB0aGVuIGJlIHVzZWQgdG8gc2lnbiB0aGUgcHJvdmlkZWQgdHJhbnNhY3Rpb24gaW5wdXQuXG4gKi9cblRyYW5zYWN0aW9uLnByb3RvdHlwZS5oYXNoRm9yU2lnbmF0dXJlID0gZnVuY3Rpb24gKGluSW5kZXgsIHByZXZPdXRTY3JpcHQsIGhhc2hUeXBlKSB7XG4gIHR5cGVmb3JjZSh0eXBlcy50dXBsZSh0eXBlcy5VSW50MzIsIHR5cGVzLkJ1ZmZlciwgLyogdHlwZXMuVUludDggKi8gdHlwZXMuTnVtYmVyKSwgYXJndW1lbnRzKVxuXG4gIC8vIGh0dHBzOi8vZ2l0aHViLmNvbS9iaXRjb2luL2JpdGNvaW4vYmxvYi9tYXN0ZXIvc3JjL3Rlc3Qvc2lnaGFzaF90ZXN0cy5jcHAjTDI5XG4gIGlmIChpbkluZGV4ID49IHRoaXMuaW5zLmxlbmd0aCkgcmV0dXJuIE9ORVxuXG4gIC8vIGlnbm9yZSBPUF9DT0RFU0VQQVJBVE9SXG4gIHZhciBvdXJTY3JpcHQgPSBic2NyaXB0LmNvbXBpbGUoYnNjcmlwdC5kZWNvbXBpbGUocHJldk91dFNjcmlwdCkuZmlsdGVyKGZ1bmN0aW9uICh4KSB7XG4gICAgcmV0dXJuIHggIT09IG9wY29kZXMuT1BfQ09ERVNFUEFSQVRPUlxuICB9KSlcblxuICB2YXIgdHhUbXAgPSB0aGlzLmNsb25lKClcblxuICAvLyBTSUdIQVNIX05PTkU6IGlnbm9yZSBhbGwgb3V0cHV0cz8gKHdpbGRjYXJkIHBheWVlKVxuICBpZiAoKGhhc2hUeXBlICYgMHgxZikgPT09IFRyYW5zYWN0aW9uLlNJR0hBU0hfTk9ORSkge1xuICAgIHR4VG1wLm91dHMgPSBbXVxuXG4gICAgLy8gaWdub3JlIHNlcXVlbmNlIG51bWJlcnMgKGV4Y2VwdCBhdCBpbkluZGV4KVxuICAgIHR4VG1wLmlucy5mb3JFYWNoKGZ1bmN0aW9uIChpbnB1dCwgaSkge1xuICAgICAgaWYgKGkgPT09IGluSW5kZXgpIHJldHVyblxuXG4gICAgICBpbnB1dC5zZXF1ZW5jZSA9IDBcbiAgICB9KVxuXG4gICAgLy8gU0lHSEFTSF9TSU5HTEU6IGlnbm9yZSBhbGwgb3V0cHV0cywgZXhjZXB0IGF0IHRoZSBzYW1lIGluZGV4P1xuICB9IGVsc2UgaWYgKChoYXNoVHlwZSAmIDB4MWYpID09PSBUcmFuc2FjdGlvbi5TSUdIQVNIX1NJTkdMRSkge1xuICAgIC8vIGh0dHBzOi8vZ2l0aHViLmNvbS9iaXRjb2luL2JpdGNvaW4vYmxvYi9tYXN0ZXIvc3JjL3Rlc3Qvc2lnaGFzaF90ZXN0cy5jcHAjTDYwXG4gICAgaWYgKGluSW5kZXggPj0gdGhpcy5vdXRzLmxlbmd0aCkgcmV0dXJuIE9ORVxuXG4gICAgLy8gdHJ1bmNhdGUgb3V0cHV0cyBhZnRlclxuICAgIHR4VG1wLm91dHMubGVuZ3RoID0gaW5JbmRleCArIDFcblxuICAgIC8vIFwiYmxhbmtcIiBvdXRwdXRzIGJlZm9yZVxuICAgIGZvciAodmFyIGkgPSAwOyBpIDwgaW5JbmRleDsgaSsrKSB7XG4gICAgICB0eFRtcC5vdXRzW2ldID0gQkxBTktfT1VUUFVUXG4gICAgfVxuXG4gICAgLy8gaWdub3JlIHNlcXVlbmNlIG51bWJlcnMgKGV4Y2VwdCBhdCBpbkluZGV4KVxuICAgIHR4VG1wLmlucy5mb3JFYWNoKGZ1bmN0aW9uIChpbnB1dCwgeSkge1xuICAgICAgaWYgKHkgPT09IGluSW5kZXgpIHJldHVyblxuXG4gICAgICBpbnB1dC5zZXF1ZW5jZSA9IDBcbiAgICB9KVxuICB9XG5cbiAgLy8gU0lHSEFTSF9BTllPTkVDQU5QQVk6IGlnbm9yZSBpbnB1dHMgZW50aXJlbHk/XG4gIGlmIChoYXNoVHlwZSAmIFRyYW5zYWN0aW9uLlNJR0hBU0hfQU5ZT05FQ0FOUEFZKSB7XG4gICAgdHhUbXAuaW5zID0gW3R4VG1wLmluc1tpbkluZGV4XV1cbiAgICB0eFRtcC5pbnNbMF0uc2NyaXB0ID0gb3VyU2NyaXB0XG5cbiAgICAvLyBTSUdIQVNIX0FMTDogb25seSBpZ25vcmUgaW5wdXQgc2NyaXB0c1xuICB9IGVsc2Uge1xuICAgIC8vIFwiYmxhbmtcIiBvdGhlcnMgaW5wdXQgc2NyaXB0c1xuICAgIHR4VG1wLmlucy5mb3JFYWNoKGZ1bmN0aW9uIChpbnB1dCkgeyBpbnB1dC5zY3JpcHQgPSBFTVBUWV9TQ1JJUFQgfSlcbiAgICB0eFRtcC5pbnNbaW5JbmRleF0uc2NyaXB0ID0gb3VyU2NyaXB0XG4gIH1cblxuICAvLyBzZXJpYWxpemUgYW5kIGhhc2hcbiAgdmFyIGJ1ZmZlciA9IEJ1ZmZlci5hbGxvY1Vuc2FmZSh0eFRtcC5fX2J5dGVMZW5ndGgoZmFsc2UpICsgNClcbiAgYnVmZmVyLndyaXRlSW50MzJMRShoYXNoVHlwZSwgYnVmZmVyLmxlbmd0aCAtIDQpXG4gIHR4VG1wLl9fdG9CdWZmZXIoYnVmZmVyLCAwLCBmYWxzZSlcblxuICByZXR1cm4gYmNyeXB0by5oYXNoMjU2KGJ1ZmZlcilcbn1cblxuLyoqXG4gKiBDYWxjdWxhdGUgdGhlIGhhc2ggdG8gdmVyaWZ5IHRoZSBzaWduYXR1cmUgYWdhaW5zdFxuICogQHBhcmFtIGluSW5kZXhcbiAqIEBwYXJhbSBwcmV2b3V0U2NyaXB0XG4gKiBAcGFyYW0gdmFsdWUgLSBUaGUgcHJldmlvdXMgb3V0cHV0J3MgYW1vdW50XG4gKiBAcGFyYW0gaGFzaFR5cGVcbiAqIEBwYXJhbSBpc1NlZ3dpdFxuICogQHJldHVybnMgeyp9XG4gKi9cblRyYW5zYWN0aW9uLnByb3RvdHlwZS5oYXNoRm9yU2lnbmF0dXJlQnlOZXR3b3JrID0gZnVuY3Rpb24gKFxuICBpbkluZGV4LFxuICBwcmV2b3V0U2NyaXB0LFxuICB2YWx1ZSxcbiAgaGFzaFR5cGUsXG4gIGlzU2Vnd2l0LFxuKSB7XG4gIHN3aXRjaCAoY29pbnMuZ2V0TWFpbm5ldCh0aGlzLm5ldHdvcmspKSB7XG4gICAgY2FzZSBuZXR3b3Jrcy56Y2FzaDpcbiAgICAgIHJldHVybiB0aGlzLmhhc2hGb3JaY2FzaFNpZ25hdHVyZShpbkluZGV4LCBwcmV2b3V0U2NyaXB0LCB2YWx1ZSwgaGFzaFR5cGUpXG4gICAgY2FzZSBuZXR3b3Jrcy5iaXRjb2luY2FzaDpcbiAgICBjYXNlIG5ldHdvcmtzLmJpdGNvaW5zdjpcbiAgICBjYXNlIG5ldHdvcmtzLmJpdGNvaW5nb2xkOlxuICAgICAgLypcbiAgICAgICAgQml0Y29pbiBDYXNoIHN1cHBvcnRzIGEgRk9SS0lEIGZsYWcuIFdoZW4gc2V0LCB3ZSBoYXNoIHVzaW5nIGhhc2hpbmcgYWxnb3JpdGhtXG4gICAgICAgICB0aGF0IGlzIHVzZWQgZm9yIHNlZ3JlZ2F0ZWQgd2l0bmVzcyB0cmFuc2FjdGlvbnMgKGRlZmluZWQgaW4gQklQMTQzKS5cblxuICAgICAgICBUaGUgZmxhZyBpcyBhbHNvIHVzZWQgYnkgQml0Y29pblNWIGFuZCBCaXRjb2luR29sZFxuXG4gICAgICAgIGh0dHBzOi8vZ2l0aHViLmNvbS9iaXRjb2luY2FzaG9yZy9iaXRjb2luY2FzaC5vcmcvYmxvYi9tYXN0ZXIvc3BlYy9yZXBsYXktcHJvdGVjdGVkLXNpZ2hhc2gubWRcbiAgICAgICAqL1xuICAgICAgdmFyIGFkZEZvcmtJZCA9IGhhc2hUeXBlICYgVHJhbnNhY3Rpb24uU0lHSEFTSF9GT1JLSUQgPiAwXG5cbiAgICAgIGlmIChhZGRGb3JrSWQpIHtcbiAgICAgICAgLypcbiAgICAgICAgICBgYFRoZSBzaWdoYXNoIHR5cGUgaXMgYWx0ZXJlZCB0byBpbmNsdWRlIGEgMjQtYml0IGZvcmsgaWQgaW4gaXRzIG1vc3Qgc2lnbmlmaWNhbnQgYml0cy4nJ1xuICAgICAgICAgIFdlIGFsc28gdXNlIHVuc2lnbmVkIHJpZ2h0IHNoaWZ0IG9wZXJhdG9yIGA+Pj5gIHRvIGNhc3QgdG8gVUludDMyXG4gICAgICAgICAgaHR0cHM6Ly9kZXZlbG9wZXIubW96aWxsYS5vcmcvZW4tVVMvZG9jcy9XZWIvSmF2YVNjcmlwdC9SZWZlcmVuY2UvT3BlcmF0b3JzL1Vuc2lnbmVkX3JpZ2h0X3NoaWZ0XG4gICAgICAgICAqL1xuICAgICAgICBoYXNoVHlwZSA9IChoYXNoVHlwZSB8IHRoaXMubmV0d29yay5mb3JrSWQgPDwgOCkgPj4+IDBcbiAgICAgICAgcmV0dXJuIHRoaXMuaGFzaEZvcldpdG5lc3NWMChpbkluZGV4LCBwcmV2b3V0U2NyaXB0LCB2YWx1ZSwgaGFzaFR5cGUpXG4gICAgICB9XG4gIH1cblxuICBpZiAoaXNTZWd3aXQpIHtcbiAgICByZXR1cm4gdGhpcy5oYXNoRm9yV2l0bmVzc1YwKGluSW5kZXgsIHByZXZvdXRTY3JpcHQsIHZhbHVlLCBoYXNoVHlwZSlcbiAgfSBlbHNlIHtcbiAgICByZXR1cm4gdGhpcy5oYXNoRm9yU2lnbmF0dXJlKGluSW5kZXgsIHByZXZvdXRTY3JpcHQsIGhhc2hUeXBlKVxuICB9XG59XG5cbi8qKiBAZGVwcmVjYXRlZCB1c2UgaGFzaEZvclNpZ25hdHVyZUJ5TmV0d29yayAqL1xuLyogaXN0YW5idWwgaWdub3JlIG5leHQgKi9cblRyYW5zYWN0aW9uLnByb3RvdHlwZS5oYXNoRm9yQ2FzaFNpZ25hdHVyZSA9IGZ1bmN0aW9uICguLi5hcmdzKSB7XG4gIGlmIChcbiAgICBjb2lucy5nZXRNYWlubmV0KHRoaXMubmV0d29yaykgIT09IG5ldHdvcmtzLmJpdGNvaW5jYXNoICYmXG4gICAgY29pbnMuZ2V0TWFpbm5ldCh0aGlzLm5ldHdvcmspICE9PSBuZXR3b3Jrcy5iaXRjb2luc3ZcbiAgKSB7XG4gICAgdGhyb3cgbmV3IEVycm9yKGBjYWxsZWQgaGFzaEZvckNhc2hTaWduYXR1cmUgb24gdHJhbnNhY3Rpb24gd2l0aCBuZXR3b3JrICR7Y29pbnMuZ2V0TmV0d29ya05hbWUodGhpcy5uZXR3b3JrKX1gKVxuICB9XG4gIHJldHVybiB0aGlzLmhhc2hGb3JTaWduYXR1cmVCeU5ldHdvcmsoLi4uYXJncylcbn1cblxuLyoqIEBkZXByZWNhdGVkIHVzZSBoYXNoRm9yU2lnbmF0dXJlQnlOZXR3b3JrICovXG4vKiBpc3RhbmJ1bCBpZ25vcmUgbmV4dCAqL1xuVHJhbnNhY3Rpb24ucHJvdG90eXBlLmhhc2hGb3JHb2xkU2lnbmF0dXJlID0gZnVuY3Rpb24gKC4uLmFyZ3MpIHtcbiAgaWYgKGNvaW5zLmdldE1haW5uZXQodGhpcy5uZXR3b3JrKSAhPT0gbmV0d29ya3MuYml0Y29pbmdvbGQpIHtcbiAgICB0aHJvdyBuZXcgRXJyb3IoYGNhbGxlZCBoYXNoRm9yR29sZFNpZ25hdHVyZSBvbiB0cmFuc2FjdGlvbiB3aXRoIG5ldHdvcmsgJHtjb2lucy5nZXROZXR3b3JrTmFtZSh0aGlzLm5ldHdvcmspfWApXG4gIH1cbiAgcmV0dXJuIHRoaXMuaGFzaEZvclNpZ25hdHVyZUJ5TmV0d29yayguLi5hcmdzKVxufVxuXG4vKipcbiAqIEJsYWtlMmIgaGFzaGluZyBhbGdvcml0aG0gZm9yIFpjYXNoXG4gKiBAcGFyYW0gYnVmZmVyVG9IYXNoXG4gKiBAcGFyYW0gcGVyc29uYWxpemF0aW9uXG4gKiBAcmV0dXJucyAyNTYtYml0IEJMQUtFMmIgaGFzaFxuICovXG5UcmFuc2FjdGlvbi5wcm90b3R5cGUuZ2V0Qmxha2UyYkhhc2ggPSBmdW5jdGlvbiAoYnVmZmVyVG9IYXNoLCBwZXJzb25hbGl6YXRpb24pIHtcbiAgdmFyIG91dCA9IEJ1ZmZlci5hbGxvY1Vuc2FmZSgzMilcbiAgcmV0dXJuIGJsYWtlMmIob3V0Lmxlbmd0aCwgbnVsbCwgbnVsbCwgQnVmZmVyLmZyb20ocGVyc29uYWxpemF0aW9uKSkudXBkYXRlKGJ1ZmZlclRvSGFzaCkuZGlnZXN0KG91dClcbn1cblxuLyoqXG4gKiBCdWlsZCBhIGhhc2ggZm9yIGFsbCBvciBub25lIG9mIHRoZSB0cmFuc2FjdGlvbiBpbnB1dHMgZGVwZW5kaW5nIG9uIHRoZSBoYXNodHlwZVxuICogQHBhcmFtIGhhc2hUeXBlXG4gKiBAcmV0dXJucyBkb3VibGUgU0hBLTI1NiwgMjU2LWJpdCBCTEFLRTJiIGhhc2ggb3IgMjU2LWJpdCB6ZXJvIGlmIGRvZXNuJ3QgYXBwbHlcbiAqL1xuVHJhbnNhY3Rpb24ucHJvdG90eXBlLmdldFByZXZvdXRIYXNoID0gZnVuY3Rpb24gKGhhc2hUeXBlKSB7XG4gIGlmICghKGhhc2hUeXBlICYgVHJhbnNhY3Rpb24uU0lHSEFTSF9BTllPTkVDQU5QQVkpKSB7XG4gICAgdmFyIGJ1ZmZlcldyaXRlciA9IG5ldyBCdWZmZXJXcml0ZXIoQnVmZmVyLmFsbG9jVW5zYWZlKDM2ICogdGhpcy5pbnMubGVuZ3RoKSlcblxuICAgIHRoaXMuaW5zLmZvckVhY2goZnVuY3Rpb24gKHR4SW4pIHtcbiAgICAgIGJ1ZmZlcldyaXRlci53cml0ZVNsaWNlKHR4SW4uaGFzaClcbiAgICAgIGJ1ZmZlcldyaXRlci53cml0ZVVJbnQzMih0eEluLmluZGV4KVxuICAgIH0pXG5cbiAgICBpZiAoY29pbnMuaXNaY2FzaCh0aGlzLm5ldHdvcmspKSB7XG4gICAgICByZXR1cm4gdGhpcy5nZXRCbGFrZTJiSGFzaChidWZmZXJXcml0ZXIuYnVmZmVyLCAnWmNhc2hQcmV2b3V0SGFzaCcpXG4gICAgfVxuICAgIHJldHVybiBiY3J5cHRvLmhhc2gyNTYoYnVmZmVyV3JpdGVyLmJ1ZmZlcilcbiAgfVxuICByZXR1cm4gWkVST1xufVxuXG4vKipcbiAqIEJ1aWxkIGEgaGFzaCBmb3IgYWxsIG9yIG5vbmUgb2YgdGhlIHRyYW5zYWN0aW9ucyBpbnB1dHMgc2VxdWVuY2UgbnVtYmVycyBkZXBlbmRpbmcgb24gdGhlIGhhc2h0eXBlXG4gKiBAcGFyYW0gaGFzaFR5cGVcbiAqIEByZXR1cm5zIGRvdWJsZSBTSEEtMjU2LCAyNTYtYml0IEJMQUtFMmIgaGFzaCBvciAyNTYtYml0IHplcm8gaWYgZG9lc24ndCBhcHBseVxuICovXG5UcmFuc2FjdGlvbi5wcm90b3R5cGUuZ2V0U2VxdWVuY2VIYXNoID0gZnVuY3Rpb24gKGhhc2hUeXBlKSB7XG4gIGlmICghKGhhc2hUeXBlICYgVHJhbnNhY3Rpb24uU0lHSEFTSF9BTllPTkVDQU5QQVkpICYmXG4gICAgKGhhc2hUeXBlICYgMHgxZikgIT09IFRyYW5zYWN0aW9uLlNJR0hBU0hfU0lOR0xFICYmXG4gICAgKGhhc2hUeXBlICYgMHgxZikgIT09IFRyYW5zYWN0aW9uLlNJR0hBU0hfTk9ORSkge1xuICAgIHZhciBidWZmZXJXcml0ZXIgPSBuZXcgQnVmZmVyV3JpdGVyKEJ1ZmZlci5hbGxvY1Vuc2FmZSg0ICogdGhpcy5pbnMubGVuZ3RoKSlcblxuICAgIHRoaXMuaW5zLmZvckVhY2goZnVuY3Rpb24gKHR4SW4pIHtcbiAgICAgIGJ1ZmZlcldyaXRlci53cml0ZVVJbnQzMih0eEluLnNlcXVlbmNlKVxuICAgIH0pXG5cbiAgICBpZiAoY29pbnMuaXNaY2FzaCh0aGlzLm5ldHdvcmspKSB7XG4gICAgICByZXR1cm4gdGhpcy5nZXRCbGFrZTJiSGFzaChidWZmZXJXcml0ZXIuYnVmZmVyLCAnWmNhc2hTZXF1ZW5jSGFzaCcpXG4gICAgfVxuICAgIHJldHVybiBiY3J5cHRvLmhhc2gyNTYoYnVmZmVyV3JpdGVyLmJ1ZmZlcilcbiAgfVxuICByZXR1cm4gWkVST1xufVxuXG4vKipcbiAqIEJ1aWxkIGEgaGFzaCBmb3Igb25lLCBhbGwgb3Igbm9uZSBvZiB0aGUgdHJhbnNhY3Rpb24gb3V0cHV0cyBkZXBlbmRpbmcgb24gdGhlIGhhc2h0eXBlXG4gKiBAcGFyYW0gaGFzaFR5cGVcbiAqIEBwYXJhbSBpbkluZGV4XG4gKiBAcmV0dXJucyBkb3VibGUgU0hBLTI1NiwgMjU2LWJpdCBCTEFLRTJiIGhhc2ggb3IgMjU2LWJpdCB6ZXJvIGlmIGRvZXNuJ3QgYXBwbHlcbiAqL1xuVHJhbnNhY3Rpb24ucHJvdG90eXBlLmdldE91dHB1dHNIYXNoID0gZnVuY3Rpb24gKGhhc2hUeXBlLCBpbkluZGV4KSB7XG4gIHZhciBidWZmZXJXcml0ZXJcbiAgaWYgKChoYXNoVHlwZSAmIDB4MWYpICE9PSBUcmFuc2FjdGlvbi5TSUdIQVNIX1NJTkdMRSAmJiAoaGFzaFR5cGUgJiAweDFmKSAhPT0gVHJhbnNhY3Rpb24uU0lHSEFTSF9OT05FKSB7XG4gICAgLy8gRmluZCBvdXQgdGhlIHNpemUgb2YgdGhlIG91dHB1dHMgYW5kIHdyaXRlIHRoZW1cbiAgICB2YXIgdHhPdXRzU2l6ZSA9IHRoaXMub3V0cy5yZWR1Y2UoZnVuY3Rpb24gKHN1bSwgb3V0cHV0KSB7XG4gICAgICByZXR1cm4gc3VtICsgOCArIHZhclNsaWNlU2l6ZShvdXRwdXQuc2NyaXB0KVxuICAgIH0sIDApXG5cbiAgICBidWZmZXJXcml0ZXIgPSBuZXcgQnVmZmVyV3JpdGVyKEJ1ZmZlci5hbGxvY1Vuc2FmZSh0eE91dHNTaXplKSlcblxuICAgIHRoaXMub3V0cy5mb3JFYWNoKGZ1bmN0aW9uIChvdXQpIHtcbiAgICAgIGJ1ZmZlcldyaXRlci53cml0ZVVJbnQ2NChvdXQudmFsdWUpXG4gICAgICBidWZmZXJXcml0ZXIud3JpdGVWYXJTbGljZShvdXQuc2NyaXB0KVxuICAgIH0pXG5cbiAgICBpZiAoY29pbnMuaXNaY2FzaCh0aGlzLm5ldHdvcmspKSB7XG4gICAgICByZXR1cm4gdGhpcy5nZXRCbGFrZTJiSGFzaChidWZmZXJXcml0ZXIuYnVmZmVyLCAnWmNhc2hPdXRwdXRzSGFzaCcpXG4gICAgfVxuICAgIHJldHVybiBiY3J5cHRvLmhhc2gyNTYoYnVmZmVyV3JpdGVyLmJ1ZmZlcilcbiAgfSBlbHNlIGlmICgoaGFzaFR5cGUgJiAweDFmKSA9PT0gVHJhbnNhY3Rpb24uU0lHSEFTSF9TSU5HTEUgJiYgaW5JbmRleCA8IHRoaXMub3V0cy5sZW5ndGgpIHtcbiAgICAvLyBXcml0ZSBvbmx5IHRoZSBvdXRwdXQgc3BlY2lmaWVkIGluIGluSW5kZXhcbiAgICB2YXIgb3V0cHV0ID0gdGhpcy5vdXRzW2luSW5kZXhdXG5cbiAgICBidWZmZXJXcml0ZXIgPSBuZXcgQnVmZmVyV3JpdGVyKEJ1ZmZlci5hbGxvY1Vuc2FmZSg4ICsgdmFyU2xpY2VTaXplKG91dHB1dC5zY3JpcHQpKSlcbiAgICBidWZmZXJXcml0ZXIud3JpdGVVSW50NjQob3V0cHV0LnZhbHVlKVxuICAgIGJ1ZmZlcldyaXRlci53cml0ZVZhclNsaWNlKG91dHB1dC5zY3JpcHQpXG5cbiAgICBpZiAoY29pbnMuaXNaY2FzaCh0aGlzLm5ldHdvcmspKSB7XG4gICAgICByZXR1cm4gdGhpcy5nZXRCbGFrZTJiSGFzaChidWZmZXJXcml0ZXIuYnVmZmVyLCAnWmNhc2hPdXRwdXRzSGFzaCcpXG4gICAgfVxuICAgIHJldHVybiBiY3J5cHRvLmhhc2gyNTYoYnVmZmVyV3JpdGVyLmJ1ZmZlcilcbiAgfVxuICByZXR1cm4gWkVST1xufVxuXG4vKipcbiAqIEhhc2ggdHJhbnNhY3Rpb24gZm9yIHNpZ25pbmcgYSB0cmFuc3BhcmVudCB0cmFuc2FjdGlvbiBpbiBaY2FzaC4gUHJvdGVjdGVkIHRyYW5zYWN0aW9ucyBhcmUgbm90IHN1cHBvcnRlZC5cbiAqIEBwYXJhbSBpbkluZGV4XG4gKiBAcGFyYW0gcHJldk91dFNjcmlwdFxuICogQHBhcmFtIHZhbHVlXG4gKiBAcGFyYW0gaGFzaFR5cGVcbiAqIEByZXR1cm5zIGRvdWJsZSBTSEEtMjU2IG9yIDI1Ni1iaXQgQkxBS0UyYiBoYXNoXG4gKi9cblRyYW5zYWN0aW9uLnByb3RvdHlwZS5oYXNoRm9yWmNhc2hTaWduYXR1cmUgPSBmdW5jdGlvbiAoaW5JbmRleCwgcHJldk91dFNjcmlwdCwgdmFsdWUsIGhhc2hUeXBlKSB7XG4gIHR5cGVmb3JjZSh0eXBlcy50dXBsZSh0eXBlcy5VSW50MzIsIHR5cGVzLkJ1ZmZlciwgdHlwZXMuU2F0b3NoaSwgdHlwZXMuVUludDMyKSwgYXJndW1lbnRzKVxuICBpZiAoIWNvaW5zLmlzWmNhc2godGhpcy5uZXR3b3JrKSkge1xuICAgIC8qIGlzdGFuYnVsIGlnbm9yZSBuZXh0ICovXG4gICAgdGhyb3cgbmV3IEVycm9yKCdoYXNoRm9yWmNhc2hTaWduYXR1cmUgY2FuIG9ubHkgYmUgY2FsbGVkIHdoZW4gdXNpbmcgWmNhc2ggbmV0d29yaycpXG4gIH1cblxuICBpZiAoaW5JbmRleCA+PSB0aGlzLmlucy5sZW5ndGggJiYgaW5JbmRleCAhPT0gVkFMVUVfVUlOVDY0X01BWCkge1xuICAgIC8qIGlzdGFuYnVsIGlnbm9yZSBuZXh0ICovXG4gICAgdGhyb3cgbmV3IEVycm9yKCdJbnB1dCBpbmRleCBpcyBvdXQgb2YgcmFuZ2UnKVxuICB9XG5cbiAgaWYgKHRoaXMuaXNPdmVyd2ludGVyQ29tcGF0aWJsZSgpKSB7XG4gICAgdmFyIGhhc2hQcmV2b3V0cyA9IHRoaXMuZ2V0UHJldm91dEhhc2goaGFzaFR5cGUpXG4gICAgdmFyIGhhc2hTZXF1ZW5jZSA9IHRoaXMuZ2V0U2VxdWVuY2VIYXNoKGhhc2hUeXBlKVxuICAgIHZhciBoYXNoT3V0cHV0cyA9IHRoaXMuZ2V0T3V0cHV0c0hhc2goaGFzaFR5cGUsIGluSW5kZXgpXG4gICAgdmFyIGhhc2hKb2luU3BsaXRzID0gWkVST1xuICAgIHZhciBoYXNoU2hpZWxkZWRTcGVuZHMgPSBaRVJPXG4gICAgdmFyIGhhc2hTaGllbGRlZE91dHB1dHMgPSBaRVJPXG5cbiAgICB2YXIgYnVmZmVyV3JpdGVyXG4gICAgdmFyIGJhc2VCdWZmZXJTaXplID0gMFxuICAgIGJhc2VCdWZmZXJTaXplICs9IDQgKiA1ICAvLyBoZWFkZXIsIG5WZXJzaW9uR3JvdXBJZCwgbG9ja190aW1lLCBuRXhwaXJ5SGVpZ2h0LCBoYXNoVHlwZVxuICAgIGJhc2VCdWZmZXJTaXplICs9IDMyICogNCAgLy8gMjU2IGhhc2hlczogaGFzaFByZXZvdXRzLCBoYXNoU2VxdWVuY2UsIGhhc2hPdXRwdXRzLCBoYXNoSm9pblNwbGl0c1xuICAgIGlmIChpbkluZGV4ICE9PSBWQUxVRV9VSU5UNjRfTUFYKSB7XG4gICAgICAvLyBJZiB0aGlzIGhhc2ggaXMgZm9yIGEgdHJhbnNwYXJlbnQgaW5wdXQgc2lnbmF0dXJlIChpLmUuIG5vdCBmb3IgdHhUby5qb2luU3BsaXRTaWcpLCB3ZSBuZWVkIGV4dHJhIHNwYWNlXG4gICAgICBiYXNlQnVmZmVyU2l6ZSArPSA0ICogMiAgLy8gaW5wdXQuaW5kZXgsIGlucHV0LnNlcXVlbmNlXG4gICAgICBiYXNlQnVmZmVyU2l6ZSArPSA4ICAvLyB2YWx1ZVxuICAgICAgYmFzZUJ1ZmZlclNpemUgKz0gMzIgIC8vIGlucHV0Lmhhc2hcbiAgICAgIGJhc2VCdWZmZXJTaXplICs9IHZhclNsaWNlU2l6ZShwcmV2T3V0U2NyaXB0KSAgLy8gcHJldk91dFNjcmlwdFxuICAgIH1cbiAgICBpZiAodGhpcy5pc1NhcGxpbmdDb21wYXRpYmxlKCkpIHtcbiAgICAgIGJhc2VCdWZmZXJTaXplICs9IDMyICogMiAgLy8gaGFzaFNoaWVsZGVkU3BlbmRzIGFuZCBoYXNoU2hpZWxkZWRPdXRwdXRzXG4gICAgICBiYXNlQnVmZmVyU2l6ZSArPSA4ICAvLyB2YWx1ZUJhbGFuY2VcbiAgICB9XG4gICAgYnVmZmVyV3JpdGVyID0gbmV3IEJ1ZmZlcldyaXRlcihCdWZmZXIuYWxsb2MoYmFzZUJ1ZmZlclNpemUpKVxuXG4gICAgYnVmZmVyV3JpdGVyLndyaXRlSW50MzIodGhpcy5nZXRIZWFkZXIoKSlcbiAgICBidWZmZXJXcml0ZXIud3JpdGVVSW50MzIodGhpcy52ZXJzaW9uR3JvdXBJZClcbiAgICBidWZmZXJXcml0ZXIud3JpdGVTbGljZShoYXNoUHJldm91dHMpXG4gICAgYnVmZmVyV3JpdGVyLndyaXRlU2xpY2UoaGFzaFNlcXVlbmNlKVxuICAgIGJ1ZmZlcldyaXRlci53cml0ZVNsaWNlKGhhc2hPdXRwdXRzKVxuICAgIGJ1ZmZlcldyaXRlci53cml0ZVNsaWNlKGhhc2hKb2luU3BsaXRzKVxuICAgIGlmICh0aGlzLmlzU2FwbGluZ0NvbXBhdGlibGUoKSkge1xuICAgICAgYnVmZmVyV3JpdGVyLndyaXRlU2xpY2UoaGFzaFNoaWVsZGVkU3BlbmRzKVxuICAgICAgYnVmZmVyV3JpdGVyLndyaXRlU2xpY2UoaGFzaFNoaWVsZGVkT3V0cHV0cylcbiAgICB9XG4gICAgYnVmZmVyV3JpdGVyLndyaXRlVUludDMyKHRoaXMubG9ja3RpbWUpXG4gICAgYnVmZmVyV3JpdGVyLndyaXRlVUludDMyKHRoaXMuZXhwaXJ5SGVpZ2h0KVxuICAgIGlmICh0aGlzLmlzU2FwbGluZ0NvbXBhdGlibGUoKSkge1xuICAgICAgYnVmZmVyV3JpdGVyLndyaXRlU2xpY2UoVkFMVUVfSU5UNjRfWkVSTylcbiAgICB9XG4gICAgYnVmZmVyV3JpdGVyLndyaXRlVUludDMyKGhhc2hUeXBlKVxuXG4gICAgLy8gSWYgdGhpcyBoYXNoIGlzIGZvciBhIHRyYW5zcGFyZW50IGlucHV0IHNpZ25hdHVyZSAoaS5lLiBub3QgZm9yIHR4VG8uam9pblNwbGl0U2lnKTpcbiAgICBpZiAoaW5JbmRleCAhPT0gVkFMVUVfVUlOVDY0X01BWCkge1xuICAgICAgLy8gVGhlIGlucHV0IGJlaW5nIHNpZ25lZCAocmVwbGFjaW5nIHRoZSBzY3JpcHRTaWcgd2l0aCBzY3JpcHRDb2RlICsgYW1vdW50KVxuICAgICAgLy8gVGhlIHByZXZvdXQgbWF5IGFscmVhZHkgYmUgY29udGFpbmVkIGluIGhhc2hQcmV2b3V0LCBhbmQgdGhlIG5TZXF1ZW5jZVxuICAgICAgLy8gbWF5IGFscmVhZHkgYmUgY29udGFpbmVkIGluIGhhc2hTZXF1ZW5jZS5cbiAgICAgIHZhciBpbnB1dCA9IHRoaXMuaW5zW2luSW5kZXhdXG4gICAgICBidWZmZXJXcml0ZXIud3JpdGVTbGljZShpbnB1dC5oYXNoKVxuICAgICAgYnVmZmVyV3JpdGVyLndyaXRlVUludDMyKGlucHV0LmluZGV4KVxuICAgICAgYnVmZmVyV3JpdGVyLndyaXRlVmFyU2xpY2UocHJldk91dFNjcmlwdClcbiAgICAgIGJ1ZmZlcldyaXRlci53cml0ZVVJbnQ2NCh2YWx1ZSlcbiAgICAgIGJ1ZmZlcldyaXRlci53cml0ZVVJbnQzMihpbnB1dC5zZXF1ZW5jZSlcbiAgICB9XG5cbiAgICB2YXIgcGVyc29uYWxpemF0aW9uID0gQnVmZmVyLmFsbG9jKDE2KVxuICAgIHZhciBwcmVmaXggPSAnWmNhc2hTaWdIYXNoJ1xuICAgIHBlcnNvbmFsaXphdGlvbi53cml0ZShwcmVmaXgpXG4gICAgcGVyc29uYWxpemF0aW9uLndyaXRlVUludDMyTEUodGhpcy5jb25zZW5zdXNCcmFuY2hJZCwgcHJlZml4Lmxlbmd0aClcblxuICAgIHJldHVybiB0aGlzLmdldEJsYWtlMmJIYXNoKGJ1ZmZlcldyaXRlci5idWZmZXIsIHBlcnNvbmFsaXphdGlvbilcbiAgfVxuXG4gIC8qIGlzdGFuYnVsIGlnbm9yZSBuZXh0ICovXG4gIHRocm93IG5ldyBFcnJvcihgdW5zdXBwb3J0ZWQgdmVyc2lvbmApXG59XG5cblRyYW5zYWN0aW9uLnByb3RvdHlwZS5oYXNoRm9yV2l0bmVzc1YwID0gZnVuY3Rpb24gKGluSW5kZXgsIHByZXZPdXRTY3JpcHQsIHZhbHVlLCBoYXNoVHlwZSkge1xuICB0eXBlZm9yY2UodHlwZXMudHVwbGUodHlwZXMuVUludDMyLCB0eXBlcy5CdWZmZXIsIHR5cGVzLlNhdG9zaGksIHR5cGVzLlVJbnQzMiksIGFyZ3VtZW50cylcblxuICB2YXIgaGFzaFByZXZvdXRzID0gdGhpcy5nZXRQcmV2b3V0SGFzaChoYXNoVHlwZSlcbiAgdmFyIGhhc2hTZXF1ZW5jZSA9IHRoaXMuZ2V0U2VxdWVuY2VIYXNoKGhhc2hUeXBlKVxuICB2YXIgaGFzaE91dHB1dHMgPSB0aGlzLmdldE91dHB1dHNIYXNoKGhhc2hUeXBlLCBpbkluZGV4KVxuXG4gIHZhciBidWZmZXJXcml0ZXIgPSBuZXcgQnVmZmVyV3JpdGVyKEJ1ZmZlci5hbGxvY1Vuc2FmZSgxNTYgKyB2YXJTbGljZVNpemUocHJldk91dFNjcmlwdCkpKVxuICB2YXIgaW5wdXQgPSB0aGlzLmluc1tpbkluZGV4XVxuICBidWZmZXJXcml0ZXIud3JpdGVVSW50MzIodGhpcy52ZXJzaW9uKVxuICBidWZmZXJXcml0ZXIud3JpdGVTbGljZShoYXNoUHJldm91dHMpXG4gIGJ1ZmZlcldyaXRlci53cml0ZVNsaWNlKGhhc2hTZXF1ZW5jZSlcbiAgYnVmZmVyV3JpdGVyLndyaXRlU2xpY2UoaW5wdXQuaGFzaClcbiAgYnVmZmVyV3JpdGVyLndyaXRlVUludDMyKGlucHV0LmluZGV4KVxuICBidWZmZXJXcml0ZXIud3JpdGVWYXJTbGljZShwcmV2T3V0U2NyaXB0KVxuICBidWZmZXJXcml0ZXIud3JpdGVVSW50NjQodmFsdWUpXG4gIGJ1ZmZlcldyaXRlci53cml0ZVVJbnQzMihpbnB1dC5zZXF1ZW5jZSlcbiAgYnVmZmVyV3JpdGVyLndyaXRlU2xpY2UoaGFzaE91dHB1dHMpXG4gIGJ1ZmZlcldyaXRlci53cml0ZVVJbnQzMih0aGlzLmxvY2t0aW1lKVxuICBidWZmZXJXcml0ZXIud3JpdGVVSW50MzIoaGFzaFR5cGUpXG4gIHJldHVybiBiY3J5cHRvLmhhc2gyNTYoYnVmZmVyV3JpdGVyLmJ1ZmZlcilcbn1cblxuVHJhbnNhY3Rpb24ucHJvdG90eXBlLmdldEhhc2ggPSBmdW5jdGlvbiAoKSB7XG4gIHJldHVybiBiY3J5cHRvLmhhc2gyNTYodGhpcy5fX3RvQnVmZmVyKHVuZGVmaW5lZCwgdW5kZWZpbmVkLCBmYWxzZSkpXG59XG5cblRyYW5zYWN0aW9uLnByb3RvdHlwZS5nZXRJZCA9IGZ1bmN0aW9uICgpIHtcbiAgLy8gdHJhbnNhY3Rpb24gaGFzaCdzIGFyZSBkaXNwbGF5ZWQgaW4gcmV2ZXJzZSBvcmRlclxuICByZXR1cm4gdGhpcy5nZXRIYXNoKCkucmV2ZXJzZSgpLnRvU3RyaW5nKCdoZXgnKVxufVxuXG5UcmFuc2FjdGlvbi5wcm90b3R5cGUudG9CdWZmZXIgPSBmdW5jdGlvbiAoYnVmZmVyLCBpbml0aWFsT2Zmc2V0KSB7XG4gIHJldHVybiB0aGlzLl9fdG9CdWZmZXIoYnVmZmVyLCBpbml0aWFsT2Zmc2V0LCB0cnVlKVxufVxuXG5UcmFuc2FjdGlvbi5wcm90b3R5cGUuX190b0J1ZmZlciA9IGZ1bmN0aW9uIChidWZmZXIsIGluaXRpYWxPZmZzZXQsIF9fYWxsb3dXaXRuZXNzKSB7XG4gIGlmICghYnVmZmVyKSBidWZmZXIgPSBCdWZmZXIuYWxsb2NVbnNhZmUodGhpcy5fX2J5dGVMZW5ndGgoX19hbGxvd1dpdG5lc3MpKVxuXG4gIGNvbnN0IGJ1ZmZlcldyaXRlciA9IG5ldyBCdWZmZXJXcml0ZXIoYnVmZmVyLCBpbml0aWFsT2Zmc2V0IHx8IDApXG5cbiAgZnVuY3Rpb24gd3JpdGVVSW50MTYgKGkpIHtcbiAgICBidWZmZXJXcml0ZXIub2Zmc2V0ID0gYnVmZmVyV3JpdGVyLmJ1ZmZlci53cml0ZVVJbnQxNkxFKGksIGJ1ZmZlcldyaXRlci5vZmZzZXQpXG4gIH1cblxuICBpZiAodGhpcy5pc092ZXJ3aW50ZXJDb21wYXRpYmxlKCkpIHtcbiAgICB2YXIgbWFzayA9ICh0aGlzLm92ZXJ3aW50ZXJlZCA/IDEgOiAwKVxuICAgIGJ1ZmZlcldyaXRlci53cml0ZUludDMyKHRoaXMudmVyc2lvbiB8IChtYXNrIDw8IDMxKSkgIC8vIFNldCBvdmVyd2ludGVyIGJpdFxuICAgIGJ1ZmZlcldyaXRlci53cml0ZVVJbnQzMih0aGlzLnZlcnNpb25Hcm91cElkKVxuICB9IGVsc2UgaWYgKHRoaXMuaXNEYXNoU3BlY2lhbFRyYW5zYWN0aW9uKCkpIHtcbiAgICB3cml0ZVVJbnQxNih0aGlzLnZlcnNpb24pXG4gICAgd3JpdGVVSW50MTYodGhpcy50eXBlKVxuICB9IGVsc2Uge1xuICAgIGJ1ZmZlcldyaXRlci53cml0ZUludDMyKHRoaXMudmVyc2lvbilcbiAgfVxuXG4gIHZhciBoYXNXaXRuZXNzZXMgPSBfX2FsbG93V2l0bmVzcyAmJiB0aGlzLmhhc1dpdG5lc3NlcygpXG5cbiAgaWYgKGhhc1dpdG5lc3Nlcykge1xuICAgIGJ1ZmZlcldyaXRlci53cml0ZVVJbnQ4KFRyYW5zYWN0aW9uLkFEVkFOQ0VEX1RSQU5TQUNUSU9OX01BUktFUilcbiAgICBidWZmZXJXcml0ZXIud3JpdGVVSW50OChUcmFuc2FjdGlvbi5BRFZBTkNFRF9UUkFOU0FDVElPTl9GTEFHKVxuICB9XG5cbiAgYnVmZmVyV3JpdGVyLndyaXRlVmFySW50KHRoaXMuaW5zLmxlbmd0aClcblxuICB0aGlzLmlucy5mb3JFYWNoKGZ1bmN0aW9uICh0eEluKSB7XG4gICAgYnVmZmVyV3JpdGVyLndyaXRlU2xpY2UodHhJbi5oYXNoKVxuICAgIGJ1ZmZlcldyaXRlci53cml0ZVVJbnQzMih0eEluLmluZGV4KVxuICAgIGJ1ZmZlcldyaXRlci53cml0ZVZhclNsaWNlKHR4SW4uc2NyaXB0KVxuICAgIGJ1ZmZlcldyaXRlci53cml0ZVVJbnQzMih0eEluLnNlcXVlbmNlKVxuICB9KVxuXG4gIGJ1ZmZlcldyaXRlci53cml0ZVZhckludCh0aGlzLm91dHMubGVuZ3RoKVxuICB0aGlzLm91dHMuZm9yRWFjaChmdW5jdGlvbiAodHhPdXQpIHtcbiAgICBpZiAoIXR4T3V0LnZhbHVlQnVmZmVyKSB7XG4gICAgICBidWZmZXJXcml0ZXIud3JpdGVVSW50NjQodHhPdXQudmFsdWUpXG4gICAgfSBlbHNlIHtcbiAgICAgIGJ1ZmZlcldyaXRlci53cml0ZVNsaWNlKHR4T3V0LnZhbHVlQnVmZmVyKVxuICAgIH1cblxuICAgIGJ1ZmZlcldyaXRlci53cml0ZVZhclNsaWNlKHR4T3V0LnNjcmlwdClcbiAgfSlcblxuICBpZiAoaGFzV2l0bmVzc2VzKSB7XG4gICAgdGhpcy5pbnMuZm9yRWFjaChmdW5jdGlvbiAoaW5wdXQpIHtcbiAgICAgIGJ1ZmZlcldyaXRlci53cml0ZVZlY3RvcihpbnB1dC53aXRuZXNzKVxuICAgIH0pXG4gIH1cblxuICBidWZmZXJXcml0ZXIud3JpdGVVSW50MzIodGhpcy5sb2NrdGltZSlcblxuICBpZiAodGhpcy5pc092ZXJ3aW50ZXJDb21wYXRpYmxlKCkpIHtcbiAgICBidWZmZXJXcml0ZXIud3JpdGVVSW50MzIodGhpcy5leHBpcnlIZWlnaHQpXG4gIH1cblxuICBpZiAodGhpcy5pc1NhcGxpbmdDb21wYXRpYmxlKCkpIHtcbiAgICBidWZmZXJXcml0ZXIud3JpdGVTbGljZShWQUxVRV9JTlQ2NF9aRVJPKVxuICAgIGJ1ZmZlcldyaXRlci53cml0ZVZhckludCgwKSAvLyB2U2hpZWxkZWRTcGVuZExlbmd0aFxuICAgIGJ1ZmZlcldyaXRlci53cml0ZVZhckludCgwKSAvLyB2U2hpZWxkZWRPdXRwdXRMZW5ndGhcbiAgfVxuXG4gIGlmICh0aGlzLnN1cHBvcnRzSm9pblNwbGl0cygpKSB7XG4gICAgYnVmZmVyV3JpdGVyLndyaXRlVmFySW50KDApIC8vIGpvaW5zU3BsaXRzIGxlbmd0aFxuICB9XG5cbiAgaWYgKHRoaXMuaXNEYXNoU3BlY2lhbFRyYW5zYWN0aW9uKCkpIHtcbiAgICBidWZmZXJXcml0ZXIud3JpdGVWYXJTbGljZSh0aGlzLmV4dHJhUGF5bG9hZClcbiAgfVxuXG4gIGlmIChpbml0aWFsT2Zmc2V0ICE9PSB1bmRlZmluZWQpIHJldHVybiBidWZmZXIuc2xpY2UoaW5pdGlhbE9mZnNldCwgYnVmZmVyV3JpdGVyLm9mZnNldClcbiAgLy8gYXZvaWQgc2xpY2luZyB1bmxlc3MgbmVjZXNzYXJ5XG4gIC8vIFRPRE8gKGh0dHBzOi8vZ2l0aHViLmNvbS9CaXRHby9iaXRnby11dHhvLWxpYi9pc3N1ZXMvMTEpOiB3ZSBzaG91bGRuJ3QgaGF2ZSB0byBzbGljZSB0aGUgZmluYWwgYnVmZmVyXG4gIHJldHVybiBidWZmZXIuc2xpY2UoMCwgYnVmZmVyV3JpdGVyLm9mZnNldClcbn1cblxuVHJhbnNhY3Rpb24ucHJvdG90eXBlLnRvSGV4ID0gZnVuY3Rpb24gKCkge1xuICByZXR1cm4gdGhpcy50b0J1ZmZlcigpLnRvU3RyaW5nKCdoZXgnKVxufVxuXG5UcmFuc2FjdGlvbi5wcm90b3R5cGUuc2V0SW5wdXRTY3JpcHQgPSBmdW5jdGlvbiAoaW5kZXgsIHNjcmlwdFNpZykge1xuICB0eXBlZm9yY2UodHlwZXMudHVwbGUodHlwZXMuTnVtYmVyLCB0eXBlcy5CdWZmZXIpLCBhcmd1bWVudHMpXG5cbiAgdGhpcy5pbnNbaW5kZXhdLnNjcmlwdCA9IHNjcmlwdFNpZ1xufVxuXG5UcmFuc2FjdGlvbi5wcm90b3R5cGUuc2V0V2l0bmVzcyA9IGZ1bmN0aW9uIChpbmRleCwgd2l0bmVzcykge1xuICB0eXBlZm9yY2UodHlwZXMudHVwbGUodHlwZXMuTnVtYmVyLCBbdHlwZXMuQnVmZmVyXSksIGFyZ3VtZW50cylcblxuICB0aGlzLmluc1tpbmRleF0ud2l0bmVzcyA9IHdpdG5lc3Ncbn1cblxubW9kdWxlLmV4cG9ydHMgPSBUcmFuc2FjdGlvblxuIl19