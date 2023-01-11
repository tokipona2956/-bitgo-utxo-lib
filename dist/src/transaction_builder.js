var Buffer = require('safe-buffer').Buffer;
var baddress = require('./address');
var bcrypto = require('./crypto');
var bscript = require('./script');
var btemplates = require('./templates');
var coins = require('./coins');
var networks = require('./networks');
var ops = require('bitcoin-ops');
var typeforce = require('typeforce');
var types = require('./types');
var scriptTypes = btemplates.types;
var SIGNABLE = [btemplates.types.P2PKH, btemplates.types.P2PK, btemplates.types.MULTISIG];
var P2SH = SIGNABLE.concat([btemplates.types.P2WPKH, btemplates.types.P2WSH]);
var ECPair = require('./ecpair');
var ECSignature = require('./ecsignature');
var Transaction = require('./transaction');
const { getMainnet, getNetworkName } = require('./coins');
var debug = require('debug')('bitgo:utxolib:txbuilder');
function supportedType(type) {
    return SIGNABLE.indexOf(type) !== -1;
}
function supportedP2SHType(type) {
    return P2SH.indexOf(type) !== -1;
}
function extractChunks(type, chunks, script) {
    var pubKeys = [];
    var signatures = [];
    switch (type) {
        case scriptTypes.P2PKH:
            // if (redeemScript) throw new Error('Nonstandard... P2SH(P2PKH)')
            pubKeys = chunks.slice(1);
            signatures = chunks.slice(0, 1);
            break;
        case scriptTypes.P2PK:
            pubKeys[0] = script ? btemplates.pubKey.output.decode(script) : undefined;
            signatures = chunks.slice(0, 1);
            break;
        case scriptTypes.MULTISIG:
            if (script) {
                var multisig = btemplates.multisig.output.decode(script);
                pubKeys = multisig.pubKeys;
            }
            signatures = chunks.slice(1).map(function (chunk) {
                return chunk.length === 0 ? undefined : chunk;
            });
            break;
    }
    return {
        pubKeys: pubKeys,
        signatures: signatures
    };
}
function expandInput(scriptSig, witnessStack) {
    if (scriptSig.length === 0 && witnessStack.length === 0)
        return {};
    var prevOutScript;
    var prevOutType;
    var scriptType;
    var script;
    var redeemScript;
    var witnessScript;
    var witnessScriptType;
    var redeemScriptType;
    var witness = false;
    var p2wsh = false;
    var p2sh = false;
    var witnessProgram;
    var chunks;
    var scriptSigChunks = bscript.decompile(scriptSig);
    var sigType = btemplates.classifyInput(scriptSigChunks, true);
    if (sigType === scriptTypes.P2SH) {
        p2sh = true;
        redeemScript = scriptSigChunks[scriptSigChunks.length - 1];
        redeemScriptType = btemplates.classifyOutput(redeemScript);
        prevOutScript = btemplates.scriptHash.output.encode(bcrypto.hash160(redeemScript));
        prevOutType = scriptTypes.P2SH;
        script = redeemScript;
    }
    var classifyWitness = btemplates.classifyWitness(witnessStack, true);
    if (classifyWitness === scriptTypes.P2WSH) {
        witnessScript = witnessStack[witnessStack.length - 1];
        witnessScriptType = btemplates.classifyOutput(witnessScript);
        p2wsh = true;
        witness = true;
        if (scriptSig.length === 0) {
            prevOutScript = btemplates.witnessScriptHash.output.encode(bcrypto.sha256(witnessScript));
            prevOutType = scriptTypes.P2WSH;
            if (redeemScript !== undefined) {
                throw new Error('Redeem script given when unnecessary');
            }
            // bare witness
        }
        else {
            if (!redeemScript) {
                throw new Error('No redeemScript provided for P2WSH, but scriptSig non-empty');
            }
            witnessProgram = btemplates.witnessScriptHash.output.encode(bcrypto.sha256(witnessScript));
            if (!redeemScript.equals(witnessProgram)) {
                throw new Error('Redeem script didn\'t match witnessScript');
            }
        }
        if (!supportedType(btemplates.classifyOutput(witnessScript))) {
            throw new Error('unsupported witness script');
        }
        script = witnessScript;
        scriptType = witnessScriptType;
        chunks = witnessStack.slice(0, -1);
    }
    else if (classifyWitness === scriptTypes.P2WPKH) {
        witness = true;
        var key = witnessStack[witnessStack.length - 1];
        var keyHash = bcrypto.hash160(key);
        if (scriptSig.length === 0) {
            prevOutScript = btemplates.witnessPubKeyHash.output.encode(keyHash);
            prevOutType = scriptTypes.P2WPKH;
            if (typeof redeemScript !== 'undefined') {
                throw new Error('Redeem script given when unnecessary');
            }
        }
        else {
            if (!redeemScript) {
                throw new Error('No redeemScript provided for P2WPKH, but scriptSig wasn\'t empty');
            }
            witnessProgram = btemplates.witnessPubKeyHash.output.encode(keyHash);
            if (!redeemScript.equals(witnessProgram)) {
                throw new Error('Redeem script did not have the right witness program');
            }
        }
        scriptType = scriptTypes.P2PKH;
        chunks = witnessStack;
    }
    else if (redeemScript) {
        if (!supportedP2SHType(redeemScriptType)) {
            throw new Error('Bad redeemscript!');
        }
        script = redeemScript;
        scriptType = redeemScriptType;
        chunks = scriptSigChunks.slice(0, -1);
    }
    else {
        prevOutType = scriptType = btemplates.classifyInput(scriptSig);
        chunks = scriptSigChunks;
    }
    var expanded = extractChunks(scriptType, chunks, script);
    var result = {
        pubKeys: expanded.pubKeys,
        signatures: expanded.signatures,
        prevOutScript: prevOutScript,
        prevOutType: prevOutType,
        signType: scriptType,
        signScript: script,
        witness: Boolean(witness)
    };
    if (p2sh) {
        result.redeemScript = redeemScript;
        result.redeemScriptType = redeemScriptType;
    }
    if (p2wsh) {
        result.witnessScript = witnessScript;
        result.witnessScriptType = witnessScriptType;
    }
    return result;
}
// could be done in expandInput, but requires the original Transaction for hashForSignature
function fixMultisigOrder(input, transaction, vin, value, network) {
    if (input.redeemScriptType !== scriptTypes.MULTISIG || !input.redeemScript)
        return;
    if (input.pubKeys.length === input.signatures.length)
        return;
    network = network || networks.bitcoin;
    var unmatched = input.signatures.concat();
    input.signatures = input.pubKeys.map(function (pubKey) {
        var keyPair = ECPair.fromPublicKeyBuffer(pubKey);
        var match;
        // check for a signature
        unmatched.some(function (signature, i) {
            // skip if undefined || OP_0
            if (!signature)
                return false;
            if (coins.isZcash(network) && value === undefined) {
                return false;
            }
            // TODO: avoid O(n) hashForSignature
            var parsed = ECSignature.parseScriptSignature(signature);
            var hash = transaction.hashForSignatureByNetwork(vin, input.signScript, value, parsed.hashType, !!input.witness);
            // skip if signature does not match pubKey
            if (!keyPair.verify(hash, parsed.signature))
                return false;
            // remove matched signature from unmatched
            unmatched[i] = undefined;
            match = signature;
            return true;
        });
        return match;
    });
}
function expandOutput(script, scriptType, ourPubKey) {
    typeforce(types.Buffer, script);
    var scriptChunks = bscript.decompile(script);
    if (!scriptType) {
        scriptType = btemplates.classifyOutput(script);
    }
    var pubKeys = [];
    switch (scriptType) {
        // does our hash160(pubKey) match the output scripts?
        case scriptTypes.P2PKH:
            if (!ourPubKey)
                break;
            var pkh1 = scriptChunks[2];
            var pkh2 = bcrypto.hash160(ourPubKey);
            if (pkh1.equals(pkh2))
                pubKeys = [ourPubKey];
            break;
        // does our hash160(pubKey) match the output scripts?
        case scriptTypes.P2WPKH:
            if (!ourPubKey)
                break;
            var wpkh1 = scriptChunks[1];
            var wpkh2 = bcrypto.hash160(ourPubKey);
            if (wpkh1.equals(wpkh2))
                pubKeys = [ourPubKey];
            break;
        case scriptTypes.P2PK:
            pubKeys = scriptChunks.slice(0, 1);
            break;
        case scriptTypes.MULTISIG:
            pubKeys = scriptChunks.slice(1, -2);
            break;
        default: return { scriptType: scriptType };
    }
    return {
        pubKeys: pubKeys,
        scriptType: scriptType,
        signatures: pubKeys.map(function () { return undefined; })
    };
}
function checkP2SHInput(input, redeemScriptHash) {
    if (input.prevOutType) {
        if (input.prevOutType !== scriptTypes.P2SH)
            throw new Error('PrevOutScript must be P2SH');
        var prevOutScriptScriptHash = bscript.decompile(input.prevOutScript)[1];
        if (!prevOutScriptScriptHash.equals(redeemScriptHash))
            throw new Error('Inconsistent hash160(RedeemScript)');
    }
}
function checkP2WSHInput(input, witnessScriptHash) {
    if (input.prevOutType) {
        if (input.prevOutType !== scriptTypes.P2WSH)
            throw new Error('PrevOutScript must be P2WSH');
        var scriptHash = bscript.decompile(input.prevOutScript)[1];
        if (!scriptHash.equals(witnessScriptHash))
            throw new Error('Inconsistent sha25(WitnessScript)');
    }
}
function prepareInput(input, kpPubKey, redeemScript, witnessValue, witnessScript) {
    var expanded;
    var prevOutType;
    var prevOutScript;
    var p2sh = false;
    var p2shType;
    var redeemScriptHash;
    var witness = false;
    var p2wsh = false;
    var witnessType;
    var witnessScriptHash;
    var signType;
    var signScript;
    if (redeemScript && witnessScript) {
        redeemScriptHash = bcrypto.hash160(redeemScript);
        witnessScriptHash = bcrypto.sha256(witnessScript);
        checkP2SHInput(input, redeemScriptHash);
        if (!redeemScript.equals(btemplates.witnessScriptHash.output.encode(witnessScriptHash)))
            throw new Error('Witness script inconsistent with redeem script');
        expanded = expandOutput(witnessScript, undefined, kpPubKey);
        if (!expanded.pubKeys)
            throw new Error('WitnessScript not supported "' + bscript.toASM(redeemScript) + '"');
        prevOutType = btemplates.types.P2SH;
        prevOutScript = btemplates.scriptHash.output.encode(redeemScriptHash);
        p2sh = witness = p2wsh = true;
        p2shType = btemplates.types.P2WSH;
        signType = witnessType = expanded.scriptType;
        signScript = witnessScript;
    }
    else if (redeemScript) {
        redeemScriptHash = bcrypto.hash160(redeemScript);
        checkP2SHInput(input, redeemScriptHash);
        expanded = expandOutput(redeemScript, undefined, kpPubKey);
        if (!expanded.pubKeys)
            throw new Error('RedeemScript not supported "' + bscript.toASM(redeemScript) + '"');
        prevOutType = btemplates.types.P2SH;
        prevOutScript = btemplates.scriptHash.output.encode(redeemScriptHash);
        p2sh = true;
        signType = p2shType = expanded.scriptType;
        signScript = redeemScript;
        witness = signType === btemplates.types.P2WPKH;
    }
    else if (witnessScript) {
        witnessScriptHash = bcrypto.sha256(witnessScript);
        checkP2WSHInput(input, witnessScriptHash);
        expanded = expandOutput(witnessScript, undefined, kpPubKey);
        if (!expanded.pubKeys)
            throw new Error('WitnessScript not supported "' + bscript.toASM(redeemScript) + '"');
        prevOutType = btemplates.types.P2WSH;
        prevOutScript = btemplates.witnessScriptHash.output.encode(witnessScriptHash);
        witness = p2wsh = true;
        signType = witnessType = expanded.scriptType;
        signScript = witnessScript;
    }
    else if (input.prevOutType) {
        // embedded scripts are not possible without a redeemScript
        if (input.prevOutType === scriptTypes.P2SH ||
            input.prevOutType === scriptTypes.P2WSH) {
            throw new Error('PrevOutScript is ' + input.prevOutType + ', requires redeemScript');
        }
        prevOutType = input.prevOutType;
        prevOutScript = input.prevOutScript;
        expanded = expandOutput(input.prevOutScript, input.prevOutType, kpPubKey);
        if (!expanded.pubKeys)
            return;
        witness = (input.prevOutType === scriptTypes.P2WPKH);
        signType = prevOutType;
        signScript = prevOutScript;
    }
    else {
        prevOutScript = btemplates.pubKeyHash.output.encode(bcrypto.hash160(kpPubKey));
        expanded = expandOutput(prevOutScript, scriptTypes.P2PKH, kpPubKey);
        prevOutType = scriptTypes.P2PKH;
        witness = false;
        signType = prevOutType;
        signScript = prevOutScript;
    }
    if (signType === scriptTypes.P2WPKH) {
        signScript = btemplates.pubKeyHash.output.encode(btemplates.witnessPubKeyHash.output.decode(signScript));
    }
    if (p2sh) {
        input.redeemScript = redeemScript;
        input.redeemScriptType = p2shType;
    }
    if (p2wsh) {
        input.witnessScript = witnessScript;
        input.witnessScriptType = witnessType;
    }
    input.pubKeys = expanded.pubKeys;
    input.signatures = expanded.signatures;
    input.signScript = signScript;
    input.signType = signType;
    input.prevOutScript = prevOutScript;
    input.prevOutType = prevOutType;
    input.witness = witness;
}
function buildStack(type, signatures, pubKeys, allowIncomplete) {
    if (type === scriptTypes.P2PKH) {
        if (signatures.length === 1 && Buffer.isBuffer(signatures[0]) && pubKeys.length === 1)
            return btemplates.pubKeyHash.input.encodeStack(signatures[0], pubKeys[0]);
    }
    else if (type === scriptTypes.P2PK) {
        if (signatures.length === 1 && Buffer.isBuffer(signatures[0]))
            return btemplates.pubKey.input.encodeStack(signatures[0]);
    }
    else if (type === scriptTypes.MULTISIG) {
        if (signatures.length > 0) {
            signatures = signatures.map(function (signature) {
                return signature || ops.OP_0;
            });
            if (!allowIncomplete) {
                // remove blank signatures
                signatures = signatures.filter(function (x) { return x !== ops.OP_0; });
            }
            return btemplates.multisig.input.encodeStack(signatures);
        }
    }
    else {
        throw new Error('Not yet supported');
    }
    if (!allowIncomplete)
        throw new Error('Not enough signatures provided');
    return [];
}
function buildInput(input, allowIncomplete) {
    var scriptType = input.prevOutType;
    var sig = [];
    var witness = [];
    if (supportedType(scriptType)) {
        sig = buildStack(scriptType, input.signatures, input.pubKeys, allowIncomplete);
    }
    var p2sh = false;
    if (scriptType === btemplates.types.P2SH) {
        // We can remove this error later when we have a guarantee prepareInput
        // rejects unsignable scripts - it MUST be signable at this point.
        if (!allowIncomplete && !supportedP2SHType(input.redeemScriptType)) {
            throw new Error('Impossible to sign this type');
        }
        if (supportedType(input.redeemScriptType)) {
            sig = buildStack(input.redeemScriptType, input.signatures, input.pubKeys, allowIncomplete);
        }
        // If it wasn't SIGNABLE, it's witness, defer to that
        if (input.redeemScriptType) {
            p2sh = true;
            scriptType = input.redeemScriptType;
        }
    }
    switch (scriptType) {
        // P2WPKH is a special case of P2PKH
        case btemplates.types.P2WPKH:
            witness = buildStack(btemplates.types.P2PKH, input.signatures, input.pubKeys, allowIncomplete);
            break;
        case btemplates.types.P2WSH:
            // We can remove this check later
            if (!allowIncomplete && !supportedType(input.witnessScriptType)) {
                throw new Error('Impossible to sign this type');
            }
            if (supportedType(input.witnessScriptType)) {
                witness = buildStack(input.witnessScriptType, input.signatures, input.pubKeys, allowIncomplete);
                witness.push(input.witnessScript);
                scriptType = input.witnessScriptType;
            }
            break;
    }
    // append redeemScript if necessary
    if (p2sh) {
        sig.push(input.redeemScript);
    }
    return {
        type: scriptType,
        script: bscript.compile(sig),
        witness: witness
    };
}
// By default, assume is a bitcoin transaction
function TransactionBuilder(network, maximumFeeRate) {
    this.prevTxMap = {};
    this.network = network || networks.bitcoin;
    // WARNING: This is __NOT__ to be relied on, its just another potential safety mechanism (safety in-depth)
    this.maximumFeeRate = maximumFeeRate || 2500;
    this.inputs = [];
    this.tx = new Transaction(this.network);
}
TransactionBuilder.prototype.setLockTime = function (locktime) {
    typeforce(types.UInt32, locktime);
    // if any signatures exist, throw
    if (this.inputs.some(function (input) {
        if (!input.signatures)
            return false;
        return input.signatures.some(function (s) { return s; });
    })) {
        throw new Error('No, this would invalidate signatures');
    }
    this.tx.locktime = locktime;
};
TransactionBuilder.prototype.setVersion = function (version, overwinter = true) {
    typeforce(types.UInt32, version);
    if (coins.isZcash(this.network)) {
        if (!this.network.consensusBranchId.hasOwnProperty(this.tx.version)) {
            /* istanbul ignore next */
            throw new Error('Unsupported Zcash transaction');
        }
        this.tx.overwintered = (overwinter ? 1 : 0);
        this.tx.consensusBranchId = this.network.consensusBranchId[version];
    }
    this.tx.version = version;
};
TransactionBuilder.prototype.setConsensusBranchId = function (consensusBranchId) {
    if (!coins.isZcash(this.network)) {
        /* istanbul ignore next */
        throw new Error('consensusBranchId can only be set for Zcash transactions');
    }
    if (!this.inputs.every(function (input) { return input.signatures === undefined; })) {
        /* istanbul ignore next */
        throw new Error('Changing the consensusBranchId for a partially signed transaction would invalidate signatures');
    }
    typeforce(types.UInt32, consensusBranchId);
    this.tx.consensusBranchId = consensusBranchId;
};
TransactionBuilder.prototype.setVersionGroupId = function (versionGroupId) {
    if (!(coins.isZcash(this.network) && this.tx.isOverwinterCompatible())) {
        /* istanbul ignore next */
        throw new Error('expiryHeight can only be set for Zcash starting at overwinter version. Current network: ' +
            getNetworkName(this.network) + ', version: ' + this.tx.version);
    }
    typeforce(types.UInt32, versionGroupId);
    this.tx.versionGroupId = versionGroupId;
};
TransactionBuilder.prototype.setExpiryHeight = function (expiryHeight) {
    if (!(coins.isZcash(this.network) && this.tx.isOverwinterCompatible())) {
        /* istanbul ignore next */
        throw new Error('expiryHeight can only be set for Zcash starting at overwinter version. Current network: ' +
            getNetworkName(this.network) + ', version: ' + this.tx.version);
    }
    typeforce(types.UInt32, expiryHeight);
    this.tx.expiryHeight = expiryHeight;
};
TransactionBuilder.fromTransaction = function (transaction, network) {
    var txbNetwork = network || networks.bitcoin;
    var txb = new TransactionBuilder(txbNetwork);
    if (getMainnet(txb.network) !== getMainnet(transaction.network)) {
        throw new Error('This transaction is incompatible with the transaction builder');
    }
    // Copy transaction fields
    txb.setVersion(transaction.version, transaction.overwintered);
    txb.setLockTime(transaction.locktime);
    if (coins.isZcash(txbNetwork)) {
        // Copy Zcash overwinter fields. Omitted if the transaction builder is not for Zcash.
        if (txb.tx.isOverwinterCompatible()) {
            txb.setVersionGroupId(transaction.versionGroupId);
            txb.setExpiryHeight(transaction.expiryHeight);
        }
        txb.setConsensusBranchId(transaction.consensusBranchId);
    }
    // Copy Dash special transaction fields. Omitted if the transaction builder is not for Dash.
    if (coins.isDash(txbNetwork)) {
        typeforce(types.UInt16, transaction.type);
        txb.tx.type = transaction.type;
        if (txb.tx.versionSupportsDashSpecialTransactions()) {
            typeforce(types.Buffer, transaction.extraPayload);
            txb.tx.extraPayload = transaction.extraPayload;
        }
    }
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
            value: txIn.value
        });
    });
    // fix some things not possible through the public API
    txb.inputs.forEach(function (input, i) {
        fixMultisigOrder(input, transaction, i, input.value, txbNetwork);
    });
    return txb;
};
TransactionBuilder.prototype.addInput = function (txHash, vout, sequence, prevOutScript) {
    if (!this.__canModifyInputs()) {
        throw new Error('No, this would invalidate signatures');
    }
    var value;
    // is it a hex string?
    if (typeof txHash === 'string') {
        // transaction hashs's are displayed in reverse order, un-reverse it
        txHash = Buffer.from(txHash, 'hex').reverse();
        // is it a Transaction object?
    }
    else if (txHash instanceof Transaction) {
        var txOut = txHash.outs[vout];
        prevOutScript = txOut.script;
        value = txOut.value;
        txHash = txHash.getHash();
    }
    return this.__addInputUnsafe(txHash, vout, {
        sequence: sequence,
        prevOutScript: prevOutScript,
        value: value
    });
};
TransactionBuilder.prototype.__addInputUnsafe = function (txHash, vout, options) {
    if (Transaction.isCoinbaseHash(txHash)) {
        throw new Error('coinbase inputs not supported');
    }
    var prevTxOut = txHash.toString('hex') + ':' + vout;
    if (this.prevTxMap[prevTxOut] !== undefined)
        throw new Error('Duplicate TxOut: ' + prevTxOut);
    var input = {};
    // derive what we can from the scriptSig
    if (options.script !== undefined) {
        input = expandInput(options.script, options.witness || []);
    }
    // if an input value was given, retain it
    if (options.value !== undefined) {
        input.value = options.value;
    }
    // derive what we can from the previous transactions output script
    if (!input.prevOutScript && options.prevOutScript) {
        var prevOutType;
        if (!input.pubKeys && !input.signatures) {
            var expanded = expandOutput(options.prevOutScript);
            if (expanded.pubKeys) {
                input.pubKeys = expanded.pubKeys;
                input.signatures = expanded.signatures;
            }
            prevOutType = expanded.scriptType;
        }
        input.prevOutScript = options.prevOutScript;
        input.prevOutType = prevOutType || btemplates.classifyOutput(options.prevOutScript);
    }
    var vin = this.tx.addInput(txHash, vout, options.sequence, options.scriptSig);
    this.inputs[vin] = input;
    this.prevTxMap[prevTxOut] = vin;
    return vin;
};
TransactionBuilder.prototype.addOutput = function (scriptPubKey, value) {
    if (!this.__canModifyOutputs()) {
        throw new Error('No, this would invalidate signatures');
    }
    // Attempt to get a script if it's a base58 address string
    if (typeof scriptPubKey === 'string') {
        scriptPubKey = baddress.toOutputScript(scriptPubKey, this.network);
    }
    return this.tx.addOutput(scriptPubKey, value);
};
TransactionBuilder.prototype.build = function () {
    return this.__build(false);
};
TransactionBuilder.prototype.buildIncomplete = function () {
    return this.__build(true);
};
TransactionBuilder.prototype.__build = function (allowIncomplete) {
    if (!allowIncomplete) {
        if (!this.tx.ins.length)
            throw new Error('Transaction has no inputs');
        if (!this.tx.outs.length)
            throw new Error('Transaction has no outputs');
    }
    var tx = this.tx.clone();
    // Create script signatures from inputs
    this.inputs.forEach(function (input, i) {
        var scriptType = input.witnessScriptType || input.redeemScriptType || input.prevOutType;
        if (!scriptType && !allowIncomplete)
            throw new Error('Transaction is not complete');
        var result = buildInput(input, allowIncomplete);
        // skip if no result
        if (!allowIncomplete) {
            if (!supportedType(result.type) && result.type !== btemplates.types.P2WPKH) {
                throw new Error(result.type + ' not supported');
            }
        }
        tx.setInputScript(i, result.script);
        tx.setWitness(i, result.witness);
    });
    if (!allowIncomplete) {
        // do not rely on this, its merely a last resort
        if (this.__overMaximumFees(tx.virtualSize())) {
            throw new Error('Transaction has absurd fees');
        }
    }
    return tx;
};
function canSign(input) {
    return input.prevOutScript !== undefined &&
        input.signScript !== undefined &&
        input.pubKeys !== undefined &&
        input.signatures !== undefined &&
        input.signatures.length === input.pubKeys.length &&
        input.pubKeys.length > 0 &&
        (input.witness === false ||
            (input.witness === true && input.value !== undefined));
}
TransactionBuilder.prototype.sign = function (vin, keyPair, redeemScript, hashType, witnessValue, witnessScript) {
    debug('Signing transaction: (input: %d, hashType: %d, witnessVal: %s, witnessScript: %j)', vin, hashType, witnessValue, witnessScript);
    debug('Transaction Builder network: %j', this.network);
    // TODO: remove keyPair.network matching in 4.0.0
    if (keyPair.network && keyPair.network !== this.network)
        throw new TypeError('Inconsistent network');
    if (!this.inputs[vin])
        throw new Error('No input at index: ' + vin);
    hashType = hashType || Transaction.SIGHASH_ALL;
    var input = this.inputs[vin];
    // if redeemScript was previously provided, enforce consistency
    if (input.redeemScript !== undefined &&
        redeemScript &&
        !input.redeemScript.equals(redeemScript)) {
        throw new Error('Inconsistent redeemScript');
    }
    var kpPubKey = keyPair.publicKey || keyPair.getPublicKeyBuffer();
    if (!canSign(input)) {
        if (witnessValue !== undefined) {
            if (input.value !== undefined && input.value !== witnessValue)
                throw new Error('Input didn\'t match witnessValue');
            typeforce(types.Satoshi, witnessValue);
            input.value = witnessValue;
        }
        debug('Preparing input %d for signing', vin);
        if (!canSign(input))
            prepareInput(input, kpPubKey, redeemScript, witnessValue, witnessScript);
        if (!canSign(input))
            throw Error(input.prevOutType + ' not supported');
    }
    // ready to sign
    var signatureHash = this.tx.hashForSignatureByNetwork(vin, input.signScript, witnessValue, hashType, !!input.witness);
    // enforce in order signing of public keys
    var signed = input.pubKeys.some(function (pubKey, i) {
        if (!kpPubKey.equals(pubKey))
            return false;
        if (input.signatures[i])
            throw new Error('Signature already exists');
        if (kpPubKey.length !== 33 &&
            input.signType === scriptTypes.P2WPKH)
            throw new Error('BIP143 rejects uncompressed public keys in P2WPKH or P2WSH');
        var signature = keyPair.sign(signatureHash);
        if (Buffer.isBuffer(signature))
            signature = ECSignature.fromRSBuffer(signature);
        debug('Produced signature (r: %s, s: %s)', signature.r, signature.s);
        input.signatures[i] = signature.toScriptSignature(hashType);
        return true;
    });
    if (!signed)
        throw new Error('Key pair cannot sign for this input');
};
function signatureHashType(buffer) {
    return buffer.readUInt8(buffer.length - 1);
}
TransactionBuilder.prototype.__canModifyInputs = function () {
    return this.inputs.every(function (input) {
        // any signatures?
        if (input.signatures === undefined)
            return true;
        return input.signatures.every(function (signature) {
            if (!signature)
                return true;
            var hashType = signatureHashType(signature);
            // if SIGHASH_ANYONECANPAY is set, signatures would not
            // be invalidated by more inputs
            return hashType & Transaction.SIGHASH_ANYONECANPAY;
        });
    });
};
TransactionBuilder.prototype.__canModifyOutputs = function () {
    var nInputs = this.tx.ins.length;
    var nOutputs = this.tx.outs.length;
    return this.inputs.every(function (input) {
        if (input.signatures === undefined)
            return true;
        return input.signatures.every(function (signature) {
            if (!signature)
                return true;
            var hashType = signatureHashType(signature);
            var hashTypeMod = hashType & 0x1f;
            if (hashTypeMod === Transaction.SIGHASH_NONE)
                return true;
            if (hashTypeMod === Transaction.SIGHASH_SINGLE) {
                // if SIGHASH_SINGLE is set, and nInputs > nOutputs
                // some signatures would be invalidated by the addition
                // of more outputs
                return nInputs <= nOutputs;
            }
        });
    });
};
TransactionBuilder.prototype.__overMaximumFees = function (bytes) {
    // not all inputs will have .value defined
    var incoming = this.inputs.reduce(function (a, x) { return a + (x.value >>> 0); }, 0);
    // but all outputs do, and if we have any input value
    // we can immediately determine if the outputs are too small
    var outgoing = this.tx.outs.reduce(function (a, x) { return a + x.value; }, 0);
    var fee = incoming - outgoing;
    var feeRate = fee / bytes;
    return feeRate > this.maximumFeeRate;
};
module.exports = TransactionBuilder;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoidHJhbnNhY3Rpb25fYnVpbGRlci5qcyIsInNvdXJjZVJvb3QiOiIiLCJzb3VyY2VzIjpbIi4uLy4uL3NyYy90cmFuc2FjdGlvbl9idWlsZGVyLmpzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiJBQUFBLElBQUksTUFBTSxHQUFHLE9BQU8sQ0FBQyxhQUFhLENBQUMsQ0FBQyxNQUFNLENBQUE7QUFDMUMsSUFBSSxRQUFRLEdBQUcsT0FBTyxDQUFDLFdBQVcsQ0FBQyxDQUFBO0FBQ25DLElBQUksT0FBTyxHQUFHLE9BQU8sQ0FBQyxVQUFVLENBQUMsQ0FBQTtBQUNqQyxJQUFJLE9BQU8sR0FBRyxPQUFPLENBQUMsVUFBVSxDQUFDLENBQUE7QUFDakMsSUFBSSxVQUFVLEdBQUcsT0FBTyxDQUFDLGFBQWEsQ0FBQyxDQUFBO0FBQ3ZDLElBQUksS0FBSyxHQUFHLE9BQU8sQ0FBQyxTQUFTLENBQUMsQ0FBQTtBQUM5QixJQUFJLFFBQVEsR0FBRyxPQUFPLENBQUMsWUFBWSxDQUFDLENBQUE7QUFDcEMsSUFBSSxHQUFHLEdBQUcsT0FBTyxDQUFDLGFBQWEsQ0FBQyxDQUFBO0FBQ2hDLElBQUksU0FBUyxHQUFHLE9BQU8sQ0FBQyxXQUFXLENBQUMsQ0FBQTtBQUNwQyxJQUFJLEtBQUssR0FBRyxPQUFPLENBQUMsU0FBUyxDQUFDLENBQUE7QUFDOUIsSUFBSSxXQUFXLEdBQUcsVUFBVSxDQUFDLEtBQUssQ0FBQTtBQUNsQyxJQUFJLFFBQVEsR0FBRyxDQUFDLFVBQVUsQ0FBQyxLQUFLLENBQUMsS0FBSyxFQUFFLFVBQVUsQ0FBQyxLQUFLLENBQUMsSUFBSSxFQUFFLFVBQVUsQ0FBQyxLQUFLLENBQUMsUUFBUSxDQUFDLENBQUE7QUFDekYsSUFBSSxJQUFJLEdBQUcsUUFBUSxDQUFDLE1BQU0sQ0FBQyxDQUFDLFVBQVUsQ0FBQyxLQUFLLENBQUMsTUFBTSxFQUFFLFVBQVUsQ0FBQyxLQUFLLENBQUMsS0FBSyxDQUFDLENBQUMsQ0FBQTtBQUU3RSxJQUFJLE1BQU0sR0FBRyxP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QUFJLENBQUE7WUFDekQsSUFBSSxXQUFXLEtBQUssV0FBVyxDQUFDLGNBQWMsRUFBRTtnQkFDOUMsbURBQW1EO2dCQUNuRCx1REFBdUQ7Z0JBQ3ZELGtCQUFrQjtnQkFDbEIsT0FBTyxPQUFPLElBQUksUUFBUSxDQUFBO2FBQzNCO1FBQ0gsQ0FBQyxDQUFDLENBQUE7SUFDSixDQUFDLENBQUMsQ0FBQTtBQUNKLENBQUMsQ0FBQTtBQUVELGtCQUFrQixDQUFDLFNBQVMsQ0FBQyxpQkFBaUIsR0FBRyxVQUFVLEtBQUs7SUFDOUQsMENBQTBDO0lBQzFDLElBQUksUUFBUSxHQUFHLElBQUksQ0FBQyxNQUFNLENBQUMsTUFBTSxDQUFDLFVBQVUsQ0FBQyxFQUFFLENBQUMsSUFBSSxPQUFPLENBQUMsR0FBRyxDQUFDLENBQUMsQ0FBQyxLQUFLLEtBQUssQ0FBQyxDQUFDLENBQUEsQ0FBQyxDQUFDLEVBQUUsQ0FBQyxDQUFDLENBQUE7SUFFcEYscURBQXFEO0lBQ3JELDREQUE0RDtJQUM1RCxJQUFJLFFBQVEsR0FBRyxJQUFJLENBQUMsRUFBRSxDQUFDLElBQUksQ0FBQyxNQUFNLENBQUMsVUFBVSxDQUFDLEVBQUUsQ0FBQyxJQUFJLE9BQU8sQ0FBQyxHQUFHLENBQUMsQ0FBQyxLQUFLLENBQUEsQ0FBQyxDQUFDLEVBQUUsQ0FBQyxDQUFDLENBQUE7SUFDN0UsSUFBSSxHQUFHLEdBQUcsUUFBUSxHQUFHLFFBQVEsQ0FBQTtJQUM3QixJQUFJLE9BQU8sR0FBRyxHQUFHLEdBQUcsS0FBSyxDQUFBO0lBRXpCLE9BQU8sT0FBTyxHQUFHLElBQUksQ0FBQyxjQUFjLENBQUE7QUFDdEMsQ0FBQyxDQUFBO0FBRUQsTUFBTSxDQUFDLE9BQU8sR0FBRyxrQkFBa0IsQ0FBQSIsInNvdXJjZXNDb250ZW50IjpbInZhciBCdWZmZXIgPSByZXF1aXJlKCdzYWZlLWJ1ZmZlcicpLkJ1ZmZlclxudmFyIGJhZGRyZXNzID0gcmVxdWlyZSgnLi9hZGRyZXNzJylcbnZhciBiY3J5cHRvID0gcmVxdWlyZSgnLi9jcnlwdG8nKVxudmFyIGJzY3JpcHQgPSByZXF1aXJlKCcuL3NjcmlwdCcpXG52YXIgYnRlbXBsYXRlcyA9IHJlcXVpcmUoJy4vdGVtcGxhdGVzJylcbnZhciBjb2lucyA9IHJlcXVpcmUoJy4vY29pbnMnKVxudmFyIG5ldHdvcmtzID0gcmVxdWlyZSgnLi9uZXR3b3JrcycpXG52YXIgb3BzID0gcmVxdWlyZSgnYml0Y29pbi1vcHMnKVxudmFyIHR5cGVmb3JjZSA9IHJlcXVpcmUoJ3R5cGVmb3JjZScpXG52YXIgdHlwZXMgPSByZXF1aXJlKCcuL3R5cGVzJylcbnZhciBzY3JpcHRUeXBlcyA9IGJ0ZW1wbGF0ZXMudHlwZXNcbnZhciBTSUdOQUJMRSA9IFtidGVtcGxhdGVzLnR5cGVzLlAyUEtILCBidGVtcGxhdGVzLnR5cGVzLlAyUEssIGJ0ZW1wbGF0ZXMudHlwZXMuTVVMVElTSUddXG52YXIgUDJTSCA9IFNJR05BQkxFLmNvbmNhdChbYnRlbXBsYXRlcy50eXBlcy5QMldQS0gsIGJ0ZW1wbGF0ZXMudHlwZXMuUDJXU0hdKVxuXG52YXIgRUNQYWlyID0gcmVxdWlyZSgnLi9lY3BhaXInKVxudmFyIEVDU2lnbmF0dXJlID0gcmVxdWlyZSgnLi9lY3NpZ25hdHVyZScpXG52YXIgVHJhbnNhY3Rpb24gPSByZXF1aXJlKCcuL3RyYW5zYWN0aW9uJylcbmNvbnN0IHsgZ2V0TWFpbm5ldCwgZ2V0TmV0d29ya05hbWUgfSA9IHJlcXVpcmUoJy4vY29pbnMnKVxuXG52YXIgZGVidWcgPSByZXF1aXJlKCdkZWJ1ZycpKCdiaXRnbzp1dHhvbGliOnR4YnVpbGRlcicpXG5cbmZ1bmN0aW9uIHN1cHBvcnRlZFR5cGUgKHR5cGUpIHtcbiAgcmV0dXJuIFNJR05BQkxFLmluZGV4T2YodHlwZSkgIT09IC0xXG59XG5cbmZ1bmN0aW9uIHN1cHBvcnRlZFAyU0hUeXBlICh0eXBlKSB7XG4gIHJldHVybiBQMlNILmluZGV4T2YodHlwZSkgIT09IC0xXG59XG5cbmZ1bmN0aW9uIGV4dHJhY3RDaHVua3MgKHR5cGUsIGNodW5rcywgc2NyaXB0KSB7XG4gIHZhciBwdWJLZXlzID0gW11cbiAgdmFyIHNpZ25hdHVyZXMgPSBbXVxuICBzd2l0Y2ggKHR5cGUpIHtcbiAgICBjYXNlIHNjcmlwdFR5cGVzLlAyUEtIOlxuICAgICAgLy8gaWYgKHJlZGVlbVNjcmlwdCkgdGhyb3cgbmV3IEVycm9yKCdOb25zdGFuZGFyZC4uLiBQMlNIKFAyUEtIKScpXG4gICAgICBwdWJLZXlzID0gY2h1bmtzLnNsaWNlKDEpXG4gICAgICBzaWduYXR1cmVzID0gY2h1bmtzLnNsaWNlKDAsIDEpXG4gICAgICBicmVha1xuXG4gICAgY2FzZSBzY3JpcHRUeXBlcy5QMlBLOlxuICAgICAgcHViS2V5c1swXSA9IHNjcmlwdCA/IGJ0ZW1wbGF0ZXMucHViS2V5Lm91dHB1dC5kZWNvZGUoc2NyaXB0KSA6IHVuZGVmaW5lZFxuICAgICAgc2lnbmF0dXJlcyA9IGNodW5rcy5zbGljZSgwLCAxKVxuICAgICAgYnJlYWtcblxuICAgIGNhc2Ugc2NyaXB0VHlwZXMuTVVMVElTSUc6XG4gICAgICBpZiAoc2NyaXB0KSB7XG4gICAgICAgIHZhciBtdWx0aXNpZyA9IGJ0ZW1wbGF0ZXMubXVsdGlzaWcub3V0cHV0LmRlY29kZShzY3JpcHQpXG4gICAgICAgIHB1YktleXMgPSBtdWx0aXNpZy5wdWJLZXlzXG4gICAgICB9XG5cbiAgICAgIHNpZ25hdHVyZXMgPSBjaHVua3Muc2xpY2UoMSkubWFwKGZ1bmN0aW9uIChjaHVuaykge1xuICAgICAgICByZXR1cm4gY2h1bmsubGVuZ3RoID09PSAwID8gdW5kZWZpbmVkIDogY2h1bmtcbiAgICAgIH0pXG4gICAgICBicmVha1xuICB9XG5cbiAgcmV0dXJuIHtcbiAgICBwdWJLZXlzOiBwdWJLZXlzLFxuICAgIHNpZ25hdHVyZXM6IHNpZ25hdHVyZXNcbiAgfVxufVxuZnVuY3Rpb24gZXhwYW5kSW5wdXQgKHNjcmlwdFNpZywgd2l0bmVzc1N0YWNrKSB7XG4gIGlmIChzY3JpcHRTaWcubGVuZ3RoID09PSAwICYmIHdpdG5lc3NTdGFjay5sZW5ndGggPT09IDApIHJldHVybiB7fVxuXG4gIHZhciBwcmV2T3V0U2NyaXB0XG4gIHZhciBwcmV2T3V0VHlwZVxuICB2YXIgc2NyaXB0VHlwZVxuICB2YXIgc2NyaXB0XG4gIHZhciByZWRlZW1TY3JpcHRcbiAgdmFyIHdpdG5lc3NTY3JpcHRcbiAgdmFyIHdpdG5lc3NTY3JpcHRUeXBlXG4gIHZhciByZWRlZW1TY3JpcHRUeXBlXG4gIHZhciB3aXRuZXNzID0gZmFsc2VcbiAgdmFyIHAyd3NoID0gZmFsc2VcbiAgdmFyIHAyc2ggPSBmYWxzZVxuICB2YXIgd2l0bmVzc1Byb2dyYW1cbiAgdmFyIGNodW5rc1xuXG4gIHZhciBzY3JpcHRTaWdDaHVua3MgPSBic2NyaXB0LmRlY29tcGlsZShzY3JpcHRTaWcpXG4gIHZhciBzaWdUeXBlID0gYnRlbXBsYXRlcy5jbGFzc2lmeUlucHV0KHNjcmlwdFNpZ0NodW5rcywgdHJ1ZSlcbiAgaWYgKHNpZ1R5cGUgPT09IHNjcmlwdFR5cGVzLlAyU0gpIHtcbiAgICBwMnNoID0gdHJ1ZVxuICAgIHJlZGVlbVNjcmlwdCA9IHNjcmlwdFNpZ0NodW5rc1tzY3JpcHRTaWdDaHVua3MubGVuZ3RoIC0gMV1cbiAgICByZWRlZW1TY3JpcHRUeXBlID0gYnRlbXBsYXRlcy5jbGFzc2lmeU91dHB1dChyZWRlZW1TY3JpcHQpXG4gICAgcHJldk91dFNjcmlwdCA9IGJ0ZW1wbGF0ZXMuc2NyaXB0SGFzaC5vdXRwdXQuZW5jb2RlKGJjcnlwdG8uaGFzaDE2MChyZWRlZW1TY3JpcHQpKVxuICAgIHByZXZPdXRUeXBlID0gc2NyaXB0VHlwZXMuUDJTSFxuICAgIHNjcmlwdCA9IHJlZGVlbVNjcmlwdFxuICB9XG5cbiAgdmFyIGNsYXNzaWZ5V2l0bmVzcyA9IGJ0ZW1wbGF0ZXMuY2xhc3NpZnlXaXRuZXNzKHdpdG5lc3NTdGFjaywgdHJ1ZSlcbiAgaWYgKGNsYXNzaWZ5V2l0bmVzcyA9PT0gc2NyaXB0VHlwZXMuUDJXU0gpIHtcbiAgICB3aXRuZXNzU2NyaXB0ID0gd2l0bmVzc1N0YWNrW3dpdG5lc3NTdGFjay5sZW5ndGggLSAxXVxuICAgIHdpdG5lc3NTY3JpcHRUeXBlID0gYnRlbXBsYXRlcy5jbGFzc2lmeU91dHB1dCh3aXRuZXNzU2NyaXB0KVxuICAgIHAyd3NoID0gdHJ1ZVxuICAgIHdpdG5lc3MgPSB0cnVlXG4gICAgaWYgKHNjcmlwdFNpZy5sZW5ndGggPT09IDApIHtcbiAgICAgIHByZXZPdXRTY3JpcHQgPSBidGVtcGxhdGVzLndpdG5lc3NTY3JpcHRIYXNoLm91dHB1dC5lbmNvZGUoYmNyeXB0by5zaGEyNTYod2l0bmVzc1NjcmlwdCkpXG4gICAgICBwcmV2T3V0VHlwZSA9IHNjcmlwdFR5cGVzLlAyV1NIXG4gICAgICBpZiAocmVkZWVtU2NyaXB0ICE9PSB1bmRlZmluZWQpIHtcbiAgICAgICAgdGhyb3cgbmV3IEVycm9yKCdSZWRlZW0gc2NyaXB0IGdpdmVuIHdoZW4gdW5uZWNlc3NhcnknKVxuICAgICAgfVxuICAgICAgLy8gYmFyZSB3aXRuZXNzXG4gICAgfSBlbHNlIHtcbiAgICAgIGlmICghcmVkZWVtU2NyaXB0KSB7XG4gICAgICAgIHRocm93IG5ldyBFcnJvcignTm8gcmVkZWVtU2NyaXB0IHByb3ZpZGVkIGZvciBQMldTSCwgYnV0IHNjcmlwdFNpZyBub24tZW1wdHknKVxuICAgICAgfVxuICAgICAgd2l0bmVzc1Byb2dyYW0gPSBidGVtcGxhdGVzLndpdG5lc3NTY3JpcHRIYXNoLm91dHB1dC5lbmNvZGUoYmNyeXB0by5zaGEyNTYod2l0bmVzc1NjcmlwdCkpXG4gICAgICBpZiAoIXJlZGVlbVNjcmlwdC5lcXVhbHMod2l0bmVzc1Byb2dyYW0pKSB7XG4gICAgICAgIHRocm93IG5ldyBFcnJvcignUmVkZWVtIHNjcmlwdCBkaWRuXFwndCBtYXRjaCB3aXRuZXNzU2NyaXB0JylcbiAgICAgIH1cbiAgICB9XG5cbiAgICBpZiAoIXN1cHBvcnRlZFR5cGUoYnRlbXBsYXRlcy5jbGFzc2lmeU91dHB1dCh3aXRuZXNzU2NyaXB0KSkpIHtcbiAgICAgIHRocm93IG5ldyBFcnJvcigndW5zdXBwb3J0ZWQgd2l0bmVzcyBzY3JpcHQnKVxuICAgIH1cblxuICAgIHNjcmlwdCA9IHdpdG5lc3NTY3JpcHRcbiAgICBzY3JpcHRUeXBlID0gd2l0bmVzc1NjcmlwdFR5cGVcbiAgICBjaHVua3MgPSB3aXRuZXNzU3RhY2suc2xpY2UoMCwgLTEpXG4gIH0gZWxzZSBpZiAoY2xhc3NpZnlXaXRuZXNzID09PSBzY3JpcHRUeXBlcy5QMldQS0gpIHtcbiAgICB3aXRuZXNzID0gdHJ1ZVxuICAgIHZhciBrZXkgPSB3aXRuZXNzU3RhY2tbd2l0bmVzc1N0YWNrLmxlbmd0aCAtIDFdXG4gICAgdmFyIGtleUhhc2ggPSBiY3J5cHRvLmhhc2gxNjAoa2V5KVxuICAgIGlmIChzY3JpcHRTaWcubGVuZ3RoID09PSAwKSB7XG4gICAgICBwcmV2T3V0U2NyaXB0ID0gYnRlbXBsYXRlcy53aXRuZXNzUHViS2V5SGFzaC5vdXRwdXQuZW5jb2RlKGtleUhhc2gpXG4gICAgICBwcmV2T3V0VHlwZSA9IHNjcmlwdFR5cGVzLlAyV1BLSFxuICAgICAgaWYgKHR5cGVvZiByZWRlZW1TY3JpcHQgIT09ICd1bmRlZmluZWQnKSB7XG4gICAgICAgIHRocm93IG5ldyBFcnJvcignUmVkZWVtIHNjcmlwdCBnaXZlbiB3aGVuIHVubmVjZXNzYXJ5JylcbiAgICAgIH1cbiAgICB9IGVsc2Uge1xuICAgICAgaWYgKCFyZWRlZW1TY3JpcHQpIHtcbiAgICAgICAgdGhyb3cgbmV3IEVycm9yKCdObyByZWRlZW1TY3JpcHQgcHJvdmlkZWQgZm9yIFAyV1BLSCwgYnV0IHNjcmlwdFNpZyB3YXNuXFwndCBlbXB0eScpXG4gICAgICB9XG4gICAgICB3aXRuZXNzUHJvZ3JhbSA9IGJ0ZW1wbGF0ZXMud2l0bmVzc1B1YktleUhhc2gub3V0cHV0LmVuY29kZShrZXlIYXNoKVxuICAgICAgaWYgKCFyZWRlZW1TY3JpcHQuZXF1YWxzKHdpdG5lc3NQcm9ncmFtKSkge1xuICAgICAgICB0aHJvdyBuZXcgRXJyb3IoJ1JlZGVlbSBzY3JpcHQgZGlkIG5vdCBoYXZlIHRoZSByaWdodCB3aXRuZXNzIHByb2dyYW0nKVxuICAgICAgfVxuICAgIH1cblxuICAgIHNjcmlwdFR5cGUgPSBzY3JpcHRUeXBlcy5QMlBLSFxuICAgIGNodW5rcyA9IHdpdG5lc3NTdGFja1xuICB9IGVsc2UgaWYgKHJlZGVlbVNjcmlwdCkge1xuICAgIGlmICghc3VwcG9ydGVkUDJTSFR5cGUocmVkZWVtU2NyaXB0VHlwZSkpIHtcbiAgICAgIHRocm93IG5ldyBFcnJvcignQmFkIHJlZGVlbXNjcmlwdCEnKVxuICAgIH1cblxuICAgIHNjcmlwdCA9IHJlZGVlbVNjcmlwdFxuICAgIHNjcmlwdFR5cGUgPSByZWRlZW1TY3JpcHRUeXBlXG4gICAgY2h1bmtzID0gc2NyaXB0U2lnQ2h1bmtzLnNsaWNlKDAsIC0xKVxuICB9IGVsc2Uge1xuICAgIHByZXZPdXRUeXBlID0gc2NyaXB0VHlwZSA9IGJ0ZW1wbGF0ZXMuY2xhc3NpZnlJbnB1dChzY3JpcHRTaWcpXG4gICAgY2h1bmtzID0gc2NyaXB0U2lnQ2h1bmtzXG4gIH1cblxuICB2YXIgZXhwYW5kZWQgPSBleHRyYWN0Q2h1bmtzKHNjcmlwdFR5cGUsIGNodW5rcywgc2NyaXB0KVxuXG4gIHZhciByZXN1bHQgPSB7XG4gICAgcHViS2V5czogZXhwYW5kZWQucHViS2V5cyxcbiAgICBzaWduYXR1cmVzOiBleHBhbmRlZC5zaWduYXR1cmVzLFxuICAgIHByZXZPdXRTY3JpcHQ6IHByZXZPdXRTY3JpcHQsXG4gICAgcHJldk91dFR5cGU6IHByZXZPdXRUeXBlLFxuICAgIHNpZ25UeXBlOiBzY3JpcHRUeXBlLFxuICAgIHNpZ25TY3JpcHQ6IHNjcmlwdCxcbiAgICB3aXRuZXNzOiBCb29sZWFuKHdpdG5lc3MpXG4gIH1cblxuICBpZiAocDJzaCkge1xuICAgIHJlc3VsdC5yZWRlZW1TY3JpcHQgPSByZWRlZW1TY3JpcHRcbiAgICByZXN1bHQucmVkZWVtU2NyaXB0VHlwZSA9IHJlZGVlbVNjcmlwdFR5cGVcbiAgfVxuXG4gIGlmIChwMndzaCkge1xuICAgIHJlc3VsdC53aXRuZXNzU2NyaXB0ID0gd2l0bmVzc1NjcmlwdFxuICAgIHJlc3VsdC53aXRuZXNzU2NyaXB0VHlwZSA9IHdpdG5lc3NTY3JpcHRUeXBlXG4gIH1cblxuICByZXR1cm4gcmVzdWx0XG59XG5cbi8vIGNvdWxkIGJlIGRvbmUgaW4gZXhwYW5kSW5wdXQsIGJ1dCByZXF1aXJlcyB0aGUgb3JpZ2luYWwgVHJhbnNhY3Rpb24gZm9yIGhhc2hGb3JTaWduYXR1cmVcbmZ1bmN0aW9uIGZpeE11bHRpc2lnT3JkZXIgKGlucHV0LCB0cmFuc2FjdGlvbiwgdmluLCB2YWx1ZSwgbmV0d29yaykge1xuICBpZiAoaW5wdXQucmVkZWVtU2NyaXB0VHlwZSAhPT0gc2NyaXB0VHlwZXMuTVVMVElTSUcgfHwgIWlucHV0LnJlZGVlbVNjcmlwdCkgcmV0dXJuXG4gIGlmIChpbnB1dC5wdWJLZXlzLmxlbmd0aCA9PT0gaW5wdXQuc2lnbmF0dXJlcy5sZW5ndGgpIHJldHVyblxuXG4gIG5ldHdvcmsgPSBuZXR3b3JrIHx8IG5ldHdvcmtzLmJpdGNvaW5cbiAgdmFyIHVubWF0Y2hlZCA9IGlucHV0LnNpZ25hdHVyZXMuY29uY2F0KClcblxuICBpbnB1dC5zaWduYXR1cmVzID0gaW5wdXQucHViS2V5cy5tYXAoZnVuY3Rpb24gKHB1YktleSkge1xuICAgIHZhciBrZXlQYWlyID0gRUNQYWlyLmZyb21QdWJsaWNLZXlCdWZmZXIocHViS2V5KVxuICAgIHZhciBtYXRjaFxuXG4gICAgLy8gY2hlY2sgZm9yIGEgc2lnbmF0dXJlXG4gICAgdW5tYXRjaGVkLnNvbWUoZnVuY3Rpb24gKHNpZ25hdHVyZSwgaSkge1xuICAgICAgLy8gc2tpcCBpZiB1bmRlZmluZWQgfHwgT1BfMFxuICAgICAgaWYgKCFzaWduYXR1cmUpIHJldHVybiBmYWxzZVxuICAgICAgaWYgKGNvaW5zLmlzWmNhc2gobmV0d29yaykgJiYgdmFsdWUgPT09IHVuZGVmaW5lZCkge1xuICAgICAgICByZXR1cm4gZmFsc2VcbiAgICAgIH1cblxuICAgICAgLy8gVE9ETzogYXZvaWQgTyhuKSBoYXNoRm9yU2lnbmF0dXJlXG4gICAgICB2YXIgcGFyc2VkID0gRUNTaWduYXR1cmUucGFyc2VTY3JpcHRTaWduYXR1cmUoc2lnbmF0dXJlKVxuICAgICAgdmFyIGhhc2ggPSB0cmFuc2FjdGlvbi5oYXNoRm9yU2lnbmF0dXJlQnlOZXR3b3JrKFxuICAgICAgICB2aW4sXG4gICAgICAgIGlucHV0LnNpZ25TY3JpcHQsXG4gICAgICAgIHZhbHVlLFxuICAgICAgICBwYXJzZWQuaGFzaFR5cGUsXG4gICAgICAgICEhaW5wdXQud2l0bmVzcyxcbiAgICAgIClcblxuICAgICAgLy8gc2tpcCBpZiBzaWduYXR1cmUgZG9lcyBub3QgbWF0Y2ggcHViS2V5XG4gICAgICBpZiAoIWtleVBhaXIudmVyaWZ5KGhhc2gsIHBhcnNlZC5zaWduYXR1cmUpKSByZXR1cm4gZmFsc2VcblxuICAgICAgLy8gcmVtb3ZlIG1hdGNoZWQgc2lnbmF0dXJlIGZyb20gdW5tYXRjaGVkXG4gICAgICB1bm1hdGNoZWRbaV0gPSB1bmRlZmluZWRcbiAgICAgIG1hdGNoID0gc2lnbmF0dXJlXG5cbiAgICAgIHJldHVybiB0cnVlXG4gICAgfSlcblxuICAgIHJldHVybiBtYXRjaFxuICB9KVxufVxuXG5mdW5jdGlvbiBleHBhbmRPdXRwdXQgKHNjcmlwdCwgc2NyaXB0VHlwZSwgb3VyUHViS2V5KSB7XG4gIHR5cGVmb3JjZSh0eXBlcy5CdWZmZXIsIHNjcmlwdClcblxuICB2YXIgc2NyaXB0Q2h1bmtzID0gYnNjcmlwdC5kZWNvbXBpbGUoc2NyaXB0KVxuICBpZiAoIXNjcmlwdFR5cGUpIHtcbiAgICBzY3JpcHRUeXBlID0gYnRlbXBsYXRlcy5jbGFzc2lmeU91dHB1dChzY3JpcHQpXG4gIH1cblxuICB2YXIgcHViS2V5cyA9IFtdXG5cbiAgc3dpdGNoIChzY3JpcHRUeXBlKSB7XG4gICAgLy8gZG9lcyBvdXIgaGFzaDE2MChwdWJLZXkpIG1hdGNoIHRoZSBvdXRwdXQgc2NyaXB0cz9cbiAgICBjYXNlIHNjcmlwdFR5cGVzLlAyUEtIOlxuICAgICAgaWYgKCFvdXJQdWJLZXkpIGJyZWFrXG5cbiAgICAgIHZhciBwa2gxID0gc2NyaXB0Q2h1bmtzWzJdXG4gICAgICB2YXIgcGtoMiA9IGJjcnlwdG8uaGFzaDE2MChvdXJQdWJLZXkpXG4gICAgICBpZiAocGtoMS5lcXVhbHMocGtoMikpIHB1YktleXMgPSBbb3VyUHViS2V5XVxuICAgICAgYnJlYWtcblxuICAgIC8vIGRvZXMgb3VyIGhhc2gxNjAocHViS2V5KSBtYXRjaCB0aGUgb3V0cHV0IHNjcmlwdHM/XG4gICAgY2FzZSBzY3JpcHRUeXBlcy5QMldQS0g6XG4gICAgICBpZiAoIW91clB1YktleSkgYnJlYWtcblxuICAgICAgdmFyIHdwa2gxID0gc2NyaXB0Q2h1bmtzWzFdXG4gICAgICB2YXIgd3BraDIgPSBiY3J5cHRvLmhhc2gxNjAob3VyUHViS2V5KVxuICAgICAgaWYgKHdwa2gxLmVxdWFscyh3cGtoMikpIHB1YktleXMgPSBbb3VyUHViS2V5XVxuICAgICAgYnJlYWtcblxuICAgIGNhc2Ugc2NyaXB0VHlwZXMuUDJQSzpcbiAgICAgIHB1YktleXMgPSBzY3JpcHRDaHVua3Muc2xpY2UoMCwgMSlcbiAgICAgIGJyZWFrXG5cbiAgICBjYXNlIHNjcmlwdFR5cGVzLk1VTFRJU0lHOlxuICAgICAgcHViS2V5cyA9IHNjcmlwdENodW5rcy5zbGljZSgxLCAtMilcbiAgICAgIGJyZWFrXG5cbiAgICBkZWZhdWx0OiByZXR1cm4geyBzY3JpcHRUeXBlOiBzY3JpcHRUeXBlIH1cbiAgfVxuXG4gIHJldHVybiB7XG4gICAgcHViS2V5czogcHViS2V5cyxcbiAgICBzY3JpcHRUeXBlOiBzY3JpcHRUeXBlLFxuICAgIHNpZ25hdHVyZXM6IHB1YktleXMubWFwKGZ1bmN0aW9uICgpIHsgcmV0dXJuIHVuZGVmaW5lZCB9KVxuICB9XG59XG5cbmZ1bmN0aW9uIGNoZWNrUDJTSElucHV0IChpbnB1dCwgcmVkZWVtU2NyaXB0SGFzaCkge1xuICBpZiAoaW5wdXQucHJldk91dFR5cGUpIHtcbiAgICBpZiAoaW5wdXQucHJldk91dFR5cGUgIT09IHNjcmlwdFR5cGVzLlAyU0gpIHRocm93IG5ldyBFcnJvcignUHJldk91dFNjcmlwdCBtdXN0IGJlIFAyU0gnKVxuXG4gICAgdmFyIHByZXZPdXRTY3JpcHRTY3JpcHRIYXNoID0gYnNjcmlwdC5kZWNvbXBpbGUoaW5wdXQucHJldk91dFNjcmlwdClbMV1cbiAgICBpZiAoIXByZXZPdXRTY3JpcHRTY3JpcHRIYXNoLmVxdWFscyhyZWRlZW1TY3JpcHRIYXNoKSkgdGhyb3cgbmV3IEVycm9yKCdJbmNvbnNpc3RlbnQgaGFzaDE2MChSZWRlZW1TY3JpcHQpJylcbiAgfVxufVxuXG5mdW5jdGlvbiBjaGVja1AyV1NISW5wdXQgKGlucHV0LCB3aXRuZXNzU2NyaXB0SGFzaCkge1xuICBpZiAoaW5wdXQucHJldk91dFR5cGUpIHtcbiAgICBpZiAoaW5wdXQucHJldk91dFR5cGUgIT09IHNjcmlwdFR5cGVzLlAyV1NIKSB0aHJvdyBuZXcgRXJyb3IoJ1ByZXZPdXRTY3JpcHQgbXVzdCBiZSBQMldTSCcpXG5cbiAgICB2YXIgc2NyaXB0SGFzaCA9IGJzY3JpcHQuZGVjb21waWxlKGlucHV0LnByZXZPdXRTY3JpcHQpWzFdXG4gICAgaWYgKCFzY3JpcHRIYXNoLmVxdWFscyh3aXRuZXNzU2NyaXB0SGFzaCkpIHRocm93IG5ldyBFcnJvcignSW5jb25zaXN0ZW50IHNoYTI1KFdpdG5lc3NTY3JpcHQpJylcbiAgfVxufVxuXG5mdW5jdGlvbiBwcmVwYXJlSW5wdXQgKGlucHV0LCBrcFB1YktleSwgcmVkZWVtU2NyaXB0LCB3aXRuZXNzVmFsdWUsIHdpdG5lc3NTY3JpcHQpIHtcbiAgdmFyIGV4cGFuZGVkXG4gIHZhciBwcmV2T3V0VHlwZVxuICB2YXIgcHJldk91dFNjcmlwdFxuXG4gIHZhciBwMnNoID0gZmFsc2VcbiAgdmFyIHAyc2hUeXBlXG4gIHZhciByZWRlZW1TY3JpcHRIYXNoXG5cbiAgdmFyIHdpdG5lc3MgPSBmYWxzZVxuICB2YXIgcDJ3c2ggPSBmYWxzZVxuICB2YXIgd2l0bmVzc1R5cGVcbiAgdmFyIHdpdG5lc3NTY3JpcHRIYXNoXG5cbiAgdmFyIHNpZ25UeXBlXG4gIHZhciBzaWduU2NyaXB0XG5cbiAgaWYgKHJlZGVlbVNjcmlwdCAmJiB3aXRuZXNzU2NyaXB0KSB7XG4gICAgcmVkZWVtU2NyaXB0SGFzaCA9IGJjcnlwdG8uaGFzaDE2MChyZWRlZW1TY3JpcHQpXG4gICAgd2l0bmVzc1NjcmlwdEhhc2ggPSBiY3J5cHRvLnNoYTI1Nih3aXRuZXNzU2NyaXB0KVxuICAgIGNoZWNrUDJTSElucHV0KGlucHV0LCByZWRlZW1TY3JpcHRIYXNoKVxuXG4gICAgaWYgKCFyZWRlZW1TY3JpcHQuZXF1YWxzKGJ0ZW1wbGF0ZXMud2l0bmVzc1NjcmlwdEhhc2gub3V0cHV0LmVuY29kZSh3aXRuZXNzU2NyaXB0SGFzaCkpKSB0aHJvdyBuZXcgRXJyb3IoJ1dpdG5lc3Mgc2NyaXB0IGluY29uc2lzdGVudCB3aXRoIHJlZGVlbSBzY3JpcHQnKVxuXG4gICAgZXhwYW5kZWQgPSBleHBhbmRPdXRwdXQod2l0bmVzc1NjcmlwdCwgdW5kZWZpbmVkLCBrcFB1YktleSlcbiAgICBpZiAoIWV4cGFuZGVkLnB1YktleXMpIHRocm93IG5ldyBFcnJvcignV2l0bmVzc1NjcmlwdCBub3Qgc3VwcG9ydGVkIFwiJyArIGJzY3JpcHQudG9BU00ocmVkZWVtU2NyaXB0KSArICdcIicpXG5cbiAgICBwcmV2T3V0VHlwZSA9IGJ0ZW1wbGF0ZXMudHlwZXMuUDJTSFxuICAgIHByZXZPdXRTY3JpcHQgPSBidGVtcGxhdGVzLnNjcmlwdEhhc2gub3V0cHV0LmVuY29kZShyZWRlZW1TY3JpcHRIYXNoKVxuICAgIHAyc2ggPSB3aXRuZXNzID0gcDJ3c2ggPSB0cnVlXG4gICAgcDJzaFR5cGUgPSBidGVtcGxhdGVzLnR5cGVzLlAyV1NIXG4gICAgc2lnblR5cGUgPSB3aXRuZXNzVHlwZSA9IGV4cGFuZGVkLnNjcmlwdFR5cGVcbiAgICBzaWduU2NyaXB0ID0gd2l0bmVzc1NjcmlwdFxuICB9IGVsc2UgaWYgKHJlZGVlbVNjcmlwdCkge1xuICAgIHJlZGVlbVNjcmlwdEhhc2ggPSBiY3J5cHRvLmhhc2gxNjAocmVkZWVtU2NyaXB0KVxuICAgIGNoZWNrUDJTSElucHV0KGlucHV0LCByZWRlZW1TY3JpcHRIYXNoKVxuXG4gICAgZXhwYW5kZWQgPSBleHBhbmRPdXRwdXQocmVkZWVtU2NyaXB0LCB1bmRlZmluZWQsIGtwUHViS2V5KVxuICAgIGlmICghZXhwYW5kZWQucHViS2V5cykgdGhyb3cgbmV3IEVycm9yKCdSZWRlZW1TY3JpcHQgbm90IHN1cHBvcnRlZCBcIicgKyBic2NyaXB0LnRvQVNNKHJlZGVlbVNjcmlwdCkgKyAnXCInKVxuXG4gICAgcHJldk91dFR5cGUgPSBidGVtcGxhdGVzLnR5cGVzLlAyU0hcbiAgICBwcmV2T3V0U2NyaXB0ID0gYnRlbXBsYXRlcy5zY3JpcHRIYXNoLm91dHB1dC5lbmNvZGUocmVkZWVtU2NyaXB0SGFzaClcbiAgICBwMnNoID0gdHJ1ZVxuICAgIHNpZ25UeXBlID0gcDJzaFR5cGUgPSBleHBhbmRlZC5zY3JpcHRUeXBlXG4gICAgc2lnblNjcmlwdCA9IHJlZGVlbVNjcmlwdFxuICAgIHdpdG5lc3MgPSBzaWduVHlwZSA9PT0gYnRlbXBsYXRlcy50eXBlcy5QMldQS0hcbiAgfSBlbHNlIGlmICh3aXRuZXNzU2NyaXB0KSB7XG4gICAgd2l0bmVzc1NjcmlwdEhhc2ggPSBiY3J5cHRvLnNoYTI1Nih3aXRuZXNzU2NyaXB0KVxuICAgIGNoZWNrUDJXU0hJbnB1dChpbnB1dCwgd2l0bmVzc1NjcmlwdEhhc2gpXG5cbiAgICBleHBhbmRlZCA9IGV4cGFuZE91dHB1dCh3aXRuZXNzU2NyaXB0LCB1bmRlZmluZWQsIGtwUHViS2V5KVxuICAgIGlmICghZXhwYW5kZWQucHViS2V5cykgdGhyb3cgbmV3IEVycm9yKCdXaXRuZXNzU2NyaXB0IG5vdCBzdXBwb3J0ZWQgXCInICsgYnNjcmlwdC50b0FTTShyZWRlZW1TY3JpcHQpICsgJ1wiJylcblxuICAgIHByZXZPdXRUeXBlID0gYnRlbXBsYXRlcy50eXBlcy5QMldTSFxuICAgIHByZXZPdXRTY3JpcHQgPSBidGVtcGxhdGVzLndpdG5lc3NTY3JpcHRIYXNoLm91dHB1dC5lbmNvZGUod2l0bmVzc1NjcmlwdEhhc2gpXG4gICAgd2l0bmVzcyA9IHAyd3NoID0gdHJ1ZVxuICAgIHNpZ25UeXBlID0gd2l0bmVzc1R5cGUgPSBleHBhbmRlZC5zY3JpcHRUeXBlXG4gICAgc2lnblNjcmlwdCA9IHdpdG5lc3NTY3JpcHRcbiAgfSBlbHNlIGlmIChpbnB1dC5wcmV2T3V0VHlwZSkge1xuICAgIC8vIGVtYmVkZGVkIHNjcmlwdHMgYXJlIG5vdCBwb3NzaWJsZSB3aXRob3V0IGEgcmVkZWVtU2NyaXB0XG4gICAgaWYgKGlucHV0LnByZXZPdXRUeXBlID09PSBzY3JpcHRUeXBlcy5QMlNIIHx8XG4gICAgICBpbnB1dC5wcmV2T3V0VHlwZSA9PT0gc2NyaXB0VHlwZXMuUDJXU0gpIHtcbiAgICAgIHRocm93IG5ldyBFcnJvcignUHJldk91dFNjcmlwdCBpcyAnICsgaW5wdXQucHJldk91dFR5cGUgKyAnLCByZXF1aXJlcyByZWRlZW1TY3JpcHQnKVxuICAgIH1cblxuICAgIHByZXZPdXRUeXBlID0gaW5wdXQucHJldk91dFR5cGVcbiAgICBwcmV2T3V0U2NyaXB0ID0gaW5wdXQucHJldk91dFNjcmlwdFxuICAgIGV4cGFuZGVkID0gZXhwYW5kT3V0cHV0KGlucHV0LnByZXZPdXRTY3JpcHQsIGlucHV0LnByZXZPdXRUeXBlLCBrcFB1YktleSlcbiAgICBpZiAoIWV4cGFuZGVkLnB1YktleXMpIHJldHVyblxuXG4gICAgd2l0bmVzcyA9IChpbnB1dC5wcmV2T3V0VHlwZSA9PT0gc2NyaXB0VHlwZXMuUDJXUEtIKVxuICAgIHNpZ25UeXBlID0gcHJldk91dFR5cGVcbiAgICBzaWduU2NyaXB0ID0gcHJldk91dFNjcmlwdFxuICB9IGVsc2Uge1xuICAgIHByZXZPdXRTY3JpcHQgPSBidGVtcGxhdGVzLnB1YktleUhhc2gub3V0cHV0LmVuY29kZShiY3J5cHRvLmhhc2gxNjAoa3BQdWJLZXkpKVxuICAgIGV4cGFuZGVkID0gZXhwYW5kT3V0cHV0KHByZXZPdXRTY3JpcHQsIHNjcmlwdFR5cGVzLlAyUEtILCBrcFB1YktleSlcblxuICAgIHByZXZPdXRUeXBlID0gc2NyaXB0VHlwZXMuUDJQS0hcbiAgICB3aXRuZXNzID0gZmFsc2VcbiAgICBzaWduVHlwZSA9IHByZXZPdXRUeXBlXG4gICAgc2lnblNjcmlwdCA9IHByZXZPdXRTY3JpcHRcbiAgfVxuXG4gIGlmIChzaWduVHlwZSA9PT0gc2NyaXB0VHlwZXMuUDJXUEtIKSB7XG4gICAgc2lnblNjcmlwdCA9IGJ0ZW1wbGF0ZXMucHViS2V5SGFzaC5vdXRwdXQuZW5jb2RlKGJ0ZW1wbGF0ZXMud2l0bmVzc1B1YktleUhhc2gub3V0cHV0LmRlY29kZShzaWduU2NyaXB0KSlcbiAgfVxuXG4gIGlmIChwMnNoKSB7XG4gICAgaW5wdXQucmVkZWVtU2NyaXB0ID0gcmVkZWVtU2NyaXB0XG4gICAgaW5wdXQucmVkZWVtU2NyaXB0VHlwZSA9IHAyc2hUeXBlXG4gIH1cblxuICBpZiAocDJ3c2gpIHtcbiAgICBpbnB1dC53aXRuZXNzU2NyaXB0ID0gd2l0bmVzc1NjcmlwdFxuICAgIGlucHV0LndpdG5lc3NTY3JpcHRUeXBlID0gd2l0bmVzc1R5cGVcbiAgfVxuXG4gIGlucHV0LnB1YktleXMgPSBleHBhbmRlZC5wdWJLZXlzXG4gIGlucHV0LnNpZ25hdHVyZXMgPSBleHBhbmRlZC5zaWduYXR1cmVzXG4gIGlucHV0LnNpZ25TY3JpcHQgPSBzaWduU2NyaXB0XG4gIGlucHV0LnNpZ25UeXBlID0gc2lnblR5cGVcbiAgaW5wdXQucHJldk91dFNjcmlwdCA9IHByZXZPdXRTY3JpcHRcbiAgaW5wdXQucHJldk91dFR5cGUgPSBwcmV2T3V0VHlwZVxuICBpbnB1dC53aXRuZXNzID0gd2l0bmVzc1xufVxuXG5mdW5jdGlvbiBidWlsZFN0YWNrICh0eXBlLCBzaWduYXR1cmVzLCBwdWJLZXlzLCBhbGxvd0luY29tcGxldGUpIHtcbiAgaWYgKHR5cGUgPT09IHNjcmlwdFR5cGVzLlAyUEtIKSB7XG4gICAgaWYgKHNpZ25hdHVyZXMubGVuZ3RoID09PSAxICYmIEJ1ZmZlci5pc0J1ZmZlcihzaWduYXR1cmVzWzBdKSAmJiBwdWJLZXlzLmxlbmd0aCA9PT0gMSkgcmV0dXJuIGJ0ZW1wbGF0ZXMucHViS2V5SGFzaC5pbnB1dC5lbmNvZGVTdGFjayhzaWduYXR1cmVzWzBdLCBwdWJLZXlzWzBdKVxuICB9IGVsc2UgaWYgKHR5cGUgPT09IHNjcmlwdFR5cGVzLlAyUEspIHtcbiAgICBpZiAoc2lnbmF0dXJlcy5sZW5ndGggPT09IDEgJiYgQnVmZmVyLmlzQnVmZmVyKHNpZ25hdHVyZXNbMF0pKSByZXR1cm4gYnRlbXBsYXRlcy5wdWJLZXkuaW5wdXQuZW5jb2RlU3RhY2soc2lnbmF0dXJlc1swXSlcbiAgfSBlbHNlIGlmICh0eXBlID09PSBzY3JpcHRUeXBlcy5NVUxUSVNJRykge1xuICAgIGlmIChzaWduYXR1cmVzLmxlbmd0aCA+IDApIHtcbiAgICAgIHNpZ25hdHVyZXMgPSBzaWduYXR1cmVzLm1hcChmdW5jdGlvbiAoc2lnbmF0dXJlKSB7XG4gICAgICAgIHJldHVybiBzaWduYXR1cmUgfHwgb3BzLk9QXzBcbiAgICAgIH0pXG4gICAgICBpZiAoIWFsbG93SW5jb21wbGV0ZSkge1xuICAgICAgICAvLyByZW1vdmUgYmxhbmsgc2lnbmF0dXJlc1xuICAgICAgICBzaWduYXR1cmVzID0gc2lnbmF0dXJlcy5maWx0ZXIoZnVuY3Rpb24gKHgpIHsgcmV0dXJuIHggIT09IG9wcy5PUF8wIH0pXG4gICAgICB9XG5cbiAgICAgIHJldHVybiBidGVtcGxhdGVzLm11bHRpc2lnLmlucHV0LmVuY29kZVN0YWNrKHNpZ25hdHVyZXMpXG4gICAgfVxuICB9IGVsc2Uge1xuICAgIHRocm93IG5ldyBFcnJvcignTm90IHlldCBzdXBwb3J0ZWQnKVxuICB9XG5cbiAgaWYgKCFhbGxvd0luY29tcGxldGUpIHRocm93IG5ldyBFcnJvcignTm90IGVub3VnaCBzaWduYXR1cmVzIHByb3ZpZGVkJylcbiAgcmV0dXJuIFtdXG59XG5cbmZ1bmN0aW9uIGJ1aWxkSW5wdXQgKGlucHV0LCBhbGxvd0luY29tcGxldGUpIHtcbiAgdmFyIHNjcmlwdFR5cGUgPSBpbnB1dC5wcmV2T3V0VHlwZVxuICB2YXIgc2lnID0gW11cbiAgdmFyIHdpdG5lc3MgPSBbXVxuXG4gIGlmIChzdXBwb3J0ZWRUeXBlKHNjcmlwdFR5cGUpKSB7XG4gICAgc2lnID0gYnVpbGRTdGFjayhzY3JpcHRUeXBlLCBpbnB1dC5zaWduYXR1cmVzLCBpbnB1dC5wdWJLZXlzLCBhbGxvd0luY29tcGxldGUpXG4gIH1cblxuICB2YXIgcDJzaCA9IGZhbHNlXG4gIGlmIChzY3JpcHRUeXBlID09PSBidGVtcGxhdGVzLnR5cGVzLlAyU0gpIHtcbiAgICAvLyBXZSBjYW4gcmVtb3ZlIHRoaXMgZXJyb3IgbGF0ZXIgd2hlbiB3ZSBoYXZlIGEgZ3VhcmFudGVlIHByZXBhcmVJbnB1dFxuICAgIC8vIHJlamVjdHMgdW5zaWduYWJsZSBzY3JpcHRzIC0gaXQgTVVTVCBiZSBzaWduYWJsZSBhdCB0aGlzIHBvaW50LlxuICAgIGlmICghYWxsb3dJbmNvbXBsZXRlICYmICFzdXBwb3J0ZWRQMlNIVHlwZShpbnB1dC5yZWRlZW1TY3JpcHRUeXBlKSkge1xuICAgICAgdGhyb3cgbmV3IEVycm9yKCdJbXBvc3NpYmxlIHRvIHNpZ24gdGhpcyB0eXBlJylcbiAgICB9XG5cbiAgICBpZiAoc3VwcG9ydGVkVHlwZShpbnB1dC5yZWRlZW1TY3JpcHRUeXBlKSkge1xuICAgICAgc2lnID0gYnVpbGRTdGFjayhpbnB1dC5yZWRlZW1TY3JpcHRUeXBlLCBpbnB1dC5zaWduYXR1cmVzLCBpbnB1dC5wdWJLZXlzLCBhbGxvd0luY29tcGxldGUpXG4gICAgfVxuXG4gICAgLy8gSWYgaXQgd2Fzbid0IFNJR05BQkxFLCBpdCdzIHdpdG5lc3MsIGRlZmVyIHRvIHRoYXRcbiAgICBpZiAoaW5wdXQucmVkZWVtU2NyaXB0VHlwZSkge1xuICAgICAgcDJzaCA9IHRydWVcbiAgICAgIHNjcmlwdFR5cGUgPSBpbnB1dC5yZWRlZW1TY3JpcHRUeXBlXG4gICAgfVxuICB9XG5cbiAgc3dpdGNoIChzY3JpcHRUeXBlKSB7XG4gICAgLy8gUDJXUEtIIGlzIGEgc3BlY2lhbCBjYXNlIG9mIFAyUEtIXG4gICAgY2FzZSBidGVtcGxhdGVzLnR5cGVzLlAyV1BLSDpcbiAgICAgIHdpdG5lc3MgPSBidWlsZFN0YWNrKGJ0ZW1wbGF0ZXMudHlwZXMuUDJQS0gsIGlucHV0LnNpZ25hdHVyZXMsIGlucHV0LnB1YktleXMsIGFsbG93SW5jb21wbGV0ZSlcbiAgICAgIGJyZWFrXG5cbiAgICBjYXNlIGJ0ZW1wbGF0ZXMudHlwZXMuUDJXU0g6XG4gICAgICAvLyBXZSBjYW4gcmVtb3ZlIHRoaXMgY2hlY2sgbGF0ZXJcbiAgICAgIGlmICghYWxsb3dJbmNvbXBsZXRlICYmICFzdXBwb3J0ZWRUeXBlKGlucHV0LndpdG5lc3NTY3JpcHRUeXBlKSkge1xuICAgICAgICB0aHJvdyBuZXcgRXJyb3IoJ0ltcG9zc2libGUgdG8gc2lnbiB0aGlzIHR5cGUnKVxuICAgICAgfVxuXG4gICAgICBpZiAoc3VwcG9ydGVkVHlwZShpbnB1dC53aXRuZXNzU2NyaXB0VHlwZSkpIHtcbiAgICAgICAgd2l0bmVzcyA9IGJ1aWxkU3RhY2soaW5wdXQud2l0bmVzc1NjcmlwdFR5cGUsIGlucHV0LnNpZ25hdHVyZXMsIGlucHV0LnB1YktleXMsIGFsbG93SW5jb21wbGV0ZSlcbiAgICAgICAgd2l0bmVzcy5wdXNoKGlucHV0LndpdG5lc3NTY3JpcHQpXG4gICAgICAgIHNjcmlwdFR5cGUgPSBpbnB1dC53aXRuZXNzU2NyaXB0VHlwZVxuICAgICAgfVxuICAgICAgYnJlYWtcbiAgfVxuXG4gIC8vIGFwcGVuZCByZWRlZW1TY3JpcHQgaWYgbmVjZXNzYXJ5XG4gIGlmIChwMnNoKSB7XG4gICAgc2lnLnB1c2goaW5wdXQucmVkZWVtU2NyaXB0KVxuICB9XG5cbiAgcmV0dXJuIHtcbiAgICB0eXBlOiBzY3JpcHRUeXBlLFxuICAgIHNjcmlwdDogYnNjcmlwdC5jb21waWxlKHNpZyksXG4gICAgd2l0bmVzczogd2l0bmVzc1xuICB9XG59XG5cbi8vIEJ5IGRlZmF1bHQsIGFzc3VtZSBpcyBhIGJpdGNvaW4gdHJhbnNhY3Rpb25cbmZ1bmN0aW9uIFRyYW5zYWN0aW9uQnVpbGRlciAobmV0d29yaywgbWF4aW11bUZlZVJhdGUpIHtcbiAgdGhpcy5wcmV2VHhNYXAgPSB7fVxuICB0aGlzLm5ldHdvcmsgPSBuZXR3b3JrIHx8IG5ldHdvcmtzLmJpdGNvaW5cblxuICAvLyBXQVJOSU5HOiBUaGlzIGlzIF9fTk9UX18gdG8gYmUgcmVsaWVkIG9uLCBpdHMganVzdCBhbm90aGVyIHBvdGVudGlhbCBzYWZldHkgbWVjaGFuaXNtIChzYWZldHkgaW4tZGVwdGgpXG4gIHRoaXMubWF4aW11bUZlZVJhdGUgPSBtYXhpbXVtRmVlUmF0ZSB8fCAyNTAwXG5cbiAgdGhpcy5pbnB1dHMgPSBbXVxuICB0aGlzLnR4ID0gbmV3IFRyYW5zYWN0aW9uKHRoaXMubmV0d29yaylcbn1cblxuVHJhbnNhY3Rpb25CdWlsZGVyLnByb3RvdHlwZS5zZXRMb2NrVGltZSA9IGZ1bmN0aW9uIChsb2NrdGltZSkge1xuICB0eXBlZm9yY2UodHlwZXMuVUludDMyLCBsb2NrdGltZSlcblxuICAvLyBpZiBhbnkgc2lnbmF0dXJlcyBleGlzdCwgdGhyb3dcbiAgaWYgKHRoaXMuaW5wdXRzLnNvbWUoZnVuY3Rpb24gKGlucHV0KSB7XG4gICAgaWYgKCFpbnB1dC5zaWduYXR1cmVzKSByZXR1cm4gZmFsc2VcblxuICAgIHJldHVybiBpbnB1dC5zaWduYXR1cmVzLnNvbWUoZnVuY3Rpb24gKHMpIHsgcmV0dXJuIHMgfSlcbiAgfSkpIHtcbiAgICB0aHJvdyBuZXcgRXJyb3IoJ05vLCB0aGlzIHdvdWxkIGludmFsaWRhdGUgc2lnbmF0dXJlcycpXG4gIH1cblxuICB0aGlzLnR4LmxvY2t0aW1lID0gbG9ja3RpbWVcbn1cblxuVHJhbnNhY3Rpb25CdWlsZGVyLnByb3RvdHlwZS5zZXRWZXJzaW9uID0gZnVuY3Rpb24gKHZlcnNpb24sIG92ZXJ3aW50ZXIgPSB0cnVlKSB7XG4gIHR5cGVmb3JjZSh0eXBlcy5VSW50MzIsIHZlcnNpb24pXG5cbiAgaWYgKGNvaW5zLmlzWmNhc2godGhpcy5uZXR3b3JrKSkge1xuICAgIGlmICghdGhpcy5uZXR3b3JrLmNvbnNlbnN1c0JyYW5jaElkLmhhc093blByb3BlcnR5KHRoaXMudHgudmVyc2lvbikpIHtcbiAgICAgIC8qIGlzdGFuYnVsIGlnbm9yZSBuZXh0ICovXG4gICAgICB0aHJvdyBuZXcgRXJyb3IoJ1Vuc3VwcG9ydGVkIFpjYXNoIHRyYW5zYWN0aW9uJylcbiAgICB9XG4gICAgdGhpcy50eC5vdmVyd2ludGVyZWQgPSAob3ZlcndpbnRlciA/IDEgOiAwKVxuICAgIHRoaXMudHguY29uc2Vuc3VzQnJhbmNoSWQgPSB0aGlzLm5ldHdvcmsuY29uc2Vuc3VzQnJhbmNoSWRbdmVyc2lvbl1cbiAgfVxuICB0aGlzLnR4LnZlcnNpb24gPSB2ZXJzaW9uXG59XG5cblRyYW5zYWN0aW9uQnVpbGRlci5wcm90b3R5cGUuc2V0Q29uc2Vuc3VzQnJhbmNoSWQgPSBmdW5jdGlvbiAoY29uc2Vuc3VzQnJhbmNoSWQpIHtcbiAgaWYgKCFjb2lucy5pc1pjYXNoKHRoaXMubmV0d29yaykpIHtcbiAgICAvKiBpc3RhbmJ1bCBpZ25vcmUgbmV4dCAqL1xuICAgIHRocm93IG5ldyBFcnJvcignY29uc2Vuc3VzQnJhbmNoSWQgY2FuIG9ubHkgYmUgc2V0IGZvciBaY2FzaCB0cmFuc2FjdGlvbnMnKVxuICB9XG4gIGlmICghdGhpcy5pbnB1dHMuZXZlcnkoZnVuY3Rpb24gKGlucHV0KSB7IHJldHVybiBpbnB1dC5zaWduYXR1cmVzID09PSB1bmRlZmluZWQgfSkpIHtcbiAgICAvKiBpc3RhbmJ1bCBpZ25vcmUgbmV4dCAqL1xuICAgIHRocm93IG5ldyBFcnJvcignQ2hhbmdpbmcgdGhlIGNvbnNlbnN1c0JyYW5jaElkIGZvciBhIHBhcnRpYWxseSBzaWduZWQgdHJhbnNhY3Rpb24gd291bGQgaW52YWxpZGF0ZSBzaWduYXR1cmVzJylcbiAgfVxuICB0eXBlZm9yY2UodHlwZXMuVUludDMyLCBjb25zZW5zdXNCcmFuY2hJZClcbiAgdGhpcy50eC5jb25zZW5zdXNCcmFuY2hJZCA9IGNvbnNlbnN1c0JyYW5jaElkXG59XG5cblRyYW5zYWN0aW9uQnVpbGRlci5wcm90b3R5cGUuc2V0VmVyc2lvbkdyb3VwSWQgPSBmdW5jdGlvbiAodmVyc2lvbkdyb3VwSWQpIHtcbiAgaWYgKCEoY29pbnMuaXNaY2FzaCh0aGlzLm5ldHdvcmspICYmIHRoaXMudHguaXNPdmVyd2ludGVyQ29tcGF0aWJsZSgpKSkge1xuICAgIC8qIGlzdGFuYnVsIGlnbm9yZSBuZXh0ICovXG4gICAgdGhyb3cgbmV3IEVycm9yKCdleHBpcnlIZWlnaHQgY2FuIG9ubHkgYmUgc2V0IGZvciBaY2FzaCBzdGFydGluZyBhdCBvdmVyd2ludGVyIHZlcnNpb24uIEN1cnJlbnQgbmV0d29yazogJyArXG4gICAgICBnZXROZXR3b3JrTmFtZSh0aGlzLm5ldHdvcmspICsgJywgdmVyc2lvbjogJyArIHRoaXMudHgudmVyc2lvbilcbiAgfVxuICB0eXBlZm9yY2UodHlwZXMuVUludDMyLCB2ZXJzaW9uR3JvdXBJZClcbiAgdGhpcy50eC52ZXJzaW9uR3JvdXBJZCA9IHZlcnNpb25Hcm91cElkXG59XG5cblRyYW5zYWN0aW9uQnVpbGRlci5wcm90b3R5cGUuc2V0RXhwaXJ5SGVpZ2h0ID0gZnVuY3Rpb24gKGV4cGlyeUhlaWdodCkge1xuICBpZiAoIShjb2lucy5pc1pjYXNoKHRoaXMubmV0d29yaykgJiYgdGhpcy50eC5pc092ZXJ3aW50ZXJDb21wYXRpYmxlKCkpKSB7XG4gICAgLyogaXN0YW5idWwgaWdub3JlIG5leHQgKi9cbiAgICB0aHJvdyBuZXcgRXJyb3IoJ2V4cGlyeUhlaWdodCBjYW4gb25seSBiZSBzZXQgZm9yIFpjYXNoIHN0YXJ0aW5nIGF0IG92ZXJ3aW50ZXIgdmVyc2lvbi4gQ3VycmVudCBuZXR3b3JrOiAnICtcbiAgICAgIGdldE5ldHdvcmtOYW1lKHRoaXMubmV0d29yaykgKyAnLCB2ZXJzaW9uOiAnICsgdGhpcy50eC52ZXJzaW9uKVxuICB9XG4gIHR5cGVmb3JjZSh0eXBlcy5VSW50MzIsIGV4cGlyeUhlaWdodClcbiAgdGhpcy50eC5leHBpcnlIZWlnaHQgPSBleHBpcnlIZWlnaHRcbn1cblxuVHJhbnNhY3Rpb25CdWlsZGVyLmZyb21UcmFuc2FjdGlvbiA9IGZ1bmN0aW9uICh0cmFuc2FjdGlvbiwgbmV0d29yaykge1xuICB2YXIgdHhiTmV0d29yayA9IG5ldHdvcmsgfHwgbmV0d29ya3MuYml0Y29pblxuICB2YXIgdHhiID0gbmV3IFRyYW5zYWN0aW9uQnVpbGRlcih0eGJOZXR3b3JrKVxuXG4gIGlmIChnZXRNYWlubmV0KHR4Yi5uZXR3b3JrKSAhPT0gZ2V0TWFpbm5ldCh0cmFuc2FjdGlvbi5uZXR3b3JrKSkge1xuICAgIHRocm93IG5ldyBFcnJvcignVGhpcyB0cmFuc2FjdGlvbiBpcyBpbmNvbXBhdGlibGUgd2l0aCB0aGUgdHJhbnNhY3Rpb24gYnVpbGRlcicpXG4gIH1cblxuICAvLyBDb3B5IHRyYW5zYWN0aW9uIGZpZWxkc1xuICB0eGIuc2V0VmVyc2lvbih0cmFuc2FjdGlvbi52ZXJzaW9uLCB0cmFuc2FjdGlvbi5vdmVyd2ludGVyZWQpXG4gIHR4Yi5zZXRMb2NrVGltZSh0cmFuc2FjdGlvbi5sb2NrdGltZSlcblxuICBpZiAoY29pbnMuaXNaY2FzaCh0eGJOZXR3b3JrKSkge1xuICAgIC8vIENvcHkgWmNhc2ggb3ZlcndpbnRlciBmaWVsZHMuIE9taXR0ZWQgaWYgdGhlIHRyYW5zYWN0aW9uIGJ1aWxkZXIgaXMgbm90IGZvciBaY2FzaC5cbiAgICBpZiAodHhiLnR4LmlzT3ZlcndpbnRlckNvbXBhdGlibGUoKSkge1xuICAgICAgdHhiLnNldFZlcnNpb25Hcm91cElkKHRyYW5zYWN0aW9uLnZlcnNpb25Hcm91cElkKVxuICAgICAgdHhiLnNldEV4cGlyeUhlaWdodCh0cmFuc2FjdGlvbi5leHBpcnlIZWlnaHQpXG4gICAgfVxuXG4gICAgdHhiLnNldENvbnNlbnN1c0JyYW5jaElkKHRyYW5zYWN0aW9uLmNvbnNlbnN1c0JyYW5jaElkKVxuICB9XG5cbiAgLy8gQ29weSBEYXNoIHNwZWNpYWwgdHJhbnNhY3Rpb24gZmllbGRzLiBPbWl0dGVkIGlmIHRoZSB0cmFuc2FjdGlvbiBidWlsZGVyIGlzIG5vdCBmb3IgRGFzaC5cbiAgaWYgKGNvaW5zLmlzRGFzaCh0eGJOZXR3b3JrKSkge1xuICAgIHR5cGVmb3JjZSh0eXBlcy5VSW50MTYsIHRyYW5zYWN0aW9uLnR5cGUpXG4gICAgdHhiLnR4LnR5cGUgPSB0cmFuc2FjdGlvbi50eXBlXG5cbiAgICBpZiAodHhiLnR4LnZlcnNpb25TdXBwb3J0c0Rhc2hTcGVjaWFsVHJhbnNhY3Rpb25zKCkpIHtcbiAgICAgIHR5cGVmb3JjZSh0eXBlcy5CdWZmZXIsIHRyYW5zYWN0aW9uLmV4dHJhUGF5bG9hZClcbiAgICAgIHR4Yi50eC5leHRyYVBheWxvYWQgPSB0cmFuc2FjdGlvbi5leHRyYVBheWxvYWRcbiAgICB9XG4gIH1cblxuICAvLyBDb3B5IG91dHB1dHMgKGRvbmUgZmlyc3QgdG8gYXZvaWQgc2lnbmF0dXJlIGludmFsaWRhdGlvbilcbiAgdHJhbnNhY3Rpb24ub3V0cy5mb3JFYWNoKGZ1bmN0aW9uICh0eE91dCkge1xuICAgIHR4Yi5hZGRPdXRwdXQodHhPdXQuc2NyaXB0LCB0eE91dC52YWx1ZSlcbiAgfSlcblxuICAvLyBDb3B5IGlucHV0c1xuICB0cmFuc2FjdGlvbi5pbnMuZm9yRWFjaChmdW5jdGlvbiAodHhJbikge1xuICAgIHR4Yi5fX2FkZElucHV0VW5zYWZlKHR4SW4uaGFzaCwgdHhJbi5pbmRleCwge1xuICAgICAgc2VxdWVuY2U6IHR4SW4uc2VxdWVuY2UsXG4gICAgICBzY3JpcHQ6IHR4SW4uc2NyaXB0LFxuICAgICAgd2l0bmVzczogdHhJbi53aXRuZXNzLFxuICAgICAgdmFsdWU6IHR4SW4udmFsdWVcbiAgICB9KVxuICB9KVxuXG4gIC8vIGZpeCBzb21lIHRoaW5ncyBub3QgcG9zc2libGUgdGhyb3VnaCB0aGUgcHVibGljIEFQSVxuICB0eGIuaW5wdXRzLmZvckVhY2goZnVuY3Rpb24gKGlucHV0LCBpKSB7XG4gICAgZml4TXVsdGlzaWdPcmRlcihpbnB1dCwgdHJhbnNhY3Rpb24sIGksIGlucHV0LnZhbHVlLCB0eGJOZXR3b3JrKVxuICB9KVxuXG4gIHJldHVybiB0eGJcbn1cblxuVHJhbnNhY3Rpb25CdWlsZGVyLnByb3RvdHlwZS5hZGRJbnB1dCA9IGZ1bmN0aW9uICh0eEhhc2gsIHZvdXQsIHNlcXVlbmNlLCBwcmV2T3V0U2NyaXB0KSB7XG4gIGlmICghdGhpcy5fX2Nhbk1vZGlmeUlucHV0cygpKSB7XG4gICAgdGhyb3cgbmV3IEVycm9yKCdObywgdGhpcyB3b3VsZCBpbnZhbGlkYXRlIHNpZ25hdHVyZXMnKVxuICB9XG5cbiAgdmFyIHZhbHVlXG5cbiAgLy8gaXMgaXQgYSBoZXggc3RyaW5nP1xuICBpZiAodHlwZW9mIHR4SGFzaCA9PT0gJ3N0cmluZycpIHtcbiAgICAvLyB0cmFuc2FjdGlvbiBoYXNocydzIGFyZSBkaXNwbGF5ZWQgaW4gcmV2ZXJzZSBvcmRlciwgdW4tcmV2ZXJzZSBpdFxuICAgIHR4SGFzaCA9IEJ1ZmZlci5mcm9tKHR4SGFzaCwgJ2hleCcpLnJldmVyc2UoKVxuXG4gIC8vIGlzIGl0IGEgVHJhbnNhY3Rpb24gb2JqZWN0P1xuICB9IGVsc2UgaWYgKHR4SGFzaCBpbnN0YW5jZW9mIFRyYW5zYWN0aW9uKSB7XG4gICAgdmFyIHR4T3V0ID0gdHhIYXNoLm91dHNbdm91dF1cbiAgICBwcmV2T3V0U2NyaXB0ID0gdHhPdXQuc2NyaXB0XG4gICAgdmFsdWUgPSB0eE91dC52YWx1ZVxuXG4gICAgdHhIYXNoID0gdHhIYXNoLmdldEhhc2goKVxuICB9XG5cbiAgcmV0dXJuIHRoaXMuX19hZGRJbnB1dFVuc2FmZSh0eEhhc2gsIHZvdXQsIHtcbiAgICBzZXF1ZW5jZTogc2VxdWVuY2UsXG4gICAgcHJldk91dFNjcmlwdDogcHJldk91dFNjcmlwdCxcbiAgICB2YWx1ZTogdmFsdWVcbiAgfSlcbn1cblxuVHJhbnNhY3Rpb25CdWlsZGVyLnByb3RvdHlwZS5fX2FkZElucHV0VW5zYWZlID0gZnVuY3Rpb24gKHR4SGFzaCwgdm91dCwgb3B0aW9ucykge1xuICBpZiAoVHJhbnNhY3Rpb24uaXNDb2luYmFzZUhhc2godHhIYXNoKSkge1xuICAgIHRocm93IG5ldyBFcnJvcignY29pbmJhc2UgaW5wdXRzIG5vdCBzdXBwb3J0ZWQnKVxuICB9XG5cbiAgdmFyIHByZXZUeE91dCA9IHR4SGFzaC50b1N0cmluZygnaGV4JykgKyAnOicgKyB2b3V0XG4gIGlmICh0aGlzLnByZXZUeE1hcFtwcmV2VHhPdXRdICE9PSB1bmRlZmluZWQpIHRocm93IG5ldyBFcnJvcignRHVwbGljYXRlIFR4T3V0OiAnICsgcHJldlR4T3V0KVxuXG4gIHZhciBpbnB1dCA9IHt9XG5cbiAgLy8gZGVyaXZlIHdoYXQgd2UgY2FuIGZyb20gdGhlIHNjcmlwdFNpZ1xuICBpZiAob3B0aW9ucy5zY3JpcHQgIT09IHVuZGVmaW5lZCkge1xuICAgIGlucHV0ID0gZXhwYW5kSW5wdXQob3B0aW9ucy5zY3JpcHQsIG9wdGlvbnMud2l0bmVzcyB8fCBbXSlcbiAgfVxuXG4gIC8vIGlmIGFuIGlucHV0IHZhbHVlIHdhcyBnaXZlbiwgcmV0YWluIGl0XG4gIGlmIChvcHRpb25zLnZhbHVlICE9PSB1bmRlZmluZWQpIHtcbiAgICBpbnB1dC52YWx1ZSA9IG9wdGlvbnMudmFsdWVcbiAgfVxuXG4gIC8vIGRlcml2ZSB3aGF0IHdlIGNhbiBmcm9tIHRoZSBwcmV2aW91cyB0cmFuc2FjdGlvbnMgb3V0cHV0IHNjcmlwdFxuICBpZiAoIWlucHV0LnByZXZPdXRTY3JpcHQgJiYgb3B0aW9ucy5wcmV2T3V0U2NyaXB0KSB7XG4gICAgdmFyIHByZXZPdXRUeXBlXG5cbiAgICBpZiAoIWlucHV0LnB1YktleXMgJiYgIWlucHV0LnNpZ25hdHVyZXMpIHtcbiAgICAgIHZhciBleHBhbmRlZCA9IGV4cGFuZE91dHB1dChvcHRpb25zLnByZXZPdXRTY3JpcHQpXG5cbiAgICAgIGlmIChleHBhbmRlZC5wdWJLZXlzKSB7XG4gICAgICAgIGlucHV0LnB1YktleXMgPSBleHBhbmRlZC5wdWJLZXlzXG4gICAgICAgIGlucHV0LnNpZ25hdHVyZXMgPSBleHBhbmRlZC5zaWduYXR1cmVzXG4gICAgICB9XG5cbiAgICAgIHByZXZPdXRUeXBlID0gZXhwYW5kZWQuc2NyaXB0VHlwZVxuICAgIH1cblxuICAgIGlucHV0LnByZXZPdXRTY3JpcHQgPSBvcHRpb25zLnByZXZPdXRTY3JpcHRcbiAgICBpbnB1dC5wcmV2T3V0VHlwZSA9IHByZXZPdXRUeXBlIHx8IGJ0ZW1wbGF0ZXMuY2xhc3NpZnlPdXRwdXQob3B0aW9ucy5wcmV2T3V0U2NyaXB0KVxuICB9XG5cbiAgdmFyIHZpbiA9IHRoaXMudHguYWRkSW5wdXQodHhIYXNoLCB2b3V0LCBvcHRpb25zLnNlcXVlbmNlLCBvcHRpb25zLnNjcmlwdFNpZylcbiAgdGhpcy5pbnB1dHNbdmluXSA9IGlucHV0XG4gIHRoaXMucHJldlR4TWFwW3ByZXZUeE91dF0gPSB2aW5cbiAgcmV0dXJuIHZpblxufVxuXG5UcmFuc2FjdGlvbkJ1aWxkZXIucHJvdG90eXBlLmFkZE91dHB1dCA9IGZ1bmN0aW9uIChzY3JpcHRQdWJLZXksIHZhbHVlKSB7XG4gIGlmICghdGhpcy5fX2Nhbk1vZGlmeU91dHB1dHMoKSkge1xuICAgIHRocm93IG5ldyBFcnJvcignTm8sIHRoaXMgd291bGQgaW52YWxpZGF0ZSBzaWduYXR1cmVzJylcbiAgfVxuXG4gIC8vIEF0dGVtcHQgdG8gZ2V0IGEgc2NyaXB0IGlmIGl0J3MgYSBiYXNlNTggYWRkcmVzcyBzdHJpbmdcbiAgaWYgKHR5cGVvZiBzY3JpcHRQdWJLZXkgPT09ICdzdHJpbmcnKSB7XG4gICAgc2NyaXB0UHViS2V5ID0gYmFkZHJlc3MudG9PdXRwdXRTY3JpcHQoc2NyaXB0UHViS2V5LCB0aGlzLm5ldHdvcmspXG4gIH1cblxuICByZXR1cm4gdGhpcy50eC5hZGRPdXRwdXQoc2NyaXB0UHViS2V5LCB2YWx1ZSlcbn1cblxuVHJhbnNhY3Rpb25CdWlsZGVyLnByb3RvdHlwZS5idWlsZCA9IGZ1bmN0aW9uICgpIHtcbiAgcmV0dXJuIHRoaXMuX19idWlsZChmYWxzZSlcbn1cblRyYW5zYWN0aW9uQnVpbGRlci5wcm90b3R5cGUuYnVpbGRJbmNvbXBsZXRlID0gZnVuY3Rpb24gKCkge1xuICByZXR1cm4gdGhpcy5fX2J1aWxkKHRydWUpXG59XG5cblRyYW5zYWN0aW9uQnVpbGRlci5wcm90b3R5cGUuX19idWlsZCA9IGZ1bmN0aW9uIChhbGxvd0luY29tcGxldGUpIHtcbiAgaWYgKCFhbGxvd0luY29tcGxldGUpIHtcbiAgICBpZiAoIXRoaXMudHguaW5zLmxlbmd0aCkgdGhyb3cgbmV3IEVycm9yKCdUcmFuc2FjdGlvbiBoYXMgbm8gaW5wdXRzJylcbiAgICBpZiAoIXRoaXMudHgub3V0cy5sZW5ndGgpIHRocm93IG5ldyBFcnJvcignVHJhbnNhY3Rpb24gaGFzIG5vIG91dHB1dHMnKVxuICB9XG5cbiAgdmFyIHR4ID0gdGhpcy50eC5jbG9uZSgpXG4gIC8vIENyZWF0ZSBzY3JpcHQgc2lnbmF0dXJlcyBmcm9tIGlucHV0c1xuICB0aGlzLmlucHV0cy5mb3JFYWNoKGZ1bmN0aW9uIChpbnB1dCwgaSkge1xuICAgIHZhciBzY3JpcHRUeXBlID0gaW5wdXQud2l0bmVzc1NjcmlwdFR5cGUgfHwgaW5wdXQucmVkZWVtU2NyaXB0VHlwZSB8fCBpbnB1dC5wcmV2T3V0VHlwZVxuICAgIGlmICghc2NyaXB0VHlwZSAmJiAhYWxsb3dJbmNvbXBsZXRlKSB0aHJvdyBuZXcgRXJyb3IoJ1RyYW5zYWN0aW9uIGlzIG5vdCBjb21wbGV0ZScpXG4gICAgdmFyIHJlc3VsdCA9IGJ1aWxkSW5wdXQoaW5wdXQsIGFsbG93SW5jb21wbGV0ZSlcblxuICAgIC8vIHNraXAgaWYgbm8gcmVzdWx0XG4gICAgaWYgKCFhbGxvd0luY29tcGxldGUpIHtcbiAgICAgIGlmICghc3VwcG9ydGVkVHlwZShyZXN1bHQudHlwZSkgJiYgcmVzdWx0LnR5cGUgIT09IGJ0ZW1wbGF0ZXMudHlwZXMuUDJXUEtIKSB7XG4gICAgICAgIHRocm93IG5ldyBFcnJvcihyZXN1bHQudHlwZSArICcgbm90IHN1cHBvcnRlZCcpXG4gICAgICB9XG4gICAgfVxuXG4gICAgdHguc2V0SW5wdXRTY3JpcHQoaSwgcmVzdWx0LnNjcmlwdClcbiAgICB0eC5zZXRXaXRuZXNzKGksIHJlc3VsdC53aXRuZXNzKVxuICB9KVxuXG4gIGlmICghYWxsb3dJbmNvbXBsZXRlKSB7XG4gICAgLy8gZG8gbm90IHJlbHkgb24gdGhpcywgaXRzIG1lcmVseSBhIGxhc3QgcmVzb3J0XG4gICAgaWYgKHRoaXMuX19vdmVyTWF4aW11bUZlZXModHgudmlydHVhbFNpemUoKSkpIHtcbiAgICAgIHRocm93IG5ldyBFcnJvcignVHJhbnNhY3Rpb24gaGFzIGFic3VyZCBmZWVzJylcbiAgICB9XG4gIH1cblxuICByZXR1cm4gdHhcbn1cblxuZnVuY3Rpb24gY2FuU2lnbiAoaW5wdXQpIHtcbiAgcmV0dXJuIGlucHV0LnByZXZPdXRTY3JpcHQgIT09IHVuZGVmaW5lZCAmJlxuICAgIGlucHV0LnNpZ25TY3JpcHQgIT09IHVuZGVmaW5lZCAmJlxuICAgIGlucHV0LnB1YktleXMgIT09IHVuZGVmaW5lZCAmJlxuICAgIGlucHV0LnNpZ25hdHVyZXMgIT09IHVuZGVmaW5lZCAmJlxuICAgIGlucHV0LnNpZ25hdHVyZXMubGVuZ3RoID09PSBpbnB1dC5wdWJLZXlzLmxlbmd0aCAmJlxuICAgIGlucHV0LnB1YktleXMubGVuZ3RoID4gMCAmJlxuICAgIChcbiAgICAgIGlucHV0LndpdG5lc3MgPT09IGZhbHNlIHx8XG4gICAgICAoaW5wdXQud2l0bmVzcyA9PT0gdHJ1ZSAmJiBpbnB1dC52YWx1ZSAhPT0gdW5kZWZpbmVkKVxuICAgIClcbn1cblxuVHJhbnNhY3Rpb25CdWlsZGVyLnByb3RvdHlwZS5zaWduID0gZnVuY3Rpb24gKHZpbiwga2V5UGFpciwgcmVkZWVtU2NyaXB0LCBoYXNoVHlwZSwgd2l0bmVzc1ZhbHVlLCB3aXRuZXNzU2NyaXB0KSB7XG4gIGRlYnVnKCdTaWduaW5nIHRyYW5zYWN0aW9uOiAoaW5wdXQ6ICVkLCBoYXNoVHlwZTogJWQsIHdpdG5lc3NWYWw6ICVzLCB3aXRuZXNzU2NyaXB0OiAlaiknLCB2aW4sIGhhc2hUeXBlLCB3aXRuZXNzVmFsdWUsIHdpdG5lc3NTY3JpcHQpXG4gIGRlYnVnKCdUcmFuc2FjdGlvbiBCdWlsZGVyIG5ldHdvcms6ICVqJywgdGhpcy5uZXR3b3JrKVxuXG4gIC8vIFRPRE86IHJlbW92ZSBrZXlQYWlyLm5ldHdvcmsgbWF0Y2hpbmcgaW4gNC4wLjBcbiAgaWYgKGtleVBhaXIubmV0d29yayAmJiBrZXlQYWlyLm5ldHdvcmsgIT09IHRoaXMubmV0d29yaykgdGhyb3cgbmV3IFR5cGVFcnJvcignSW5jb25zaXN0ZW50IG5ldHdvcmsnKVxuICBpZiAoIXRoaXMuaW5wdXRzW3Zpbl0pIHRocm93IG5ldyBFcnJvcignTm8gaW5wdXQgYXQgaW5kZXg6ICcgKyB2aW4pXG4gIGhhc2hUeXBlID0gaGFzaFR5cGUgfHwgVHJhbnNhY3Rpb24uU0lHSEFTSF9BTExcblxuICB2YXIgaW5wdXQgPSB0aGlzLmlucHV0c1t2aW5dXG5cbiAgLy8gaWYgcmVkZWVtU2NyaXB0IHdhcyBwcmV2aW91c2x5IHByb3ZpZGVkLCBlbmZvcmNlIGNvbnNpc3RlbmN5XG4gIGlmIChpbnB1dC5yZWRlZW1TY3JpcHQgIT09IHVuZGVmaW5lZCAmJlxuICAgICAgcmVkZWVtU2NyaXB0ICYmXG4gICAgICAhaW5wdXQucmVkZWVtU2NyaXB0LmVxdWFscyhyZWRlZW1TY3JpcHQpKSB7XG4gICAgdGhyb3cgbmV3IEVycm9yKCdJbmNvbnNpc3RlbnQgcmVkZWVtU2NyaXB0JylcbiAgfVxuXG4gIHZhciBrcFB1YktleSA9IGtleVBhaXIucHVibGljS2V5IHx8IGtleVBhaXIuZ2V0UHVibGljS2V5QnVmZmVyKClcbiAgaWYgKCFjYW5TaWduKGlucHV0KSkge1xuICAgIGlmICh3aXRuZXNzVmFsdWUgIT09IHVuZGVmaW5lZCkge1xuICAgICAgaWYgKGlucHV0LnZhbHVlICE9PSB1bmRlZmluZWQgJiYgaW5wdXQudmFsdWUgIT09IHdpdG5lc3NWYWx1ZSkgdGhyb3cgbmV3IEVycm9yKCdJbnB1dCBkaWRuXFwndCBtYXRjaCB3aXRuZXNzVmFsdWUnKVxuICAgICAgdHlwZWZvcmNlKHR5cGVzLlNhdG9zaGksIHdpdG5lc3NWYWx1ZSlcbiAgICAgIGlucHV0LnZhbHVlID0gd2l0bmVzc1ZhbHVlXG4gICAgfVxuXG4gICAgZGVidWcoJ1ByZXBhcmluZyBpbnB1dCAlZCBmb3Igc2lnbmluZycsIHZpbilcblxuICAgIGlmICghY2FuU2lnbihpbnB1dCkpIHByZXBhcmVJbnB1dChpbnB1dCwga3BQdWJLZXksIHJlZGVlbVNjcmlwdCwgd2l0bmVzc1ZhbHVlLCB3aXRuZXNzU2NyaXB0KVxuICAgIGlmICghY2FuU2lnbihpbnB1dCkpIHRocm93IEVycm9yKGlucHV0LnByZXZPdXRUeXBlICsgJyBub3Qgc3VwcG9ydGVkJylcbiAgfVxuXG4gIC8vIHJlYWR5IHRvIHNpZ25cbiAgdmFyIHNpZ25hdHVyZUhhc2ggPSB0aGlzLnR4Lmhhc2hGb3JTaWduYXR1cmVCeU5ldHdvcmsoXG4gICAgdmluLFxuICAgIGlucHV0LnNpZ25TY3JpcHQsXG4gICAgd2l0bmVzc1ZhbHVlLFxuICAgIGhhc2hUeXBlLFxuICAgICEhaW5wdXQud2l0bmVzcyxcbiAgKVxuXG4gIC8vIGVuZm9yY2UgaW4gb3JkZXIgc2lnbmluZyBvZiBwdWJsaWMga2V5c1xuICB2YXIgc2lnbmVkID0gaW5wdXQucHViS2V5cy5zb21lKGZ1bmN0aW9uIChwdWJLZXksIGkpIHtcbiAgICBpZiAoIWtwUHViS2V5LmVxdWFscyhwdWJLZXkpKSByZXR1cm4gZmFsc2VcbiAgICBpZiAoaW5wdXQuc2lnbmF0dXJlc1tpXSkgdGhyb3cgbmV3IEVycm9yKCdTaWduYXR1cmUgYWxyZWFkeSBleGlzdHMnKVxuICAgIGlmIChrcFB1YktleS5sZW5ndGggIT09IDMzICYmXG4gICAgICBpbnB1dC5zaWduVHlwZSA9PT0gc2NyaXB0VHlwZXMuUDJXUEtIKSB0aHJvdyBuZXcgRXJyb3IoJ0JJUDE0MyByZWplY3RzIHVuY29tcHJlc3NlZCBwdWJsaWMga2V5cyBpbiBQMldQS0ggb3IgUDJXU0gnKVxuXG4gICAgdmFyIHNpZ25hdHVyZSA9IGtleVBhaXIuc2lnbihzaWduYXR1cmVIYXNoKVxuICAgIGlmIChCdWZmZXIuaXNCdWZmZXIoc2lnbmF0dXJlKSkgc2lnbmF0dXJlID0gRUNTaWduYXR1cmUuZnJvbVJTQnVmZmVyKHNpZ25hdHVyZSlcblxuICAgIGRlYnVnKCdQcm9kdWNlZCBzaWduYXR1cmUgKHI6ICVzLCBzOiAlcyknLCBzaWduYXR1cmUuciwgc2lnbmF0dXJlLnMpXG5cbiAgICBpbnB1dC5zaWduYXR1cmVzW2ldID0gc2lnbmF0dXJlLnRvU2NyaXB0U2lnbmF0dXJlKGhhc2hUeXBlKVxuICAgIHJldHVybiB0cnVlXG4gIH0pXG5cbiAgaWYgKCFzaWduZWQpIHRocm93IG5ldyBFcnJvcignS2V5IHBhaXIgY2Fubm90IHNpZ24gZm9yIHRoaXMgaW5wdXQnKVxufVxuXG5mdW5jdGlvbiBzaWduYXR1cmVIYXNoVHlwZSAoYnVmZmVyKSB7XG4gIHJldHVybiBidWZmZXIucmVhZFVJbnQ4KGJ1ZmZlci5sZW5ndGggLSAxKVxufVxuXG5UcmFuc2FjdGlvbkJ1aWxkZXIucHJvdG90eXBlLl9fY2FuTW9kaWZ5SW5wdXRzID0gZnVuY3Rpb24gKCkge1xuICByZXR1cm4gdGhpcy5pbnB1dHMuZXZlcnkoZnVuY3Rpb24gKGlucHV0KSB7XG4gICAgLy8gYW55IHNpZ25hdHVyZXM/XG4gICAgaWYgKGlucHV0LnNpZ25hdHVyZXMgPT09IHVuZGVmaW5lZCkgcmV0dXJuIHRydWVcblxuICAgIHJldHVybiBpbnB1dC5zaWduYXR1cmVzLmV2ZXJ5KGZ1bmN0aW9uIChzaWduYXR1cmUpIHtcbiAgICAgIGlmICghc2lnbmF0dXJlKSByZXR1cm4gdHJ1ZVxuICAgICAgdmFyIGhhc2hUeXBlID0gc2lnbmF0dXJlSGFzaFR5cGUoc2lnbmF0dXJlKVxuXG4gICAgICAvLyBpZiBTSUdIQVNIX0FOWU9ORUNBTlBBWSBpcyBzZXQsIHNpZ25hdHVyZXMgd291bGQgbm90XG4gICAgICAvLyBiZSBpbnZhbGlkYXRlZCBieSBtb3JlIGlucHV0c1xuICAgICAgcmV0dXJuIGhhc2hUeXBlICYgVHJhbnNhY3Rpb24uU0lHSEFTSF9BTllPTkVDQU5QQVlcbiAgICB9KVxuICB9KVxufVxuXG5UcmFuc2FjdGlvbkJ1aWxkZXIucHJvdG90eXBlLl9fY2FuTW9kaWZ5T3V0cHV0cyA9IGZ1bmN0aW9uICgpIHtcbiAgdmFyIG5JbnB1dHMgPSB0aGlzLnR4Lmlucy5sZW5ndGhcbiAgdmFyIG5PdXRwdXRzID0gdGhpcy50eC5vdXRzLmxlbmd0aFxuXG4gIHJldHVybiB0aGlzLmlucHV0cy5ldmVyeShmdW5jdGlvbiAoaW5wdXQpIHtcbiAgICBpZiAoaW5wdXQuc2lnbmF0dXJlcyA9PT0gdW5kZWZpbmVkKSByZXR1cm4gdHJ1ZVxuXG4gICAgcmV0dXJuIGlucHV0LnNpZ25hdHVyZXMuZXZlcnkoZnVuY3Rpb24gKHNpZ25hdHVyZSkge1xuICAgICAgaWYgKCFzaWduYXR1cmUpIHJldHVybiB0cnVlXG4gICAgICB2YXIgaGFzaFR5cGUgPSBzaWduYXR1cmVIYXNoVHlwZShzaWduYXR1cmUpXG5cbiAgICAgIHZhciBoYXNoVHlwZU1vZCA9IGhhc2hUeXBlICYgMHgxZlxuICAgICAgaWYgKGhhc2hUeXBlTW9kID09PSBUcmFuc2FjdGlvbi5TSUdIQVNIX05PTkUpIHJldHVybiB0cnVlXG4gICAgICBpZiAoaGFzaFR5cGVNb2QgPT09IFRyYW5zYWN0aW9uLlNJR0hBU0hfU0lOR0xFKSB7XG4gICAgICAgIC8vIGlmIFNJR0hBU0hfU0lOR0xFIGlzIHNldCwgYW5kIG5JbnB1dHMgPiBuT3V0cHV0c1xuICAgICAgICAvLyBzb21lIHNpZ25hdHVyZXMgd291bGQgYmUgaW52YWxpZGF0ZWQgYnkgdGhlIGFkZGl0aW9uXG4gICAgICAgIC8vIG9mIG1vcmUgb3V0cHV0c1xuICAgICAgICByZXR1cm4gbklucHV0cyA8PSBuT3V0cHV0c1xuICAgICAgfVxuICAgIH0pXG4gIH0pXG59XG5cblRyYW5zYWN0aW9uQnVpbGRlci5wcm90b3R5cGUuX19vdmVyTWF4aW11bUZlZXMgPSBmdW5jdGlvbiAoYnl0ZXMpIHtcbiAgLy8gbm90IGFsbCBpbnB1dHMgd2lsbCBoYXZlIC52YWx1ZSBkZWZpbmVkXG4gIHZhciBpbmNvbWluZyA9IHRoaXMuaW5wdXRzLnJlZHVjZShmdW5jdGlvbiAoYSwgeCkgeyByZXR1cm4gYSArICh4LnZhbHVlID4+PiAwKSB9LCAwKVxuXG4gIC8vIGJ1dCBhbGwgb3V0cHV0cyBkbywgYW5kIGlmIHdlIGhhdmUgYW55IGlucHV0IHZhbHVlXG4gIC8vIHdlIGNhbiBpbW1lZGlhdGVseSBkZXRlcm1pbmUgaWYgdGhlIG91dHB1dHMgYXJlIHRvbyBzbWFsbFxuICB2YXIgb3V0Z29pbmcgPSB0aGlzLnR4Lm91dHMucmVkdWNlKGZ1bmN0aW9uIChhLCB4KSB7IHJldHVybiBhICsgeC52YWx1ZSB9LCAwKVxuICB2YXIgZmVlID0gaW5jb21pbmcgLSBvdXRnb2luZ1xuICB2YXIgZmVlUmF0ZSA9IGZlZSAvIGJ5dGVzXG5cbiAgcmV0dXJuIGZlZVJhdGUgPiB0aGlzLm1heGltdW1GZWVSYXRlXG59XG5cbm1vZHVsZS5leHBvcnRzID0gVHJhbnNhY3Rpb25CdWlsZGVyXG4iXX0=