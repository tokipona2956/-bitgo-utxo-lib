"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.signInput2Of3 = exports.signInputP2shP2pk = exports.verifySignatureWithPublicKey = exports.verifySignatureWithPublicKeys = exports.verifySignature = exports.getSignatureVerifications = exports.parseSignatureScript2Of3 = exports.parseSignatureScript = exports.getDefaultSigHash = exports.isPlaceholderSignature = void 0;
const opcodes = require("bitcoin-ops");
const ecc = require('tiny-secp256k1');
const bitcoinjs_lib_1 = require("bitcoinjs-lib");
const UtxoTransaction_1 = require("./UtxoTransaction");
const outputScripts_1 = require("./outputScripts");
const types_1 = require("./types");
const networks_1 = require("../networks");
const inputTypes = [
    'multisig',
    'nonstandard',
    'nulldata',
    'pubkey',
    'pubkeyhash',
    'scripthash',
    'witnesspubkeyhash',
    'witnessscripthash',
    'taproot',
    'taprootnofn',
    'witnesscommitment',
];
function isPlaceholderSignature(v) {
    if (Buffer.isBuffer(v)) {
        return v.length === 0;
    }
    return v === 0;
}
exports.isPlaceholderSignature = isPlaceholderSignature;
function getDefaultSigHash(network, scriptType) {
    switch (networks_1.getMainnet(network)) {
        case networks_1.networks.bitcoincash:
        case networks_1.networks.bitcoinsv:
        case networks_1.networks.bitcoingold:
            return bitcoinjs_lib_1.Transaction.SIGHASH_ALL | UtxoTransaction_1.UtxoTransaction.SIGHASH_FORKID;
        default:
            return scriptType === 'p2tr' ? bitcoinjs_lib_1.Transaction.SIGHASH_DEFAULT : bitcoinjs_lib_1.Transaction.SIGHASH_ALL;
    }
}
exports.getDefaultSigHash = getDefaultSigHash;
/**
 * Parse a transaction's signature script to obtain public keys, signatures, the sig script,
 * and other properties.
 *
 * Only supports script types used in BitGo transactions.
 *
 * @param input
 * @returns ParsedSignatureScript
 */
function parseSignatureScript(input) {
    const isSegwitInput = input.witness.length > 0;
    const isNativeSegwitInput = input.script.length === 0;
    let decompiledSigScript;
    let inputClassification;
    if (isSegwitInput) {
        // The decompiledSigScript is the script containing the signatures, public keys, and the script that was committed
        // to (pubScript). If this is a segwit input the decompiledSigScript is in the witness, regardless of whether it
        // is native or not. The inputClassification is determined based on whether or not the input is native to give an
        // accurate classification. Note that p2shP2wsh inputs will be classified as p2sh and not p2wsh.
        decompiledSigScript = input.witness;
        if (isNativeSegwitInput) {
            inputClassification = bitcoinjs_lib_1.classify.witness(decompiledSigScript, true);
        }
        else {
            inputClassification = bitcoinjs_lib_1.classify.input(input.script, true);
        }
    }
    else {
        inputClassification = bitcoinjs_lib_1.classify.input(input.script, true);
        decompiledSigScript = bitcoinjs_lib_1.script.decompile(input.script);
    }
    if (!decompiledSigScript) {
        return { scriptType: undefined, isSegwitInput, inputClassification };
    }
    if (inputClassification === 'pubkeyhash') {
        /* istanbul ignore next */
        if (!decompiledSigScript || decompiledSigScript.length !== 2) {
            throw new Error('unexpected signature for p2pkh');
        }
        const [signature, publicKey] = decompiledSigScript;
        /* istanbul ignore next */
        if (!Buffer.isBuffer(signature) || !Buffer.isBuffer(publicKey)) {
            throw new Error('unexpected signature for p2pkh');
        }
        const publicKeys = [publicKey];
        const signatures = [signature];
        const pubScript = bitcoinjs_lib_1.payments.p2pkh({ pubkey: publicKey }).output;
        return {
            scriptType: 'p2pkh',
            isSegwitInput,
            inputClassification,
            signatures,
            publicKeys,
            pubScript,
        };
    }
    if (inputClassification === 'taproot') {
        // assumes no annex
        if (input.witness.length !== 4) {
            throw new Error(`unrecognized taproot input`);
        }
        const [sig1, sig2, tapscript, controlBlock] = input.witness;
        const tapscriptClassification = bitcoinjs_lib_1.classify.output(tapscript);
        if (tapscriptClassification !== 'taprootnofn') {
            throw new Error(`tapscript must be n of n multisig`);
        }
        const publicKeys = bitcoinjs_lib_1.payments.p2tr_ns({ output: tapscript }).pubkeys;
        if (!publicKeys || publicKeys.length !== 2) {
            throw new Error('expected 2 pubkeys');
        }
        const signatures = [sig1, sig2].map((b) => {
            if (Buffer.isBuffer(b)) {
                return b;
            }
            throw new Error(`unexpected signature element ${b}`);
        });
        const scriptPathLevel = controlBlock.length === 65 ? 1 : controlBlock.length === 97 ? 2 : undefined;
        /* istanbul ignore next */
        if (scriptPathLevel === undefined) {
            throw new Error(`unexpected control block length ${controlBlock.length}`);
        }
        return {
            scriptType: 'p2tr',
            isSegwitInput,
            inputClassification,
            publicKeys: publicKeys,
            signatures,
            pubScript: tapscript,
            controlBlock,
            scriptPathLevel,
        };
    }
    // Note the assumption here that if we have a p2sh or p2wsh input it will be multisig (appropriate because the
    // BitGo platform only supports multisig within these types of inputs, with the exception of replay protection inputs,
    // which are single signature p2sh). Signatures are all but the last entry in the decompiledSigScript.
    // The redeemScript/witnessScript (depending on which type of input this is) is the last entry in
    // the decompiledSigScript (denoted here as the pubScript). The public keys are the second through
    // antepenultimate entries in the decompiledPubScript. See below for a visual representation of the typical 2-of-3
    // multisig setup:
    //
    //   decompiledSigScript = 0 <sig1> <sig2> [<sig3>] <pubScript>
    //   decompiledPubScript = 2 <pub1> <pub2> <pub3> 3 OP_CHECKMULTISIG
    //
    // Transactions built with `.build()` only have two signatures `<sig1>` and `<sig2>` in _decompiledSigScript_.
    // Transactions built with `.buildIncomplete()` have three signatures, where missing signatures are substituted with `OP_0`.
    if (inputClassification !== 'scripthash' && inputClassification !== 'witnessscripthash') {
        return { scriptType: undefined, isSegwitInput, inputClassification };
    }
    const pubScript = decompiledSigScript[decompiledSigScript.length - 1];
    /* istanbul ignore next */
    if (!Buffer.isBuffer(pubScript)) {
        throw new Error(`invalid pubScript`);
    }
    const p2shOutputClassification = bitcoinjs_lib_1.classify.output(pubScript);
    if (inputClassification === 'scripthash' && p2shOutputClassification === 'pubkey') {
        return {
            scriptType: 'p2shP2pk',
            isSegwitInput,
            inputClassification,
            p2shOutputClassification,
        };
    }
    if (p2shOutputClassification !== 'multisig') {
        return {
            scriptType: undefined,
            isSegwitInput,
            inputClassification,
            p2shOutputClassification,
        };
    }
    const decompiledPubScript = bitcoinjs_lib_1.script.decompile(pubScript);
    if (decompiledPubScript === null) {
        /* istanbul ignore next */
        throw new Error(`could not decompile pubScript`);
    }
    const expectedScriptLength = 
    // complete transactions with 2 signatures
    decompiledSigScript.length === 4 ||
        // incomplete transaction with 3 signatures or signature placeholders
        decompiledSigScript.length === 5;
    if (!expectedScriptLength) {
        return { scriptType: undefined, isSegwitInput, inputClassification };
    }
    if (isSegwitInput) {
        /* istanbul ignore next */
        if (!Buffer.isBuffer(decompiledSigScript[0])) {
            throw new Error(`expected decompiledSigScript[0] to be a buffer for segwit inputs`);
        }
        /* istanbul ignore next */
        if (decompiledSigScript[0].length !== 0) {
            throw new Error(`witness stack expected to start with empty buffer`);
        }
    }
    else if (decompiledSigScript[0] !== opcodes.OP_0) {
        throw new Error(`sigScript expected to start with OP_0`);
    }
    const signatures = decompiledSigScript.slice(1 /* ignore leading OP_0 */, -1 /* ignore trailing pubScript */);
    /* istanbul ignore next */
    if (signatures.length !== 2 && signatures.length !== 3) {
        throw new Error(`expected 2 or 3 signatures, got ${signatures.length}`);
    }
    /* istanbul ignore next */
    if (decompiledPubScript.length !== 6) {
        throw new Error(`unexpected decompiledPubScript length`);
    }
    const publicKeys = decompiledPubScript.slice(1, -2);
    publicKeys.forEach((b) => {
        /* istanbul ignore next */
        if (!Buffer.isBuffer(b)) {
            throw new Error();
        }
    });
    if (!types_1.isTriple(publicKeys)) {
        /* istanbul ignore next */
        throw new Error(`expected 3 public keys, got ${publicKeys.length}`);
    }
    // Op codes 81 through 96 represent numbers 1 through 16 (see https://en.bitcoin.it/wiki/Script#Opcodes), which is
    // why we subtract by 80 to get the number of signatures (n) and the number of public keys (m) in an n-of-m setup.
    const len = decompiledPubScript.length;
    const signatureThreshold = decompiledPubScript[0] - 80;
    /* istanbul ignore next */
    if (signatureThreshold !== 2) {
        throw new Error(`expected signatureThreshold 2, got ${signatureThreshold}`);
    }
    const nPubKeys = decompiledPubScript[len - 2] - 80;
    /* istanbul ignore next */
    if (nPubKeys !== 3) {
        throw new Error(`expected nPubKeys 3, got ${nPubKeys}`);
    }
    const lastOpCode = decompiledPubScript[len - 1];
    /* istanbul ignore next */
    if (lastOpCode !== opcodes.OP_CHECKMULTISIG) {
        throw new Error(`expected opcode #${opcodes.OP_CHECKMULTISIG}, got opcode #${lastOpCode}`);
    }
    const scriptType = input.witness.length
        ? input.script.length
            ? 'p2shP2wsh'
            : 'p2wsh'
        : input.script.length
            ? 'p2sh'
            : undefined;
    if (scriptType === undefined) {
        throw new Error('illegal state');
    }
    return {
        scriptType,
        isSegwitInput,
        inputClassification,
        p2shOutputClassification,
        signatures: signatures.map((b) => {
            if (Buffer.isBuffer(b) || b === 0) {
                return b;
            }
            throw new Error(`unexpected signature element ${b}`);
        }),
        publicKeys,
        pubScript,
    };
}
exports.parseSignatureScript = parseSignatureScript;
function parseSignatureScript2Of3(input) {
    const result = parseSignatureScript(input);
    if (![bitcoinjs_lib_1.classify.types.P2WSH, bitcoinjs_lib_1.classify.types.P2SH, bitcoinjs_lib_1.classify.types.P2PKH, bitcoinjs_lib_1.classify.types.P2TR].includes(result.inputClassification)) {
        throw new Error(`unexpected inputClassification ${result.inputClassification}`);
    }
    if (!result.signatures) {
        throw new Error(`missing signatures`);
    }
    if (result.publicKeys.length !== 3 &&
        (result.publicKeys.length !== 2 || result.inputClassification !== bitcoinjs_lib_1.classify.types.P2TR)) {
        throw new Error(`unexpected pubkey count`);
    }
    if (!result.pubScript || result.pubScript.length === 0) {
        throw new Error(`pubScript missing or empty`);
    }
    return result;
}
exports.parseSignatureScript2Of3 = parseSignatureScript2Of3;
/**
 * @deprecated - use {@see verifySignaturesWithPublicKeys} instead
 * Get signature verifications for multsig transaction
 * @param transaction
 * @param inputIndex
 * @param amount - must be set for segwit transactions and BIP143 transactions
 * @param verificationSettings
 * @param prevOutputs - must be set for p2tr transactions
 * @returns SignatureVerification[] - in order of parsed non-empty signatures
 */
function getSignatureVerifications(transaction, inputIndex, amount, verificationSettings = {}, prevOutputs) {
    /* istanbul ignore next */
    if (!transaction.ins) {
        throw new Error(`invalid transaction`);
    }
    const input = transaction.ins[inputIndex];
    /* istanbul ignore next */
    if (!input) {
        throw new Error(`no input at index ${inputIndex}`);
    }
    if ((!input.script || input.script.length === 0) && input.witness.length === 0) {
        // Unsigned input: no signatures.
        return [];
    }
    const parsedScript = parseSignatureScript2Of3(input);
    const signatures = parsedScript.signatures
        .filter((s) => s && s.length)
        .filter((s, i) => verificationSettings.signatureIndex === undefined || verificationSettings.signatureIndex === i);
    const publicKeys = parsedScript.publicKeys.filter((buf) => verificationSettings.publicKey === undefined ||
        verificationSettings.publicKey.equals(buf) ||
        verificationSettings.publicKey.slice(1).equals(buf));
    return signatures.map((signatureBuffer) => {
        if (signatureBuffer === 0 || signatureBuffer.length === 0) {
            return { signedBy: undefined };
        }
        let hashType = bitcoinjs_lib_1.Transaction.SIGHASH_DEFAULT;
        if (signatureBuffer.length === 65) {
            hashType = signatureBuffer[signatureBuffer.length - 1];
            signatureBuffer = signatureBuffer.slice(0, -1);
        }
        if (parsedScript.inputClassification === bitcoinjs_lib_1.classify.types.P2TR) {
            if (verificationSettings.signatureIndex !== undefined) {
                throw new Error(`signatureIndex parameter not supported for p2tr`);
            }
            if (!prevOutputs) {
                throw new Error(`prevOutputs not set`);
            }
            if (prevOutputs.length !== transaction.ins.length) {
                throw new Error(`prevOutputs length ${prevOutputs.length}, expected ${transaction.ins.length}`);
            }
            const { controlBlock, pubScript } = parsedScript;
            if (!controlBlock) {
                throw new Error('expected controlBlock');
            }
            const leafHash = bitcoinjs_lib_1.taproot.getTapleafHash(controlBlock, pubScript);
            const signatureHash = transaction.hashForWitnessV1(inputIndex, prevOutputs.map(({ script }) => script), prevOutputs.map(({ value }) => value), hashType, leafHash);
            const signedBy = publicKeys.filter((k) => Buffer.isBuffer(signatureBuffer) && bitcoinjs_lib_1.schnorrBip340.verifySchnorr(signatureHash, k, signatureBuffer));
            if (signedBy.length === 0) {
                return { signedBy: undefined };
            }
            if (signedBy.length === 1) {
                return { signedBy: signedBy[0] };
            }
            throw new Error(`illegal state: signed by multiple public keys`);
        }
        else {
            // slice the last byte from the signature hash input because it's the hash type
            const { signature, hashType } = bitcoinjs_lib_1.ScriptSignature.decode(signatureBuffer);
            const transactionHash = parsedScript.isSegwitInput
                ? transaction.hashForWitnessV0(inputIndex, parsedScript.pubScript, amount, hashType)
                : transaction.hashForSignatureByNetwork(inputIndex, parsedScript.pubScript, amount, hashType);
            const signedBy = publicKeys.filter((publicKey) => ecc.verify(transactionHash, publicKey, signature, 
            /*
              Strict verification (require lower-S value), as required by BIP-0146
              https://github.com/bitcoin/bips/blob/master/bip-0146.mediawiki
              https://github.com/bitcoin-core/secp256k1/blob/ac83be33/include/secp256k1.h#L478-L508
              https://github.com/bitcoinjs/tiny-secp256k1/blob/v1.1.6/js.js#L231-L233
            */
            true));
            if (signedBy.length === 0) {
                return { signedBy: undefined };
            }
            if (signedBy.length === 1) {
                return { signedBy: signedBy[0] };
            }
            throw new Error(`illegal state: signed by multiple public keys`);
        }
    });
}
exports.getSignatureVerifications = getSignatureVerifications;
/**
 * @deprecated use {@see verifySignatureWithPublicKeys} instead
 * @param transaction
 * @param inputIndex
 * @param amount
 * @param verificationSettings - if publicKey is specified, returns true iff any signature is signed by publicKey.
 * @param prevOutputs - must be set for p2tr transactions
 */
function verifySignature(transaction, inputIndex, amount, verificationSettings = {}, prevOutputs) {
    const signatureVerifications = getSignatureVerifications(transaction, inputIndex, amount, verificationSettings, prevOutputs).filter((v) => 
    // If no publicKey is set in verificationSettings, all signatures must be valid.
    // Otherwise, a single valid signature by the specified pubkey is sufficient.
    verificationSettings.publicKey === undefined ||
        (v.signedBy !== undefined &&
            (verificationSettings.publicKey.equals(v.signedBy) ||
                verificationSettings.publicKey.slice(1).equals(v.signedBy))));
    return signatureVerifications.length > 0 && signatureVerifications.every((v) => v.signedBy !== undefined);
}
exports.verifySignature = verifySignature;
/**
 * @param v
 * @param publicKey
 * @return true iff signature is by publicKey (or xonly variant of publicKey)
 */
function isSignatureByPublicKey(v, publicKey) {
    return (!!v.signedBy &&
        (v.signedBy.equals(publicKey) ||
            /* for p2tr signatures, we pass the pubkey in 33-byte format recover it from the signature in 32-byte format */
            (publicKey.length === 33 && isSignatureByPublicKey(v, publicKey.slice(1)))));
}
/**
 * @param transaction
 * @param inputIndex
 * @param prevOutputs - transaction outputs for inputs
 * @param publicKeys - public keys to check signatures for
 * @return array of booleans indicating a valid signature for every pubkey in _publicKeys_
 */
function verifySignatureWithPublicKeys(transaction, inputIndex, prevOutputs, publicKeys) {
    if (transaction.ins.length !== prevOutputs.length) {
        throw new Error(`input length must match prevOutputs length`);
    }
    const signatureVerifications = getSignatureVerifications(transaction, inputIndex, prevOutputs[inputIndex].value, {}, prevOutputs);
    return publicKeys.map((publicKey) => !!signatureVerifications.find((v) => isSignatureByPublicKey(v, publicKey)));
}
exports.verifySignatureWithPublicKeys = verifySignatureWithPublicKeys;
/**
 * Wrapper for {@see verifySignatureWithPublicKeys} for single pubkey
 * @param transaction
 * @param inputIndex
 * @param prevOutputs
 * @param publicKey
 * @return true iff signature is valid
 */
function verifySignatureWithPublicKey(transaction, inputIndex, prevOutputs, publicKey) {
    return verifySignatureWithPublicKeys(transaction, inputIndex, prevOutputs, [publicKey])[0];
}
exports.verifySignatureWithPublicKey = verifySignatureWithPublicKey;
function signInputP2shP2pk(txBuilder, vin, keyPair) {
    const prevOutScriptType = 'p2sh-p2pk';
    const { redeemScript, witnessScript } = outputScripts_1.createOutputScriptP2shP2pk(keyPair.publicKey);
    keyPair.network = txBuilder.network;
    txBuilder.sign({
        vin,
        prevOutScriptType,
        keyPair,
        hashType: getDefaultSigHash(txBuilder.network),
        redeemScript,
        witnessScript,
        witnessValue: undefined,
    });
}
exports.signInputP2shP2pk = signInputP2shP2pk;
function signInput2Of3(txBuilder, vin, scriptType, pubkeys, keyPair, cosigner, amount) {
    let controlBlock;
    let redeemScript;
    let witnessScript;
    const prevOutScriptType = outputScripts_1.scriptType2Of3AsPrevOutType(scriptType);
    if (scriptType === 'p2tr') {
        ({ witnessScript, controlBlock } = outputScripts_1.createSpendScriptP2tr(pubkeys, [keyPair.publicKey, cosigner]));
    }
    else {
        ({ redeemScript, witnessScript } = outputScripts_1.createOutputScript2of3(pubkeys, scriptType));
    }
    keyPair.network = txBuilder.network;
    txBuilder.sign({
        vin,
        prevOutScriptType,
        keyPair,
        hashType: getDefaultSigHash(txBuilder.network, scriptType),
        redeemScript,
        witnessScript,
        witnessValue: amount,
        controlBlock,
    });
}
exports.signInput2Of3 = signInput2Of3;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoic2lnbmF0dXJlLmpzIiwic291cmNlUm9vdCI6IiIsInNvdXJjZXMiOlsiLi4vLi4vLi4vc3JjL2JpdGdvL3NpZ25hdHVyZS50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOzs7QUFBQSx1Q0FBdUM7QUFHdkMsTUFBTSxHQUFHLEdBQUcsT0FBTyxDQUFDLGdCQUFnQixDQUFDLENBQUM7QUFFdEMsaURBVXVCO0FBRXZCLHVEQUFvRDtBQUVwRCxtREFPeUI7QUFDekIsbUNBQTJDO0FBQzNDLDBDQUE0RDtBQUU1RCxNQUFNLFVBQVUsR0FBRztJQUNqQixVQUFVO0lBQ1YsYUFBYTtJQUNiLFVBQVU7SUFDVixRQUFRO0lBQ1IsWUFBWTtJQUNaLFlBQVk7SUFDWixtQkFBbUI7SUFDbkIsbUJBQW1CO0lBQ25CLFNBQVM7SUFDVCxhQUFhO0lBQ2IsbUJBQW1CO0NBQ1gsQ0FBQztBQUlYLFNBQWdCLHNCQUFzQixDQUFDLENBQWtCO0lBQ3ZELElBQUksTUFBTSxDQUFDLFFBQVEsQ0FBQyxDQUFDLENBQUMsRUFBRTtRQUN0QixPQUFPLENBQUMsQ0FBQyxNQUFNLEtBQUssQ0FBQyxDQUFDO0tBQ3ZCO0lBQ0QsT0FBTyxDQUFDLEtBQUssQ0FBQyxDQUFDO0FBQ2pCLENBQUM7QUFMRCx3REFLQztBQXFERCxTQUFnQixpQkFBaUIsQ0FBQyxPQUFnQixFQUFFLFVBQTJCO0lBQzdFLFFBQVEscUJBQVUsQ0FBQyxPQUFPLENBQUMsRUFBRTtRQUMzQixLQUFLLG1CQUFRLENBQUMsV0FBVyxDQUFDO1FBQzFCLEtBQUssbUJBQVEsQ0FBQyxTQUFTLENBQUM7UUFDeEIsS0FBSyxtQkFBUSxDQUFDLFdBQVc7WUFDdkIsT0FBTywyQkFBVyxDQUFDLFdBQVcsR0FBRyxpQ0FBZSxDQUFDLGNBQWMsQ0FBQztRQUNsRTtZQUNFLE9BQU8sVUFBVSxLQUFLLE1BQU0sQ0FBQyxDQUFDLENBQUMsMkJBQVcsQ0FBQyxlQUFlLENBQUMsQ0FBQyxDQUFDLDJCQUFXLENBQUMsV0FBVyxDQUFDO0tBQ3hGO0FBQ0gsQ0FBQztBQVRELDhDQVNDO0FBRUQ7Ozs7Ozs7O0dBUUc7QUFDSCxTQUFnQixvQkFBb0IsQ0FDbEMsS0FBYztJQU9kLE1BQU0sYUFBYSxHQUFHLEtBQUssQ0FBQyxPQUFPLENBQUMsTUFBTSxHQUFHLENBQUMsQ0FBQztJQUMvQyxNQUFNLG1CQUFtQixHQUFHLEtBQUssQ0FBQyxNQUFNLENBQUMsTUFBTSxLQUFLLENBQUMsQ0FBQztJQUN0RCxJQUFJLG1CQUFrRCxDQUFDO0lBQ3ZELElBQUksbUJBQThCLENBQUM7SUFDbkMsSUFBSSxhQUFhLEVBQUU7UUFDakIsa0hBQWtIO1FBQ2xILGdIQUFnSDtRQUNoSCxpSEFBaUg7UUFDakgsZ0dBQWdHO1FBQ2hHLG1CQUFtQixHQUFHLEtBQUssQ0FBQyxPQUFPLENBQUM7UUFDcEMsSUFBSSxtQkFBbUIsRUFBRTtZQUN2QixtQkFBbUIsR0FBRyx3QkFBUSxDQUFDLE9BQU8sQ0FBQyxtQkFBK0IsRUFBRSxJQUFJLENBQWMsQ0FBQztTQUM1RjthQUFNO1lBQ0wsbUJBQW1CLEdBQUcsd0JBQVEsQ0FBQyxLQUFLLENBQUMsS0FBSyxDQUFDLE1BQU0sRUFBRSxJQUFJLENBQWMsQ0FBQztTQUN2RTtLQUNGO1NBQU07UUFDTCxtQkFBbUIsR0FBRyx3QkFBUSxDQUFDLEtBQUssQ0FBQyxLQUFLLENBQUMsTUFBTSxFQUFFLElBQUksQ0FBYyxDQUFDO1FBQ3RFLG1CQUFtQixHQUFHLHNCQUFNLENBQUMsU0FBUyxDQUFDLEtBQUssQ0FBQyxNQUFNLENBQUMsQ0FBQztLQUN0RDtJQUVELElBQUksQ0FBQyxtQkFBbUIsRUFBRTtRQUN4QixPQUFPLEVBQUUsVUFBVSxFQUFFLFNBQVMsRUFBRSxhQUFhLEVBQUUsbUJBQW1CLEVBQUUsQ0FBQztLQUN0RTtJQUVELElBQUksbUJBQW1CLEtBQUssWUFBWSxFQUFFO1FBQ3hDLDBCQUEwQjtRQUMxQixJQUFJLENBQUMsbUJBQW1CLElBQUksbUJBQW1CLENBQUMsTUFBTSxLQUFLLENBQUMsRUFBRTtZQUM1RCxNQUFNLElBQUksS0FBSyxDQUFDLGdDQUFnQyxDQUFDLENBQUM7U0FDbkQ7UUFDRCxNQUFNLENBQUMsU0FBUyxFQUFFLFNBQVMsQ0FBQyxHQUFHLG1CQUFtQixDQUFDO1FBQ25ELDBCQUEwQjtRQUMxQixJQUFJLENBQUMsTUFBTSxDQUFDLFFBQVEsQ0FBQyxTQUFTLENBQUMsSUFBSSxDQUFDLE1BQU0sQ0FBQyxRQUFRLENBQUMsU0FBUyxDQUFDLEVBQUU7WUFDOUQsTUFBTSxJQUFJLEtBQUssQ0FBQyxnQ0FBZ0MsQ0FBQyxDQUFDO1NBQ25EO1FBQ0QsTUFBTSxVQUFVLEdBQWEsQ0FBQyxTQUFTLENBQUMsQ0FBQztRQUN6QyxNQUFNLFVBQVUsR0FBYSxDQUFDLFNBQVMsQ0FBQyxDQUFDO1FBQ3pDLE1BQU0sU0FBUyxHQUFHLHdCQUFRLENBQUMsS0FBSyxDQUFDLEVBQUUsTUFBTSxFQUFFLFNBQVMsRUFBRSxDQUFDLENBQUMsTUFBTSxDQUFDO1FBRS9ELE9BQU87WUFDTCxVQUFVLEVBQUUsT0FBTztZQUNuQixhQUFhO1lBQ2IsbUJBQW1CO1lBQ25CLFVBQVU7WUFDVixVQUFVO1lBQ1YsU0FBUztTQUNWLENBQUM7S0FDSDtJQUVELElBQUksbUJBQW1CLEtBQUssU0FBUyxFQUFFO1FBQ3JDLG1CQUFtQjtRQUNuQixJQUFJLEtBQUssQ0FBQyxPQUFPLENBQUMsTUFBTSxLQUFLLENBQUMsRUFBRTtZQUM5QixNQUFNLElBQUksS0FBSyxDQUFDLDRCQUE0QixDQUFDLENBQUM7U0FDL0M7UUFDRCxNQUFNLENBQUMsSUFBSSxFQUFFLElBQUksRUFBRSxTQUFTLEVBQUUsWUFBWSxDQUFDLEdBQUcsS0FBSyxDQUFDLE9BQU8sQ0FBQztRQUM1RCxNQUFNLHVCQUF1QixHQUFHLHdCQUFRLENBQUMsTUFBTSxDQUFDLFNBQVMsQ0FBQyxDQUFDO1FBQzNELElBQUksdUJBQXVCLEtBQUssYUFBYSxFQUFFO1lBQzdDLE1BQU0sSUFBSSxLQUFLLENBQUMsbUNBQW1DLENBQUMsQ0FBQztTQUN0RDtRQUVELE1BQU0sVUFBVSxHQUFHLHdCQUFRLENBQUMsT0FBTyxDQUFDLEVBQUUsTUFBTSxFQUFFLFNBQVMsRUFBRSxDQUFDLENBQUMsT0FBTyxDQUFDO1FBQ25FLElBQUksQ0FBQyxVQUFVLElBQUksVUFBVSxDQUFDLE1BQU0sS0FBSyxDQUFDLEVBQUU7WUFDMUMsTUFBTSxJQUFJLEtBQUssQ0FBQyxvQkFBb0IsQ0FBQyxDQUFDO1NBQ3ZDO1FBRUQsTUFBTSxVQUFVLEdBQUcsQ0FBQyxJQUFJLEVBQUUsSUFBSSxDQUFDLENBQUMsR0FBRyxDQUFDLENBQUMsQ0FBQyxFQUFFLEVBQUU7WUFDeEMsSUFBSSxNQUFNLENBQUMsUUFBUSxDQUFDLENBQUMsQ0FBQyxFQUFFO2dCQUN0QixPQUFPLENBQUMsQ0FBQzthQUNWO1lBQ0QsTUFBTSxJQUFJLEtBQUssQ0FBQyxnQ0FBZ0MsQ0FBQyxFQUFFLENBQUMsQ0FBQztRQUN2RCxDQUFDLENBQXFCLENBQUM7UUFFdkIsTUFBTSxlQUFlLEdBQUcsWUFBWSxDQUFDLE1BQU0sS0FBSyxFQUFFLENBQUMsQ0FBQyxDQUFDLENBQUMsQ0FBQyxDQUFDLENBQUMsWUFBWSxDQUFDLE1BQU0sS0FBSyxFQUFFLENBQUMsQ0FBQyxDQUFDLENBQUMsQ0FBQyxDQUFDLENBQUMsU0FBUyxDQUFDO1FBRXBHLDBCQUEwQjtRQUMxQixJQUFJLGVBQWUsS0FBSyxTQUFTLEVBQUU7WUFDakMsTUFBTSxJQUFJLEtBQUssQ0FBQyxtQ0FBbUMsWUFBWSxDQUFDLE1BQU0sRUFBRSxDQUFDLENBQUM7U0FDM0U7UUFFRCxPQUFPO1lBQ0wsVUFBVSxFQUFFLE1BQU07WUFDbEIsYUFBYTtZQUNiLG1CQUFtQjtZQUNuQixVQUFVLEVBQUUsVUFBOEI7WUFDMUMsVUFBVTtZQUNWLFNBQVMsRUFBRSxTQUFTO1lBQ3BCLFlBQVk7WUFDWixlQUFlO1NBQ2hCLENBQUM7S0FDSDtJQUVELDhHQUE4RztJQUM5RyxzSEFBc0g7SUFDdEgsc0dBQXNHO0lBQ3RHLGlHQUFpRztJQUNqRyxrR0FBa0c7SUFDbEcsa0hBQWtIO0lBQ2xILGtCQUFrQjtJQUNsQixFQUFFO0lBQ0YsK0RBQStEO0lBQy9ELG9FQUFvRTtJQUNwRSxFQUFFO0lBQ0YsOEdBQThHO0lBQzlHLDRIQUE0SDtJQUM1SCxJQUFJLG1CQUFtQixLQUFLLFlBQVksSUFBSSxtQkFBbUIsS0FBSyxtQkFBbUIsRUFBRTtRQUN2RixPQUFPLEVBQUUsVUFBVSxFQUFFLFNBQVMsRUFBRSxhQUFhLEVBQUUsbUJBQW1CLEVBQUUsQ0FBQztLQUN0RTtJQUVELE1BQU0sU0FBUyxHQUFHLG1CQUFtQixDQUFDLG1CQUFtQixDQUFDLE1BQU0sR0FBRyxDQUFDLENBQUMsQ0FBQztJQUN0RSwwQkFBMEI7SUFDMUIsSUFBSSxDQUFDLE1BQU0sQ0FBQyxRQUFRLENBQUMsU0FBUyxDQUFDLEVBQUU7UUFDL0IsTUFBTSxJQUFJLEtBQUssQ0FBQyxtQkFBbUIsQ0FBQyxDQUFDO0tBQ3RDO0lBRUQsTUFBTSx3QkFBd0IsR0FBRyx3QkFBUSxDQUFDLE1BQU0sQ0FBQyxTQUFTLENBQUMsQ0FBQztJQUU1RCxJQUFJLG1CQUFtQixLQUFLLFlBQVksSUFBSSx3QkFBd0IsS0FBSyxRQUFRLEVBQUU7UUFDakYsT0FBTztZQUNMLFVBQVUsRUFBRSxVQUFVO1lBQ3RCLGFBQWE7WUFDYixtQkFBbUI7WUFDbkIsd0JBQXdCO1NBQ3pCLENBQUM7S0FDSDtJQUVELElBQUksd0JBQXdCLEtBQUssVUFBVSxFQUFFO1FBQzNDLE9BQU87WUFDTCxVQUFVLEVBQUUsU0FBUztZQUNyQixhQUFhO1lBQ2IsbUJBQW1CO1lBQ25CLHdCQUF3QjtTQUN6QixDQUFDO0tBQ0g7SUFFRCxNQUFNLG1CQUFtQixHQUFHLHNCQUFNLENBQUMsU0FBUyxDQUFDLFNBQVMsQ0FBQyxDQUFDO0lBQ3hELElBQUksbUJBQW1CLEtBQUssSUFBSSxFQUFFO1FBQ2hDLDBCQUEwQjtRQUMxQixNQUFNLElBQUksS0FBSyxDQUFDLCtCQUErQixDQUFDLENBQUM7S0FDbEQ7SUFFRCxNQUFNLG9CQUFvQjtJQUN4QiwwQ0FBMEM7SUFDMUMsbUJBQW1CLENBQUMsTUFBTSxLQUFLLENBQUM7UUFDaEMscUVBQXFFO1FBQ3JFLG1CQUFtQixDQUFDLE1BQU0sS0FBSyxDQUFDLENBQUM7SUFFbkMsSUFBSSxDQUFDLG9CQUFvQixFQUFFO1FBQ3pCLE9BQU8sRUFBRSxVQUFVLEVBQUUsU0FBUyxFQUFFLGFBQWEsRUFBRSxtQkFBbUIsRUFBRSxDQUFDO0tBQ3RFO0lBRUQsSUFBSSxhQUFhLEVBQUU7UUFDakIsMEJBQTBCO1FBQzFCLElBQUksQ0FBQyxNQUFNLENBQUMsUUFBUSxDQUFDLG1CQUFtQixDQUFDLENBQUMsQ0FBQyxDQUFDLEVBQUU7WUFDNUMsTUFBTSxJQUFJLEtBQUssQ0FBQyxrRUFBa0UsQ0FBQyxDQUFDO1NBQ3JGO1FBQ0QsMEJBQTBCO1FBQzFCLElBQUksbUJBQW1CLENBQUMsQ0FBQyxDQUFDLENBQUMsTUFBTSxLQUFLLENBQUMsRUFBRTtZQUN2QyxNQUFNLElBQUksS0FBSyxDQUFDLG1EQUFtRCxDQUFDLENBQUM7U0FDdEU7S0FDRjtTQUFNLElBQUksbUJBQW1CLENBQUMsQ0FBQyxDQUFDLEtBQUssT0FBTyxDQUFDLElBQUksRUFBRTtRQUNsRCxNQUFNLElBQUksS0FBSyxDQUFDLHVDQUF1QyxDQUFDLENBQUM7S0FDMUQ7SUFFRCxNQUFNLFVBQVUsR0FBRyxtQkFBbUIsQ0FBQyxLQUFLLENBQUMsQ0FBQyxDQUFDLHlCQUF5QixFQUFFLENBQUMsQ0FBQyxDQUFDLCtCQUErQixDQUFDLENBQUM7SUFDOUcsMEJBQTBCO0lBQzFCLElBQUksVUFBVSxDQUFDLE1BQU0sS0FBSyxDQUFDLElBQUksVUFBVSxDQUFDLE1BQU0sS0FBSyxDQUFDLEVBQUU7UUFDdEQsTUFBTSxJQUFJLEtBQUssQ0FBQyxtQ0FBbUMsVUFBVSxDQUFDLE1BQU0sRUFBRSxDQUFDLENBQUM7S0FDekU7SUFFRCwwQkFBMEI7SUFDMUIsSUFBSSxtQkFBbUIsQ0FBQyxNQUFNLEtBQUssQ0FBQyxFQUFFO1FBQ3BDLE1BQU0sSUFBSSxLQUFLLENBQUMsdUNBQXVDLENBQUMsQ0FBQztLQUMxRDtJQUNELE1BQU0sVUFBVSxHQUFHLG1CQUFtQixDQUFDLEtBQUssQ0FBQyxDQUFDLEVBQUUsQ0FBQyxDQUFDLENBQWEsQ0FBQztJQUNoRSxVQUFVLENBQUMsT0FBTyxDQUFDLENBQUMsQ0FBQyxFQUFFLEVBQUU7UUFDdkIsMEJBQTBCO1FBQzFCLElBQUksQ0FBQyxNQUFNLENBQUMsUUFBUSxDQUFDLENBQUMsQ0FBQyxFQUFFO1lBQ3ZCLE1BQU0sSUFBSSxLQUFLLEVBQUUsQ0FBQztTQUNuQjtJQUNILENBQUMsQ0FBQyxDQUFDO0lBQ0gsSUFBSSxDQUFDLGdCQUFRLENBQUMsVUFBVSxDQUFDLEVBQUU7UUFDekIsMEJBQTBCO1FBQzFCLE1BQU0sSUFBSSxLQUFLLENBQUMsK0JBQStCLFVBQVUsQ0FBQyxNQUFNLEVBQUUsQ0FBQyxDQUFDO0tBQ3JFO0lBRUQsa0hBQWtIO0lBQ2xILGtIQUFrSDtJQUNsSCxNQUFNLEdBQUcsR0FBRyxtQkFBbUIsQ0FBQyxNQUFNLENBQUM7SUFDdkMsTUFBTSxrQkFBa0IsR0FBSSxtQkFBbUIsQ0FBQyxDQUFDLENBQVksR0FBRyxFQUFFLENBQUM7SUFDbkUsMEJBQTBCO0lBQzFCLElBQUksa0JBQWtCLEtBQUssQ0FBQyxFQUFFO1FBQzVCLE1BQU0sSUFBSSxLQUFLLENBQUMsc0NBQXNDLGtCQUFrQixFQUFFLENBQUMsQ0FBQztLQUM3RTtJQUNELE1BQU0sUUFBUSxHQUFJLG1CQUFtQixDQUFDLEdBQUcsR0FBRyxDQUFDLENBQVksR0FBRyxFQUFFLENBQUM7SUFDL0QsMEJBQTBCO0lBQzFCLElBQUksUUFBUSxLQUFLLENBQUMsRUFBRTtRQUNsQixNQUFNLElBQUksS0FBSyxDQUFDLDRCQUE0QixRQUFRLEVBQUUsQ0FBQyxDQUFDO0tBQ3pEO0lBRUQsTUFBTSxVQUFVLEdBQUcsbUJBQW1CLENBQUMsR0FBRyxHQUFHLENBQUMsQ0FBQyxDQUFDO0lBQ2hELDBCQUEwQjtJQUMxQixJQUFJLFVBQVUsS0FBSyxPQUFPLENBQUMsZ0JBQWdCLEVBQUU7UUFDM0MsTUFBTSxJQUFJLEtBQUssQ0FBQyxvQkFBb0IsT0FBTyxDQUFDLGdCQUFnQixpQkFBaUIsVUFBVSxFQUFFLENBQUMsQ0FBQztLQUM1RjtJQUVELE1BQU0sVUFBVSxHQUFHLEtBQUssQ0FBQyxPQUFPLENBQUMsTUFBTTtRQUNyQyxDQUFDLENBQUMsS0FBSyxDQUFDLE1BQU0sQ0FBQyxNQUFNO1lBQ25CLENBQUMsQ0FBQyxXQUFXO1lBQ2IsQ0FBQyxDQUFDLE9BQU87UUFDWCxDQUFDLENBQUMsS0FBSyxDQUFDLE1BQU0sQ0FBQyxNQUFNO1lBQ3JCLENBQUMsQ0FBQyxNQUFNO1lBQ1IsQ0FBQyxDQUFDLFNBQVMsQ0FBQztJQUNkLElBQUksVUFBVSxLQUFLLFNBQVMsRUFBRTtRQUM1QixNQUFNLElBQUksS0FBSyxDQUFDLGVBQWUsQ0FBQyxDQUFDO0tBQ2xDO0lBRUQsT0FBTztRQUNMLFVBQVU7UUFDVixhQUFhO1FBQ2IsbUJBQW1CO1FBQ25CLHdCQUF3QjtRQUN4QixVQUFVLEVBQUUsVUFBVSxDQUFDLEdBQUcsQ0FBQyxDQUFDLENBQUMsRUFBRSxFQUFFO1lBQy9CLElBQUksTUFBTSxDQUFDLFFBQVEsQ0FBQyxDQUFDLENBQUMsSUFBSSxDQUFDLEtBQUssQ0FBQyxFQUFFO2dCQUNqQyxPQUFPLENBQUMsQ0FBQzthQUNWO1lBQ0QsTUFBTSxJQUFJLEtBQUssQ0FBQyxnQ0FBZ0MsQ0FBQyxFQUFFLENBQUMsQ0FBQztRQUN2RCxDQUFDLENBQWdEO1FBQ2pELFVBQVU7UUFDVixTQUFTO0tBQ1YsQ0FBQztBQUNKLENBQUM7QUE3T0Qsb0RBNk9DO0FBRUQsU0FBZ0Isd0JBQXdCLENBQUMsS0FBYztJQUNyRCxNQUFNLE1BQU0sR0FBRyxvQkFBb0IsQ0FBQyxLQUFLLENBQThCLENBQUM7SUFFeEUsSUFDRSxDQUFDLENBQUMsd0JBQVEsQ0FBQyxLQUFLLENBQUMsS0FBSyxFQUFFLHdCQUFRLENBQUMsS0FBSyxDQUFDLElBQUksRUFBRSx3QkFBUSxDQUFDLEtBQUssQ0FBQyxLQUFLLEVBQUUsd0JBQVEsQ0FBQyxLQUFLLENBQUMsSUFBSSxDQUFDLENBQUMsUUFBUSxDQUM5RixNQUFNLENBQUMsbUJBQW1CLENBQzNCLEVBQ0Q7UUFDQSxNQUFNLElBQUksS0FBSyxDQUFDLGtDQUFrQyxNQUFNLENBQUMsbUJBQW1CLEVBQUUsQ0FBQyxDQUFDO0tBQ2pGO0lBQ0QsSUFBSSxDQUFDLE1BQU0sQ0FBQyxVQUFVLEVBQUU7UUFDdEIsTUFBTSxJQUFJLEtBQUssQ0FBQyxvQkFBb0IsQ0FBQyxDQUFDO0tBQ3ZDO0lBQ0QsSUFDRSxNQUFNLENBQUMsVUFBVSxDQUFDLE1BQU0sS0FBSyxDQUFDO1FBQzlCLENBQUMsTUFBTSxDQUFDLFVBQVUsQ0FBQyxNQUFNLEtBQUssQ0FBQyxJQUFJLE1BQU0sQ0FBQyxtQkFBbUIsS0FBSyx3QkFBUSxDQUFDLEtBQUssQ0FBQyxJQUFJLENBQUMsRUFDdEY7UUFDQSxNQUFNLElBQUksS0FBSyxDQUFDLHlCQUF5QixDQUFDLENBQUM7S0FDNUM7SUFDRCxJQUFJLENBQUMsTUFBTSxDQUFDLFNBQVMsSUFBSSxNQUFNLENBQUMsU0FBUyxDQUFDLE1BQU0sS0FBSyxDQUFDLEVBQUU7UUFDdEQsTUFBTSxJQUFJLEtBQUssQ0FBQyw0QkFBNEIsQ0FBQyxDQUFDO0tBQy9DO0lBRUQsT0FBTyxNQUFNLENBQUM7QUFDaEIsQ0FBQztBQXhCRCw0REF3QkM7QUEwQkQ7Ozs7Ozs7OztHQVNHO0FBQ0gsU0FBZ0IseUJBQXlCLENBQ3ZDLFdBQTRCLEVBQzVCLFVBQWtCLEVBQ2xCLE1BQWMsRUFDZCx1QkFBNkMsRUFBRSxFQUMvQyxXQUF3QjtJQUV4QiwwQkFBMEI7SUFDMUIsSUFBSSxDQUFDLFdBQVcsQ0FBQyxHQUFHLEVBQUU7UUFDcEIsTUFBTSxJQUFJLEtBQUssQ0FBQyxxQkFBcUIsQ0FBQyxDQUFDO0tBQ3hDO0lBRUQsTUFBTSxLQUFLLEdBQUcsV0FBVyxDQUFDLEdBQUcsQ0FBQyxVQUFVLENBQUMsQ0FBQztJQUMxQywwQkFBMEI7SUFDMUIsSUFBSSxDQUFDLEtBQUssRUFBRTtRQUNWLE1BQU0sSUFBSSxLQUFLLENBQUMscUJBQXFCLFVBQVUsRUFBRSxDQUFDLENBQUM7S0FDcEQ7SUFFRCxJQUFJLENBQUMsQ0FBQyxLQUFLLENBQUMsTUFBTSxJQUFJLEtBQUssQ0FBQyxNQUFNLENBQUMsTUFBTSxLQUFLLENBQUMsQ0FBQyxJQUFJLEtBQUssQ0FBQyxPQUFPLENBQUMsTUFBTSxLQUFLLENBQUMsRUFBRTtRQUM5RSxpQ0FBaUM7UUFDakMsT0FBTyxFQUFFLENBQUM7S0FDWDtJQUVELE1BQU0sWUFBWSxHQUFHLHdCQUF3QixDQUFDLEtBQUssQ0FBQyxDQUFDO0lBRXJELE1BQU0sVUFBVSxHQUFHLFlBQVksQ0FBQyxVQUFVO1NBQ3ZDLE1BQU0sQ0FBQyxDQUFDLENBQUMsRUFBRSxFQUFFLENBQUMsQ0FBQyxJQUFJLENBQUMsQ0FBQyxNQUFNLENBQUM7U0FDNUIsTUFBTSxDQUFDLENBQUMsQ0FBQyxFQUFFLENBQUMsRUFBRSxFQUFFLENBQUMsb0JBQW9CLENBQUMsY0FBYyxLQUFLLFNBQVMsSUFBSSxvQkFBb0IsQ0FBQyxjQUFjLEtBQUssQ0FBQyxDQUFDLENBQUM7SUFFcEgsTUFBTSxVQUFVLEdBQUcsWUFBWSxDQUFDLFVBQVUsQ0FBQyxNQUFNLENBQy9DLENBQUMsR0FBRyxFQUFFLEVBQUUsQ0FDTixvQkFBb0IsQ0FBQyxTQUFTLEtBQUssU0FBUztRQUM1QyxvQkFBb0IsQ0FBQyxTQUFTLENBQUMsTUFBTSxDQUFDLEdBQUcsQ0FBQztRQUMxQyxvQkFBb0IsQ0FBQyxTQUFTLENBQUMsS0FBSyxDQUFDLENBQUMsQ0FBQyxDQUFDLE1BQU0sQ0FBQyxHQUFHLENBQUMsQ0FDdEQsQ0FBQztJQUVGLE9BQU8sVUFBVSxDQUFDLEdBQUcsQ0FBQyxDQUFDLGVBQWUsRUFBRSxFQUFFO1FBQ3hDLElBQUksZUFBZSxLQUFLLENBQUMsSUFBSSxlQUFlLENBQUMsTUFBTSxLQUFLLENBQUMsRUFBRTtZQUN6RCxPQUFPLEVBQUUsUUFBUSxFQUFFLFNBQVMsRUFBRSxDQUFDO1NBQ2hDO1FBRUQsSUFBSSxRQUFRLEdBQUcsMkJBQVcsQ0FBQyxlQUFlLENBQUM7UUFFM0MsSUFBSSxlQUFlLENBQUMsTUFBTSxLQUFLLEVBQUUsRUFBRTtZQUNqQyxRQUFRLEdBQUcsZUFBZSxDQUFDLGVBQWUsQ0FBQyxNQUFNLEdBQUcsQ0FBQyxDQUFDLENBQUM7WUFDdkQsZUFBZSxHQUFHLGVBQWUsQ0FBQyxLQUFLLENBQUMsQ0FBQyxFQUFFLENBQUMsQ0FBQyxDQUFDLENBQUM7U0FDaEQ7UUFFRCxJQUFJLFlBQVksQ0FBQyxtQkFBbUIsS0FBSyx3QkFBUSxDQUFDLEtBQUssQ0FBQyxJQUFJLEVBQUU7WUFDNUQsSUFBSSxvQkFBb0IsQ0FBQyxjQUFjLEtBQUssU0FBUyxFQUFFO2dCQUNyRCxNQUFNLElBQUksS0FBSyxDQUFDLGlEQUFpRCxDQUFDLENBQUM7YUFDcEU7WUFFRCxJQUFJLENBQUMsV0FBVyxFQUFFO2dCQUNoQixNQUFNLElBQUksS0FBSyxDQUFDLHFCQUFxQixDQUFDLENBQUM7YUFDeEM7WUFFRCxJQUFJLFdBQVcsQ0FBQyxNQUFNLEtBQUssV0FBVyxDQUFDLEdBQUcsQ0FBQyxNQUFNLEVBQUU7Z0JBQ2pELE1BQU0sSUFBSSxLQUFLLENBQUMsc0JBQXNCLFdBQVcsQ0FBQyxNQUFNLGNBQWMsV0FBVyxDQUFDLEdBQUcsQ0FBQyxNQUFNLEVBQUUsQ0FBQyxDQUFDO2FBQ2pHO1lBRUQsTUFBTSxFQUFFLFlBQVksRUFBRSxTQUFTLEVBQUUsR0FBRyxZQUE0QyxDQUFDO1lBQ2pGLElBQUksQ0FBQyxZQUFZLEVBQUU7Z0JBQ2pCLE1BQU0sSUFBSSxLQUFLLENBQUMsdUJBQXVCLENBQUMsQ0FBQzthQUMxQztZQUNELE1BQU0sUUFBUSxHQUFHLHVCQUFPLENBQUMsY0FBYyxDQUFDLFlBQVksRUFBRSxTQUFTLENBQUMsQ0FBQztZQUNqRSxNQUFNLGFBQWEsR0FBRyxXQUFXLENBQUMsZ0JBQWdCLENBQ2hELFVBQVUsRUFDVixXQUFXLENBQUMsR0FBRyxDQUFDLENBQUMsRUFBRSxNQUFNLEVBQUUsRUFBRSxFQUFFLENBQUMsTUFBTSxDQUFDLEVBQ3ZDLFdBQVcsQ0FBQyxHQUFHLENBQUMsQ0FBQyxFQUFFLEtBQUssRUFBRSxFQUFFLEVBQUUsQ0FBQyxLQUFLLENBQUMsRUFDckMsUUFBUSxFQUNSLFFBQVEsQ0FDVCxDQUFDO1lBRUYsTUFBTSxRQUFRLEdBQUcsVUFBVSxDQUFDLE1BQU0sQ0FDaEMsQ0FBQyxDQUFDLEVBQUUsRUFBRSxDQUFDLE1BQU0sQ0FBQyxRQUFRLENBQUMsZUFBZSxDQUFDLElBQUksNkJBQWEsQ0FBQyxhQUFhLENBQUMsYUFBYSxFQUFFLENBQUMsRUFBRSxlQUFlLENBQUMsQ0FDMUcsQ0FBQztZQUVGLElBQUksUUFBUSxDQUFDLE1BQU0sS0FBSyxDQUFDLEVBQUU7Z0JBQ3pCLE9BQU8sRUFBRSxRQUFRLEVBQUUsU0FBUyxFQUFFLENBQUM7YUFDaEM7WUFDRCxJQUFJLFFBQVEsQ0FBQyxNQUFNLEtBQUssQ0FBQyxFQUFFO2dCQUN6QixPQUFPLEVBQUUsUUFBUSxFQUFFLFFBQVEsQ0FBQyxDQUFDLENBQUMsRUFBRSxDQUFDO2FBQ2xDO1lBQ0QsTUFBTSxJQUFJLEtBQUssQ0FBQywrQ0FBK0MsQ0FBQyxDQUFDO1NBQ2xFO2FBQU07WUFDTCwrRUFBK0U7WUFDL0UsTUFBTSxFQUFFLFNBQVMsRUFBRSxRQUFRLEVBQUUsR0FBRywrQkFBZSxDQUFDLE1BQU0sQ0FBQyxlQUFlLENBQUMsQ0FBQztZQUN4RSxNQUFNLGVBQWUsR0FBRyxZQUFZLENBQUMsYUFBYTtnQkFDaEQsQ0FBQyxDQUFDLFdBQVcsQ0FBQyxnQkFBZ0IsQ0FBQyxVQUFVLEVBQUUsWUFBWSxDQUFDLFNBQVMsRUFBRSxNQUFNLEVBQUUsUUFBUSxDQUFDO2dCQUNwRixDQUFDLENBQUMsV0FBVyxDQUFDLHlCQUF5QixDQUFDLFVBQVUsRUFBRSxZQUFZLENBQUMsU0FBUyxFQUFFLE1BQU0sRUFBRSxRQUFRLENBQUMsQ0FBQztZQUNoRyxNQUFNLFFBQVEsR0FBRyxVQUFVLENBQUMsTUFBTSxDQUFDLENBQUMsU0FBUyxFQUFFLEVBQUUsQ0FDL0MsR0FBRyxDQUFDLE1BQU0sQ0FDUixlQUFlLEVBQ2YsU0FBUyxFQUNULFNBQVM7WUFDVDs7Ozs7Y0FLRTtZQUNGLElBQUksQ0FDTCxDQUNGLENBQUM7WUFFRixJQUFJLFFBQVEsQ0FBQyxNQUFNLEtBQUssQ0FBQyxFQUFFO2dCQUN6QixPQUFPLEVBQUUsUUFBUSxFQUFFLFNBQVMsRUFBRSxDQUFDO2FBQ2hDO1lBQ0QsSUFBSSxRQUFRLENBQUMsTUFBTSxLQUFLLENBQUMsRUFBRTtnQkFDekIsT0FBTyxFQUFFLFFBQVEsRUFBRSxRQUFRLENBQUMsQ0FBQyxDQUFDLEVBQUUsQ0FBQzthQUNsQztZQUNELE1BQU0sSUFBSSxLQUFLLENBQUMsK0NBQStDLENBQUMsQ0FBQztTQUNsRTtJQUNILENBQUMsQ0FBQyxDQUFDO0FBQ0wsQ0FBQztBQW5IRCw4REFtSEM7QUFFRDs7Ozs7OztHQU9HO0FBQ0gsU0FBZ0IsZUFBZSxDQUM3QixXQUE0QixFQUM1QixVQUFrQixFQUNsQixNQUFjLEVBQ2QsdUJBQTZDLEVBQUUsRUFDL0MsV0FBd0I7SUFFeEIsTUFBTSxzQkFBc0IsR0FBRyx5QkFBeUIsQ0FDdEQsV0FBVyxFQUNYLFVBQVUsRUFDVixNQUFNLEVBQ04sb0JBQW9CLEVBQ3BCLFdBQVcsQ0FDWixDQUFDLE1BQU0sQ0FDTixDQUFDLENBQUMsRUFBRSxFQUFFO0lBQ0osZ0ZBQWdGO0lBQ2hGLDZFQUE2RTtJQUM3RSxvQkFBb0IsQ0FBQyxTQUFTLEtBQUssU0FBUztRQUM1QyxDQUFDLENBQUMsQ0FBQyxRQUFRLEtBQUssU0FBUztZQUN2QixDQUFDLG9CQUFvQixDQUFDLFNBQVMsQ0FBQyxNQUFNLENBQUMsQ0FBQyxDQUFDLFFBQVEsQ0FBQztnQkFDaEQsb0JBQW9CLENBQUMsU0FBUyxDQUFDLEtBQUssQ0FBQyxDQUFDLENBQUMsQ0FBQyxNQUFNLENBQUMsQ0FBQyxDQUFDLFFBQVEsQ0FBQyxDQUFDLENBQUMsQ0FDbkUsQ0FBQztJQUVGLE9BQU8sc0JBQXNCLENBQUMsTUFBTSxHQUFHLENBQUMsSUFBSSxzQkFBc0IsQ0FBQyxLQUFLLENBQUMsQ0FBQyxDQUFDLEVBQUUsRUFBRSxDQUFDLENBQUMsQ0FBQyxRQUFRLEtBQUssU0FBUyxDQUFDLENBQUM7QUFDNUcsQ0FBQztBQXhCRCwwQ0F3QkM7QUFFRDs7OztHQUlHO0FBQ0gsU0FBUyxzQkFBc0IsQ0FBQyxDQUF3QixFQUFFLFNBQWlCO0lBQ3pFLE9BQU8sQ0FDTCxDQUFDLENBQUMsQ0FBQyxDQUFDLFFBQVE7UUFDWixDQUFDLENBQUMsQ0FBQyxRQUFRLENBQUMsTUFBTSxDQUFDLFNBQVMsQ0FBQztZQUMzQiwrR0FBK0c7WUFDL0csQ0FBQyxTQUFTLENBQUMsTUFBTSxLQUFLLEVBQUUsSUFBSSxzQkFBc0IsQ0FBQyxDQUFDLEVBQUUsU0FBUyxDQUFDLEtBQUssQ0FBQyxDQUFDLENBQUMsQ0FBQyxDQUFDLENBQUMsQ0FDOUUsQ0FBQztBQUNKLENBQUM7QUFFRDs7Ozs7O0dBTUc7QUFDSCxTQUFnQiw2QkFBNkIsQ0FDM0MsV0FBNEIsRUFDNUIsVUFBa0IsRUFDbEIsV0FBdUIsRUFDdkIsVUFBb0I7SUFFcEIsSUFBSSxXQUFXLENBQUMsR0FBRyxDQUFDLE1BQU0sS0FBSyxXQUFXLENBQUMsTUFBTSxFQUFFO1FBQ2pELE1BQU0sSUFBSSxLQUFLLENBQUMsNENBQTRDLENBQUMsQ0FBQztLQUMvRDtJQUVELE1BQU0sc0JBQXNCLEdBQUcseUJBQXlCLENBQ3RELFdBQVcsRUFDWCxVQUFVLEVBQ1YsV0FBVyxDQUFDLFVBQVUsQ0FBQyxDQUFDLEtBQUssRUFDN0IsRUFBRSxFQUNGLFdBQVcsQ0FDWixDQUFDO0lBRUYsT0FBTyxVQUFVLENBQUMsR0FBRyxDQUFDLENBQUMsU0FBUyxFQUFFLEVBQUUsQ0FBQyxDQUFDLENBQUMsc0JBQXNCLENBQUMsSUFBSSxDQUFDLENBQUMsQ0FBQyxFQUFFLEVBQUUsQ0FBQyxzQkFBc0IsQ0FBQyxDQUFDLEVBQUUsU0FBUyxDQUFDLENBQUMsQ0FBQyxDQUFDO0FBQ25ILENBQUM7QUFuQkQsc0VBbUJDO0FBRUQ7Ozs7Ozs7R0FPRztBQUNILFNBQWdCLDRCQUE0QixDQUMxQyxXQUE0QixFQUM1QixVQUFrQixFQUNsQixXQUF1QixFQUN2QixTQUFpQjtJQUVqQixPQUFPLDZCQUE2QixDQUFDLFdBQVcsRUFBRSxVQUFVLEVBQUUsV0FBVyxFQUFFLENBQUMsU0FBUyxDQUFDLENBQUMsQ0FBQyxDQUFDLENBQUMsQ0FBQztBQUM3RixDQUFDO0FBUEQsb0VBT0M7QUFFRCxTQUFnQixpQkFBaUIsQ0FBQyxTQUFpQyxFQUFFLEdBQVcsRUFBRSxPQUE2QjtJQUM3RyxNQUFNLGlCQUFpQixHQUFHLFdBQVcsQ0FBQztJQUN0QyxNQUFNLEVBQUUsWUFBWSxFQUFFLGFBQWEsRUFBRSxHQUFHLDBDQUEwQixDQUFDLE9BQU8sQ0FBQyxTQUFTLENBQUMsQ0FBQztJQUN0RixPQUFPLENBQUMsT0FBTyxHQUFHLFNBQVMsQ0FBQyxPQUFPLENBQUM7SUFFcEMsU0FBUyxDQUFDLElBQUksQ0FBQztRQUNiLEdBQUc7UUFDSCxpQkFBaUI7UUFDakIsT0FBTztRQUNQLFFBQVEsRUFBRSxpQkFBaUIsQ0FBQyxTQUFTLENBQUMsT0FBa0IsQ0FBQztRQUN6RCxZQUFZO1FBQ1osYUFBYTtRQUNiLFlBQVksRUFBRSxTQUFTO0tBQ3hCLENBQUMsQ0FBQztBQUNMLENBQUM7QUFkRCw4Q0FjQztBQUVELFNBQWdCLGFBQWEsQ0FDM0IsU0FBaUMsRUFDakMsR0FBVyxFQUNYLFVBQTBCLEVBQzFCLE9BQXVCLEVBQ3ZCLE9BQTZCLEVBQzdCLFFBQWdCLEVBQ2hCLE1BQWM7SUFFZCxJQUFJLFlBQVksQ0FBQztJQUNqQixJQUFJLFlBQVksQ0FBQztJQUNqQixJQUFJLGFBQWEsQ0FBQztJQUVsQixNQUFNLGlCQUFpQixHQUFHLDJDQUEyQixDQUFDLFVBQVUsQ0FBQyxDQUFDO0lBQ2xFLElBQUksVUFBVSxLQUFLLE1BQU0sRUFBRTtRQUN6QixDQUFDLEVBQUUsYUFBYSxFQUFFLFlBQVksRUFBRSxHQUFHLHFDQUFxQixDQUFDLE9BQU8sRUFBRSxDQUFDLE9BQU8sQ0FBQyxTQUFTLEVBQUUsUUFBUSxDQUFDLENBQUMsQ0FBQyxDQUFDO0tBQ25HO1NBQU07UUFDTCxDQUFDLEVBQUUsWUFBWSxFQUFFLGFBQWEsRUFBRSxHQUFHLHNDQUFzQixDQUFDLE9BQU8sRUFBRSxVQUFVLENBQUMsQ0FBQyxDQUFDO0tBQ2pGO0lBRUQsT0FBTyxDQUFDLE9BQU8sR0FBRyxTQUFTLENBQUMsT0FBTyxDQUFDO0lBRXBDLFNBQVMsQ0FBQyxJQUFJLENBQUM7UUFDYixHQUFHO1FBQ0gsaUJBQWlCO1FBQ2pCLE9BQU87UUFDUCxRQUFRLEVBQUUsaUJBQWlCLENBQUMsU0FBUyxDQUFDLE9BQWtCLEVBQUUsVUFBVSxDQUFDO1FBQ3JFLFlBQVk7UUFDWixhQUFhO1FBQ2IsWUFBWSxFQUFFLE1BQU07UUFDcEIsWUFBWTtLQUNiLENBQUMsQ0FBQztBQUNMLENBQUM7QUFoQ0Qsc0NBZ0NDIiwic291cmNlc0NvbnRlbnQiOlsiaW1wb3J0ICogYXMgb3Bjb2RlcyBmcm9tICdiaXRjb2luLW9wcyc7XG5pbXBvcnQgKiBhcyBiaXAzMiBmcm9tICdiaXAzMic7XG5cbmNvbnN0IGVjYyA9IHJlcXVpcmUoJ3Rpbnktc2VjcDI1NmsxJyk7XG5cbmltcG9ydCB7XG4gIHBheW1lbnRzLFxuICBzY3JpcHQsXG4gIFRyYW5zYWN0aW9uLFxuICBUeElucHV0LFxuICBzY2hub3JyQmlwMzQwLFxuICBjbGFzc2lmeSxcbiAgdGFwcm9vdCxcbiAgVHhPdXRwdXQsXG4gIFNjcmlwdFNpZ25hdHVyZSxcbn0gZnJvbSAnYml0Y29pbmpzLWxpYic7XG5cbmltcG9ydCB7IFV0eG9UcmFuc2FjdGlvbiB9IGZyb20gJy4vVXR4b1RyYW5zYWN0aW9uJztcbmltcG9ydCB7IFV0eG9UcmFuc2FjdGlvbkJ1aWxkZXIgfSBmcm9tICcuL1V0eG9UcmFuc2FjdGlvbkJ1aWxkZXInO1xuaW1wb3J0IHtcbiAgY3JlYXRlT3V0cHV0U2NyaXB0Mm9mMyxcbiAgY3JlYXRlT3V0cHV0U2NyaXB0UDJzaFAycGssXG4gIGNyZWF0ZVNwZW5kU2NyaXB0UDJ0cixcbiAgU2NyaXB0VHlwZSxcbiAgU2NyaXB0VHlwZTJPZjMsXG4gIHNjcmlwdFR5cGUyT2YzQXNQcmV2T3V0VHlwZSxcbn0gZnJvbSAnLi9vdXRwdXRTY3JpcHRzJztcbmltcG9ydCB7IGlzVHJpcGxlLCBUcmlwbGUgfSBmcm9tICcuL3R5cGVzJztcbmltcG9ydCB7IGdldE1haW5uZXQsIE5ldHdvcmssIG5ldHdvcmtzIH0gZnJvbSAnLi4vbmV0d29ya3MnO1xuXG5jb25zdCBpbnB1dFR5cGVzID0gW1xuICAnbXVsdGlzaWcnLFxuICAnbm9uc3RhbmRhcmQnLFxuICAnbnVsbGRhdGEnLFxuICAncHVia2V5JyxcbiAgJ3B1YmtleWhhc2gnLFxuICAnc2NyaXB0aGFzaCcsXG4gICd3aXRuZXNzcHVia2V5aGFzaCcsXG4gICd3aXRuZXNzc2NyaXB0aGFzaCcsXG4gICd0YXByb290JyxcbiAgJ3RhcHJvb3Rub2ZuJyxcbiAgJ3dpdG5lc3Njb21taXRtZW50Jyxcbl0gYXMgY29uc3Q7XG5cbnR5cGUgSW5wdXRUeXBlID0gdHlwZW9mIGlucHV0VHlwZXNbbnVtYmVyXTtcblxuZXhwb3J0IGZ1bmN0aW9uIGlzUGxhY2Vob2xkZXJTaWduYXR1cmUodjogbnVtYmVyIHwgQnVmZmVyKTogYm9vbGVhbiB7XG4gIGlmIChCdWZmZXIuaXNCdWZmZXIodikpIHtcbiAgICByZXR1cm4gdi5sZW5ndGggPT09IDA7XG4gIH1cbiAgcmV0dXJuIHYgPT09IDA7XG59XG5cbmV4cG9ydCBpbnRlcmZhY2UgUGFyc2VkU2lnbmF0dXJlU2NyaXB0IHtcbiAgc2NyaXB0VHlwZTogU2NyaXB0VHlwZSB8ICdwMnBraCcgfCB1bmRlZmluZWQ7XG4gIGlzU2Vnd2l0SW5wdXQ6IGJvb2xlYW47XG4gIGlucHV0Q2xhc3NpZmljYXRpb246IElucHV0VHlwZTtcbiAgcDJzaE91dHB1dENsYXNzaWZpY2F0aW9uPzogc3RyaW5nO1xufVxuXG5leHBvcnQgaW50ZXJmYWNlIFBhcnNlZFNpZ25hdHVyZVNjcmlwdFVua25vd24gZXh0ZW5kcyBQYXJzZWRTaWduYXR1cmVTY3JpcHQge1xuICBzY3JpcHRUeXBlOiB1bmRlZmluZWQ7XG59XG5cbmV4cG9ydCBpbnRlcmZhY2UgUGFyc2VkU2lnbmF0dXJlU2NyaXB0UDJQSyBleHRlbmRzIFBhcnNlZFNpZ25hdHVyZVNjcmlwdCB7XG4gIHNjcmlwdFR5cGU6ICdwMnNoUDJwayc7XG4gIGlucHV0Q2xhc3NpZmljYXRpb246ICdzY3JpcHRoYXNoJztcbn1cblxuZXhwb3J0IGludGVyZmFjZSBQYXJzZWRTaWduYXR1cmVTY3JpcHRQMlBLSCBleHRlbmRzIFBhcnNlZFNpZ25hdHVyZVNjcmlwdCB7XG4gIHNjcmlwdFR5cGU6ICdwMnBraCc7XG4gIGlucHV0Q2xhc3NpZmljYXRpb246ICdwdWJrZXloYXNoJztcbiAgc2lnbmF0dXJlczogW0J1ZmZlcl07XG4gIHB1YmxpY0tleXM6IFtCdWZmZXJdO1xuICBwdWJTY3JpcHQ/OiBCdWZmZXI7XG59XG5cbmV4cG9ydCBpbnRlcmZhY2UgUGFyc2VkU2lnbmF0dXJlU2NyaXB0Mk9mMyBleHRlbmRzIFBhcnNlZFNpZ25hdHVyZVNjcmlwdCB7XG4gIHNjcmlwdFR5cGU6ICdwMnNoJyB8ICdwMnNoUDJ3c2gnIHwgJ3Ayd3NoJztcbiAgaW5wdXRDbGFzc2lmaWNhdGlvbjogJ3NjcmlwdGhhc2gnIHwgJ3dpdG5lc3NzY3JpcHRoYXNoJztcbiAgcHVibGljS2V5czogW0J1ZmZlciwgQnVmZmVyLCBCdWZmZXJdO1xuICBzaWduYXR1cmVzOlxuICAgIHwgW0J1ZmZlciwgQnVmZmVyXSAvLyBmdWxseS1zaWduZWQgdHJhbnNhY3Rpb25zIHdpdGggc2lnbmF0dXJlc1xuICAgIC8qIFBhcnRpYWxseSBzaWduZWQgdHJhbnNhY3Rpb25zIHdpdGggcGxhY2Vob2xkZXIgc2lnbmF0dXJlcy5cbiAgICAgICBGb3IgcDJzaCwgdGhlIHBsYWNlaG9sZGVyIGlzIE9QXzAgKG51bWJlciAwKSAqL1xuICAgIHwgW0J1ZmZlciB8IDAsIEJ1ZmZlciB8IDAsIEJ1ZmZlciB8IDBdO1xuICBwdWJTY3JpcHQ6IEJ1ZmZlcjtcbn1cblxuZXhwb3J0IGludGVyZmFjZSBQYXJzZWRTaWduYXR1cmVTY3JpcHRUYXByb290IGV4dGVuZHMgUGFyc2VkU2lnbmF0dXJlU2NyaXB0IHtcbiAgc2NyaXB0VHlwZTogJ3AydHInO1xuICBpbnB1dENsYXNzaWZpY2F0aW9uOiAndGFwcm9vdCc7XG4gIC8vIFAyVFIgdGFwc2NyaXB0IHNwZW5kcyBhcmUgZm9yIGtleXBhdGggc3BlbmRzIG9yIDItb2YtMiBtdWx0aXNpZyBzY3JpcHRzXG4gIC8vIEEgc2luZ2xlIHNpZ25hdHVyZSBpbmRpY2F0ZXMgYSBrZXlwYXRoIHNwZW5kLlxuICAvLyBUd28gc2lnbmF0dXJlcyBpbmRpY2F0ZSBhIHNjcmlwdFBhdGggc3BlbmQuXG4gIHB1YmxpY0tleXM6IFtCdWZmZXJdIHwgW0J1ZmZlciwgQnVmZmVyXTtcbiAgc2lnbmF0dXJlczogW0J1ZmZlcl0gfCBbQnVmZmVyLCBCdWZmZXJdO1xuICAvLyBGb3Igc2NyaXB0cGF0aCBzaWduYXR1cmVzLCB0aGlzIGNvbnRhaW5zIHRoZSBjb250cm9sIGJsb2NrIGRhdGEuIEZvciBrZXlwYXRoIHNpZ25hdHVyZXMgdGhpcyBpcyB1bmRlZmluZWQuXG4gIGNvbnRyb2xCbG9jazogQnVmZmVyIHwgdW5kZWZpbmVkO1xuICAvLyBGb3Igc2NyaXB0cGF0aCBzaWduYXR1cmVzLCB0aGlzIGluZGljYXRlcyB0aGUgbGV2ZWwgaW5zaWRlIHRoZSB0YXB0cmVlLiBGb3Iga2V5cGF0aCBzaWduYXR1cmVzIHRoaXMgaXMgdW5kZWZpbmVkLlxuICBzY3JpcHRQYXRoTGV2ZWw6IG51bWJlciB8IHVuZGVmaW5lZDtcbiAgcHViU2NyaXB0OiBCdWZmZXI7XG59XG5cbmV4cG9ydCBmdW5jdGlvbiBnZXREZWZhdWx0U2lnSGFzaChuZXR3b3JrOiBOZXR3b3JrLCBzY3JpcHRUeXBlPzogU2NyaXB0VHlwZTJPZjMpOiBudW1iZXIge1xuICBzd2l0Y2ggKGdldE1haW5uZXQobmV0d29yaykpIHtcbiAgICBjYXNlIG5ldHdvcmtzLmJpdGNvaW5jYXNoOlxuICAgIGNhc2UgbmV0d29ya3MuYml0Y29pbnN2OlxuICAgIGNhc2UgbmV0d29ya3MuYml0Y29pbmdvbGQ6XG4gICAgICByZXR1cm4gVHJhbnNhY3Rpb24uU0lHSEFTSF9BTEwgfCBVdHhvVHJhbnNhY3Rpb24uU0lHSEFTSF9GT1JLSUQ7XG4gICAgZGVmYXVsdDpcbiAgICAgIHJldHVybiBzY3JpcHRUeXBlID09PSAncDJ0cicgPyBUcmFuc2FjdGlvbi5TSUdIQVNIX0RFRkFVTFQgOiBUcmFuc2FjdGlvbi5TSUdIQVNIX0FMTDtcbiAgfVxufVxuXG4vKipcbiAqIFBhcnNlIGEgdHJhbnNhY3Rpb24ncyBzaWduYXR1cmUgc2NyaXB0IHRvIG9idGFpbiBwdWJsaWMga2V5cywgc2lnbmF0dXJlcywgdGhlIHNpZyBzY3JpcHQsXG4gKiBhbmQgb3RoZXIgcHJvcGVydGllcy5cbiAqXG4gKiBPbmx5IHN1cHBvcnRzIHNjcmlwdCB0eXBlcyB1c2VkIGluIEJpdEdvIHRyYW5zYWN0aW9ucy5cbiAqXG4gKiBAcGFyYW0gaW5wdXRcbiAqIEByZXR1cm5zIFBhcnNlZFNpZ25hdHVyZVNjcmlwdFxuICovXG5leHBvcnQgZnVuY3Rpb24gcGFyc2VTaWduYXR1cmVTY3JpcHQoXG4gIGlucHV0OiBUeElucHV0XG4pOlxuICB8IFBhcnNlZFNpZ25hdHVyZVNjcmlwdFVua25vd25cbiAgfCBQYXJzZWRTaWduYXR1cmVTY3JpcHRQMlBLXG4gIHwgUGFyc2VkU2lnbmF0dXJlU2NyaXB0UDJQS0hcbiAgfCBQYXJzZWRTaWduYXR1cmVTY3JpcHQyT2YzXG4gIHwgUGFyc2VkU2lnbmF0dXJlU2NyaXB0VGFwcm9vdCB7XG4gIGNvbnN0IGlzU2Vnd2l0SW5wdXQgPSBpbnB1dC53aXRuZXNzLmxlbmd0aCA+IDA7XG4gIGNvbnN0IGlzTmF0aXZlU2Vnd2l0SW5wdXQgPSBpbnB1dC5zY3JpcHQubGVuZ3RoID09PSAwO1xuICBsZXQgZGVjb21waWxlZFNpZ1NjcmlwdDogQXJyYXk8QnVmZmVyIHwgbnVtYmVyPiB8IG51bGw7XG4gIGxldCBpbnB1dENsYXNzaWZpY2F0aW9uOiBJbnB1dFR5cGU7XG4gIGlmIChpc1NlZ3dpdElucHV0KSB7XG4gICAgLy8gVGhlIGRlY29tcGlsZWRTaWdTY3JpcHQgaXMgdGhlIHNjcmlwdCBjb250YWluaW5nIHRoZSBzaWduYXR1cmVzLCBwdWJsaWMga2V5cywgYW5kIHRoZSBzY3JpcHQgdGhhdCB3YXMgY29tbWl0dGVkXG4gICAgLy8gdG8gKHB1YlNjcmlwdCkuIElmIHRoaXMgaXMgYSBzZWd3aXQgaW5wdXQgdGhlIGRlY29tcGlsZWRTaWdTY3JpcHQgaXMgaW4gdGhlIHdpdG5lc3MsIHJlZ2FyZGxlc3Mgb2Ygd2hldGhlciBpdFxuICAgIC8vIGlzIG5hdGl2ZSBvciBub3QuIFRoZSBpbnB1dENsYXNzaWZpY2F0aW9uIGlzIGRldGVybWluZWQgYmFzZWQgb24gd2hldGhlciBvciBub3QgdGhlIGlucHV0IGlzIG5hdGl2ZSB0byBnaXZlIGFuXG4gICAgLy8gYWNjdXJhdGUgY2xhc3NpZmljYXRpb24uIE5vdGUgdGhhdCBwMnNoUDJ3c2ggaW5wdXRzIHdpbGwgYmUgY2xhc3NpZmllZCBhcyBwMnNoIGFuZCBub3QgcDJ3c2guXG4gICAgZGVjb21waWxlZFNpZ1NjcmlwdCA9IGlucHV0LndpdG5lc3M7XG4gICAgaWYgKGlzTmF0aXZlU2Vnd2l0SW5wdXQpIHtcbiAgICAgIGlucHV0Q2xhc3NpZmljYXRpb24gPSBjbGFzc2lmeS53aXRuZXNzKGRlY29tcGlsZWRTaWdTY3JpcHQgYXMgQnVmZmVyW10sIHRydWUpIGFzIElucHV0VHlwZTtcbiAgICB9IGVsc2Uge1xuICAgICAgaW5wdXRDbGFzc2lmaWNhdGlvbiA9IGNsYXNzaWZ5LmlucHV0KGlucHV0LnNjcmlwdCwgdHJ1ZSkgYXMgSW5wdXRUeXBlO1xuICAgIH1cbiAgfSBlbHNlIHtcbiAgICBpbnB1dENsYXNzaWZpY2F0aW9uID0gY2xhc3NpZnkuaW5wdXQoaW5wdXQuc2NyaXB0LCB0cnVlKSBhcyBJbnB1dFR5cGU7XG4gICAgZGVjb21waWxlZFNpZ1NjcmlwdCA9IHNjcmlwdC5kZWNvbXBpbGUoaW5wdXQuc2NyaXB0KTtcbiAgfVxuXG4gIGlmICghZGVjb21waWxlZFNpZ1NjcmlwdCkge1xuICAgIHJldHVybiB7IHNjcmlwdFR5cGU6IHVuZGVmaW5lZCwgaXNTZWd3aXRJbnB1dCwgaW5wdXRDbGFzc2lmaWNhdGlvbiB9O1xuICB9XG5cbiAgaWYgKGlucHV0Q2xhc3NpZmljYXRpb24gPT09ICdwdWJrZXloYXNoJykge1xuICAgIC8qIGlzdGFuYnVsIGlnbm9yZSBuZXh0ICovXG4gICAgaWYgKCFkZWNvbXBpbGVkU2lnU2NyaXB0IHx8IGRlY29tcGlsZWRTaWdTY3JpcHQubGVuZ3RoICE9PSAyKSB7XG4gICAgICB0aHJvdyBuZXcgRXJyb3IoJ3VuZXhwZWN0ZWQgc2lnbmF0dXJlIGZvciBwMnBraCcpO1xuICAgIH1cbiAgICBjb25zdCBbc2lnbmF0dXJlLCBwdWJsaWNLZXldID0gZGVjb21waWxlZFNpZ1NjcmlwdDtcbiAgICAvKiBpc3RhbmJ1bCBpZ25vcmUgbmV4dCAqL1xuICAgIGlmICghQnVmZmVyLmlzQnVmZmVyKHNpZ25hdHVyZSkgfHwgIUJ1ZmZlci5pc0J1ZmZlcihwdWJsaWNLZXkpKSB7XG4gICAgICB0aHJvdyBuZXcgRXJyb3IoJ3VuZXhwZWN0ZWQgc2lnbmF0dXJlIGZvciBwMnBraCcpO1xuICAgIH1cbiAgICBjb25zdCBwdWJsaWNLZXlzOiBbQnVmZmVyXSA9IFtwdWJsaWNLZXldO1xuICAgIGNvbnN0IHNpZ25hdHVyZXM6IFtCdWZmZXJdID0gW3NpZ25hdHVyZV07XG4gICAgY29uc3QgcHViU2NyaXB0ID0gcGF5bWVudHMucDJwa2goeyBwdWJrZXk6IHB1YmxpY0tleSB9KS5vdXRwdXQ7XG5cbiAgICByZXR1cm4ge1xuICAgICAgc2NyaXB0VHlwZTogJ3AycGtoJyxcbiAgICAgIGlzU2Vnd2l0SW5wdXQsXG4gICAgICBpbnB1dENsYXNzaWZpY2F0aW9uLFxuICAgICAgc2lnbmF0dXJlcyxcbiAgICAgIHB1YmxpY0tleXMsXG4gICAgICBwdWJTY3JpcHQsXG4gICAgfTtcbiAgfVxuXG4gIGlmIChpbnB1dENsYXNzaWZpY2F0aW9uID09PSAndGFwcm9vdCcpIHtcbiAgICAvLyBhc3N1bWVzIG5vIGFubmV4XG4gICAgaWYgKGlucHV0LndpdG5lc3MubGVuZ3RoICE9PSA0KSB7XG4gICAgICB0aHJvdyBuZXcgRXJyb3IoYHVucmVjb2duaXplZCB0YXByb290IGlucHV0YCk7XG4gICAgfVxuICAgIGNvbnN0IFtzaWcxLCBzaWcyLCB0YXBzY3JpcHQsIGNvbnRyb2xCbG9ja10gPSBpbnB1dC53aXRuZXNzO1xuICAgIGNvbnN0IHRhcHNjcmlwdENsYXNzaWZpY2F0aW9uID0gY2xhc3NpZnkub3V0cHV0KHRhcHNjcmlwdCk7XG4gICAgaWYgKHRhcHNjcmlwdENsYXNzaWZpY2F0aW9uICE9PSAndGFwcm9vdG5vZm4nKSB7XG4gICAgICB0aHJvdyBuZXcgRXJyb3IoYHRhcHNjcmlwdCBtdXN0IGJlIG4gb2YgbiBtdWx0aXNpZ2ApO1xuICAgIH1cblxuICAgIGNvbnN0IHB1YmxpY0tleXMgPSBwYXltZW50cy5wMnRyX25zKHsgb3V0cHV0OiB0YXBzY3JpcHQgfSkucHVia2V5cztcbiAgICBpZiAoIXB1YmxpY0tleXMgfHwgcHVibGljS2V5cy5sZW5ndGggIT09IDIpIHtcbiAgICAgIHRocm93IG5ldyBFcnJvcignZXhwZWN0ZWQgMiBwdWJrZXlzJyk7XG4gICAgfVxuXG4gICAgY29uc3Qgc2lnbmF0dXJlcyA9IFtzaWcxLCBzaWcyXS5tYXAoKGIpID0+IHtcbiAgICAgIGlmIChCdWZmZXIuaXNCdWZmZXIoYikpIHtcbiAgICAgICAgcmV0dXJuIGI7XG4gICAgICB9XG4gICAgICB0aHJvdyBuZXcgRXJyb3IoYHVuZXhwZWN0ZWQgc2lnbmF0dXJlIGVsZW1lbnQgJHtifWApO1xuICAgIH0pIGFzIFtCdWZmZXIsIEJ1ZmZlcl07XG5cbiAgICBjb25zdCBzY3JpcHRQYXRoTGV2ZWwgPSBjb250cm9sQmxvY2subGVuZ3RoID09PSA2NSA/IDEgOiBjb250cm9sQmxvY2subGVuZ3RoID09PSA5NyA/IDIgOiB1bmRlZmluZWQ7XG5cbiAgICAvKiBpc3RhbmJ1bCBpZ25vcmUgbmV4dCAqL1xuICAgIGlmIChzY3JpcHRQYXRoTGV2ZWwgPT09IHVuZGVmaW5lZCkge1xuICAgICAgdGhyb3cgbmV3IEVycm9yKGB1bmV4cGVjdGVkIGNvbnRyb2wgYmxvY2sgbGVuZ3RoICR7Y29udHJvbEJsb2NrLmxlbmd0aH1gKTtcbiAgICB9XG5cbiAgICByZXR1cm4ge1xuICAgICAgc2NyaXB0VHlwZTogJ3AydHInLFxuICAgICAgaXNTZWd3aXRJbnB1dCxcbiAgICAgIGlucHV0Q2xhc3NpZmljYXRpb24sXG4gICAgICBwdWJsaWNLZXlzOiBwdWJsaWNLZXlzIGFzIFtCdWZmZXIsIEJ1ZmZlcl0sXG4gICAgICBzaWduYXR1cmVzLFxuICAgICAgcHViU2NyaXB0OiB0YXBzY3JpcHQsXG4gICAgICBjb250cm9sQmxvY2ssXG4gICAgICBzY3JpcHRQYXRoTGV2ZWwsXG4gICAgfTtcbiAgfVxuXG4gIC8vIE5vdGUgdGhlIGFzc3VtcHRpb24gaGVyZSB0aGF0IGlmIHdlIGhhdmUgYSBwMnNoIG9yIHAyd3NoIGlucHV0IGl0IHdpbGwgYmUgbXVsdGlzaWcgKGFwcHJvcHJpYXRlIGJlY2F1c2UgdGhlXG4gIC8vIEJpdEdvIHBsYXRmb3JtIG9ubHkgc3VwcG9ydHMgbXVsdGlzaWcgd2l0aGluIHRoZXNlIHR5cGVzIG9mIGlucHV0cywgd2l0aCB0aGUgZXhjZXB0aW9uIG9mIHJlcGxheSBwcm90ZWN0aW9uIGlucHV0cyxcbiAgLy8gd2hpY2ggYXJlIHNpbmdsZSBzaWduYXR1cmUgcDJzaCkuIFNpZ25hdHVyZXMgYXJlIGFsbCBidXQgdGhlIGxhc3QgZW50cnkgaW4gdGhlIGRlY29tcGlsZWRTaWdTY3JpcHQuXG4gIC8vIFRoZSByZWRlZW1TY3JpcHQvd2l0bmVzc1NjcmlwdCAoZGVwZW5kaW5nIG9uIHdoaWNoIHR5cGUgb2YgaW5wdXQgdGhpcyBpcykgaXMgdGhlIGxhc3QgZW50cnkgaW5cbiAgLy8gdGhlIGRlY29tcGlsZWRTaWdTY3JpcHQgKGRlbm90ZWQgaGVyZSBhcyB0aGUgcHViU2NyaXB0KS4gVGhlIHB1YmxpYyBrZXlzIGFyZSB0aGUgc2Vjb25kIHRocm91Z2hcbiAgLy8gYW50ZXBlbnVsdGltYXRlIGVudHJpZXMgaW4gdGhlIGRlY29tcGlsZWRQdWJTY3JpcHQuIFNlZSBiZWxvdyBmb3IgYSB2aXN1YWwgcmVwcmVzZW50YXRpb24gb2YgdGhlIHR5cGljYWwgMi1vZi0zXG4gIC8vIG11bHRpc2lnIHNldHVwOlxuICAvL1xuICAvLyAgIGRlY29tcGlsZWRTaWdTY3JpcHQgPSAwIDxzaWcxPiA8c2lnMj4gWzxzaWczPl0gPHB1YlNjcmlwdD5cbiAgLy8gICBkZWNvbXBpbGVkUHViU2NyaXB0ID0gMiA8cHViMT4gPHB1YjI+IDxwdWIzPiAzIE9QX0NIRUNLTVVMVElTSUdcbiAgLy9cbiAgLy8gVHJhbnNhY3Rpb25zIGJ1aWx0IHdpdGggYC5idWlsZCgpYCBvbmx5IGhhdmUgdHdvIHNpZ25hdHVyZXMgYDxzaWcxPmAgYW5kIGA8c2lnMj5gIGluIF9kZWNvbXBpbGVkU2lnU2NyaXB0Xy5cbiAgLy8gVHJhbnNhY3Rpb25zIGJ1aWx0IHdpdGggYC5idWlsZEluY29tcGxldGUoKWAgaGF2ZSB0aHJlZSBzaWduYXR1cmVzLCB3aGVyZSBtaXNzaW5nIHNpZ25hdHVyZXMgYXJlIHN1YnN0aXR1dGVkIHdpdGggYE9QXzBgLlxuICBpZiAoaW5wdXRDbGFzc2lmaWNhdGlvbiAhPT0gJ3NjcmlwdGhhc2gnICYmIGlucHV0Q2xhc3NpZmljYXRpb24gIT09ICd3aXRuZXNzc2NyaXB0aGFzaCcpIHtcbiAgICByZXR1cm4geyBzY3JpcHRUeXBlOiB1bmRlZmluZWQsIGlzU2Vnd2l0SW5wdXQsIGlucHV0Q2xhc3NpZmljYXRpb24gfTtcbiAgfVxuXG4gIGNvbnN0IHB1YlNjcmlwdCA9IGRlY29tcGlsZWRTaWdTY3JpcHRbZGVjb21waWxlZFNpZ1NjcmlwdC5sZW5ndGggLSAxXTtcbiAgLyogaXN0YW5idWwgaWdub3JlIG5leHQgKi9cbiAgaWYgKCFCdWZmZXIuaXNCdWZmZXIocHViU2NyaXB0KSkge1xuICAgIHRocm93IG5ldyBFcnJvcihgaW52YWxpZCBwdWJTY3JpcHRgKTtcbiAgfVxuXG4gIGNvbnN0IHAyc2hPdXRwdXRDbGFzc2lmaWNhdGlvbiA9IGNsYXNzaWZ5Lm91dHB1dChwdWJTY3JpcHQpO1xuXG4gIGlmIChpbnB1dENsYXNzaWZpY2F0aW9uID09PSAnc2NyaXB0aGFzaCcgJiYgcDJzaE91dHB1dENsYXNzaWZpY2F0aW9uID09PSAncHVia2V5Jykge1xuICAgIHJldHVybiB7XG4gICAgICBzY3JpcHRUeXBlOiAncDJzaFAycGsnLFxuICAgICAgaXNTZWd3aXRJbnB1dCxcbiAgICAgIGlucHV0Q2xhc3NpZmljYXRpb24sXG4gICAgICBwMnNoT3V0cHV0Q2xhc3NpZmljYXRpb24sXG4gICAgfTtcbiAgfVxuXG4gIGlmIChwMnNoT3V0cHV0Q2xhc3NpZmljYXRpb24gIT09ICdtdWx0aXNpZycpIHtcbiAgICByZXR1cm4ge1xuICAgICAgc2NyaXB0VHlwZTogdW5kZWZpbmVkLFxuICAgICAgaXNTZWd3aXRJbnB1dCxcbiAgICAgIGlucHV0Q2xhc3NpZmljYXRpb24sXG4gICAgICBwMnNoT3V0cHV0Q2xhc3NpZmljYXRpb24sXG4gICAgfTtcbiAgfVxuXG4gIGNvbnN0IGRlY29tcGlsZWRQdWJTY3JpcHQgPSBzY3JpcHQuZGVjb21waWxlKHB1YlNjcmlwdCk7XG4gIGlmIChkZWNvbXBpbGVkUHViU2NyaXB0ID09PSBudWxsKSB7XG4gICAgLyogaXN0YW5idWwgaWdub3JlIG5leHQgKi9cbiAgICB0aHJvdyBuZXcgRXJyb3IoYGNvdWxkIG5vdCBkZWNvbXBpbGUgcHViU2NyaXB0YCk7XG4gIH1cblxuICBjb25zdCBleHBlY3RlZFNjcmlwdExlbmd0aCA9XG4gICAgLy8gY29tcGxldGUgdHJhbnNhY3Rpb25zIHdpdGggMiBzaWduYXR1cmVzXG4gICAgZGVjb21waWxlZFNpZ1NjcmlwdC5sZW5ndGggPT09IDQgfHxcbiAgICAvLyBpbmNvbXBsZXRlIHRyYW5zYWN0aW9uIHdpdGggMyBzaWduYXR1cmVzIG9yIHNpZ25hdHVyZSBwbGFjZWhvbGRlcnNcbiAgICBkZWNvbXBpbGVkU2lnU2NyaXB0Lmxlbmd0aCA9PT0gNTtcblxuICBpZiAoIWV4cGVjdGVkU2NyaXB0TGVuZ3RoKSB7XG4gICAgcmV0dXJuIHsgc2NyaXB0VHlwZTogdW5kZWZpbmVkLCBpc1NlZ3dpdElucHV0LCBpbnB1dENsYXNzaWZpY2F0aW9uIH07XG4gIH1cblxuICBpZiAoaXNTZWd3aXRJbnB1dCkge1xuICAgIC8qIGlzdGFuYnVsIGlnbm9yZSBuZXh0ICovXG4gICAgaWYgKCFCdWZmZXIuaXNCdWZmZXIoZGVjb21waWxlZFNpZ1NjcmlwdFswXSkpIHtcbiAgICAgIHRocm93IG5ldyBFcnJvcihgZXhwZWN0ZWQgZGVjb21waWxlZFNpZ1NjcmlwdFswXSB0byBiZSBhIGJ1ZmZlciBmb3Igc2Vnd2l0IGlucHV0c2ApO1xuICAgIH1cbiAgICAvKiBpc3RhbmJ1bCBpZ25vcmUgbmV4dCAqL1xuICAgIGlmIChkZWNvbXBpbGVkU2lnU2NyaXB0WzBdLmxlbmd0aCAhPT0gMCkge1xuICAgICAgdGhyb3cgbmV3IEVycm9yKGB3aXRuZXNzIHN0YWNrIGV4cGVjdGVkIHRvIHN0YXJ0IHdpdGggZW1wdHkgYnVmZmVyYCk7XG4gICAgfVxuICB9IGVsc2UgaWYgKGRlY29tcGlsZWRTaWdTY3JpcHRbMF0gIT09IG9wY29kZXMuT1BfMCkge1xuICAgIHRocm93IG5ldyBFcnJvcihgc2lnU2NyaXB0IGV4cGVjdGVkIHRvIHN0YXJ0IHdpdGggT1BfMGApO1xuICB9XG5cbiAgY29uc3Qgc2lnbmF0dXJlcyA9IGRlY29tcGlsZWRTaWdTY3JpcHQuc2xpY2UoMSAvKiBpZ25vcmUgbGVhZGluZyBPUF8wICovLCAtMSAvKiBpZ25vcmUgdHJhaWxpbmcgcHViU2NyaXB0ICovKTtcbiAgLyogaXN0YW5idWwgaWdub3JlIG5leHQgKi9cbiAgaWYgKHNpZ25hdHVyZXMubGVuZ3RoICE9PSAyICYmIHNpZ25hdHVyZXMubGVuZ3RoICE9PSAzKSB7XG4gICAgdGhyb3cgbmV3IEVycm9yKGBleHBlY3RlZCAyIG9yIDMgc2lnbmF0dXJlcywgZ290ICR7c2lnbmF0dXJlcy5sZW5ndGh9YCk7XG4gIH1cblxuICAvKiBpc3RhbmJ1bCBpZ25vcmUgbmV4dCAqL1xuICBpZiAoZGVjb21waWxlZFB1YlNjcmlwdC5sZW5ndGggIT09IDYpIHtcbiAgICB0aHJvdyBuZXcgRXJyb3IoYHVuZXhwZWN0ZWQgZGVjb21waWxlZFB1YlNjcmlwdCBsZW5ndGhgKTtcbiAgfVxuICBjb25zdCBwdWJsaWNLZXlzID0gZGVjb21waWxlZFB1YlNjcmlwdC5zbGljZSgxLCAtMikgYXMgQnVmZmVyW107XG4gIHB1YmxpY0tleXMuZm9yRWFjaCgoYikgPT4ge1xuICAgIC8qIGlzdGFuYnVsIGlnbm9yZSBuZXh0ICovXG4gICAgaWYgKCFCdWZmZXIuaXNCdWZmZXIoYikpIHtcbiAgICAgIHRocm93IG5ldyBFcnJvcigpO1xuICAgIH1cbiAgfSk7XG4gIGlmICghaXNUcmlwbGUocHVibGljS2V5cykpIHtcbiAgICAvKiBpc3RhbmJ1bCBpZ25vcmUgbmV4dCAqL1xuICAgIHRocm93IG5ldyBFcnJvcihgZXhwZWN0ZWQgMyBwdWJsaWMga2V5cywgZ290ICR7cHVibGljS2V5cy5sZW5ndGh9YCk7XG4gIH1cblxuICAvLyBPcCBjb2RlcyA4MSB0aHJvdWdoIDk2IHJlcHJlc2VudCBudW1iZXJzIDEgdGhyb3VnaCAxNiAoc2VlIGh0dHBzOi8vZW4uYml0Y29pbi5pdC93aWtpL1NjcmlwdCNPcGNvZGVzKSwgd2hpY2ggaXNcbiAgLy8gd2h5IHdlIHN1YnRyYWN0IGJ5IDgwIHRvIGdldCB0aGUgbnVtYmVyIG9mIHNpZ25hdHVyZXMgKG4pIGFuZCB0aGUgbnVtYmVyIG9mIHB1YmxpYyBrZXlzIChtKSBpbiBhbiBuLW9mLW0gc2V0dXAuXG4gIGNvbnN0IGxlbiA9IGRlY29tcGlsZWRQdWJTY3JpcHQubGVuZ3RoO1xuICBjb25zdCBzaWduYXR1cmVUaHJlc2hvbGQgPSAoZGVjb21waWxlZFB1YlNjcmlwdFswXSBhcyBudW1iZXIpIC0gODA7XG4gIC8qIGlzdGFuYnVsIGlnbm9yZSBuZXh0ICovXG4gIGlmIChzaWduYXR1cmVUaHJlc2hvbGQgIT09IDIpIHtcbiAgICB0aHJvdyBuZXcgRXJyb3IoYGV4cGVjdGVkIHNpZ25hdHVyZVRocmVzaG9sZCAyLCBnb3QgJHtzaWduYXR1cmVUaHJlc2hvbGR9YCk7XG4gIH1cbiAgY29uc3QgblB1YktleXMgPSAoZGVjb21waWxlZFB1YlNjcmlwdFtsZW4gLSAyXSBhcyBudW1iZXIpIC0gODA7XG4gIC8qIGlzdGFuYnVsIGlnbm9yZSBuZXh0ICovXG4gIGlmIChuUHViS2V5cyAhPT0gMykge1xuICAgIHRocm93IG5ldyBFcnJvcihgZXhwZWN0ZWQgblB1YktleXMgMywgZ290ICR7blB1YktleXN9YCk7XG4gIH1cblxuICBjb25zdCBsYXN0T3BDb2RlID0gZGVjb21waWxlZFB1YlNjcmlwdFtsZW4gLSAxXTtcbiAgLyogaXN0YW5idWwgaWdub3JlIG5leHQgKi9cbiAgaWYgKGxhc3RPcENvZGUgIT09IG9wY29kZXMuT1BfQ0hFQ0tNVUxUSVNJRykge1xuICAgIHRocm93IG5ldyBFcnJvcihgZXhwZWN0ZWQgb3Bjb2RlICMke29wY29kZXMuT1BfQ0hFQ0tNVUxUSVNJR30sIGdvdCBvcGNvZGUgIyR7bGFzdE9wQ29kZX1gKTtcbiAgfVxuXG4gIGNvbnN0IHNjcmlwdFR5cGUgPSBpbnB1dC53aXRuZXNzLmxlbmd0aFxuICAgID8gaW5wdXQuc2NyaXB0Lmxlbmd0aFxuICAgICAgPyAncDJzaFAyd3NoJ1xuICAgICAgOiAncDJ3c2gnXG4gICAgOiBpbnB1dC5zY3JpcHQubGVuZ3RoXG4gICAgPyAncDJzaCdcbiAgICA6IHVuZGVmaW5lZDtcbiAgaWYgKHNjcmlwdFR5cGUgPT09IHVuZGVmaW5lZCkge1xuICAgIHRocm93IG5ldyBFcnJvcignaWxsZWdhbCBzdGF0ZScpO1xuICB9XG5cbiAgcmV0dXJuIHtcbiAgICBzY3JpcHRUeXBlLFxuICAgIGlzU2Vnd2l0SW5wdXQsXG4gICAgaW5wdXRDbGFzc2lmaWNhdGlvbixcbiAgICBwMnNoT3V0cHV0Q2xhc3NpZmljYXRpb24sXG4gICAgc2lnbmF0dXJlczogc2lnbmF0dXJlcy5tYXAoKGIpID0+IHtcbiAgICAgIGlmIChCdWZmZXIuaXNCdWZmZXIoYikgfHwgYiA9PT0gMCkge1xuICAgICAgICByZXR1cm4gYjtcbiAgICAgIH1cbiAgICAgIHRocm93IG5ldyBFcnJvcihgdW5leHBlY3RlZCBzaWduYXR1cmUgZWxlbWVudCAke2J9YCk7XG4gICAgfSkgYXMgW0J1ZmZlciwgQnVmZmVyXSB8IFtCdWZmZXIsIEJ1ZmZlciwgQnVmZmVyXSxcbiAgICBwdWJsaWNLZXlzLFxuICAgIHB1YlNjcmlwdCxcbiAgfTtcbn1cblxuZXhwb3J0IGZ1bmN0aW9uIHBhcnNlU2lnbmF0dXJlU2NyaXB0Mk9mMyhpbnB1dDogVHhJbnB1dCk6IFBhcnNlZFNpZ25hdHVyZVNjcmlwdDJPZjMgfCBQYXJzZWRTaWduYXR1cmVTY3JpcHRUYXByb290IHtcbiAgY29uc3QgcmVzdWx0ID0gcGFyc2VTaWduYXR1cmVTY3JpcHQoaW5wdXQpIGFzIFBhcnNlZFNpZ25hdHVyZVNjcmlwdDJPZjM7XG5cbiAgaWYgKFxuICAgICFbY2xhc3NpZnkudHlwZXMuUDJXU0gsIGNsYXNzaWZ5LnR5cGVzLlAyU0gsIGNsYXNzaWZ5LnR5cGVzLlAyUEtILCBjbGFzc2lmeS50eXBlcy5QMlRSXS5pbmNsdWRlcyhcbiAgICAgIHJlc3VsdC5pbnB1dENsYXNzaWZpY2F0aW9uXG4gICAgKVxuICApIHtcbiAgICB0aHJvdyBuZXcgRXJyb3IoYHVuZXhwZWN0ZWQgaW5wdXRDbGFzc2lmaWNhdGlvbiAke3Jlc3VsdC5pbnB1dENsYXNzaWZpY2F0aW9ufWApO1xuICB9XG4gIGlmICghcmVzdWx0LnNpZ25hdHVyZXMpIHtcbiAgICB0aHJvdyBuZXcgRXJyb3IoYG1pc3Npbmcgc2lnbmF0dXJlc2ApO1xuICB9XG4gIGlmIChcbiAgICByZXN1bHQucHVibGljS2V5cy5sZW5ndGggIT09IDMgJiZcbiAgICAocmVzdWx0LnB1YmxpY0tleXMubGVuZ3RoICE9PSAyIHx8IHJlc3VsdC5pbnB1dENsYXNzaWZpY2F0aW9uICE9PSBjbGFzc2lmeS50eXBlcy5QMlRSKVxuICApIHtcbiAgICB0aHJvdyBuZXcgRXJyb3IoYHVuZXhwZWN0ZWQgcHVia2V5IGNvdW50YCk7XG4gIH1cbiAgaWYgKCFyZXN1bHQucHViU2NyaXB0IHx8IHJlc3VsdC5wdWJTY3JpcHQubGVuZ3RoID09PSAwKSB7XG4gICAgdGhyb3cgbmV3IEVycm9yKGBwdWJTY3JpcHQgbWlzc2luZyBvciBlbXB0eWApO1xuICB9XG5cbiAgcmV0dXJuIHJlc3VsdDtcbn1cblxuLyoqXG4gKiBDb25zdHJhaW50cyBmb3Igc2lnbmF0dXJlIHZlcmlmaWNhdGlvbnMuXG4gKiBQYXJhbWV0ZXJzIGFyZSBjb25qdW5jdGl2ZTogaWYgbXVsdGlwbGUgcGFyYW1ldGVycyBhcmUgc2V0LCBhIHZlcmlmaWNhdGlvbiBmb3IgYW4gaW5kaXZpZHVhbFxuICogc2lnbmF0dXJlIG11c3Qgc2F0aXNmeSBhbGwgb2YgdGhlbS5cbiAqL1xuZXhwb3J0IHR5cGUgVmVyaWZpY2F0aW9uU2V0dGluZ3MgPSB7XG4gIC8qKlxuICAgKiBUaGUgaW5kZXggb2YgdGhlIHNpZ25hdHVyZSB0byB2ZXJpZnkuIE9ubHkgaXRlcmF0ZXMgb3ZlciBub24tZW1wdHkgc2lnbmF0dXJlcy5cbiAgICovXG4gIHNpZ25hdHVyZUluZGV4PzogbnVtYmVyO1xuICAvKipcbiAgICogVGhlIHB1YmxpYyBrZXkgdG8gdmVyaWZ5LlxuICAgKi9cbiAgcHVibGljS2V5PzogQnVmZmVyO1xufTtcblxuLyoqXG4gKiBSZXN1bHQgZm9yIGEgaW5kaXZpZHVhbCBzaWduYXR1cmUgdmVyaWZpY2F0aW9uXG4gKi9cbmV4cG9ydCB0eXBlIFNpZ25hdHVyZVZlcmlmaWNhdGlvbiA9IHtcbiAgLyoqIFNldCB0byB0aGUgcHVibGljIGtleSB0aGF0IHNpZ25lZCBmb3IgdGhlIHNpZ25hdHVyZSAqL1xuICBzaWduZWRCeTogQnVmZmVyIHwgdW5kZWZpbmVkO1xufTtcblxuLyoqXG4gKiBAZGVwcmVjYXRlZCAtIHVzZSB7QHNlZSB2ZXJpZnlTaWduYXR1cmVzV2l0aFB1YmxpY0tleXN9IGluc3RlYWRcbiAqIEdldCBzaWduYXR1cmUgdmVyaWZpY2F0aW9ucyBmb3IgbXVsdHNpZyB0cmFuc2FjdGlvblxuICogQHBhcmFtIHRyYW5zYWN0aW9uXG4gKiBAcGFyYW0gaW5wdXRJbmRleFxuICogQHBhcmFtIGFtb3VudCAtIG11c3QgYmUgc2V0IGZvciBzZWd3aXQgdHJhbnNhY3Rpb25zIGFuZCBCSVAxNDMgdHJhbnNhY3Rpb25zXG4gKiBAcGFyYW0gdmVyaWZpY2F0aW9uU2V0dGluZ3NcbiAqIEBwYXJhbSBwcmV2T3V0cHV0cyAtIG11c3QgYmUgc2V0IGZvciBwMnRyIHRyYW5zYWN0aW9uc1xuICogQHJldHVybnMgU2lnbmF0dXJlVmVyaWZpY2F0aW9uW10gLSBpbiBvcmRlciBvZiBwYXJzZWQgbm9uLWVtcHR5IHNpZ25hdHVyZXNcbiAqL1xuZXhwb3J0IGZ1bmN0aW9uIGdldFNpZ25hdHVyZVZlcmlmaWNhdGlvbnMoXG4gIHRyYW5zYWN0aW9uOiBVdHhvVHJhbnNhY3Rpb24sXG4gIGlucHV0SW5kZXg6IG51bWJlcixcbiAgYW1vdW50OiBudW1iZXIsXG4gIHZlcmlmaWNhdGlvblNldHRpbmdzOiBWZXJpZmljYXRpb25TZXR0aW5ncyA9IHt9LFxuICBwcmV2T3V0cHV0cz86IFR4T3V0cHV0W11cbik6IFNpZ25hdHVyZVZlcmlmaWNhdGlvbltdIHtcbiAgLyogaXN0YW5idWwgaWdub3JlIG5leHQgKi9cbiAgaWYgKCF0cmFuc2FjdGlvbi5pbnMpIHtcbiAgICB0aHJvdyBuZXcgRXJyb3IoYGludmFsaWQgdHJhbnNhY3Rpb25gKTtcbiAgfVxuXG4gIGNvbnN0IGlucHV0ID0gdHJhbnNhY3Rpb24uaW5zW2lucHV0SW5kZXhdO1xuICAvKiBpc3RhbmJ1bCBpZ25vcmUgbmV4dCAqL1xuICBpZiAoIWlucHV0KSB7XG4gICAgdGhyb3cgbmV3IEVycm9yKGBubyBpbnB1dCBhdCBpbmRleCAke2lucHV0SW5kZXh9YCk7XG4gIH1cblxuICBpZiAoKCFpbnB1dC5zY3JpcHQgfHwgaW5wdXQuc2NyaXB0Lmxlbmd0aCA9PT0gMCkgJiYgaW5wdXQud2l0bmVzcy5sZW5ndGggPT09IDApIHtcbiAgICAvLyBVbnNpZ25lZCBpbnB1dDogbm8gc2lnbmF0dXJlcy5cbiAgICByZXR1cm4gW107XG4gIH1cblxuICBjb25zdCBwYXJzZWRTY3JpcHQgPSBwYXJzZVNpZ25hdHVyZVNjcmlwdDJPZjMoaW5wdXQpO1xuXG4gIGNvbnN0IHNpZ25hdHVyZXMgPSBwYXJzZWRTY3JpcHQuc2lnbmF0dXJlc1xuICAgIC5maWx0ZXIoKHMpID0+IHMgJiYgcy5sZW5ndGgpXG4gICAgLmZpbHRlcigocywgaSkgPT4gdmVyaWZpY2F0aW9uU2V0dGluZ3Muc2lnbmF0dXJlSW5kZXggPT09IHVuZGVmaW5lZCB8fCB2ZXJpZmljYXRpb25TZXR0aW5ncy5zaWduYXR1cmVJbmRleCA9PT0gaSk7XG5cbiAgY29uc3QgcHVibGljS2V5cyA9IHBhcnNlZFNjcmlwdC5wdWJsaWNLZXlzLmZpbHRlcihcbiAgICAoYnVmKSA9PlxuICAgICAgdmVyaWZpY2F0aW9uU2V0dGluZ3MucHVibGljS2V5ID09PSB1bmRlZmluZWQgfHxcbiAgICAgIHZlcmlmaWNhdGlvblNldHRpbmdzLnB1YmxpY0tleS5lcXVhbHMoYnVmKSB8fFxuICAgICAgdmVyaWZpY2F0aW9uU2V0dGluZ3MucHVibGljS2V5LnNsaWNlKDEpLmVxdWFscyhidWYpXG4gICk7XG5cbiAgcmV0dXJuIHNpZ25hdHVyZXMubWFwKChzaWduYXR1cmVCdWZmZXIpID0+IHtcbiAgICBpZiAoc2lnbmF0dXJlQnVmZmVyID09PSAwIHx8IHNpZ25hdHVyZUJ1ZmZlci5sZW5ndGggPT09IDApIHtcbiAgICAgIHJldHVybiB7IHNpZ25lZEJ5OiB1bmRlZmluZWQgfTtcbiAgICB9XG5cbiAgICBsZXQgaGFzaFR5cGUgPSBUcmFuc2FjdGlvbi5TSUdIQVNIX0RFRkFVTFQ7XG5cbiAgICBpZiAoc2lnbmF0dXJlQnVmZmVyLmxlbmd0aCA9PT0gNjUpIHtcbiAgICAgIGhhc2hUeXBlID0gc2lnbmF0dXJlQnVmZmVyW3NpZ25hdHVyZUJ1ZmZlci5sZW5ndGggLSAxXTtcbiAgICAgIHNpZ25hdHVyZUJ1ZmZlciA9IHNpZ25hdHVyZUJ1ZmZlci5zbGljZSgwLCAtMSk7XG4gICAgfVxuXG4gICAgaWYgKHBhcnNlZFNjcmlwdC5pbnB1dENsYXNzaWZpY2F0aW9uID09PSBjbGFzc2lmeS50eXBlcy5QMlRSKSB7XG4gICAgICBpZiAodmVyaWZpY2F0aW9uU2V0dGluZ3Muc2lnbmF0dXJlSW5kZXggIT09IHVuZGVmaW5lZCkge1xuICAgICAgICB0aHJvdyBuZXcgRXJyb3IoYHNpZ25hdHVyZUluZGV4IHBhcmFtZXRlciBub3Qgc3VwcG9ydGVkIGZvciBwMnRyYCk7XG4gICAgICB9XG5cbiAgICAgIGlmICghcHJldk91dHB1dHMpIHtcbiAgICAgICAgdGhyb3cgbmV3IEVycm9yKGBwcmV2T3V0cHV0cyBub3Qgc2V0YCk7XG4gICAgICB9XG5cbiAgICAgIGlmIChwcmV2T3V0cHV0cy5sZW5ndGggIT09IHRyYW5zYWN0aW9uLmlucy5sZW5ndGgpIHtcbiAgICAgICAgdGhyb3cgbmV3IEVycm9yKGBwcmV2T3V0cHV0cyBsZW5ndGggJHtwcmV2T3V0cHV0cy5sZW5ndGh9LCBleHBlY3RlZCAke3RyYW5zYWN0aW9uLmlucy5sZW5ndGh9YCk7XG4gICAgICB9XG5cbiAgICAgIGNvbnN0IHsgY29udHJvbEJsb2NrLCBwdWJTY3JpcHQgfSA9IHBhcnNlZFNjcmlwdCBhcyBQYXJzZWRTaWduYXR1cmVTY3JpcHRUYXByb290O1xuICAgICAgaWYgKCFjb250cm9sQmxvY2spIHtcbiAgICAgICAgdGhyb3cgbmV3IEVycm9yKCdleHBlY3RlZCBjb250cm9sQmxvY2snKTtcbiAgICAgIH1cbiAgICAgIGNvbnN0IGxlYWZIYXNoID0gdGFwcm9vdC5nZXRUYXBsZWFmSGFzaChjb250cm9sQmxvY2ssIHB1YlNjcmlwdCk7XG4gICAgICBjb25zdCBzaWduYXR1cmVIYXNoID0gdHJhbnNhY3Rpb24uaGFzaEZvcldpdG5lc3NWMShcbiAgICAgICAgaW5wdXRJbmRleCxcbiAgICAgICAgcHJldk91dHB1dHMubWFwKCh7IHNjcmlwdCB9KSA9PiBzY3JpcHQpLFxuICAgICAgICBwcmV2T3V0cHV0cy5tYXAoKHsgdmFsdWUgfSkgPT4gdmFsdWUpLFxuICAgICAgICBoYXNoVHlwZSxcbiAgICAgICAgbGVhZkhhc2hcbiAgICAgICk7XG5cbiAgICAgIGNvbnN0IHNpZ25lZEJ5ID0gcHVibGljS2V5cy5maWx0ZXIoXG4gICAgICAgIChrKSA9PiBCdWZmZXIuaXNCdWZmZXIoc2lnbmF0dXJlQnVmZmVyKSAmJiBzY2hub3JyQmlwMzQwLnZlcmlmeVNjaG5vcnIoc2lnbmF0dXJlSGFzaCwgaywgc2lnbmF0dXJlQnVmZmVyKVxuICAgICAgKTtcblxuICAgICAgaWYgKHNpZ25lZEJ5Lmxlbmd0aCA9PT0gMCkge1xuICAgICAgICByZXR1cm4geyBzaWduZWRCeTogdW5kZWZpbmVkIH07XG4gICAgICB9XG4gICAgICBpZiAoc2lnbmVkQnkubGVuZ3RoID09PSAxKSB7XG4gICAgICAgIHJldHVybiB7IHNpZ25lZEJ5OiBzaWduZWRCeVswXSB9O1xuICAgICAgfVxuICAgICAgdGhyb3cgbmV3IEVycm9yKGBpbGxlZ2FsIHN0YXRlOiBzaWduZWQgYnkgbXVsdGlwbGUgcHVibGljIGtleXNgKTtcbiAgICB9IGVsc2Uge1xuICAgICAgLy8gc2xpY2UgdGhlIGxhc3QgYnl0ZSBmcm9tIHRoZSBzaWduYXR1cmUgaGFzaCBpbnB1dCBiZWNhdXNlIGl0J3MgdGhlIGhhc2ggdHlwZVxuICAgICAgY29uc3QgeyBzaWduYXR1cmUsIGhhc2hUeXBlIH0gPSBTY3JpcHRTaWduYXR1cmUuZGVjb2RlKHNpZ25hdHVyZUJ1ZmZlcik7XG4gICAgICBjb25zdCB0cmFuc2FjdGlvbkhhc2ggPSBwYXJzZWRTY3JpcHQuaXNTZWd3aXRJbnB1dFxuICAgICAgICA/IHRyYW5zYWN0aW9uLmhhc2hGb3JXaXRuZXNzVjAoaW5wdXRJbmRleCwgcGFyc2VkU2NyaXB0LnB1YlNjcmlwdCwgYW1vdW50LCBoYXNoVHlwZSlcbiAgICAgICAgOiB0cmFuc2FjdGlvbi5oYXNoRm9yU2lnbmF0dXJlQnlOZXR3b3JrKGlucHV0SW5kZXgsIHBhcnNlZFNjcmlwdC5wdWJTY3JpcHQsIGFtb3VudCwgaGFzaFR5cGUpO1xuICAgICAgY29uc3Qgc2lnbmVkQnkgPSBwdWJsaWNLZXlzLmZpbHRlcigocHVibGljS2V5KSA9PlxuICAgICAgICBlY2MudmVyaWZ5KFxuICAgICAgICAgIHRyYW5zYWN0aW9uSGFzaCxcbiAgICAgICAgICBwdWJsaWNLZXksXG4gICAgICAgICAgc2lnbmF0dXJlLFxuICAgICAgICAgIC8qXG4gICAgICAgICAgICBTdHJpY3QgdmVyaWZpY2F0aW9uIChyZXF1aXJlIGxvd2VyLVMgdmFsdWUpLCBhcyByZXF1aXJlZCBieSBCSVAtMDE0NlxuICAgICAgICAgICAgaHR0cHM6Ly9naXRodWIuY29tL2JpdGNvaW4vYmlwcy9ibG9iL21hc3Rlci9iaXAtMDE0Ni5tZWRpYXdpa2lcbiAgICAgICAgICAgIGh0dHBzOi8vZ2l0aHViLmNvbS9iaXRjb2luLWNvcmUvc2VjcDI1NmsxL2Jsb2IvYWM4M2JlMzMvaW5jbHVkZS9zZWNwMjU2azEuaCNMNDc4LUw1MDhcbiAgICAgICAgICAgIGh0dHBzOi8vZ2l0aHViLmNvbS9iaXRjb2luanMvdGlueS1zZWNwMjU2azEvYmxvYi92MS4xLjYvanMuanMjTDIzMS1MMjMzXG4gICAgICAgICAgKi9cbiAgICAgICAgICB0cnVlXG4gICAgICAgIClcbiAgICAgICk7XG5cbiAgICAgIGlmIChzaWduZWRCeS5sZW5ndGggPT09IDApIHtcbiAgICAgICAgcmV0dXJuIHsgc2lnbmVkQnk6IHVuZGVmaW5lZCB9O1xuICAgICAgfVxuICAgICAgaWYgKHNpZ25lZEJ5Lmxlbmd0aCA9PT0gMSkge1xuICAgICAgICByZXR1cm4geyBzaWduZWRCeTogc2lnbmVkQnlbMF0gfTtcbiAgICAgIH1cbiAgICAgIHRocm93IG5ldyBFcnJvcihgaWxsZWdhbCBzdGF0ZTogc2lnbmVkIGJ5IG11bHRpcGxlIHB1YmxpYyBrZXlzYCk7XG4gICAgfVxuICB9KTtcbn1cblxuLyoqXG4gKiBAZGVwcmVjYXRlZCB1c2Uge0BzZWUgdmVyaWZ5U2lnbmF0dXJlV2l0aFB1YmxpY0tleXN9IGluc3RlYWRcbiAqIEBwYXJhbSB0cmFuc2FjdGlvblxuICogQHBhcmFtIGlucHV0SW5kZXhcbiAqIEBwYXJhbSBhbW91bnRcbiAqIEBwYXJhbSB2ZXJpZmljYXRpb25TZXR0aW5ncyAtIGlmIHB1YmxpY0tleSBpcyBzcGVjaWZpZWQsIHJldHVybnMgdHJ1ZSBpZmYgYW55IHNpZ25hdHVyZSBpcyBzaWduZWQgYnkgcHVibGljS2V5LlxuICogQHBhcmFtIHByZXZPdXRwdXRzIC0gbXVzdCBiZSBzZXQgZm9yIHAydHIgdHJhbnNhY3Rpb25zXG4gKi9cbmV4cG9ydCBmdW5jdGlvbiB2ZXJpZnlTaWduYXR1cmUoXG4gIHRyYW5zYWN0aW9uOiBVdHhvVHJhbnNhY3Rpb24sXG4gIGlucHV0SW5kZXg6IG51bWJlcixcbiAgYW1vdW50OiBudW1iZXIsXG4gIHZlcmlmaWNhdGlvblNldHRpbmdzOiBWZXJpZmljYXRpb25TZXR0aW5ncyA9IHt9LFxuICBwcmV2T3V0cHV0cz86IFR4T3V0cHV0W11cbik6IGJvb2xlYW4ge1xuICBjb25zdCBzaWduYXR1cmVWZXJpZmljYXRpb25zID0gZ2V0U2lnbmF0dXJlVmVyaWZpY2F0aW9ucyhcbiAgICB0cmFuc2FjdGlvbixcbiAgICBpbnB1dEluZGV4LFxuICAgIGFtb3VudCxcbiAgICB2ZXJpZmljYXRpb25TZXR0aW5ncyxcbiAgICBwcmV2T3V0cHV0c1xuICApLmZpbHRlcihcbiAgICAodikgPT5cbiAgICAgIC8vIElmIG5vIHB1YmxpY0tleSBpcyBzZXQgaW4gdmVyaWZpY2F0aW9uU2V0dGluZ3MsIGFsbCBzaWduYXR1cmVzIG11c3QgYmUgdmFsaWQuXG4gICAgICAvLyBPdGhlcndpc2UsIGEgc2luZ2xlIHZhbGlkIHNpZ25hdHVyZSBieSB0aGUgc3BlY2lmaWVkIHB1YmtleSBpcyBzdWZmaWNpZW50LlxuICAgICAgdmVyaWZpY2F0aW9uU2V0dGluZ3MucHVibGljS2V5ID09PSB1bmRlZmluZWQgfHxcbiAgICAgICh2LnNpZ25lZEJ5ICE9PSB1bmRlZmluZWQgJiZcbiAgICAgICAgKHZlcmlmaWNhdGlvblNldHRpbmdzLnB1YmxpY0tleS5lcXVhbHModi5zaWduZWRCeSkgfHxcbiAgICAgICAgICB2ZXJpZmljYXRpb25TZXR0aW5ncy5wdWJsaWNLZXkuc2xpY2UoMSkuZXF1YWxzKHYuc2lnbmVkQnkpKSlcbiAgKTtcblxuICByZXR1cm4gc2lnbmF0dXJlVmVyaWZpY2F0aW9ucy5sZW5ndGggPiAwICYmIHNpZ25hdHVyZVZlcmlmaWNhdGlvbnMuZXZlcnkoKHYpID0+IHYuc2lnbmVkQnkgIT09IHVuZGVmaW5lZCk7XG59XG5cbi8qKlxuICogQHBhcmFtIHZcbiAqIEBwYXJhbSBwdWJsaWNLZXlcbiAqIEByZXR1cm4gdHJ1ZSBpZmYgc2lnbmF0dXJlIGlzIGJ5IHB1YmxpY0tleSAob3IgeG9ubHkgdmFyaWFudCBvZiBwdWJsaWNLZXkpXG4gKi9cbmZ1bmN0aW9uIGlzU2lnbmF0dXJlQnlQdWJsaWNLZXkodjogU2lnbmF0dXJlVmVyaWZpY2F0aW9uLCBwdWJsaWNLZXk6IEJ1ZmZlcik6IGJvb2xlYW4ge1xuICByZXR1cm4gKFxuICAgICEhdi5zaWduZWRCeSAmJlxuICAgICh2LnNpZ25lZEJ5LmVxdWFscyhwdWJsaWNLZXkpIHx8XG4gICAgICAvKiBmb3IgcDJ0ciBzaWduYXR1cmVzLCB3ZSBwYXNzIHRoZSBwdWJrZXkgaW4gMzMtYnl0ZSBmb3JtYXQgcmVjb3ZlciBpdCBmcm9tIHRoZSBzaWduYXR1cmUgaW4gMzItYnl0ZSBmb3JtYXQgKi9cbiAgICAgIChwdWJsaWNLZXkubGVuZ3RoID09PSAzMyAmJiBpc1NpZ25hdHVyZUJ5UHVibGljS2V5KHYsIHB1YmxpY0tleS5zbGljZSgxKSkpKVxuICApO1xufVxuXG4vKipcbiAqIEBwYXJhbSB0cmFuc2FjdGlvblxuICogQHBhcmFtIGlucHV0SW5kZXhcbiAqIEBwYXJhbSBwcmV2T3V0cHV0cyAtIHRyYW5zYWN0aW9uIG91dHB1dHMgZm9yIGlucHV0c1xuICogQHBhcmFtIHB1YmxpY0tleXMgLSBwdWJsaWMga2V5cyB0byBjaGVjayBzaWduYXR1cmVzIGZvclxuICogQHJldHVybiBhcnJheSBvZiBib29sZWFucyBpbmRpY2F0aW5nIGEgdmFsaWQgc2lnbmF0dXJlIGZvciBldmVyeSBwdWJrZXkgaW4gX3B1YmxpY0tleXNfXG4gKi9cbmV4cG9ydCBmdW5jdGlvbiB2ZXJpZnlTaWduYXR1cmVXaXRoUHVibGljS2V5cyhcbiAgdHJhbnNhY3Rpb246IFV0eG9UcmFuc2FjdGlvbixcbiAgaW5wdXRJbmRleDogbnVtYmVyLFxuICBwcmV2T3V0cHV0czogVHhPdXRwdXRbXSxcbiAgcHVibGljS2V5czogQnVmZmVyW11cbik6IGJvb2xlYW5bXSB7XG4gIGlmICh0cmFuc2FjdGlvbi5pbnMubGVuZ3RoICE9PSBwcmV2T3V0cHV0cy5sZW5ndGgpIHtcbiAgICB0aHJvdyBuZXcgRXJyb3IoYGlucHV0IGxlbmd0aCBtdXN0IG1hdGNoIHByZXZPdXRwdXRzIGxlbmd0aGApO1xuICB9XG5cbiAgY29uc3Qgc2lnbmF0dXJlVmVyaWZpY2F0aW9ucyA9IGdldFNpZ25hdHVyZVZlcmlmaWNhdGlvbnMoXG4gICAgdHJhbnNhY3Rpb24sXG4gICAgaW5wdXRJbmRleCxcbiAgICBwcmV2T3V0cHV0c1tpbnB1dEluZGV4XS52YWx1ZSxcbiAgICB7fSxcbiAgICBwcmV2T3V0cHV0c1xuICApO1xuXG4gIHJldHVybiBwdWJsaWNLZXlzLm1hcCgocHVibGljS2V5KSA9PiAhIXNpZ25hdHVyZVZlcmlmaWNhdGlvbnMuZmluZCgodikgPT4gaXNTaWduYXR1cmVCeVB1YmxpY0tleSh2LCBwdWJsaWNLZXkpKSk7XG59XG5cbi8qKlxuICogV3JhcHBlciBmb3Ige0BzZWUgdmVyaWZ5U2lnbmF0dXJlV2l0aFB1YmxpY0tleXN9IGZvciBzaW5nbGUgcHVia2V5XG4gKiBAcGFyYW0gdHJhbnNhY3Rpb25cbiAqIEBwYXJhbSBpbnB1dEluZGV4XG4gKiBAcGFyYW0gcHJldk91dHB1dHNcbiAqIEBwYXJhbSBwdWJsaWNLZXlcbiAqIEByZXR1cm4gdHJ1ZSBpZmYgc2lnbmF0dXJlIGlzIHZhbGlkXG4gKi9cbmV4cG9ydCBmdW5jdGlvbiB2ZXJpZnlTaWduYXR1cmVXaXRoUHVibGljS2V5KFxuICB0cmFuc2FjdGlvbjogVXR4b1RyYW5zYWN0aW9uLFxuICBpbnB1dEluZGV4OiBudW1iZXIsXG4gIHByZXZPdXRwdXRzOiBUeE91dHB1dFtdLFxuICBwdWJsaWNLZXk6IEJ1ZmZlclxuKTogYm9vbGVhbiB7XG4gIHJldHVybiB2ZXJpZnlTaWduYXR1cmVXaXRoUHVibGljS2V5cyh0cmFuc2FjdGlvbiwgaW5wdXRJbmRleCwgcHJldk91dHB1dHMsIFtwdWJsaWNLZXldKVswXTtcbn1cblxuZXhwb3J0IGZ1bmN0aW9uIHNpZ25JbnB1dFAyc2hQMnBrKHR4QnVpbGRlcjogVXR4b1RyYW5zYWN0aW9uQnVpbGRlciwgdmluOiBudW1iZXIsIGtleVBhaXI6IGJpcDMyLkJJUDMySW50ZXJmYWNlKTogdm9pZCB7XG4gIGNvbnN0IHByZXZPdXRTY3JpcHRUeXBlID0gJ3Ayc2gtcDJwayc7XG4gIGNvbnN0IHsgcmVkZWVtU2NyaXB0LCB3aXRuZXNzU2NyaXB0IH0gPSBjcmVhdGVPdXRwdXRTY3JpcHRQMnNoUDJwayhrZXlQYWlyLnB1YmxpY0tleSk7XG4gIGtleVBhaXIubmV0d29yayA9IHR4QnVpbGRlci5uZXR3b3JrO1xuXG4gIHR4QnVpbGRlci5zaWduKHtcbiAgICB2aW4sXG4gICAgcHJldk91dFNjcmlwdFR5cGUsXG4gICAga2V5UGFpcixcbiAgICBoYXNoVHlwZTogZ2V0RGVmYXVsdFNpZ0hhc2godHhCdWlsZGVyLm5ldHdvcmsgYXMgTmV0d29yayksXG4gICAgcmVkZWVtU2NyaXB0LFxuICAgIHdpdG5lc3NTY3JpcHQsXG4gICAgd2l0bmVzc1ZhbHVlOiB1bmRlZmluZWQsXG4gIH0pO1xufVxuXG5leHBvcnQgZnVuY3Rpb24gc2lnbklucHV0Mk9mMyhcbiAgdHhCdWlsZGVyOiBVdHhvVHJhbnNhY3Rpb25CdWlsZGVyLFxuICB2aW46IG51bWJlcixcbiAgc2NyaXB0VHlwZTogU2NyaXB0VHlwZTJPZjMsXG4gIHB1YmtleXM6IFRyaXBsZTxCdWZmZXI+LFxuICBrZXlQYWlyOiBiaXAzMi5CSVAzMkludGVyZmFjZSxcbiAgY29zaWduZXI6IEJ1ZmZlcixcbiAgYW1vdW50OiBudW1iZXJcbik6IHZvaWQge1xuICBsZXQgY29udHJvbEJsb2NrO1xuICBsZXQgcmVkZWVtU2NyaXB0O1xuICBsZXQgd2l0bmVzc1NjcmlwdDtcblxuICBjb25zdCBwcmV2T3V0U2NyaXB0VHlwZSA9IHNjcmlwdFR5cGUyT2YzQXNQcmV2T3V0VHlwZShzY3JpcHRUeXBlKTtcbiAgaWYgKHNjcmlwdFR5cGUgPT09ICdwMnRyJykge1xuICAgICh7IHdpdG5lc3NTY3JpcHQsIGNvbnRyb2xCbG9jayB9ID0gY3JlYXRlU3BlbmRTY3JpcHRQMnRyKHB1YmtleXMsIFtrZXlQYWlyLnB1YmxpY0tleSwgY29zaWduZXJdKSk7XG4gIH0gZWxzZSB7XG4gICAgKHsgcmVkZWVtU2NyaXB0LCB3aXRuZXNzU2NyaXB0IH0gPSBjcmVhdGVPdXRwdXRTY3JpcHQyb2YzKHB1YmtleXMsIHNjcmlwdFR5cGUpKTtcbiAgfVxuXG4gIGtleVBhaXIubmV0d29yayA9IHR4QnVpbGRlci5uZXR3b3JrO1xuXG4gIHR4QnVpbGRlci5zaWduKHtcbiAgICB2aW4sXG4gICAgcHJldk91dFNjcmlwdFR5cGUsXG4gICAga2V5UGFpcixcbiAgICBoYXNoVHlwZTogZ2V0RGVmYXVsdFNpZ0hhc2godHhCdWlsZGVyLm5ldHdvcmsgYXMgTmV0d29yaywgc2NyaXB0VHlwZSksXG4gICAgcmVkZWVtU2NyaXB0LFxuICAgIHdpdG5lc3NTY3JpcHQsXG4gICAgd2l0bmVzc1ZhbHVlOiBhbW91bnQsXG4gICAgY29udHJvbEJsb2NrLFxuICB9KTtcbn1cbiJdfQ==