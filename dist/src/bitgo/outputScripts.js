"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.createSpendScriptP2tr = exports.createPaymentP2tr = exports.createOutputScript2of3 = exports.createOutputScriptP2shP2pk = exports.scriptType2Of3AsPrevOutType = exports.isSupportedScriptType = exports.isScriptType2Of3 = exports.scriptTypes2Of3 = exports.scriptTypeP2shP2pk = exports.scriptTypeForChain = void 0;
const assert = require("assert");
const bitcoinjs = require("bitcoinjs-lib");
const __1 = require("..");
const types_1 = require("./types");
var chains_1 = require("./wallet/chains");
Object.defineProperty(exports, "scriptTypeForChain", { enumerable: true, get: function () { return chains_1.scriptTypeForChain; } });
exports.scriptTypeP2shP2pk = 'p2shP2pk';
exports.scriptTypes2Of3 = ['p2sh', 'p2shP2wsh', 'p2wsh', 'p2tr'];
function isScriptType2Of3(t) {
    return exports.scriptTypes2Of3.includes(t);
}
exports.isScriptType2Of3 = isScriptType2Of3;
/**
 * @param network
 * @param scriptType
 * @return true iff script type is supported for network
 */
function isSupportedScriptType(network, scriptType) {
    switch (scriptType) {
        case 'p2sh':
        case 'p2shP2pk':
            return true;
        case 'p2shP2wsh':
        case 'p2wsh':
            return __1.supportsSegwit(network);
        case 'p2tr':
            return __1.supportsTaproot(network);
    }
    /* istanbul ignore next */
    throw new Error(`unexpected script type ${scriptType}`);
}
exports.isSupportedScriptType = isSupportedScriptType;
/**
 * @param t
 * @return string prevOut as defined in PREVOUT_TYPES (bitcoinjs-lib/.../transaction_builder.js)
 */
function scriptType2Of3AsPrevOutType(t) {
    switch (t) {
        case 'p2sh':
            return 'p2sh-p2ms';
        case 'p2shP2wsh':
            return 'p2sh-p2wsh-p2ms';
        case 'p2wsh':
            return 'p2wsh-p2ms';
        case 'p2tr':
            return 'p2tr-p2ns';
    }
    /* istanbul ignore next */
    throw new Error(`unsupported script type ${t}`);
}
exports.scriptType2Of3AsPrevOutType = scriptType2Of3AsPrevOutType;
/**
 * Return scripts for p2sh-p2pk (used for BCH/BSV replay protection)
 * @param pubkey
 */
function createOutputScriptP2shP2pk(pubkey) {
    const p2pk = bitcoinjs.payments.p2pk({ pubkey });
    const p2sh = bitcoinjs.payments.p2sh({ redeem: p2pk });
    if (!p2sh.output || !p2pk.output) {
        throw new Error(`invalid state`);
    }
    return {
        scriptPubKey: p2sh.output,
        redeemScript: p2pk.output,
    };
}
exports.createOutputScriptP2shP2pk = createOutputScriptP2shP2pk;
/**
 * Return scripts for 2-of-3 multisig output
 * @param pubkeys - the key triple for multisig
 * @param scriptType
 * @param network - if set, performs sanity check for scriptType support
 * @returns {{redeemScript, witnessScript, scriptPubKey}}
 */
function createOutputScript2of3(pubkeys, scriptType, network) {
    if (network) {
        if (!isSupportedScriptType(network, scriptType)) {
            throw new Error(`unsupported script type ${scriptType} for network`);
        }
    }
    if (!types_1.isTriple(pubkeys)) {
        throw new Error(`must provide pubkey triple`);
    }
    pubkeys.forEach((key) => {
        if (key.length !== 33) {
            throw new Error(`Unexpected key length ${key.length}. Must use compressed keys.`);
        }
    });
    if (scriptType === 'p2tr') {
        // p2tr addresses use a combination of 2 of 2 multisig scripts distinct from
        // the 2 of 3 multisig used for other script types
        return createTaprootScript2of3(pubkeys);
    }
    const script2of3 = bitcoinjs.payments.p2ms({ m: 2, pubkeys });
    assert(script2of3.output);
    let scriptPubKey;
    let redeemScript;
    let witnessScript;
    switch (scriptType) {
        case 'p2sh':
            redeemScript = script2of3;
            scriptPubKey = bitcoinjs.payments.p2sh({ redeem: script2of3 });
            break;
        case 'p2shP2wsh':
            witnessScript = script2of3;
            redeemScript = bitcoinjs.payments.p2wsh({ redeem: script2of3 });
            scriptPubKey = bitcoinjs.payments.p2sh({ redeem: redeemScript });
            break;
        case 'p2wsh':
            witnessScript = script2of3;
            scriptPubKey = bitcoinjs.payments.p2wsh({ redeem: witnessScript });
            break;
        default:
            throw new Error(`unknown multisig script type ${scriptType}`);
    }
    assert(scriptPubKey);
    assert(scriptPubKey.output);
    return {
        scriptPubKey: scriptPubKey.output,
        redeemScript: redeemScript === null || redeemScript === void 0 ? void 0 : redeemScript.output,
        witnessScript: witnessScript === null || witnessScript === void 0 ? void 0 : witnessScript.output,
    };
}
exports.createOutputScript2of3 = createOutputScript2of3;
function toXOnlyPublicKey(b) {
    if (b.length === 33) {
        return b.slice(1);
    }
    if (b.length === 32) {
        return b;
    }
    throw new Error(`invalid key size ${b.length}`);
}
function getTaptreeKeyCombinations(keys) {
    const [userKey, backupKey, bitGoKey] = keys.map((k) => toXOnlyPublicKey(k));
    return [
        [userKey, bitGoKey],
        [userKey, backupKey],
        [backupKey, bitGoKey],
    ];
}
function createPaymentP2tr(pubkeys, redeemIndex) {
    const keyCombinations2of2 = getTaptreeKeyCombinations(pubkeys);
    const redeems = keyCombinations2of2.map((pubkeys, index) => bitcoinjs.payments.p2tr_ns({
        pubkeys,
        weight: index === 0 ? 2 : 1,
    }));
    return bitcoinjs.payments.p2tr({
        pubkeys: keyCombinations2of2[0],
        redeems,
        redeemIndex,
    });
}
exports.createPaymentP2tr = createPaymentP2tr;
function createSpendScriptP2tr(pubkeys, keyCombination) {
    const keyCombinations = getTaptreeKeyCombinations(pubkeys);
    const [a, b] = keyCombination.map((k) => toXOnlyPublicKey(k));
    const redeemIndex = keyCombinations.findIndex(([c, d]) => (a.equals(c) && b.equals(d)) || (a.equals(d) && b.equals(c)));
    if (redeemIndex < 0) {
        throw new Error(`could not find redeemIndex for key combination`);
    }
    const payment = createPaymentP2tr(pubkeys, redeemIndex);
    const { controlBlock } = payment;
    assert(Buffer.isBuffer(controlBlock));
    assert(payment.redeem);
    const output = payment.redeem.output;
    assert(Buffer.isBuffer(output));
    return {
        controlBlock,
        witnessScript: output,
    };
}
exports.createSpendScriptP2tr = createSpendScriptP2tr;
/**
 * Creates and returns a taproot output script using the user and bitgo keys for the aggregate
 * public key and a taptree containing a user+bitgo 2-of-2 script at the first depth level of the
 * tree and user+backup and bitgo+backup 2-of-2 scripts one level deeper.
 * @param pubkeys - a pubkey array containing the user key, backup key, and bitgo key in that order
 * @returns {{scriptPubKey}}
 */
function createTaprootScript2of3(pubkeys) {
    const { output } = createPaymentP2tr(pubkeys);
    assert(Buffer.isBuffer(output));
    return {
        scriptPubKey: output,
    };
}
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoib3V0cHV0U2NyaXB0cy5qcyIsInNvdXJjZVJvb3QiOiIiLCJzb3VyY2VzIjpbIi4uLy4uLy4uL3NyYy9iaXRnby9vdXRwdXRTY3JpcHRzLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7OztBQUFBLGlDQUFpQztBQUNqQywyQ0FBMkM7QUFFM0MsMEJBQThEO0FBRTlELG1DQUFrRDtBQUVsRCwwQ0FBcUQ7QUFBNUMsNEdBQUEsa0JBQWtCLE9BQUE7QUFFZCxRQUFBLGtCQUFrQixHQUFHLFVBQVUsQ0FBQztBQUdoQyxRQUFBLGVBQWUsR0FBRyxDQUFDLE1BQU0sRUFBRSxXQUFXLEVBQUUsT0FBTyxFQUFFLE1BQU0sQ0FBVSxDQUFDO0FBRy9FLFNBQWdCLGdCQUFnQixDQUFDLENBQVM7SUFDeEMsT0FBTyx1QkFBZSxDQUFDLFFBQVEsQ0FBQyxDQUFtQixDQUFDLENBQUM7QUFDdkQsQ0FBQztBQUZELDRDQUVDO0FBSUQ7Ozs7R0FJRztBQUNILFNBQWdCLHFCQUFxQixDQUFDLE9BQWdCLEVBQUUsVUFBc0I7SUFDNUUsUUFBUSxVQUFVLEVBQUU7UUFDbEIsS0FBSyxNQUFNLENBQUM7UUFDWixLQUFLLFVBQVU7WUFDYixPQUFPLElBQUksQ0FBQztRQUNkLEtBQUssV0FBVyxDQUFDO1FBQ2pCLEtBQUssT0FBTztZQUNWLE9BQU8sa0JBQWMsQ0FBQyxPQUFPLENBQUMsQ0FBQztRQUNqQyxLQUFLLE1BQU07WUFDVCxPQUFPLG1CQUFlLENBQUMsT0FBTyxDQUFDLENBQUM7S0FDbkM7SUFFRCwwQkFBMEI7SUFDMUIsTUFBTSxJQUFJLEtBQUssQ0FBQywwQkFBMEIsVUFBVSxFQUFFLENBQUMsQ0FBQztBQUMxRCxDQUFDO0FBZEQsc0RBY0M7QUFFRDs7O0dBR0c7QUFDSCxTQUFnQiwyQkFBMkIsQ0FBQyxDQUFpQjtJQUMzRCxRQUFRLENBQUMsRUFBRTtRQUNULEtBQUssTUFBTTtZQUNULE9BQU8sV0FBVyxDQUFDO1FBQ3JCLEtBQUssV0FBVztZQUNkLE9BQU8saUJBQWlCLENBQUM7UUFDM0IsS0FBSyxPQUFPO1lBQ1YsT0FBTyxZQUFZLENBQUM7UUFDdEIsS0FBSyxNQUFNO1lBQ1QsT0FBTyxXQUFXLENBQUM7S0FDdEI7SUFFRCwwQkFBMEI7SUFDMUIsTUFBTSxJQUFJLEtBQUssQ0FBQywyQkFBMkIsQ0FBQyxFQUFFLENBQUMsQ0FBQztBQUNsRCxDQUFDO0FBZEQsa0VBY0M7QUFlRDs7O0dBR0c7QUFDSCxTQUFnQiwwQkFBMEIsQ0FBQyxNQUFjO0lBQ3ZELE1BQU0sSUFBSSxHQUFHLFNBQVMsQ0FBQyxRQUFRLENBQUMsSUFBSSxDQUFDLEVBQUUsTUFBTSxFQUFFLENBQUMsQ0FBQztJQUNqRCxNQUFNLElBQUksR0FBRyxTQUFTLENBQUMsUUFBUSxDQUFDLElBQUksQ0FBQyxFQUFFLE1BQU0sRUFBRSxJQUFJLEVBQUUsQ0FBQyxDQUFDO0lBQ3ZELElBQUksQ0FBQyxJQUFJLENBQUMsTUFBTSxJQUFJLENBQUMsSUFBSSxDQUFDLE1BQU0sRUFBRTtRQUNoQyxNQUFNLElBQUksS0FBSyxDQUFDLGVBQWUsQ0FBQyxDQUFDO0tBQ2xDO0lBQ0QsT0FBTztRQUNMLFlBQVksRUFBRSxJQUFJLENBQUMsTUFBTTtRQUN6QixZQUFZLEVBQUUsSUFBSSxDQUFDLE1BQU07S0FDMUIsQ0FBQztBQUNKLENBQUM7QUFWRCxnRUFVQztBQUVEOzs7Ozs7R0FNRztBQUNILFNBQWdCLHNCQUFzQixDQUNwQyxPQUFpQixFQUNqQixVQUEwQixFQUMxQixPQUFpQjtJQUVqQixJQUFJLE9BQU8sRUFBRTtRQUNYLElBQUksQ0FBQyxxQkFBcUIsQ0FBQyxPQUFPLEVBQUUsVUFBVSxDQUFDLEVBQUU7WUFDL0MsTUFBTSxJQUFJLEtBQUssQ0FBQywyQkFBMkIsVUFBVSxjQUFjLENBQUMsQ0FBQztTQUN0RTtLQUNGO0lBRUQsSUFBSSxDQUFDLGdCQUFRLENBQUMsT0FBTyxDQUFDLEVBQUU7UUFDdEIsTUFBTSxJQUFJLEtBQUssQ0FBQyw0QkFBNEIsQ0FBQyxDQUFDO0tBQy9DO0lBRUQsT0FBTyxDQUFDLE9BQU8sQ0FBQyxDQUFDLEdBQUcsRUFBRSxFQUFFO1FBQ3RCLElBQUksR0FBRyxDQUFDLE1BQU0sS0FBSyxFQUFFLEVBQUU7WUFDckIsTUFBTSxJQUFJLEtBQUssQ0FBQyx5QkFBeUIsR0FBRyxDQUFDLE1BQU0sNkJBQTZCLENBQUMsQ0FBQztTQUNuRjtJQUNILENBQUMsQ0FBQyxDQUFDO0lBRUgsSUFBSSxVQUFVLEtBQUssTUFBTSxFQUFFO1FBQ3pCLDRFQUE0RTtRQUM1RSxrREFBa0Q7UUFDbEQsT0FBTyx1QkFBdUIsQ0FBQyxPQUFPLENBQUMsQ0FBQztLQUN6QztJQUVELE1BQU0sVUFBVSxHQUFHLFNBQVMsQ0FBQyxRQUFRLENBQUMsSUFBSSxDQUFDLEVBQUUsQ0FBQyxFQUFFLENBQUMsRUFBRSxPQUFPLEVBQUUsQ0FBQyxDQUFDO0lBQzlELE1BQU0sQ0FBQyxVQUFVLENBQUMsTUFBTSxDQUFDLENBQUM7SUFFMUIsSUFBSSxZQUErQixDQUFDO0lBQ3BDLElBQUksWUFBMkMsQ0FBQztJQUNoRCxJQUFJLGFBQTRDLENBQUM7SUFDakQsUUFBUSxVQUFVLEVBQUU7UUFDbEIsS0FBSyxNQUFNO1lBQ1QsWUFBWSxHQUFHLFVBQVUsQ0FBQztZQUMxQixZQUFZLEdBQUcsU0FBUyxDQUFDLFFBQVEsQ0FBQyxJQUFJLENBQUMsRUFBRSxNQUFNLEVBQUUsVUFBVSxFQUFFLENBQUMsQ0FBQztZQUMvRCxNQUFNO1FBQ1IsS0FBSyxXQUFXO1lBQ2QsYUFBYSxHQUFHLFVBQVUsQ0FBQztZQUMzQixZQUFZLEdBQUcsU0FBUyxDQUFDLFFBQVEsQ0FBQyxLQUFLLENBQUMsRUFBRSxNQUFNLEVBQUUsVUFBVSxFQUFFLENBQUMsQ0FBQztZQUNoRSxZQUFZLEdBQUcsU0FBUyxDQUFDLFFBQVEsQ0FBQyxJQUFJLENBQUMsRUFBRSxNQUFNLEVBQUUsWUFBWSxFQUFFLENBQUMsQ0FBQztZQUNqRSxNQUFNO1FBQ1IsS0FBSyxPQUFPO1lBQ1YsYUFBYSxHQUFHLFVBQVUsQ0FBQztZQUMzQixZQUFZLEdBQUcsU0FBUyxDQUFDLFFBQVEsQ0FBQyxLQUFLLENBQUMsRUFBRSxNQUFNLEVBQUUsYUFBYSxFQUFFLENBQUMsQ0FBQztZQUNuRSxNQUFNO1FBQ1I7WUFDRSxNQUFNLElBQUksS0FBSyxDQUFDLGdDQUFnQyxVQUFVLEVBQUUsQ0FBQyxDQUFDO0tBQ2pFO0lBRUQsTUFBTSxDQUFDLFlBQVksQ0FBQyxDQUFDO0lBQ3JCLE1BQU0sQ0FBQyxZQUFZLENBQUMsTUFBTSxDQUFDLENBQUM7SUFFNUIsT0FBTztRQUNMLFlBQVksRUFBRSxZQUFZLENBQUMsTUFBTTtRQUNqQyxZQUFZLEVBQUUsWUFBWSxhQUFaLFlBQVksdUJBQVosWUFBWSxDQUFFLE1BQU07UUFDbEMsYUFBYSxFQUFFLGFBQWEsYUFBYixhQUFhLHVCQUFiLGFBQWEsQ0FBRSxNQUFNO0tBQ3JDLENBQUM7QUFDSixDQUFDO0FBM0RELHdEQTJEQztBQUVELFNBQVMsZ0JBQWdCLENBQUMsQ0FBUztJQUNqQyxJQUFJLENBQUMsQ0FBQyxNQUFNLEtBQUssRUFBRSxFQUFFO1FBQ25CLE9BQU8sQ0FBQyxDQUFDLEtBQUssQ0FBQyxDQUFDLENBQUMsQ0FBQztLQUNuQjtJQUNELElBQUksQ0FBQyxDQUFDLE1BQU0sS0FBSyxFQUFFLEVBQUU7UUFDbkIsT0FBTyxDQUFDLENBQUM7S0FDVjtJQUNELE1BQU0sSUFBSSxLQUFLLENBQUMsb0JBQW9CLENBQUMsQ0FBQyxNQUFNLEVBQUUsQ0FBQyxDQUFDO0FBQ2xELENBQUM7QUFFRCxTQUFTLHlCQUF5QixDQUFDLElBQW9CO0lBQ3JELE1BQU0sQ0FBQyxPQUFPLEVBQUUsU0FBUyxFQUFFLFFBQVEsQ0FBQyxHQUFHLElBQUksQ0FBQyxHQUFHLENBQUMsQ0FBQyxDQUFDLEVBQUUsRUFBRSxDQUFDLGdCQUFnQixDQUFDLENBQUMsQ0FBQyxDQUFDLENBQUM7SUFDNUUsT0FBTztRQUNMLENBQUMsT0FBTyxFQUFFLFFBQVEsQ0FBQztRQUNuQixDQUFDLE9BQU8sRUFBRSxTQUFTLENBQUM7UUFDcEIsQ0FBQyxTQUFTLEVBQUUsUUFBUSxDQUFDO0tBQ3RCLENBQUM7QUFDSixDQUFDO0FBRUQsU0FBZ0IsaUJBQWlCLENBQUMsT0FBdUIsRUFBRSxXQUFvQjtJQUM3RSxNQUFNLG1CQUFtQixHQUFHLHlCQUF5QixDQUFDLE9BQU8sQ0FBQyxDQUFDO0lBQy9ELE1BQU0sT0FBTyxHQUFHLG1CQUFtQixDQUFDLEdBQUcsQ0FBQyxDQUFDLE9BQU8sRUFBRSxLQUFLLEVBQUUsRUFBRSxDQUN6RCxTQUFTLENBQUMsUUFBUSxDQUFDLE9BQU8sQ0FBQztRQUN6QixPQUFPO1FBQ1AsTUFBTSxFQUFFLEtBQUssS0FBSyxDQUFDLENBQUMsQ0FBQyxDQUFDLENBQUMsQ0FBQyxDQUFDLENBQUMsQ0FBQztLQUM1QixDQUFDLENBQ0gsQ0FBQztJQUVGLE9BQU8sU0FBUyxDQUFDLFFBQVEsQ0FBQyxJQUFJLENBQUM7UUFDN0IsT0FBTyxFQUFFLG1CQUFtQixDQUFDLENBQUMsQ0FBQztRQUMvQixPQUFPO1FBQ1AsV0FBVztLQUNaLENBQUMsQ0FBQztBQUNMLENBQUM7QUFkRCw4Q0FjQztBQUVELFNBQWdCLHFCQUFxQixDQUFDLE9BQXVCLEVBQUUsY0FBNkI7SUFDMUYsTUFBTSxlQUFlLEdBQUcseUJBQXlCLENBQUMsT0FBTyxDQUFDLENBQUM7SUFDM0QsTUFBTSxDQUFDLENBQUMsRUFBRSxDQUFDLENBQUMsR0FBRyxjQUFjLENBQUMsR0FBRyxDQUFDLENBQUMsQ0FBQyxFQUFFLEVBQUUsQ0FBQyxnQkFBZ0IsQ0FBQyxDQUFDLENBQUMsQ0FBQyxDQUFDO0lBQzlELE1BQU0sV0FBVyxHQUFHLGVBQWUsQ0FBQyxTQUFTLENBQzNDLENBQUMsQ0FBQyxDQUFDLEVBQUUsQ0FBQyxDQUFDLEVBQUUsRUFBRSxDQUFDLENBQUMsQ0FBQyxDQUFDLE1BQU0sQ0FBQyxDQUFDLENBQUMsSUFBSSxDQUFDLENBQUMsTUFBTSxDQUFDLENBQUMsQ0FBQyxDQUFDLElBQUksQ0FBQyxDQUFDLENBQUMsTUFBTSxDQUFDLENBQUMsQ0FBQyxJQUFJLENBQUMsQ0FBQyxNQUFNLENBQUMsQ0FBQyxDQUFDLENBQUMsQ0FDekUsQ0FBQztJQUVGLElBQUksV0FBVyxHQUFHLENBQUMsRUFBRTtRQUNuQixNQUFNLElBQUksS0FBSyxDQUFDLGdEQUFnRCxDQUFDLENBQUM7S0FDbkU7SUFFRCxNQUFNLE9BQU8sR0FBRyxpQkFBaUIsQ0FBQyxPQUFPLEVBQUUsV0FBVyxDQUFDLENBQUM7SUFDeEQsTUFBTSxFQUFFLFlBQVksRUFBRSxHQUFHLE9BQU8sQ0FBQztJQUNqQyxNQUFNLENBQUMsTUFBTSxDQUFDLFFBQVEsQ0FBQyxZQUFZLENBQUMsQ0FBQyxDQUFDO0lBRXRDLE1BQU0sQ0FBQyxPQUFPLENBQUMsTUFBTSxDQUFDLENBQUM7SUFDdkIsTUFBTSxNQUFNLEdBQUcsT0FBTyxDQUFDLE1BQU0sQ0FBQyxNQUFNLENBQUM7SUFDckMsTUFBTSxDQUFDLE1BQU0sQ0FBQyxRQUFRLENBQUMsTUFBTSxDQUFDLENBQUMsQ0FBQztJQUNoQyxPQUFPO1FBQ0wsWUFBWTtRQUNaLGFBQWEsRUFBRSxNQUFNO0tBQ3RCLENBQUM7QUFDSixDQUFDO0FBdEJELHNEQXNCQztBQUVEOzs7Ozs7R0FNRztBQUNILFNBQVMsdUJBQXVCLENBQUMsT0FBdUI7SUFDdEQsTUFBTSxFQUFFLE1BQU0sRUFBRSxHQUFHLGlCQUFpQixDQUFDLE9BQU8sQ0FBQyxDQUFDO0lBQzlDLE1BQU0sQ0FBQyxNQUFNLENBQUMsUUFBUSxDQUFDLE1BQU0sQ0FBQyxDQUFDLENBQUM7SUFDaEMsT0FBTztRQUNMLFlBQVksRUFBRSxNQUFNO0tBQ3JCLENBQUM7QUFDSixDQUFDIiwic291cmNlc0NvbnRlbnQiOlsiaW1wb3J0ICogYXMgYXNzZXJ0IGZyb20gJ2Fzc2VydCc7XG5pbXBvcnQgKiBhcyBiaXRjb2luanMgZnJvbSAnYml0Y29pbmpzLWxpYic7XG5cbmltcG9ydCB7IE5ldHdvcmssIHN1cHBvcnRzU2Vnd2l0LCBzdXBwb3J0c1RhcHJvb3QgfSBmcm9tICcuLic7XG5cbmltcG9ydCB7IGlzVHJpcGxlLCBUcmlwbGUsIFR1cGxlIH0gZnJvbSAnLi90eXBlcyc7XG5cbmV4cG9ydCB7IHNjcmlwdFR5cGVGb3JDaGFpbiB9IGZyb20gJy4vd2FsbGV0L2NoYWlucyc7XG5cbmV4cG9ydCBjb25zdCBzY3JpcHRUeXBlUDJzaFAycGsgPSAncDJzaFAycGsnO1xuZXhwb3J0IHR5cGUgU2NyaXB0VHlwZVAyc2hQMnBrID0gdHlwZW9mIHNjcmlwdFR5cGVQMnNoUDJwaztcblxuZXhwb3J0IGNvbnN0IHNjcmlwdFR5cGVzMk9mMyA9IFsncDJzaCcsICdwMnNoUDJ3c2gnLCAncDJ3c2gnLCAncDJ0ciddIGFzIGNvbnN0O1xuZXhwb3J0IHR5cGUgU2NyaXB0VHlwZTJPZjMgPSB0eXBlb2Ygc2NyaXB0VHlwZXMyT2YzW251bWJlcl07XG5cbmV4cG9ydCBmdW5jdGlvbiBpc1NjcmlwdFR5cGUyT2YzKHQ6IHN0cmluZyk6IHQgaXMgU2NyaXB0VHlwZTJPZjMge1xuICByZXR1cm4gc2NyaXB0VHlwZXMyT2YzLmluY2x1ZGVzKHQgYXMgU2NyaXB0VHlwZTJPZjMpO1xufVxuXG5leHBvcnQgdHlwZSBTY3JpcHRUeXBlID0gU2NyaXB0VHlwZVAyc2hQMnBrIHwgU2NyaXB0VHlwZTJPZjM7XG5cbi8qKlxuICogQHBhcmFtIG5ldHdvcmtcbiAqIEBwYXJhbSBzY3JpcHRUeXBlXG4gKiBAcmV0dXJuIHRydWUgaWZmIHNjcmlwdCB0eXBlIGlzIHN1cHBvcnRlZCBmb3IgbmV0d29ya1xuICovXG5leHBvcnQgZnVuY3Rpb24gaXNTdXBwb3J0ZWRTY3JpcHRUeXBlKG5ldHdvcms6IE5ldHdvcmssIHNjcmlwdFR5cGU6IFNjcmlwdFR5cGUpOiBib29sZWFuIHtcbiAgc3dpdGNoIChzY3JpcHRUeXBlKSB7XG4gICAgY2FzZSAncDJzaCc6XG4gICAgY2FzZSAncDJzaFAycGsnOlxuICAgICAgcmV0dXJuIHRydWU7XG4gICAgY2FzZSAncDJzaFAyd3NoJzpcbiAgICBjYXNlICdwMndzaCc6XG4gICAgICByZXR1cm4gc3VwcG9ydHNTZWd3aXQobmV0d29yayk7XG4gICAgY2FzZSAncDJ0cic6XG4gICAgICByZXR1cm4gc3VwcG9ydHNUYXByb290KG5ldHdvcmspO1xuICB9XG5cbiAgLyogaXN0YW5idWwgaWdub3JlIG5leHQgKi9cbiAgdGhyb3cgbmV3IEVycm9yKGB1bmV4cGVjdGVkIHNjcmlwdCB0eXBlICR7c2NyaXB0VHlwZX1gKTtcbn1cblxuLyoqXG4gKiBAcGFyYW0gdFxuICogQHJldHVybiBzdHJpbmcgcHJldk91dCBhcyBkZWZpbmVkIGluIFBSRVZPVVRfVFlQRVMgKGJpdGNvaW5qcy1saWIvLi4uL3RyYW5zYWN0aW9uX2J1aWxkZXIuanMpXG4gKi9cbmV4cG9ydCBmdW5jdGlvbiBzY3JpcHRUeXBlMk9mM0FzUHJldk91dFR5cGUodDogU2NyaXB0VHlwZTJPZjMpOiBzdHJpbmcge1xuICBzd2l0Y2ggKHQpIHtcbiAgICBjYXNlICdwMnNoJzpcbiAgICAgIHJldHVybiAncDJzaC1wMm1zJztcbiAgICBjYXNlICdwMnNoUDJ3c2gnOlxuICAgICAgcmV0dXJuICdwMnNoLXAyd3NoLXAybXMnO1xuICAgIGNhc2UgJ3Ayd3NoJzpcbiAgICAgIHJldHVybiAncDJ3c2gtcDJtcyc7XG4gICAgY2FzZSAncDJ0cic6XG4gICAgICByZXR1cm4gJ3AydHItcDJucyc7XG4gIH1cblxuICAvKiBpc3RhbmJ1bCBpZ25vcmUgbmV4dCAqL1xuICB0aHJvdyBuZXcgRXJyb3IoYHVuc3VwcG9ydGVkIHNjcmlwdCB0eXBlICR7dH1gKTtcbn1cblxuZXhwb3J0IHR5cGUgU3BlbmRhYmxlU2NyaXB0ID0ge1xuICBzY3JpcHRQdWJLZXk6IEJ1ZmZlcjtcbiAgLyoqIEBkZXByZWNhdGVkIC0gdXNlIGNyZWF0ZVNwZW5kU2NyaXB0czJvZjMgKi9cbiAgcmVkZWVtU2NyaXB0PzogQnVmZmVyO1xuICAvKiogQGRlcHJlY2F0ZWQgLSB1c2UgY3JlYXRlU3BlbmRTY3JpcHQyb2YzICovXG4gIHdpdG5lc3NTY3JpcHQ/OiBCdWZmZXI7XG59O1xuXG5leHBvcnQgdHlwZSBTcGVuZFNjcmlwdFAydHIgPSB7XG4gIGNvbnRyb2xCbG9jazogQnVmZmVyO1xuICB3aXRuZXNzU2NyaXB0OiBCdWZmZXI7XG59O1xuXG4vKipcbiAqIFJldHVybiBzY3JpcHRzIGZvciBwMnNoLXAycGsgKHVzZWQgZm9yIEJDSC9CU1YgcmVwbGF5IHByb3RlY3Rpb24pXG4gKiBAcGFyYW0gcHVia2V5XG4gKi9cbmV4cG9ydCBmdW5jdGlvbiBjcmVhdGVPdXRwdXRTY3JpcHRQMnNoUDJwayhwdWJrZXk6IEJ1ZmZlcik6IFNwZW5kYWJsZVNjcmlwdCB7XG4gIGNvbnN0IHAycGsgPSBiaXRjb2luanMucGF5bWVudHMucDJwayh7IHB1YmtleSB9KTtcbiAgY29uc3QgcDJzaCA9IGJpdGNvaW5qcy5wYXltZW50cy5wMnNoKHsgcmVkZWVtOiBwMnBrIH0pO1xuICBpZiAoIXAyc2gub3V0cHV0IHx8ICFwMnBrLm91dHB1dCkge1xuICAgIHRocm93IG5ldyBFcnJvcihgaW52YWxpZCBzdGF0ZWApO1xuICB9XG4gIHJldHVybiB7XG4gICAgc2NyaXB0UHViS2V5OiBwMnNoLm91dHB1dCxcbiAgICByZWRlZW1TY3JpcHQ6IHAycGsub3V0cHV0LFxuICB9O1xufVxuXG4vKipcbiAqIFJldHVybiBzY3JpcHRzIGZvciAyLW9mLTMgbXVsdGlzaWcgb3V0cHV0XG4gKiBAcGFyYW0gcHVia2V5cyAtIHRoZSBrZXkgdHJpcGxlIGZvciBtdWx0aXNpZ1xuICogQHBhcmFtIHNjcmlwdFR5cGVcbiAqIEBwYXJhbSBuZXR3b3JrIC0gaWYgc2V0LCBwZXJmb3JtcyBzYW5pdHkgY2hlY2sgZm9yIHNjcmlwdFR5cGUgc3VwcG9ydFxuICogQHJldHVybnMge3tyZWRlZW1TY3JpcHQsIHdpdG5lc3NTY3JpcHQsIHNjcmlwdFB1YktleX19XG4gKi9cbmV4cG9ydCBmdW5jdGlvbiBjcmVhdGVPdXRwdXRTY3JpcHQyb2YzKFxuICBwdWJrZXlzOiBCdWZmZXJbXSxcbiAgc2NyaXB0VHlwZTogU2NyaXB0VHlwZTJPZjMsXG4gIG5ldHdvcms/OiBOZXR3b3JrXG4pOiBTcGVuZGFibGVTY3JpcHQge1xuICBpZiAobmV0d29yaykge1xuICAgIGlmICghaXNTdXBwb3J0ZWRTY3JpcHRUeXBlKG5ldHdvcmssIHNjcmlwdFR5cGUpKSB7XG4gICAgICB0aHJvdyBuZXcgRXJyb3IoYHVuc3VwcG9ydGVkIHNjcmlwdCB0eXBlICR7c2NyaXB0VHlwZX0gZm9yIG5ldHdvcmtgKTtcbiAgICB9XG4gIH1cblxuICBpZiAoIWlzVHJpcGxlKHB1YmtleXMpKSB7XG4gICAgdGhyb3cgbmV3IEVycm9yKGBtdXN0IHByb3ZpZGUgcHVia2V5IHRyaXBsZWApO1xuICB9XG5cbiAgcHVia2V5cy5mb3JFYWNoKChrZXkpID0+IHtcbiAgICBpZiAoa2V5Lmxlbmd0aCAhPT0gMzMpIHtcbiAgICAgIHRocm93IG5ldyBFcnJvcihgVW5leHBlY3RlZCBrZXkgbGVuZ3RoICR7a2V5Lmxlbmd0aH0uIE11c3QgdXNlIGNvbXByZXNzZWQga2V5cy5gKTtcbiAgICB9XG4gIH0pO1xuXG4gIGlmIChzY3JpcHRUeXBlID09PSAncDJ0cicpIHtcbiAgICAvLyBwMnRyIGFkZHJlc3NlcyB1c2UgYSBjb21iaW5hdGlvbiBvZiAyIG9mIDIgbXVsdGlzaWcgc2NyaXB0cyBkaXN0aW5jdCBmcm9tXG4gICAgLy8gdGhlIDIgb2YgMyBtdWx0aXNpZyB1c2VkIGZvciBvdGhlciBzY3JpcHQgdHlwZXNcbiAgICByZXR1cm4gY3JlYXRlVGFwcm9vdFNjcmlwdDJvZjMocHVia2V5cyk7XG4gIH1cblxuICBjb25zdCBzY3JpcHQyb2YzID0gYml0Y29pbmpzLnBheW1lbnRzLnAybXMoeyBtOiAyLCBwdWJrZXlzIH0pO1xuICBhc3NlcnQoc2NyaXB0Mm9mMy5vdXRwdXQpO1xuXG4gIGxldCBzY3JpcHRQdWJLZXk6IGJpdGNvaW5qcy5QYXltZW50O1xuICBsZXQgcmVkZWVtU2NyaXB0OiBiaXRjb2luanMuUGF5bWVudCB8IHVuZGVmaW5lZDtcbiAgbGV0IHdpdG5lc3NTY3JpcHQ6IGJpdGNvaW5qcy5QYXltZW50IHwgdW5kZWZpbmVkO1xuICBzd2l0Y2ggKHNjcmlwdFR5cGUpIHtcbiAgICBjYXNlICdwMnNoJzpcbiAgICAgIHJlZGVlbVNjcmlwdCA9IHNjcmlwdDJvZjM7XG4gICAgICBzY3JpcHRQdWJLZXkgPSBiaXRjb2luanMucGF5bWVudHMucDJzaCh7IHJlZGVlbTogc2NyaXB0Mm9mMyB9KTtcbiAgICAgIGJyZWFrO1xuICAgIGNhc2UgJ3Ayc2hQMndzaCc6XG4gICAgICB3aXRuZXNzU2NyaXB0ID0gc2NyaXB0Mm9mMztcbiAgICAgIHJlZGVlbVNjcmlwdCA9IGJpdGNvaW5qcy5wYXltZW50cy5wMndzaCh7IHJlZGVlbTogc2NyaXB0Mm9mMyB9KTtcbiAgICAgIHNjcmlwdFB1YktleSA9IGJpdGNvaW5qcy5wYXltZW50cy5wMnNoKHsgcmVkZWVtOiByZWRlZW1TY3JpcHQgfSk7XG4gICAgICBicmVhaztcbiAgICBjYXNlICdwMndzaCc6XG4gICAgICB3aXRuZXNzU2NyaXB0ID0gc2NyaXB0Mm9mMztcbiAgICAgIHNjcmlwdFB1YktleSA9IGJpdGNvaW5qcy5wYXltZW50cy5wMndzaCh7IHJlZGVlbTogd2l0bmVzc1NjcmlwdCB9KTtcbiAgICAgIGJyZWFrO1xuICAgIGRlZmF1bHQ6XG4gICAgICB0aHJvdyBuZXcgRXJyb3IoYHVua25vd24gbXVsdGlzaWcgc2NyaXB0IHR5cGUgJHtzY3JpcHRUeXBlfWApO1xuICB9XG5cbiAgYXNzZXJ0KHNjcmlwdFB1YktleSk7XG4gIGFzc2VydChzY3JpcHRQdWJLZXkub3V0cHV0KTtcblxuICByZXR1cm4ge1xuICAgIHNjcmlwdFB1YktleTogc2NyaXB0UHViS2V5Lm91dHB1dCxcbiAgICByZWRlZW1TY3JpcHQ6IHJlZGVlbVNjcmlwdD8ub3V0cHV0LFxuICAgIHdpdG5lc3NTY3JpcHQ6IHdpdG5lc3NTY3JpcHQ/Lm91dHB1dCxcbiAgfTtcbn1cblxuZnVuY3Rpb24gdG9YT25seVB1YmxpY0tleShiOiBCdWZmZXIpOiBCdWZmZXIge1xuICBpZiAoYi5sZW5ndGggPT09IDMzKSB7XG4gICAgcmV0dXJuIGIuc2xpY2UoMSk7XG4gIH1cbiAgaWYgKGIubGVuZ3RoID09PSAzMikge1xuICAgIHJldHVybiBiO1xuICB9XG4gIHRocm93IG5ldyBFcnJvcihgaW52YWxpZCBrZXkgc2l6ZSAke2IubGVuZ3RofWApO1xufVxuXG5mdW5jdGlvbiBnZXRUYXB0cmVlS2V5Q29tYmluYXRpb25zKGtleXM6IFRyaXBsZTxCdWZmZXI+KTogVHVwbGU8QnVmZmVyPltdIHtcbiAgY29uc3QgW3VzZXJLZXksIGJhY2t1cEtleSwgYml0R29LZXldID0ga2V5cy5tYXAoKGspID0+IHRvWE9ubHlQdWJsaWNLZXkoaykpO1xuICByZXR1cm4gW1xuICAgIFt1c2VyS2V5LCBiaXRHb0tleV0sXG4gICAgW3VzZXJLZXksIGJhY2t1cEtleV0sXG4gICAgW2JhY2t1cEtleSwgYml0R29LZXldLFxuICBdO1xufVxuXG5leHBvcnQgZnVuY3Rpb24gY3JlYXRlUGF5bWVudFAydHIocHVia2V5czogVHJpcGxlPEJ1ZmZlcj4sIHJlZGVlbUluZGV4PzogbnVtYmVyKTogYml0Y29pbmpzLlBheW1lbnQge1xuICBjb25zdCBrZXlDb21iaW5hdGlvbnMyb2YyID0gZ2V0VGFwdHJlZUtleUNvbWJpbmF0aW9ucyhwdWJrZXlzKTtcbiAgY29uc3QgcmVkZWVtcyA9IGtleUNvbWJpbmF0aW9uczJvZjIubWFwKChwdWJrZXlzLCBpbmRleCkgPT5cbiAgICBiaXRjb2luanMucGF5bWVudHMucDJ0cl9ucyh7XG4gICAgICBwdWJrZXlzLFxuICAgICAgd2VpZ2h0OiBpbmRleCA9PT0gMCA/IDIgOiAxLFxuICAgIH0pXG4gICk7XG5cbiAgcmV0dXJuIGJpdGNvaW5qcy5wYXltZW50cy5wMnRyKHtcbiAgICBwdWJrZXlzOiBrZXlDb21iaW5hdGlvbnMyb2YyWzBdLFxuICAgIHJlZGVlbXMsXG4gICAgcmVkZWVtSW5kZXgsXG4gIH0pO1xufVxuXG5leHBvcnQgZnVuY3Rpb24gY3JlYXRlU3BlbmRTY3JpcHRQMnRyKHB1YmtleXM6IFRyaXBsZTxCdWZmZXI+LCBrZXlDb21iaW5hdGlvbjogVHVwbGU8QnVmZmVyPik6IFNwZW5kU2NyaXB0UDJ0ciB7XG4gIGNvbnN0IGtleUNvbWJpbmF0aW9ucyA9IGdldFRhcHRyZWVLZXlDb21iaW5hdGlvbnMocHVia2V5cyk7XG4gIGNvbnN0IFthLCBiXSA9IGtleUNvbWJpbmF0aW9uLm1hcCgoaykgPT4gdG9YT25seVB1YmxpY0tleShrKSk7XG4gIGNvbnN0IHJlZGVlbUluZGV4ID0ga2V5Q29tYmluYXRpb25zLmZpbmRJbmRleChcbiAgICAoW2MsIGRdKSA9PiAoYS5lcXVhbHMoYykgJiYgYi5lcXVhbHMoZCkpIHx8IChhLmVxdWFscyhkKSAmJiBiLmVxdWFscyhjKSlcbiAgKTtcblxuICBpZiAocmVkZWVtSW5kZXggPCAwKSB7XG4gICAgdGhyb3cgbmV3IEVycm9yKGBjb3VsZCBub3QgZmluZCByZWRlZW1JbmRleCBmb3Iga2V5IGNvbWJpbmF0aW9uYCk7XG4gIH1cblxuICBjb25zdCBwYXltZW50ID0gY3JlYXRlUGF5bWVudFAydHIocHVia2V5cywgcmVkZWVtSW5kZXgpO1xuICBjb25zdCB7IGNvbnRyb2xCbG9jayB9ID0gcGF5bWVudDtcbiAgYXNzZXJ0KEJ1ZmZlci5pc0J1ZmZlcihjb250cm9sQmxvY2spKTtcblxuICBhc3NlcnQocGF5bWVudC5yZWRlZW0pO1xuICBjb25zdCBvdXRwdXQgPSBwYXltZW50LnJlZGVlbS5vdXRwdXQ7XG4gIGFzc2VydChCdWZmZXIuaXNCdWZmZXIob3V0cHV0KSk7XG4gIHJldHVybiB7XG4gICAgY29udHJvbEJsb2NrLFxuICAgIHdpdG5lc3NTY3JpcHQ6IG91dHB1dCxcbiAgfTtcbn1cblxuLyoqXG4gKiBDcmVhdGVzIGFuZCByZXR1cm5zIGEgdGFwcm9vdCBvdXRwdXQgc2NyaXB0IHVzaW5nIHRoZSB1c2VyIGFuZCBiaXRnbyBrZXlzIGZvciB0aGUgYWdncmVnYXRlXG4gKiBwdWJsaWMga2V5IGFuZCBhIHRhcHRyZWUgY29udGFpbmluZyBhIHVzZXIrYml0Z28gMi1vZi0yIHNjcmlwdCBhdCB0aGUgZmlyc3QgZGVwdGggbGV2ZWwgb2YgdGhlXG4gKiB0cmVlIGFuZCB1c2VyK2JhY2t1cCBhbmQgYml0Z28rYmFja3VwIDItb2YtMiBzY3JpcHRzIG9uZSBsZXZlbCBkZWVwZXIuXG4gKiBAcGFyYW0gcHVia2V5cyAtIGEgcHVia2V5IGFycmF5IGNvbnRhaW5pbmcgdGhlIHVzZXIga2V5LCBiYWNrdXAga2V5LCBhbmQgYml0Z28ga2V5IGluIHRoYXQgb3JkZXJcbiAqIEByZXR1cm5zIHt7c2NyaXB0UHViS2V5fX1cbiAqL1xuZnVuY3Rpb24gY3JlYXRlVGFwcm9vdFNjcmlwdDJvZjMocHVia2V5czogVHJpcGxlPEJ1ZmZlcj4pOiBTcGVuZGFibGVTY3JpcHQge1xuICBjb25zdCB7IG91dHB1dCB9ID0gY3JlYXRlUGF5bWVudFAydHIocHVia2V5cyk7XG4gIGFzc2VydChCdWZmZXIuaXNCdWZmZXIob3V0cHV0KSk7XG4gIHJldHVybiB7XG4gICAgc2NyaXB0UHViS2V5OiBvdXRwdXQsXG4gIH07XG59XG4iXX0=