/// <reference types="node" />
import * as bip32 from 'bip32';
import { TxInput, TxOutput } from 'bitcoinjs-lib';
import { UtxoTransaction } from './UtxoTransaction';
import { UtxoTransactionBuilder } from './UtxoTransactionBuilder';
import { ScriptType, ScriptType2Of3 } from './outputScripts';
import { Triple } from './types';
import { Network } from '../networks';
declare const inputTypes: readonly ["multisig", "nonstandard", "nulldata", "pubkey", "pubkeyhash", "scripthash", "witnesspubkeyhash", "witnessscripthash", "taproot", "taprootnofn", "witnesscommitment"];
declare type InputType = typeof inputTypes[number];
export declare function isPlaceholderSignature(v: number | Buffer): boolean;
export interface ParsedSignatureScript {
    scriptType: ScriptType | 'p2pkh' | undefined;
    isSegwitInput: boolean;
    inputClassification: InputType;
    p2shOutputClassification?: string;
}
export interface ParsedSignatureScriptUnknown extends ParsedSignatureScript {
    scriptType: undefined;
}
export interface ParsedSignatureScriptP2PK extends ParsedSignatureScript {
    scriptType: 'p2shP2pk';
    inputClassification: 'scripthash';
}
export interface ParsedSignatureScriptP2PKH extends ParsedSignatureScript {
    scriptType: 'p2pkh';
    inputClassification: 'pubkeyhash';
    signatures: [Buffer];
    publicKeys: [Buffer];
    pubScript?: Buffer;
}
export interface ParsedSignatureScript2Of3 extends ParsedSignatureScript {
    scriptType: 'p2sh' | 'p2shP2wsh' | 'p2wsh';
    inputClassification: 'scripthash' | 'witnessscripthash';
    publicKeys: [Buffer, Buffer, Buffer];
    signatures: [Buffer, Buffer] | [Buffer | 0, Buffer | 0, Buffer | 0];
    pubScript: Buffer;
}
export interface ParsedSignatureScriptTaproot extends ParsedSignatureScript {
    scriptType: 'p2tr';
    inputClassification: 'taproot';
    publicKeys: [Buffer] | [Buffer, Buffer];
    signatures: [Buffer] | [Buffer, Buffer];
    controlBlock: Buffer | undefined;
    scriptPathLevel: number | undefined;
    pubScript: Buffer;
}
export declare function getDefaultSigHash(network: Network, scriptType?: ScriptType2Of3): number;
/**
 * Parse a transaction's signature script to obtain public keys, signatures, the sig script,
 * and other properties.
 *
 * Only supports script types used in BitGo transactions.
 *
 * @param input
 * @returns ParsedSignatureScript
 */
export declare function parseSignatureScript(input: TxInput): ParsedSignatureScriptUnknown | ParsedSignatureScriptP2PK | ParsedSignatureScriptP2PKH | ParsedSignatureScript2Of3 | ParsedSignatureScriptTaproot;
export declare function parseSignatureScript2Of3(input: TxInput): ParsedSignatureScript2Of3 | ParsedSignatureScriptTaproot;
/**
 * Constraints for signature verifications.
 * Parameters are conjunctive: if multiple parameters are set, a verification for an individual
 * signature must satisfy all of them.
 */
export declare type VerificationSettings = {
    /**
     * The index of the signature to verify. Only iterates over non-empty signatures.
     */
    signatureIndex?: number;
    /**
     * The public key to verify.
     */
    publicKey?: Buffer;
};
/**
 * Result for a individual signature verification
 */
export declare type SignatureVerification = {
    /** Set to the public key that signed for the signature */
    signedBy: Buffer | undefined;
};
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
export declare function getSignatureVerifications(transaction: UtxoTransaction, inputIndex: number, amount: number, verificationSettings?: VerificationSettings, prevOutputs?: TxOutput[]): SignatureVerification[];
/**
 * @deprecated use {@see verifySignatureWithPublicKeys} instead
 * @param transaction
 * @param inputIndex
 * @param amount
 * @param verificationSettings - if publicKey is specified, returns true iff any signature is signed by publicKey.
 * @param prevOutputs - must be set for p2tr transactions
 */
export declare function verifySignature(transaction: UtxoTransaction, inputIndex: number, amount: number, verificationSettings?: VerificationSettings, prevOutputs?: TxOutput[]): boolean;
/**
 * @param transaction
 * @param inputIndex
 * @param prevOutputs - transaction outputs for inputs
 * @param publicKeys - public keys to check signatures for
 * @return array of booleans indicating a valid signature for every pubkey in _publicKeys_
 */
export declare function verifySignatureWithPublicKeys(transaction: UtxoTransaction, inputIndex: number, prevOutputs: TxOutput[], publicKeys: Buffer[]): boolean[];
/**
 * Wrapper for {@see verifySignatureWithPublicKeys} for single pubkey
 * @param transaction
 * @param inputIndex
 * @param prevOutputs
 * @param publicKey
 * @return true iff signature is valid
 */
export declare function verifySignatureWithPublicKey(transaction: UtxoTransaction, inputIndex: number, prevOutputs: TxOutput[], publicKey: Buffer): boolean;
export declare function signInputP2shP2pk(txBuilder: UtxoTransactionBuilder, vin: number, keyPair: bip32.BIP32Interface): void;
export declare function signInput2Of3(txBuilder: UtxoTransactionBuilder, vin: number, scriptType: ScriptType2Of3, pubkeys: Triple<Buffer>, keyPair: bip32.BIP32Interface, cosigner: Buffer, amount: number): void;
export {};
//# sourceMappingURL=signature.d.ts.map