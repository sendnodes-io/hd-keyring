import { TransactionRequest } from "@ethersproject/abstract-provider";
import { Transaction as PoktTransaction } from "./wallet";
import {
  TypedDataDomain,
  TypedDataField,
} from "@ethersproject/abstract-signer";
/**
 * The encryption used to produce a key-pair.
 */
export enum KeyType {
  SECP256K1 = "secp256k1",
  ED25519 = "ed25519",
}

/**
 * Which version of serialization to use
 */
export enum SerializedKeyringVersion {
  V1 = 1,
}

/**
 * BIP39 can derive child addresses, while a fixed keyring cannot.
 */
export enum KeyringType {
  BIP39 = "bip39",
  FIXED = "fixed",
}

export type SerializedKeyring = {
  version: SerializedKeyringVersion.V1;
  fingerprint: string;
  keyType: KeyType;
  keyringType: KeyringType;
};

export interface Keyring<T> {
  readonly keyringType: KeyringType;
  readonly keyType: KeyType;
  readonly path: string;
  readonly fingerprint: string;
  serializeSync(): T;
  serialize(): Promise<T>;
  getAddresses(): Promise<string[]>;
  getAddressesSync(): string[];
  addAddresses(n?: number): Promise<string[]>;
  addAddressesSync(n?: number): string[];
  getPrivateKey(address: string): string;
  signTransaction(
    address: string,
    transaction: TransactionRequest | PoktTransaction
  ): Promise<string>;
  signTypedData(
    address: string,
    domain: TypedDataDomain,
    types: Record<string, Array<TypedDataField>>,
    value: Record<string, unknown>
  ): Promise<string>;
  signMessage(address: string, message: string): Promise<string>;
}
