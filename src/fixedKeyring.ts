import { TransactionRequest } from "@ethersproject/abstract-provider";
import {
  TypedDataDomain,
  TypedDataField,
} from "@ethersproject/abstract-signer";

import { Wallet as WalletSECP256K1 } from "@ethersproject/wallet";

import { WalletED25519, Transaction as PoktTransaction } from "./wallet";
import { computeFingerprint } from "@sendnodes/hd-node";
import {
  Keyring,
  KeyringType,
  KeyType,
  SerializedKeyring,
  SerializedKeyringVersion,
} from "./types";

export type FixedKeyringOptions = {
  keyType: KeyType;
  privateKey: string;
};

const defaultOptions = {
  [KeyType.SECP256K1]: {
    keyType: KeyType.SECP256K1,
    walletClass: WalletSECP256K1,
  },
  [KeyType.ED25519]: {
    keyType: KeyType.ED25519,
    walletClass: WalletED25519,
  },
};

export type SeralizedFixedKeyring = SerializedKeyring & {
  privateKey: string;
  keyringType: KeyringType.FIXED;
};

export class FixedKeyring implements Keyring<SeralizedFixedKeyring> {
  readonly keyringType: KeyringType = KeyringType.FIXED;

  readonly keyType: KeyType;

  /** Fingerprint or unique identifier derived from the contents of the keyring */
  readonly fingerprint: string;

  path: string;

  #wallet: WalletSECP256K1 | WalletED25519;

  constructor(_options: FixedKeyringOptions) {
    const options = defaultOptions[_options.keyType];
    this.keyType = options.keyType;
    this.#wallet = new options.walletClass(_options.privateKey);
    if (!this.#wallet || this.#wallet.privateKey === null)
      throw new Error("Invalid FixedKeyring");

    this.fingerprint = computeFingerprint(this.#wallet.address);
    this.path = "";
  }
  addAddressesSync(_?: number): string[] {
    throw new Error("Unable to derive an address");
  }
  serializeSync(): SeralizedFixedKeyring {
    return {
      fingerprint: this.fingerprint,
      version: SerializedKeyringVersion.V1,
      keyringType: KeyringType.FIXED,
      keyType: this.keyType,
      privateKey: this.#wallet.privateKey,
    };
  }

  getAddressesSync(): string[] {
    // addresses are hex so save some stress and lower case always
    return [this.#wallet.address.toLowerCase()];
  }

  async serialize(): Promise<SeralizedFixedKeyring> {
    return new Promise((resolve) => resolve(this.serializeSync()));
  }
  async getAddresses(): Promise<string[]> {
    // addresses are hex so save some stress and lower case always
    return [this.#wallet.address.toLowerCase()];
  }
  addAddresses(_?: number): Promise<string[]> {
    throw new Error("Unable to derive an address");
  }
  getPrivateKey(address: string): string {
    this.#validateAddress(address);
    return this.#wallet.privateKey;
  }
  getPublicKey(address: string): string {
    this.#validateAddress(address);
    return this.#wallet.publicKey;
  }
  async signTransaction(
    address: string,
    transaction: TransactionRequest | PoktTransaction
  ): Promise<string> {
    this.#validateAddress(address);
    const wallet = this.#wallet;
    if (wallet instanceof WalletSECP256K1) {
      return wallet.signTransaction(transaction as TransactionRequest);
    }
    return wallet.signTransaction(transaction as PoktTransaction);
  }

  async signTransactionVerified(
    address: string,
    transaction: TransactionRequest | PoktTransaction
  ): Promise<boolean> {
    this.#validateAddress(address);
    const wallet = this.#wallet;
    if (!(wallet instanceof WalletED25519)) {
      throw new Error("Only for testing Pokt Wallet");
    }
    return wallet.signTransactionVerified(transaction as PoktTransaction);
  }

  signTypedData(
    address: string,
    domain: TypedDataDomain,
    types: Record<string, TypedDataField[]>,
    value: Record<string, unknown>
  ): Promise<string> {
    this.#validateAddress(address);
    const wallet = this.#wallet;
    if (wallet instanceof WalletSECP256K1) {
      return wallet._signTypedData(domain, types, value);
    }
    throw new Error("Unsupported Method");
  }
  signMessage(address: string, message: string): Promise<string> {
    this.#validateAddress(address);
    const wallet = this.#wallet;
    return wallet.signMessage(message);
  }

  static deserialize(obj: SeralizedFixedKeyring): FixedKeyring {
    const { version, keyringType, keyType } = obj;
    if (version !== 1) {
      throw new Error(`Unknown serialization version ${obj.version}`);
    }

    if (keyringType !== KeyringType.FIXED) {
      throw new Error(
        "Only support fixed keyrings containing a single private key"
      );
    }

    const { privateKey } = obj;
    const keyring = new FixedKeyring({
      privateKey,
      keyType,
    });

    return keyring;
  }

  #validateAddress(address: string) {
    // addresses are hex so save some stress and lower case always
    if (this.#wallet.address.toLowerCase() !== address.toLowerCase())
      throw new Error("Invalid address: " + address.toLowerCase());
  }
}
