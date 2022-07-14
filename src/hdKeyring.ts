import { TransactionRequest } from "@ethersproject/abstract-provider";
import {
  TypedDataDomain,
  TypedDataField,
} from "@ethersproject/abstract-signer";
import { HDNode as HDNodeED25519, defaultPath } from "@sendnodes/hd-node";
import { HDNode as HDNodeSECP256K1 } from "@ethersproject/hdnode";
import { Wallet as WalletSECP256K1 } from "@ethersproject/wallet";

import { generateMnemonic } from "bip39";

import { normalizeHexAddress, validateAndFormatMnemonic } from "./utils";

import { WalletED25519, Transaction as PoktTransaction } from "./wallet";
import {
  Keyring,
  KeyringType,
  KeyType,
  SerializedKeyring,
  SerializedKeyringVersion,
} from "./types";

/** Use default derivation path that MetaMask uses */
export const defaultPathEth = "m/44'/60'/0'/0";
/** Default path for POKT @see https://github.com/satoshilabs/slips/blob/master/slip-0044.md */
export const defaultPathPokt = defaultPath;

export type HDKeyringOptions = {
  keyType?: KeyType;
  strength?: number;
  path?: string;
  mnemonic?: string | null;
  passphrase?: string | null;
};

export const defaultHDKeyringOptions = {
  // default path is BIP-44, where depth 5 is the address index
  [KeyType.SECP256K1]: {
    keyType: KeyType.SECP256K1,
    path: defaultPathEth,
    strength: 256,
    mnemonic: null,
    passphrase: null,
  },
  [KeyType.ED25519]: {
    keyType: KeyType.ED25519,
    path: defaultPathPokt,
    strength: 256,
    mnemonic: null,
    passphrase: null,
  },
};

export type SerializedHDKeyring = SerializedKeyring & {
  mnemonic: string;
  path: string;
  addressIndex: number;
  keyringType: KeyringType.BIP39;
};

export class HDKeyring implements Keyring<SerializedHDKeyring> {
  readonly keyringType: KeyringType = KeyringType.BIP39;

  readonly keyType: KeyType;

  readonly path: string;

  readonly fingerprint: string;

  #hdNode: HDNodeED25519 | HDNodeSECP256K1;

  #addressIndex: number;

  #wallets: (WalletSECP256K1 | WalletED25519)[];

  #addressToWallet: { [address: string]: WalletSECP256K1 | WalletED25519 };

  #mnemonic: string;

  constructor(options: HDKeyringOptions = {}) {
    options = options ?? {};

    // determine keytype
    if (options.keyType) {
      // we have a keytype assume caller knows what they are doing
      if (!defaultHDKeyringOptions[options.keyType]) {
        throw new Error("Unknown keytype: " + options.keyType);
      }
      this.keyType = options.keyType;
    }

    // sniff the path for EVM
    else if (options.path === defaultPathEth) {
      this.keyType = KeyType.SECP256K1;
    }

    // sniff the path for EVM
    else if (options.path === defaultPathPokt) {
      this.keyType = KeyType.ED25519;
    }

    // all else fails, default to POKT
    else {
      console.warn(
        "Initialized without a known path or keytype, defaulting to " +
          KeyType.ED25519
      );
      this.keyType = KeyType.ED25519;
    }

    // based on the key type, initialize with the default keyring options
    const hdOptions: Required<HDKeyringOptions> = {
      ...defaultHDKeyringOptions[this.keyType],
      ...options,
    };

    const mnemonic = validateAndFormatMnemonic(
      hdOptions.mnemonic || generateMnemonic(hdOptions.strength)
    );

    if (!mnemonic) {
      throw new Error("Invalid mnemonic.");
    }

    this.#mnemonic = mnemonic;

    const passphrase = hdOptions.passphrase ?? "";

    this.path = hdOptions.path;
    this.#hdNode =
      this.keyType === KeyType.ED25519
        ? HDNodeED25519.fromMnemonic(mnemonic, passphrase, "en").derivePath(
            this.path
          )
        : HDNodeSECP256K1.fromMnemonic(mnemonic, passphrase, "en").derivePath(
            this.path
          );
    this.fingerprint = this.#hdNode.fingerprint;
    this.#addressIndex = 0;
    this.#wallets = [];
    this.#addressToWallet = {};
  }

  getPrivateKey(address: string): string {
    const w = this.#wallets.find((w) => {
      // hex is hex
      return w.address.toUpperCase() === address.toString().toUpperCase();
    });
    if (!w) {
      throw new Error("Address is not in keyring");
    }
    return w.privateKey;
  }

  serializeSync(): SerializedHDKeyring {
    return {
      version: SerializedKeyringVersion.V1,
      fingerprint: this.fingerprint,
      mnemonic: this.#mnemonic,
      keyringType: KeyringType.BIP39,
      keyType: this.keyType,
      path: this.path,
      addressIndex: this.#addressIndex,
    };
  }

  async serialize(): Promise<SerializedHDKeyring> {
    return this.serializeSync();
  }

  static deserialize(obj: SerializedHDKeyring, passphrase?: string): HDKeyring {
    const { version, keyringType, mnemonic, path, addressIndex, keyType } = obj;
    if (version !== 1) {
      throw new Error(`Unknown serialization version ${obj.version}`);
    }

    if (keyringType !== KeyringType.BIP39) {
      throw new Error("HDKeyring only supports BIP-39 style HD wallets.");
    }

    const keyring = new HDKeyring({
      mnemonic,
      path,
      passphrase,
      keyType,
    });

    keyring.addAddressesSync(addressIndex);

    return keyring;
  }

  private _getAddressWallet(address: string): WalletSECP256K1 | WalletED25519 {
    const normAddress = normalizeHexAddress(address);
    if (
      !this.#addressToWallet[normAddress] &&
      !this.#addressToWallet[address]
    ) {
      throw new Error("Address not found!");
    }
    let wallet: WalletSECP256K1 | WalletED25519 =
      this.#addressToWallet[normAddress];
    if (!wallet) {
      wallet = this.#addressToWallet[address];
    }
    return wallet;
  }

  async signTransaction(
    address: string,
    transaction: TransactionRequest | PoktTransaction
  ): Promise<string> {
    const wallet = this._getAddressWallet(address);
    if (wallet instanceof WalletSECP256K1) {
      return wallet.signTransaction(transaction as TransactionRequest);
    }
    return wallet.signTransaction(transaction as PoktTransaction);
  }

  async signTransactionVerified(
    address: string,
    transaction: TransactionRequest | PoktTransaction
  ): Promise<boolean> {
    const wallet = this._getAddressWallet(address);
    if (!(wallet instanceof WalletED25519)) {
      throw new Error("Only for testing Pokt Wallet");
    }
    return wallet.signTransactionVerified(transaction as PoktTransaction);
  }

  async signTypedData(
    address: string,
    domain: TypedDataDomain,
    types: Record<string, Array<TypedDataField>>,
    value: Record<string, unknown>
  ): Promise<string> {
    const wallet = this._getAddressWallet(address);
    if (wallet instanceof WalletSECP256K1) {
      return wallet._signTypedData(domain, types, value);
    }
    throw new Error("Unsupported Method");
  }

  async signMessage(address: string, message: string): Promise<string> {
    const wallet = this._getAddressWallet(address);
    if (wallet instanceof WalletSECP256K1) {
      return wallet.signMessage(message);
    }
    throw new Error("Unsupported Method");
  }

  addAddressesSync(numNewAccounts = 1): string[] {
    const numAddresses = this.#addressIndex;

    if (numNewAccounts < 0 || numAddresses + numNewAccounts > 2 ** 31 - 1) {
      throw new Error("New account index out of range");
    }

    for (let i = 0; i < numNewAccounts; i += 1) {
      this.#deriveChildWallet(i + numAddresses);
    }

    this.#addressIndex += numNewAccounts;
    const addresses = this.getAddressesSync();
    return addresses.slice(-numNewAccounts);
  }

  async addAddresses(numNewAccounts = 1): Promise<string[]> {
    return this.addAddressesSync(numNewAccounts);
  }

  #deriveChildWallet(index: number): void {
    const newPath = `${index}`;
    // console.log("deriveChildWallet", newPath);
    const childNode = this.#hdNode.derivePath(newPath);
    if (this.keyType === KeyType.SECP256K1) {
      const wallet = new WalletSECP256K1(childNode.privateKey);
      this.#wallets.push(wallet);
      const address = normalizeHexAddress(wallet.address);
      this.#addressToWallet[address] = wallet;
    }
    if (this.keyType === KeyType.ED25519) {
      const wallet = new WalletED25519(childNode.privateKey);
      this.#wallets.push(wallet);
      this.#addressToWallet[wallet.address] = wallet;
    }
  }

  getAddressesSync(): string[] {
    return this.#wallets.map((w) => {
      // console.log("wallet", w);
      if (w instanceof WalletSECP256K1) {
        return normalizeHexAddress(w.address);
      }
      return w.address;
    });
  }

  async getAddresses(): Promise<string[]> {
    return this.getAddressesSync();
  }
}
