import {
  addressFromPublickey,
  publicKeyFromPrivate,
  validatePrivateKey,
  TxMsg,
  TxEncoderFactory,
  TxSignature,
  CoinDenom,
} from "@pokt-network/pocket-js/dist/index";
import { Mnemonic, HDNode, defaultPath } from "@sendnodes/hd-node/dist/index";
import { ExternallyOwnedAccount } from "@ethersproject/abstract-signer";
import { Logger } from "@ethersproject/logger";
import nacl from "tweetnacl";

export interface Transaction {
  txMsg: TxMsg;
  chainId: string;
  fee: string;
  feeDenom?: CoinDenom;
  memo?: string;
}

export interface TransactionOptions {
  useLegacyTxCodec: boolean;
}

function isAccount(value: any): value is ExternallyOwnedAccount {
  return (
    value != null &&
    value.privateKey &&
    validatePrivateKey(Buffer.from(value.privateKey, "hex")) &&
    value.address != null
  );
}

function hasMnemonic(value: any): value is { mnemonic: Mnemonic } {
  const mnemonic = value.mnemonic;
  return mnemonic && mnemonic.phrase;
}

function computeAddress(pk: string): string {
  return addressFromPublickey(
    publicKeyFromPrivate(Buffer.from(pk, "hex"))
  ).toString("hex");
}

const logger = new Logger("pokt-wallet/1.0");

export class WalletED25519 {
  private readonly _privateKey: string;
  readonly address: string;
  readonly _mnemonic: () => Mnemonic | null;

  constructor(privateKey: string | ExternallyOwnedAccount) {
    logger.checkNew(new.target, WalletED25519);

    if (isAccount(privateKey)) {
      this._privateKey = privateKey.privateKey;
      this.address = computeAddress(this._privateKey);
      if (this.address !== privateKey.address) {
        logger.throwArgumentError(
          "privateKey/address mismatch",
          "privateKey",
          "[REDACTED]"
        );
      }
      if (hasMnemonic(privateKey)) {
        const srcMnemonic = privateKey.mnemonic;
        this._mnemonic = () => ({
          phrase: srcMnemonic.phrase,
          path: srcMnemonic.path || defaultPath,
          locale: srcMnemonic.locale || "en",
        });
        const mnemonic = this.mnemonic as Mnemonic;
        const node = HDNode.fromMnemonic(
          mnemonic.phrase,
          undefined,
          mnemonic.locale
        ).derivePath(mnemonic.path);
        if (computeAddress(node.privateKey) !== this.address) {
          logger.throwArgumentError(
            "mnemonic/address mismatch",
            "privateKey",
            "[REDACTED]"
          );
        }
      } else {
        this._mnemonic = () => null;
      }
    } else {
      this._privateKey = privateKey;
      this.address = computeAddress(this._privateKey);
      this._mnemonic = () => null;
    }
  }
  get mnemonic(): Mnemonic | null {
    return this._mnemonic();
  }
  get privateKey(): string {
    return this._privateKey;
  }

  getTransactionBytes(
    transaction: Transaction,
    opts: TransactionOptions = { useLegacyTxCodec: false }
  ): Buffer {
    const entropy = Number(
      BigInt(Math.floor(Math.random() * Number.MAX_SAFE_INTEGER)).toString()
    ).toString();
    const signer = TxEncoderFactory.createEncoder(
      entropy,
      transaction.chainId,
      transaction.txMsg,
      transaction.fee,
      transaction.feeDenom,
      transaction.memo,
      opts.useLegacyTxCodec
    );
    return signer.marshalStdSignDoc();
  }

  async signTransactionBytes(bytesToSign: Buffer): Promise<Buffer> {
    const data = Uint8Array.from(bytesToSign);
    const key = Uint8Array.from(Buffer.from(this._privateKey, "hex"));
    const signature = nacl.sign.detached(data, key);
    return Buffer.from(signature);
  }

  async signTransaction(
    transaction: Transaction,
    opts: TransactionOptions = { useLegacyTxCodec: false }
  ): Promise<string> {
    try {
      const entropy = Number(
        BigInt(Math.floor(Math.random() * Number.MAX_SAFE_INTEGER)).toString()
      ).toString();
      const { chainId, txMsg, fee, feeDenom, memo } = transaction;
      const signer = TxEncoderFactory.createEncoder(
        entropy,
        chainId,
        txMsg,
        fee,
        feeDenom,
        memo,
        opts.useLegacyTxCodec
      );
      const bytesToSign = signer.marshalStdSignDoc();
      const signature = await this.signTransactionBytes(bytesToSign);
      const pubKey = publicKeyFromPrivate(Buffer.from(this._privateKey, "hex"));
      const txSignature = new TxSignature(pubKey, signature);
      const encodedTxBytes = signer.marshalStdTx(txSignature);
      return encodedTxBytes.toString("hex");
    } catch (e) {
      throw e;
    }
  }

  async signTransactionVerified(
    transaction: Transaction,
    opts: TransactionOptions = { useLegacyTxCodec: false }
  ): Promise<boolean> {
    const bytesToSign = this.getTransactionBytes(transaction, opts);
    const signature = await this.signTransactionBytes(bytesToSign);
    const publicKey = publicKeyFromPrivate(
      Buffer.from(this._privateKey, "hex")
    );

    const d = new Uint8Array(bytesToSign.toJSON().data);
    const s = new Uint8Array(signature.toJSON().data);
    const pk = new Uint8Array(publicKey.toJSON().data);

    return nacl.sign.detached.verify(d, s, pk);
  }
}
