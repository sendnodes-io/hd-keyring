import {
  Keyring,
  KeyringType,
  KeyType,
  SerializedKeyring,
  SerializedKeyringVersion,
} from "./types";
import { HDKeyring, SerializedHDKeyring } from "./hdKeyring";
import { FixedKeyring, SeralizedFixedKeyring } from "./fixedKeyring";

/**
 * Given an a object attempt to deserialize into a concrete class
 */
export function v1KeyringDeserializer(
  keyring: any
): Keyring<SerializedKeyring> | null {
  const { version, keyType, keyringType } = keyring as SerializedKeyring;

  if (version !== SerializedKeyringVersion.V1) {
    throw new Error("Cannot deserialize keyring version: " + version);
  }

  if (!Object.values(KeyringType).includes(keyringType)) {
    throw new Error("Invalid keyringType: " + keyringType);
  }

  if (!Object.values(KeyType).includes(keyType)) {
    throw new Error("Invalid keyringType: " + keyType);
  }

  const hdKeyring = keyring as SerializedHDKeyring;
  if (hdKeyring.keyringType == KeyringType.BIP39 && hdKeyring.mnemonic) {
    return HDKeyring.deserialize(keyring);
  }

  const fixedKeyring = keyring as SeralizedFixedKeyring;
  if (
    fixedKeyring.keyringType == KeyringType.FIXED &&
    fixedKeyring.privateKey
  ) {
    return FixedKeyring.deserialize(keyring);
  }

  return null;
}

export * from "./types";
export * from "./utils";
export * from "./hdKeyring";
export * from "./fixedKeyring";
export * from "./wallet";
