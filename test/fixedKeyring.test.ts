import { Transaction as PoktTransaction } from "../src/wallet";
import { MsgSend } from "@pokt-network/pocket-js/dist/index";
import { KeyType } from "../src/types";
import { FixedKeyring } from "../src/fixedKeyring";

const validPrivateKeys = [
  "987e5f7423a3cfba9e8a248dccc4e404ab629dac0ae92c4da4da2c83439d177ece71f27c5bd4f774b85e9ec8256760845823557ea751781daef064f4f6130c9f",
  "908df2c0ae8195fe52ed1af13c81ade361ef6b1052be1e6ccf67498b75c5d452b24489610796210d4be504b5e077224e3c0706f61b9fde99ccee4de4786e3e0a",
];
/********************
 * POKT FixedKeyring
 *********************/

describe("FixedKeyring Pokt", () => {
  it("can be constructed with a privateKey and keyType", () => {
    validPrivateKeys.forEach((pk) => {
      const keyring = new FixedKeyring({
        privateKey: pk,
        keyType: KeyType.ED25519,
      });
      expect(keyring.fingerprint).toBeTruthy();
      expect(keyring.fingerprint.length).toBeGreaterThan(9);
    });
  });
  it("serializes its private key", async () => {
    await Promise.all(
      validPrivateKeys.map(async (pk) => {
        const keyring = new FixedKeyring({
          privateKey: pk,
          keyType: KeyType.ED25519,
        });
        const serialized = await keyring.serialize();
        expect(serialized.privateKey).toBe(pk);
      })
    );
  });
  it("exports its private keys", () => {
    validPrivateKeys.map(async (pk) => {
      const keyring = new FixedKeyring({
        privateKey: pk,
        keyType: KeyType.ED25519,
      });
      keyring
        .getAddressesSync()
        .forEach((a) => expect(keyring.getPrivateKey(a)).toBe(pk));
    });
  });
  it("deserializes after serializing", async () => {
    await Promise.all(
      validPrivateKeys.map(async (pk) => {
        const keyring = new FixedKeyring({
          privateKey: pk,
          keyType: KeyType.ED25519,
        });
        const id1 = keyring.fingerprint;

        const serialized = await keyring.serialize();
        const deserialized = FixedKeyring.deserialize(serialized);

        expect(id1).toBe(deserialized.fingerprint);
      })
    );
  });
  it("deserializes with privateKey after serializing", async () => {
    await Promise.all(
      validPrivateKeys.map(async (pk) => {
        const keyring = new FixedKeyring({
          privateKey: pk,
          keyType: KeyType.ED25519,
        });
        const id1 = keyring.fingerprint;

        const serialized = await keyring.serialize();
        const deserialized = FixedKeyring.deserialize(serialized);

        expect(id1).toBe(deserialized.fingerprint);
      })
    );
  });
  it("fails to deserialize different versions", async () => {
    await Promise.all(
      validPrivateKeys.map(async (pk) => {
        const keyring = new FixedKeyring({
          privateKey: pk,
          keyType: KeyType.ED25519,
        });
        const serialized = await keyring.serialize();
        serialized.version = 2;
        expect(() => FixedKeyring.deserialize(serialized)).toThrowError();
      })
    );
  });
  it("generates the same IDs from the same privateKey", async () => {
    validPrivateKeys.forEach((pk) => {
      const keyring1 = new FixedKeyring({
        privateKey: pk,
        keyType: KeyType.ED25519,
      });
      const keyring2 = new FixedKeyring({
        privateKey: pk,
        keyType: KeyType.ED25519,
      });

      expect(keyring1.fingerprint).toBe(keyring2.fingerprint);
    });
  });
  it("generates a different ID from the same privateKey with a passphrase", async () => {
    const keyring1 = new FixedKeyring({
      privateKey: validPrivateKeys[0],
      keyType: KeyType.ED25519,
    });
    const keyring2 = new FixedKeyring({
      privateKey: validPrivateKeys[1],
      keyType: KeyType.ED25519,
    });

    expect(keyring1.fingerprint).not.toBe(keyring2.fingerprint);
  });
  it("fails to generate new addresses", async () => {
    await Promise.all(
      validPrivateKeys.map(async (pk) => {
        const keyring = new FixedKeyring({
          privateKey: pk,
          keyType: KeyType.ED25519,
        });
        expect(() => keyring.addAddresses(10)).toThrowError();
      })
    );
  });

  it("generates the same addresses from the same privateKey", async () => {
    await Promise.all(
      validPrivateKeys.map(async (pk) => {
        const keyring1 = new FixedKeyring({
          privateKey: pk,
          keyType: KeyType.ED25519,
        });
        const keyring2 = new FixedKeyring({
          privateKey: pk,
          keyType: KeyType.ED25519,
        });

        expect((await keyring1.getAddresses()).length).toBe(1);
        expect((await keyring2.getAddresses()).length).toBe(1);

        expect(await keyring1.getAddresses()).toStrictEqual(
          await keyring2.getAddresses()
        );
      })
    );
  });

  it("signs transactions", async () => {
    await Promise.all(
      validPrivateKeys.map(async (pk) => {
        const keyring = new FixedKeyring({
          privateKey: pk,
          keyType: KeyType.ED25519,
        });
        (await keyring.getAddresses()).forEach(async (address) => {
          const send = new MsgSend(address, address, "1000000");
          const tx: PoktTransaction = {
            txMsg: send,
            chainId: "mainnet",
            fee: "100000",
          };
          const verified = await keyring.signTransactionVerified(address, tx);
          expect(verified).toEqual(true);
        });
      })
    );
  });
});
