/* eslint-disable no-console */
import { verifyMessage, verifyTypedData } from "@ethersproject/wallet";
import {
  parse,
  recoverAddress,
  serialize,
  UnsignedTransaction,
} from "@ethersproject/transactions";
import { keccak256 } from "@ethersproject/keccak256";
import { TransactionRequest } from "@ethersproject/abstract-provider";
import { Transaction as PoktTransaction } from "../src/wallet";
import { MsgSend } from "@pokt-network/pocket-js/dist/index";
import { KeyType } from "../src/types";
import { HDKeyring } from "../src";

const validMnemonics = [
  "square time hurdle gospel crash uncle flash tomorrow city space shine sad fence ski harsh salt need edit name fold corn chuckle resource else",
  "until issue must",
  "glass skin grass cat photo essay march detail remain",
  "dream dinosaur poem cherry brief hand injury ice stuff steel bench vacant amazing bar uncover",
  "mad such absent minor vapor edge tornado wrestle convince shy battle region adapt order finish foot follow monitor",
];

type HdNodeDerivation = {
  mnemonic: string;
  addresses: string[];
  privateKeys?: string[];
};

const validDerivationsEth: HdNodeDerivation[] = [
  {
    mnemonic:
      "square time hurdle gospel crash uncle flash tomorrow city space shine sad fence ski harsh salt need edit name fold corn chuckle resource else",
    addresses: [
      "0xca19be978a1d2456d16bde3efb0a5b8946f4a1ce",
      "0xce73b34e2cdf4e00054c509cc5fdf3882d4a87c8",
      "0x0b5446d680c0e665ee63508237337c8a9fe31361",
      "0x342097b215dacc397b7adc11eb54257f6bcb680e",
      "0x53e5caff572f5d16ae00054a77a252a636e56700",
      "0x17e02708eeaa9fc8c6ed86b08af1ea2e81cf18f9",
      "0x4a8d4ad7206c24a1c7e694760dbd35df33068401",
      "0x2d43d1f8f96ff679511209280617a146b049a999",
      "0xf260e5482cc567f04f42f6229b694f3a38721ed9",
      "0xcd29ee2e1fb20fa948451fb66316da280251c439",
    ],
    privateKeys: [
      "0x6cf5a2031e021b257730ba62c7dff36829d4e5296a08b6115f7be166c03e1a46",
      "0x7047d92e716734c2b132a5b7a81588879ade8953ba55bc06a169b8acc3958806",
      "0xff30857d037d7a48ac28dd08a1db65102913cd157fd4100ca91ce3481c362bd4",
      "0x6878b13f019750963fd8b915ad02d469b01ba7c7b93d52711f289ff33db06259",
      "0xc1a4f5b54c85b0cedcf708d272884fb896ac31cbacc9d231abb465e1e5141756",
      "0x946c6288663d2f0560764da55d30c712ab22f4aeb0de00e42b940f3e44a4cc1c",
      "0x36144c66752fed74b497b3e073d327394c083d07d0878dbd4ec2c91105244ca4",
      "0x9a8ae41add310c6f9c84267e5b32c164c8ee1afd6efd9c423217014ac520b9c1",
      "0xc3c070acc77ef389a26a36c67cb803e4019d7f3ea12faa83c49c083b46d9cda8",
      "0x6cc9b6749fc800baaae1fd90ec6c9299c6eb1f63d63a5806e6ad688af2411abe",
    ],
  },
  {
    mnemonic:
      "brain surround have swap horror body response double fire dumb bring hazard",
    addresses: [
      "0x7b4322b9abe447ce86faa6121b35c84ec36945ad",
      "0x33a77a26b8523bf21bfd63f81c77f495627304e3",
      "0x2614fdc904520631f0a24ac3360393e48359fe78",
      "0xd317dcc257bedf8868b8b41a3f053604e08d3618",
      "0x0b87d62bec983a9d7832f560377e8a0876fba9cc",
      "0x6208e7af335ea9422e703b1e688b0e7f17a44a87",
      "0x74502255857e5fc38945cd6391818726fd9117e5",
      "0xc3c542dd8057f1c4a92e0bf6aa0248ed37825472",
      "0xa20ac021efb093f7f56d1e2cff31cca1c6ecac02",
      "0x260268b1cb9f4b9f6269d6051300057e3a8e1cb5",
    ],
  },
];

const validDerivationsPokt: HdNodeDerivation[] = [
  {
    mnemonic:
      "square time hurdle gospel crash uncle flash tomorrow city space shine sad fence ski harsh salt need edit name fold corn chuckle resource else",
    addresses: [
      "792c5f1a6c087f20316a802d325fdfbb9b41482a",
      "5db4684f8277a04e3ccb9f0dd47297dcd86d36ce",
      "76f106a3df83566c47304da04d401d2d6b007b23",
      "6221de1a0e75b14233863b83ada7e7a61d57f7ae",
      "eb4da08cc8ac42111c573f6f69aad23236f03356",
      "d16477c567df0d41aed5f8534774221e3732df13",
      "de85df15c7ac3e91183209406252a11266d88e2d",
      "e71eb877ac91ca98b3be464c000f89182ff3f961",
      "17a8ce1e6582f03dd11ae8dd35ccffd980051395",
      "e01b2db9c8ff150bd6b4a4507b519af625baf5b0",
    ],
    privateKeys: [
      "84002bdb55bf83420964dd4f9ba61c5161c6e11a9cc6e65f303357f886a471d4a9886f2b56c379c238106ae7ec7f2c687f9a64179f332d7729c9f8bf4e17552b",
      "3b08b7af99bdbfc58b25ff19c5ab5841d73d0dd40d8ce3769ef956fb974999f431d854b49fb27eda6e9f8436f4841286a57c4e03539a74f8788543e3f2bc5685",
      "888f6dc9cc07b9706e1c851a49b2bb219dfe3d599c4edd92b98e3619dcca2b1c129021078f74bd292e828ca58193f06d911d2b943c98c1cf2fff997ba7a4637c",
      "ae4c6214a5f8c1306892f5cab062399b4652ca348558e310f38f28caa00e09f11ca3debdac1c3488af6a8beaf9329bded65519e2f78493beceaf3db952303a19",
      "6b9f5c215ad502411619735aec967a0a88f5e541d81e6ae8e6b9d4e11ef51bad2b514ccd1106a67c540ec8b175e8280ddfa6cbbd0852720bfa096f90944419ce",
      "dbc104943429971d4742f4d3bb986457ebe9cc262e5e1c72c3549e7bb3cf4a733445dee0b376eaad480de2bc2ab8b056c60f769f6235d373bbd61d1f2df1308b",
      "95c904a09ad96170e1ec953e5fc0b314891f9ee3dab5f6d4b70ba6b5888e8b047748bb9120c781ea4a2f7788e8fc769d54f42e69ee6987bda80dea709d0d58f7",
      "24f3a4a454252708af76c5f4d475e008be9928f6256b17887bc93a5d06bf10e308b26b478ec9a0d018cfffa85befe963f0a053d5af9920d3308dd24bb4437163",
      "fd1c4f1ace006c998dbc1706f263d6368309cbbe55905e9164d564b8c2ca82ee40b583b833c587fe49b93a7b800d086067fdef53f609ee001057cf853674bd48",
      "719aac51e9563ee2ef4458cb285f887be0ab5cfb380fad65ec78a07cc6c54078dcaf474aad6329e880b621fb040d0016623729f4000c4ded38b8943459f8fcef",
    ],
  },
  {
    mnemonic:
      "dream dinosaur poem cherry brief hand injury ice stuff steel bench vacant amazing bar uncover",
    addresses: [
      "8031a497d73b187efda850c1f4d143216afc2905",
      "9064d651a40386c4b31e6536991bfa37b0fbd4f1",
      "48fc7dacd702447b9356704e46b8a9bb3a917637",
      "d484aee3930d45f54047b67eea7d2ab5724ca39d",
      "c439514540fa211026255f65bfd55ce6c04e3157",
      "931203ad5fa5a1dec0f1f488357ee1d1afc428ba",
      "a75a55481eaf2344550854009e866038e0538695",
      "8296bb68ff71416a7f73d6ef848c9eeaad76401d",
      "d58ca0b0f3b8a3227e61df9bff71143a41c1e5be",
      "a70a3036bc72d6a80dcc0ac8092815c8f1423d0e",
    ],
  },
  {
    mnemonic:
      "mad such absent minor vapor edge tornado wrestle convince shy battle region adapt order finish foot follow monitor",
    addresses: [
      "6d3cb5f4374820bca55ef190801166f697f37f70",
      "d24b7ee625f3f32835c8855a2af98e9104b176c7",
      "e41ccef3e7f523ef3e151c6df989be4addce24fa",
      "5f51c8b86c645004af317a58c6ece44e863c8f4c",
      "914d8d3ba931fafacc6a322331d9424172d4a0b1",
      "9b3cce65aa3e9fbf0fc12aa4d8af8dbdc6139d91",
      "f7768cae3f1e2fdb37da5f61e012a1df8f058c24",
      "7871c2dfcdc832b99fb7b47a19b57fbe01cd5be2",
      "57d80be8561d12728e7a410d80e8fe5681d1faf5",
      "7657b111114a4f5d1068e9450bccdb828bc35650",
    ],
  },
  {
    mnemonic:
      "now coffee gossip trim else inside exclude merge enhance voice reason virus siren hold rubber genre during brain inmate staff smooth ice spot visit",
    addresses: [
      "675f4555c045558ca8421ece3fea6074da5716a6",
      "7b9ce39dca18bc1b1d245f742da57dc973cc70fa",
      "b1358a8f5a5903be3cb4fd32e9c988b7550f964f",
      "62c86f932ddd744aa99f3fb27bcbda8c3ac25ec4",
      "eb761b09335773d7205f29b5150da1ec1d9bf5a4",
      "47ca2677dd9599d246a8dcc5abeb2f4f38e4f5c4",
      "cfd213bf40963219808053924984143a2fe1882a",
      "bb80021f53281212129263fca9c06a73b96ec243",
      "12f8f77bd3fc503eded01b6378ad6b4dc4ab4be2",
      "1b4286723d17a68da42f6c3142245eb2cd05f57b",
    ],
  },
];

const testPassphrases = ["super_secret", "1234"];

const twelveOrMoreWordMnemonics = validMnemonics.filter(
  (m) => m.split(" ").length >= 12
);

const underTwelveWorkMnemonics = validMnemonics.filter(
  (m) => m.split(" ").length < 12
);

/********************
 * POKT HDKeyring
 *********************/

describe("HDKeyring Pokt", () => {
  it("can be constructed without a mnemonic", () => {
    const keyring = new HDKeyring({ keyType: KeyType.ED25519 });
    expect(keyring.fingerprint).toBeTruthy();
    expect(keyring.fingerprint.length).toBeGreaterThan(9);
  });
  it("can be constructed with a mnemonic", () => {
    const keyring = new HDKeyring({
      mnemonic: validMnemonics[0],
      keyType: KeyType.ED25519,
    });
    expect(keyring.fingerprint).toBeTruthy();
    expect(keyring.fingerprint.length).toBeGreaterThan(9);
  });
  it("can be constructed with a mnemonic and passphrase", () => {
    const keyring = new HDKeyring({
      mnemonic: validMnemonics[0],
      passphrase: testPassphrases[0],
      keyType: KeyType.ED25519,
    });
    expect(keyring.fingerprint).toBeTruthy();
    expect(keyring.fingerprint.length).toBeGreaterThan(9);
  });
  it("cannot be constructed with an invalid mnemonic", () => {
    underTwelveWorkMnemonics.forEach((m) =>
      expect(
        () => new HDKeyring({ mnemonic: m, keyType: KeyType.ED25519 })
      ).toThrowError()
    );
  });
  it("serializes its mnemonic", async () => {
    await Promise.all(
      twelveOrMoreWordMnemonics.map(async (m) => {
        const keyring = new HDKeyring({
          mnemonic: m,
          keyType: KeyType.ED25519,
        });
        const serialized = await keyring.serialize();
        expect(serialized.mnemonic).toBe(m);
      })
    );
  });
  it("deserializes after serializing", async () => {
    await Promise.all(
      twelveOrMoreWordMnemonics.map(async (m) => {
        const keyring = new HDKeyring({
          mnemonic: m,
          keyType: KeyType.ED25519,
        });
        const id1 = keyring.fingerprint;

        const serialized = await keyring.serialize();
        const deserialized = HDKeyring.deserialize(serialized);

        expect(id1).toBe(deserialized.fingerprint);
      })
    );
  });
  it("deserializes with passphrase after serializing", async () => {
    await Promise.all(
      twelveOrMoreWordMnemonics.map(async (m) => {
        const keyring = new HDKeyring({
          mnemonic: m,
          passphrase: testPassphrases[0],
          keyType: KeyType.ED25519,
        });
        const id1 = keyring.fingerprint;

        const serialized = await keyring.serialize();
        const deserialized = HDKeyring.deserialize(
          serialized,
          testPassphrases[0]
        );

        expect(id1).toBe(deserialized.fingerprint);
      })
    );
  });
  it("fails to deserialize different versions", async () => {
    await Promise.all(
      twelveOrMoreWordMnemonics.map(async (m) => {
        const keyring = new HDKeyring({
          mnemonic: m,
          keyType: KeyType.ED25519,
        });
        const serialized = await keyring.serialize();
        serialized.version = 2;
        expect(() => HDKeyring.deserialize(serialized)).toThrowError();
      })
    );
  });
  it("generates the same IDs from the same mnemonic", async () => {
    twelveOrMoreWordMnemonics.forEach((m) => {
      const keyring1 = new HDKeyring({ mnemonic: m, keyType: KeyType.ED25519 });
      const keyring2 = new HDKeyring({ mnemonic: m, keyType: KeyType.ED25519 });

      expect(keyring1.fingerprint).toBe(keyring2.fingerprint);
    });
  });
  it("generates a different ID from the same mnemonic with a passphrase", async () => {
    twelveOrMoreWordMnemonics.forEach((m) => {
      const keyring1 = new HDKeyring({ mnemonic: m, keyType: KeyType.ED25519 });
      const keyring2 = new HDKeyring({
        mnemonic: m,
        passphrase: testPassphrases[0],
        keyType: KeyType.ED25519,
      });

      expect(keyring1.fingerprint).not.toBe(keyring2.fingerprint);
    });
  });
  it("generates distinct addresses", async () => {
    const allAddresses: string[] = [];
    await Promise.all(
      twelveOrMoreWordMnemonics.map(async (m) => {
        const keyring = new HDKeyring({
          mnemonic: m,
          keyType: KeyType.ED25519,
        });
        keyring.addAddresses(10);

        const addresses = await keyring.getAddresses();
        expect(addresses.length).toEqual(10);
        expect(new Set(addresses).size).toEqual(10);

        allAddresses.concat(addresses);
      })
    );

    expect(new Set(allAddresses).size).toEqual(allAddresses.length);
  });
  it("exports its private keys", () => {
    const { mnemonic, addresses, privateKeys } = validDerivationsPokt[0];

    if (!privateKeys) {
      return;
    }

    const keyring = new HDKeyring({
      mnemonic: mnemonic,
      keyType: KeyType.ED25519,
    });

    keyring.addAddressesSync(addresses.length).forEach((a, i) => {
      expect(keyring.getPrivateKey(a)).toBe(privateKeys[i]);
    });
  });
  it("fails to generate out-of-bounds addresses", async () => {
    const addressBounds0 = await Promise.allSettled(
      twelveOrMoreWordMnemonics.map(async (m) => {
        const keyring = new HDKeyring({
          mnemonic: m,
          keyType: KeyType.ED25519,
        });

        // Add negatives, should always fail.
        await keyring.addAddresses(-Math.random() * 10 - 1);
      })
    );

    const addressBoundsMax = await Promise.allSettled(
      twelveOrMoreWordMnemonics.map(async (m) => {
        const keyring = new HDKeyring({
          mnemonic: m,
          keyType: KeyType.ED25519,
        });

        await keyring.addAddresses(2 ** 31);
      })
    );

    const addressBoundsMaxSplit = await Promise.allSettled(
      twelveOrMoreWordMnemonics.map(async (m) => {
        const keyring = new HDKeyring({
          mnemonic: m,
          keyType: KeyType.ED25519,
        });

        // Adding more than order-of-10 addresses can get so slow it kills test
        // time, thus the small first and second splits.
        const firstSplit = Math.floor(Math.random() * 10);
        const secondSplit = Math.floor(Math.random() * 10);
        const remaining = 2 ** 31 - firstSplit;

        await keyring.addAddresses(firstSplit);
        await keyring.addAddresses(secondSplit);
        await keyring.addAddresses(remaining);
      })
    );

    expect(
      [...addressBounds0, ...addressBoundsMax, ...addressBoundsMaxSplit]
        .map(({ status }) => status)
        .every((status) => status === "rejected")
    ).toEqual(true);
  });
  it("generates addresses without off-by-one errors", async () => {
    await Promise.all(
      twelveOrMoreWordMnemonics.slice(-1).map(async (m) => {
        const keyring = new HDKeyring({
          mnemonic: m,
          keyType: KeyType.ED25519,
        });

        await keyring.addAddresses(10);

        const addresses = await keyring.getAddresses();
        expect(addresses.length).toEqual(10);
        expect(new Set(addresses).size).toEqual(10);

        const keyring2 = new HDKeyring({
          mnemonic: m,
          keyType: KeyType.ED25519,
        });

        for (let i = 0; i < 10; i += 1) {
          keyring2.addAddressesSync();
        }

        const addresses2 = await keyring2.getAddresses();
        expect(addresses2.length).toEqual(10);
        expect(new Set(addresses2).size).toEqual(10);
      })
    );
  });
  it("generates and initializes the same first address from the same mnemonic", async () => {
    await Promise.all(
      validDerivationsPokt.map(async ({ mnemonic, addresses }) => {
        const keyring = new HDKeyring({ mnemonic, keyType: KeyType.ED25519 });

        expect((await keyring.getAddresses()).length).toEqual(0);

        keyring.addAddressesSync();

        expect((await keyring.getAddresses()).length).toEqual(1);
        expect(await keyring.getAddresses()).toStrictEqual([addresses[0]]);
      })
    );
  });
  it("generates the same addresses from the same mnemonic", async () => {
    await Promise.all(
      twelveOrMoreWordMnemonics.map(async (m) => {
        const keyring1 = new HDKeyring({
          mnemonic: m,
          keyType: KeyType.ED25519,
        });
        const keyring2 = new HDKeyring({
          mnemonic: m,
          keyType: KeyType.ED25519,
        });

        keyring1.addAddressesSync();
        keyring2.addAddressesSync();

        expect((await keyring1.getAddresses()).length).toBeGreaterThan(0);
        expect((await keyring2.getAddresses()).length).toBeGreaterThan(0);

        expect(await keyring1.getAddresses()).toStrictEqual(
          await keyring2.getAddresses()
        );
      })
    );
  });
  it("generates different addresses from the same mnemonic with different passphrases", async () => {
    await Promise.all(
      twelveOrMoreWordMnemonics.map(async (m) => {
        const keyring1 = new HDKeyring({
          mnemonic: m,
          keyType: KeyType.ED25519,
        });
        const keyring2 = new HDKeyring({
          mnemonic: m,
          passphrase: testPassphrases[0],
          keyType: KeyType.ED25519,
        });
        const keyring3 = new HDKeyring({
          mnemonic: m,
          passphrase: testPassphrases[1],
          keyType: KeyType.ED25519,
        });

        keyring1.addAddressesSync();
        keyring2.addAddressesSync();
        keyring3.addAddressesSync();

        expect((await keyring1.getAddresses()).length).toBeGreaterThan(0);
        expect((await keyring2.getAddresses()).length).toBeGreaterThan(0);
        expect((await keyring3.getAddresses()).length).toBeGreaterThan(0);

        expect(await keyring1.getAddresses()).not.toStrictEqual(
          await keyring2.getAddresses()
        );
        expect(await keyring1.getAddresses()).not.toStrictEqual(
          await keyring3.getAddresses()
        );
        expect(await keyring2.getAddresses()).not.toStrictEqual(
          await keyring3.getAddresses()
        );
      })
    );
  });
  it("derives the same addresses as legacy wallets", async () => {
    await Promise.all(
      validDerivationsPokt.map(async ({ mnemonic, addresses }) => {
        const keyring = new HDKeyring({ mnemonic, keyType: KeyType.ED25519 });
        await keyring.addAddressesSync(10);
        const newAddresses = keyring.getAddressesSync();
        expect(newAddresses).toStrictEqual(addresses);
      })
    );
  });
  it("returns the correct addresses when generated 1 by 1", async () => {
    await Promise.all(
      validDerivationsPokt.slice(-1).map(async ({ mnemonic, addresses }) => {
        const keyring = new HDKeyring({ mnemonic, keyType: KeyType.ED25519 });
        for (let i = 0; i < addresses.length; i += 1) {
          const newAddresses = keyring.addAddressesSync();
          expect(newAddresses.length).toEqual(1);
          expect(newAddresses[0]).toStrictEqual(addresses[i]);
        }
      })
    );
  });
  it("signs transactions", async () => {
    await Promise.all(
      twelveOrMoreWordMnemonics.map(async (m) => {
        const keyring = new HDKeyring({
          mnemonic: m,
          keyType: KeyType.ED25519,
        });

        const addresses = await keyring.addAddresses(2);
        addresses.forEach(async (address) => {
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

/********************
 * ETH HDKeyring
 *********************/

describe("HDKeyring Eth", () => {
  it("can be constructed without a mnemonic", () => {
    const keyring = new HDKeyring({ keyType: KeyType.SECP256K1 });
    expect(keyring.fingerprint).toBeTruthy();
    expect(keyring.fingerprint.length).toBeGreaterThan(9);
  });
  it("can be constructed with a mnemonic", () => {
    const keyring = new HDKeyring({
      mnemonic: validMnemonics[0],
      keyType: KeyType.SECP256K1,
    });
    expect(keyring.fingerprint).toBeTruthy();
    expect(keyring.fingerprint.length).toBeGreaterThan(9);
  });
  it("can be constructed with a mnemonic and passphrase", () => {
    const keyring = new HDKeyring({
      mnemonic: validMnemonics[0],
      passphrase: testPassphrases[0],
      keyType: KeyType.SECP256K1,
    });
    expect(keyring.fingerprint).toBeTruthy();
    expect(keyring.fingerprint.length).toBeGreaterThan(9);
  });
  it("cannot be constructed with an invalid mnemonic", () => {
    underTwelveWorkMnemonics.forEach((m) =>
      expect(
        () => new HDKeyring({ mnemonic: m, keyType: KeyType.SECP256K1 })
      ).toThrowError()
    );
  });
  it("serializes its mnemonic", async () => {
    await Promise.all(
      twelveOrMoreWordMnemonics.map(async (m) => {
        const keyring = new HDKeyring({
          mnemonic: m,
          keyType: KeyType.SECP256K1,
        });
        const serialized = await keyring.serialize();
        expect(serialized.mnemonic).toBe(m);
      })
    );
  });
  it("deserializes after serializing", async () => {
    await Promise.all(
      twelveOrMoreWordMnemonics.map(async (m) => {
        const keyring = new HDKeyring({
          mnemonic: m,
          keyType: KeyType.SECP256K1,
        });
        const id1 = keyring.fingerprint;

        const serialized = await keyring.serialize();
        const deserialized = HDKeyring.deserialize(serialized);

        expect(id1).toBe(deserialized.fingerprint);
      })
    );
  });
  it("deserializes with passphrase after serializing", async () => {
    await Promise.all(
      twelveOrMoreWordMnemonics.map(async (m) => {
        const keyring = new HDKeyring({
          mnemonic: m,
          passphrase: testPassphrases[0],
          keyType: KeyType.SECP256K1,
        });
        const id1 = keyring.fingerprint;

        const serialized = await keyring.serialize();
        const deserialized = HDKeyring.deserialize(
          serialized,
          testPassphrases[0]
        );

        expect(id1).toBe(deserialized.fingerprint);
      })
    );
  });
  it("fails to deserialize different versions", async () => {
    await Promise.all(
      twelveOrMoreWordMnemonics.map(async (m) => {
        const keyring = new HDKeyring({
          mnemonic: m,
          keyType: KeyType.SECP256K1,
        });
        const serialized = await keyring.serialize();
        serialized.version = 2;
        expect(() => HDKeyring.deserialize(serialized)).toThrowError();
      })
    );
  });
  it("generates the same IDs from the same mnemonic", async () => {
    twelveOrMoreWordMnemonics.forEach((m) => {
      const keyring1 = new HDKeyring({
        mnemonic: m,
        keyType: KeyType.SECP256K1,
      });
      const keyring2 = new HDKeyring({
        mnemonic: m,
        keyType: KeyType.SECP256K1,
      });

      expect(keyring1.fingerprint).toBe(keyring2.fingerprint);
    });
  });
  it("generates a different ID from the same mnemonic with a passphrase", async () => {
    twelveOrMoreWordMnemonics.forEach((m) => {
      const keyring1 = new HDKeyring({
        mnemonic: m,
        keyType: KeyType.SECP256K1,
      });
      const keyring2 = new HDKeyring({
        mnemonic: m,
        passphrase: testPassphrases[0],
        keyType: KeyType.SECP256K1,
      });

      expect(keyring1.fingerprint).not.toBe(keyring2.fingerprint);
    });
  });
  it("generates distinct addresses", async () => {
    const allAddresses: string[] = [];
    await Promise.all(
      twelveOrMoreWordMnemonics.map(async (m) => {
        const keyring = new HDKeyring({
          mnemonic: m,
          keyType: KeyType.SECP256K1,
        });

        await keyring.addAddresses(10);

        const addresses = await keyring.getAddresses();
        expect(addresses.length).toEqual(10);
        expect(new Set(addresses).size).toEqual(10);

        allAddresses.concat(addresses);
      })
    );
    expect(new Set(allAddresses).size).toEqual(allAddresses.length);
  });
  it("exports its private keys", () => {
    const { mnemonic, addresses, privateKeys } = validDerivationsEth[0];

    if (!privateKeys) {
      return;
    }

    const keyring = new HDKeyring({
      mnemonic: mnemonic,
      keyType: KeyType.SECP256K1,
    });

    expect(
      keyring
        .addAddressesSync(addresses.length)
        .map((a) => keyring.getPrivateKey(a))
    ).toStrictEqual(privateKeys);
  });
  it("fails to generate out-of-bounds addresses", async () => {
    const addressBounds0 = await Promise.allSettled(
      twelveOrMoreWordMnemonics.map(async (m) => {
        const keyring = new HDKeyring({
          mnemonic: m,
          keyType: KeyType.SECP256K1,
        });

        // Add negatives, should always fail.
        await keyring.addAddresses(-Math.random() * 10 - 1);
      })
    );

    const addressBoundsMax = await Promise.allSettled(
      twelveOrMoreWordMnemonics.map(async (m) => {
        const keyring = new HDKeyring({
          mnemonic: m,
          keyType: KeyType.SECP256K1,
        });

        await keyring.addAddresses(2 ** 31);
      })
    );

    const addressBoundsMaxSplit = await Promise.allSettled(
      twelveOrMoreWordMnemonics.map(async (m) => {
        const keyring = new HDKeyring({
          mnemonic: m,
          keyType: KeyType.SECP256K1,
        });

        // Adding more than order-of-10 addresses can get so slow it kills test
        // time, thus the small first and second splits.
        const firstSplit = Math.floor(Math.random() * 10);
        const secondSplit = Math.floor(Math.random() * 10);
        const remaining = 2 ** 31 - firstSplit;

        await keyring.addAddresses(firstSplit);
        await keyring.addAddresses(secondSplit);
        await keyring.addAddresses(remaining);
      })
    );

    expect(
      [...addressBounds0, ...addressBoundsMax, ...addressBoundsMaxSplit]
        .map(({ status }) => status)
        .every((status) => status === "rejected")
    ).toEqual(true);
  });
  it("generates addresses without off-by-one errors", async () => {
    await Promise.all(
      twelveOrMoreWordMnemonics.slice(-1).map(async (m) => {
        const keyring = new HDKeyring({
          mnemonic: m,
          keyType: KeyType.SECP256K1,
        });

        await keyring.addAddresses(10);

        const addresses = await keyring.getAddresses();
        expect(addresses.length).toEqual(10);
        expect(new Set(addresses).size).toEqual(10);

        const keyring2 = new HDKeyring({
          mnemonic: m,
          keyType: KeyType.SECP256K1,
        });

        for (let i = 0; i < 10; i += 1) {
          keyring2.addAddressesSync();
        }

        const addresses2 = await keyring2.getAddresses();
        expect(addresses2.length).toEqual(10);
        expect(new Set(addresses2).size).toEqual(10);
      })
    );
  });
  it("generates and initializes the same first address from the same mnemonic", async () => {
    await Promise.all(
      validDerivationsEth.map(async ({ mnemonic, addresses }) => {
        const keyring = new HDKeyring({ mnemonic, keyType: KeyType.SECP256K1 });

        expect((await keyring.getAddresses()).length).toEqual(0);

        keyring.addAddressesSync();

        expect((await keyring.getAddresses()).length).toEqual(1);
        expect(await keyring.getAddresses()).toStrictEqual([addresses[0]]);
      })
    );
  });
  it("generates the same addresses from the same mnemonic", async () => {
    await Promise.all(
      twelveOrMoreWordMnemonics.map(async (m) => {
        const keyring1 = new HDKeyring({
          mnemonic: m,
          keyType: KeyType.SECP256K1,
        });
        const keyring2 = new HDKeyring({
          mnemonic: m,
          keyType: KeyType.SECP256K1,
        });

        keyring1.addAddressesSync();
        keyring2.addAddressesSync();

        expect((await keyring1.getAddresses()).length).toBeGreaterThan(0);
        expect((await keyring2.getAddresses()).length).toBeGreaterThan(0);

        expect(await keyring1.getAddresses()).toStrictEqual(
          await keyring2.getAddresses()
        );
      })
    );
  });
  it("generates different addresses from the same mnemonic with different passphrases", async () => {
    await Promise.all(
      twelveOrMoreWordMnemonics.map(async (m) => {
        const keyring1 = new HDKeyring({
          mnemonic: m,
          keyType: KeyType.SECP256K1,
        });
        const keyring2 = new HDKeyring({
          mnemonic: m,
          passphrase: testPassphrases[0],
          keyType: KeyType.SECP256K1,
        });
        const keyring3 = new HDKeyring({
          mnemonic: m,
          passphrase: testPassphrases[1],
          keyType: KeyType.SECP256K1,
        });

        keyring1.addAddressesSync();
        keyring2.addAddressesSync();
        keyring3.addAddressesSync();

        expect((await keyring1.getAddresses()).length).toBeGreaterThan(0);
        expect((await keyring2.getAddresses()).length).toBeGreaterThan(0);
        expect((await keyring3.getAddresses()).length).toBeGreaterThan(0);

        expect(await keyring1.getAddresses()).not.toStrictEqual(
          await keyring2.getAddresses()
        );
        expect(await keyring1.getAddresses()).not.toStrictEqual(
          await keyring3.getAddresses()
        );
        expect(await keyring2.getAddresses()).not.toStrictEqual(
          await keyring3.getAddresses()
        );
      })
    );
  });
  it("derives the same addresses as legacy wallets", async () => {
    await Promise.all(
      validDerivationsEth.map(async ({ mnemonic, addresses }) => {
        const keyring = new HDKeyring({ mnemonic, keyType: KeyType.SECP256K1 });
        await keyring.addAddressesSync(10);
        const newAddresses = keyring.getAddressesSync();
        expect(newAddresses).toStrictEqual(addresses);
      })
    );
  });
  it("returns the correct addresses when generated 1 by 1", async () => {
    await Promise.all(
      validDerivationsEth.slice(-1).map(async ({ mnemonic, addresses }) => {
        const keyring = new HDKeyring({ mnemonic, keyType: KeyType.SECP256K1 });
        for (let i = 0; i < addresses.length; i += 1) {
          const newAddresses = keyring.addAddressesSync();
          expect(newAddresses.length).toEqual(1);
          expect(newAddresses[0]).toStrictEqual(addresses[i]);
        }
      })
    );
  });
  it("signs messages recoverably", async () => {
    await Promise.all(
      twelveOrMoreWordMnemonics.map(async (m) => {
        const keyring = new HDKeyring({
          mnemonic: m,
          keyType: KeyType.SECP256K1,
        });

        const addresses = await keyring.addAddresses(2);
        addresses.forEach(async (address) => {
          const message = "recoverThisMessage";
          const sig = await keyring.signMessage(address, message);
          expect(await verifyMessage(message, sig).toLowerCase()).toEqual(
            address
          );
        });
      })
    );
  });
  it("signs transactions recoverably", async () => {
    await Promise.all(
      twelveOrMoreWordMnemonics.map(async (m) => {
        const keyring = new HDKeyring({
          mnemonic: m,
          keyType: KeyType.SECP256K1,
        });

        const addresses = await keyring.addAddresses(2);
        addresses.forEach(async (address) => {
          const tx: TransactionRequest = {
            to: address,
            value: 300000,
            gasLimit: 300000,
            gasPrice: 300000,
            nonce: 300000,
          };
          const signedTx = await keyring.signTransaction(address, tx);
          const parsed = parse(signedTx);
          const sig = {
            r: parsed.r as string,
            s: parsed.s as string,
            v: parsed.v as number,
          };
          const digest = keccak256(serialize(<UnsignedTransaction>tx));
          expect(recoverAddress(digest, sig).toLowerCase()).toEqual(address);
        });
      })
    );
  });
  it("signs typed data recoverably", async () => {
    await Promise.all(
      twelveOrMoreWordMnemonics.map(async (m) => {
        const keyring = new HDKeyring({
          mnemonic: m,
          keyType: KeyType.SECP256K1,
        });

        const addresses = await keyring.addAddresses(2);
        addresses.forEach(async (address) => {
          const domain = {
            name: "Ether Mail",
            version: "1",
            chainId: 1,
            verifyingContract: "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC",
          };

          const types = {
            Person: [{ name: "name", type: "string" }],
            Mail: [
              { name: "from", type: "Person" },
              { name: "to", type: "Person" },
              { name: "contents", type: "string" },
            ],
          };

          const value = {
            contents: "Hello, Bob!",
            from: {
              name: "Alice",
            },
            to: {
              name: "Bob",
            },
          };

          const sig = await keyring.signTypedData(
            address,
            domain,
            types,
            value
          );

          expect(
            verifyTypedData(domain, types, value, sig).toLowerCase()
          ).toEqual(address);
        });
      })
    );
  });
});
