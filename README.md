# hd-keyring

A class to manage [BIP-32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki) compatible [hierarchical deterministic (HD) wallets](https://learnmeabitcoin.com/technical/hd-wallets), with added support for ed25519 keys.

## Building and Developing

- NodeJS 14
- PNPM

### Quickstart

```sh
$ npm install -g pnpm # if you don't have pnpm globally installed
$ pnpm install # install all dependencies; rerun with --ignore-scripts if
               # scrypt node-gyp failures prevent the install from completing
$ pnpm test -- --watch # start a continuous test that will auto-run with changes
```

Once the continuous test build is running, you can make whatever changes to
the code and make sure tests continue to pass.
