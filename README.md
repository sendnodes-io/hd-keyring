# hd-keyring

A class to manage [BIP-32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki) compatible [hierarchical deterministic (HD) wallets](https://learnmeabitcoin.com/technical/hd-wallets), with added support for ed25519 keys.

## Building and Developing

#### Required Software

If you can't use the macOS setup script, here is the software you'll need to
install:

- `nvm`: [Instructions](https://github.com/nvm-sh/nvm#installing-and-updating)
- `yarn`: [Instructions](https://classic.yarnpkg.com/lang/en/docs/install/)

### Quickstart

```sh
$ nvm use
$ npm install -g yarn # if you don't have yarn globally installed
$ yarn install # install all dependencies; rerun with --ignore-scripts if
               # scrypt node-gyp failures prevent the install from completing
$ yarn test --watch # start a continuous test that will auto-run with changes
```

Once the continuous test build is running, you can make whatever changes to
the code and make sure tests continue to pass.
