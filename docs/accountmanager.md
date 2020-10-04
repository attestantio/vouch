# Account managers
Account managers are the interface between Vouch and the accounts for which it validates.  Account managers provide the list of validating accounts and carry out signing operations.

Vouch currently supports two account managers: Dirk and wallet.  Dirk is a remote keymanager that provides additional features such as distributed key generation, threshold signing, and slashing protection.  Wallet is a local keymanager that is quick and easy to set up.

**It is recommended that Dirk be used for all production installations, due to the additional protections it provides.  Although Vouch attempts to avoid requesting signatures that could cause a slashing event, it does not have in-built slashing protection and relies on Dirk for this functionality.**

## `dirk`
The `dirk` account manager obtains account information from [Dirk](https://github.com/attestantio/dirk), and uses Dirk for remote signing.  It is important to understand that this account manager never holds the private keys, instead it sends the data to sign to the Dirk server, which carries out signing as well as slashing prevention.

The basic configuration for using Dirk is as follows:

```YAML
accountmanager:
  dirk:
    endpoints:
      - signer.example.com:8881
    client-cert: file:///home/me/certs/validator.example.com.crt
    client-key: file:///home/me/certs/validator.example.com.key
    ca-cert: file:///home/me/certs/ca.crt
    accounts:
      - my validators
```

Each item is explained in more detail below.

### endpoints
`endpoints` is a list of addresses that host Dirk servers that can respond to your requests.  There can be multiple Dirk servers, for example:
  - the servers hold different accounts
  - the servers are part of a signing threshold group

At least one endpoint is required for the Dirk account manager.

### client-cert
Dirk requires all clients to use certificates to identify themselves.  Creating these certificates is detailed in the relevant [Dirk documentation](https://github.com/attestantio/dirk/blob/master/docs/getting_started.md#creating-certificates).  `client-cert` is the client certificate that identifies this Vouch instance.  This is required.

### client-key
`client-key` is the client key that identifies this Vouch instance.  This is required.

### ca-cert
`ca-cert` is the certificate of the certificate authority by Dirk to sign the client certificate.  This is required if Dirk is using its own certificate authority to generate client certificates (which is the usual case).

### accounts
`accounts` is a list of accounts that Vouch will request from Dirk.  This is an account specifier, and can be supplied in various forms for example:

  - **`wallet`** will return all accounts in _wallet_
  - **`wallet/Validator.*`** will return all accounts in _wallet_ starting with _Validator_
  - **`wallet/Validator.*[02468]`** will return all accounts in _wallet_ starting with _Validator_ and ending in an even number

At least one account specifier is required for the Dirk account manager.

## `wallet`
The `wallet` account manager obtains account information from local wallets, and signs locally.  It supports wallets created by [ethdo](https://github.com/wealdtech/ethdo).

The basic configuration for using wallet is as follows:
```YAML
accountmanager:
  wallet:
    locations:
      - /home/me/wallets
    accounts:
      - my validators
    passphrases:
      - file:///home/me/secrets/passphrase
```

Each item is explained in more detail below.

### locations
`locations` is the list of locations to search for local wallets.

If no locations are supplied, the [default location for wallets](https://github.com/wealdtech/go-eth2-wallet-store-filesystem#usage) will be used.

### accounts
`accounts` is the list of accounts that Vouch will request locally.  This is an account specifier, and can be supplied in various forms for example:

  - **`wallet`** will return all accounts in _wallet_
  - **`wallet/Validator.*`** will return all accounts in _wallet_ starting with _Validator_
  - **`wallet/Validator.*[02468]`** will return all accounts in _wallet_ starting with _Validator_ and ending in an even number

At least one account specifier is required for the wallet account manager.

### passphrases
`passphrases` is a list of passphrases that will be used to unlock the accounts.  Each item in the list is a [Majordomo](https://github.com/wealdtech/go-majordomo) URL.
