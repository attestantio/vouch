# Getting started
This document provides steps to set up a Vouch instance using validators in a local wallet.

**Please note that the wallet keymanager does not provide slashing protection.  It is recommended that the Dirk keymanager be used for all production installations, due to the additional protections it provides.**

It assumes there is a local wallet called "Validators" that has been created by `ethdo`, that the wallet has one or more accounts in it, and that those accounts have been configured as validators on an Ethereum 2 network.

It also assumes there is an accessible instance of the Ethereum 2 beacon chain that is fully synced with the current state of the chain.

#### Configuring Vouch
A basic configuration file can be created in the user's home directory with the name `.vouch.yml` and the following contents:

```YAML
beacon-node-address: localhost:5052
accountmanager:
  wallet:
    accounts:
      - Validators
    passphrases:
      - secret
blockrelay:
  fallback-recipient-address: '0x0000000000000000000000000000000000000001'
metrics:
  prometheus:
    listen-address: '127.0.0.1:12345'
```

`beacon-node-address` should be changed to access a suitable beacon node.

The passphrase `secret` should be changed to be the passphrase you used to secure the accounts.

`default-address` should be changed to an execution address to which execution block rewards should be sent.

#### Starting Vouch

To start Vouch type:
```
$ vouch
{"level":"info","version":"v0.6.0","time":"2020-09-25T14:46:45+01:00","message":"Starting vouch"}
{"level":"info","time":"2020-09-25T14:46:46+01:00","message":"Starting standard submitter strategy"}
{"level":"info","time":"2020-09-25T14:46:46+01:00","message":"Starting simple beacon block proposal strategy"}
{"level":"info","service":"controller","impl":"standard","accounts":2,"time":"2020-09-25T14:46:46+01:00","message":"Initial validating accounts"}
{"level":"info","time":"2020-09-25T14:46:46+01:00","message":"All services operational"}
```


At this point Vouch is operational and validation for the configured validators should begin.
