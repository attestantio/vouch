# Execution configuration

N.B. This documentation is for version 2 of the execution configuration file.  Version 1 files are [still supported](./execlayer.md), however version 1 is deprecated and support for it will be removed in a future update.

The goals of the execution configuration file are:

- clarity: it should be as clear as possible as to which values a particular proposer will use
- flexibility: it should be possible to provide configurations that meet all requirements
- expandability: it should be possible to expand the configuration file with additional options in future with minimal changes to the structure
- compactness: it should be as small as possible without losing clarity or flexibility

The system is designed to allow for sensible specification of default values, along with overrides where necessary.  For a given proposer, its configuration will be obtained from the following locations:

1. proposer-specific values in the execution configuration
2. default values in the execution configuration
3. fallback values in Vouch configuration

## Fallback values
Configuration of fallback values is part of the Vouch configuration, provided under the `blockrelay` key.  The minimal configuration is as follows:

```yaml
blockrelay:
  fallback-fee-recipient: '0x0123…cdef'
```

This will use the provided address `0x0123…cdef` as the fee recipient for all beacon block proposals.  Block proposals requested from beacon nodes will use their local execution client to obtain execution payloads.

It is also possible to specify a fallback gas limit:

```yaml
blockrelay:
  fallback-fee-recipient: '0x0123…cdef'
  fallback-gas-limit: 30000000
```

Although in general it is better to leave this value out, as Vouch has its own fallback value configured and changing this could affect the execution network.

## Specifying an execution configuration
For more advanced configurations an execution configuration file is required.  Access to the configuration file is usually through a simple URL, for example:

```yaml
blockrelay:
  fallback-fee-recipient: '0x0123…cdef'
  config:
    url: 'file:///home/vouch/config.json'
```

(Note that the `fallback-fee-recipient` value is still present, and is required for Vouch to operate in the situation that the configuration file is inaccessible or unreadable.)

The URL can be any valid [Majordomo](https://github.com/wealdtech/go-majordomo) URL.  Of special note is the [HTTP confidant](https://github.com/wealdtech/go-majordomo/blob/master/confidants/http/service.go#L32), for which Vouch provides additional features.  Notably, the call is made as a POST request with its body containing the public keys of the validators for which Vouch is currently validating, for example:

```json
[
  "0x1111…1111",
  "0x2222…2222"
]
```

Also, additional configuration parameters can be provided to secure the connection using HTTPS.  A full example of such a configuration is:

```yaml
blockrelay:
  fallback-fee-recipient: '0x0123…cdef'
  config:
    url: 'https://www.example.com/config.json'
    client-cert: 'file:///home/vouch/certs/my-client.crt'
    client-key: 'file:///home/vouch/certs/my-client.key'
    ca-cert: 'file:///home/vouch/certs/ca.crt'
```

The combination of the list of public keys and certificate-level authentication allows for servers to provide dynamic execution configuration information if required.

## Structure of the execution configuration file
The simplest configuration is as follows:

```json
{
  "version": 2
}
```

This contains no useful data,and as such Vouch will use the pre-configured fallback fee recipient for all blocks.  If the fee recipient is to be supplied in the configuration it can be done so as follows:

```json
{
  "version": 2,
  "fee_recipient": "0x0123…cdef"
}
```

It is also possible to add the gas limit here:

```json
{
  "version": 2,
  "fee_recipient": "0x0123…cdef",
  "gas_limit": "30000000"
}
```

So far, all execution block building will be local.  If use of MEV relays is required to obtain blocks this can be added as follows:

```json
{
  "version": 2,
  "fee_recipient": "0x0123…cdef",
  "gas_limit": "30000000",
  "relays": {
    "https://relay1.com/": {},
    "https://relay2.com/": {}
  }
}
```

The above configuration will contract two MEV relays at `relay1.com` and `relay2.com` when proposing blocks.

Relays often come with public keys in their URLs, for example `https://0xac6e…37ae@relay1.com/`.  These can be supplied in the configuration as follows:

```json
{
  "version": 2,
  "fee_recipient": "0x0123…cdef",
  "gas_limit": "30000000",
  "relays": {
    "https://relay1.com/": {
      "public_key": "0xac6e…37ae"
    },
    "https://relay2.com/": {
      "public_key": "0x8b5d…6b8f"
    }
  }
}
```

When a public key is supplied with a relay it allows Vouch to confirm that the bid received from the relay has been signed by that relay.  If Vouch detects an incorrect signature it suggests that either the relay is malfunctioning or the data sent between the relay and Vouch has been intercepted and altered.  As such, Vouch rejects information received from MEV relays with incorrect signatures.

It is possible to specify a minimum value of blocks that are accepted from relays as follows:

```json
{
  "version": 2,
  "fee_recipient": "0x0123…cdef",
  "gas_limit": "30000000",
  "min_value": "0.1",
  "relays": {
    "https://relay1.com/": {
      "public_key": "0xac6e…37ae"
    },
    "https://relay2.com/": {
      "public_key": "0x8b5d…6b8f"
    }
  }
}
```

With the value specified in Ether.  The value can be overridden for specific relays by including it in the relay's configuration:

```json
{
  "version": 2,
  "fee_recipient": "0x0123…cdef",
  "gas_limit": "30000000",
  "min_value": "0.1",
  "relays": {
    "https://relay1.com/": {
      "public_key": "0xac6e…37ae",
      "min_value": "0.2"
    },
    "https://relay2.com/": {
      "public_key": "0x8b5d…6b8f"
    }
  }
}
```

Note that if there is no minimum value specified it is assumed to be 0 _i.e._ any bid from the relay will be considered.

The fee recipient and gas limit can also be overridden for specific relays:

```json
{
  "version": 2,
  "fee_recipient": "0x0123…cdef",
  "gas_limit": "30000000",
  "min_value": "0.1",
  "relays": {
    "https://relay1.com/": {
      "public_key": "0xac6e…37ae",
      "min_value": "0.2"
    },
    "https://relay2.com/": {
      "public_key": "0x8b5d…6b8f",
      "fee_recipient": "0xfedc…3210",
      "gas_limit": "60000000"
    }
  }
}
```

So far, the configurations will apply to all of Vouch's validators when they propose blocks.  It is possible to provide overrides for proposing validators by listing them under the proposer section, for example:

```json
{
  "version": 2,
  "fee_recipient": "0x0123…cdef",
  "gas_limit": "30000000",
  "min_value": "0.1",
  "relays": {
    "https://relay1.com/": {
      "public_key": "0xac6e…37ae",
      "min_value": "0.2"
    },
    "https://relay2.com/": {
      "public_key": "0x8b5d…6b8f",
      "fee_recipient": "0xfedc…3210",
      "gas_limit": "60000000"
    }
  },
  "proposers": [
    {
      "proposer": "0x8021…8bbe",
      "fee_recipient": "0x1111…1111"
    },
    {
      "proposer": "0x8c27…0821",
      "min_value": "0.4"
    }
  ]
}
```

In this case the validator whose public key is `0x8021…8bbe` will use its own fee recipient address, but take the rest of its configuration from the defaults.  Similarly, the validator whose public key is `0x8c27…0821` will use a minimum value of 0.4Ξ for all relays.  It is also possible to override relay-specific information, for example:

```json
{
  "version": 2,
  "fee_recipient": "0x0123…cdef",
  "gas_limit": "30000000",
  "min_value": "0.1",
  "relays": {
    "https://relay1.com/": {
      "public_key": "0xac6e…37ae",
      "min_value": "0.2"
    },
    "https://relay2.com/": {
      "public_key": "0x8b5d…6b8f",
      "fee_recipient": "0xfedc…3210",
      "gas_limit": "60000000"
    }
  },
  "proposers": [
    {
      "proposer": "0x8021…8bbe",
      "relays": {
        "https://relay1.com/": {
          "min_value": "0.5"
        }
      }
    }
  ]
}
```

In this case the validator whose public key is `0x8021…8bbe` will use a minimum value of 0.5Ξ for relay 1, and not use relay 2 at all.

It is also possible to add and remove relays for a particular proposer, for example:

```json
{
  "version": 2,
  "fee_recipient": "0x0123…cdef",
  "gas_limit": "30000000",
  "min_value": "0.1",
  "relays": {
    "https://relay1.com/": {
      "public_key": "0xac6e…37ae",
      "min_value": "0.2"
    },
    "https://relay2.com/": {
      "public_key": "0x8b5d…6b8f",
      "fee_recipient": "0xfedc…3210",
      "gas_limit": "60000000"
    }
  },
  "proposers": [
    {
      "proposer": "0x8021…8bbe",
      "relays": {
        "https://relay2.com/": {
          "disabled": true
        },
        "https://relay3.com/": {}
      }
    }
  ]
}
```

In this case the validator whose public key is `0x8021…8bbe` will use relays 1 and 3, and not relay 2.

Finally, it is possible for a proposer to use their own unique relay configuration, for example:

```json
{
  "version": 2,
  "fee_recipient": "0x0123…cdef",
  "gas_limit": "30000000",
  "min_value": "0.1",
  "relays": {
    "https://relay1.com/": {
      "public_key": "0xac6e…37ae",
      "min_value": "0.2"
    },
    "https://relay2.com/": {
      "public_key": "0x8b5d…6b8f",
      "fee_recipient": "0xfedc…3210",
      "gas_limit": "60000000"
    }
  },
  "proposers": [
    {
      "proposer": "0x8021…8bbe",
      "reset_relays": true,
      "relays": {
        "https://relay3.com/": {},
        "https://relay4.com/": {}
      }
    }
  ]
}
```

In this case the use of `reset_relays` means that the relays for the proposer are only relay 3 and relay 4.

And finally: it is possible to use account specifiers rather than public keys to define proposer-specific configuration.  The advantage of account specifiers is that they can cover multiple validators with a single proposer entry, for example:

```json
{
  "version": 2,
  "fee_recipient": "0x0123…cdef",
  "gas_limit": "30000000",
  "min_value": "0.1",
  "relays": {
    "https://relay1.com/": {
      "public_key": "0xac6e…37ae",
      "min_value": "0.2"
    },
    "https://relay2.com/": {
      "public_key": "0x8b5d…6b8f",
      "fee_recipient": "0xfedc…3210",
      "gas_limit": "60000000"
    }
  },
  "proposers": [
    {
      "proposer": "^Wallet 1/.*$",
      "fee_recipient": "0x1111…1111"
    },
    {
      "proposer": "^Wallet 2/Account [123]$",
      "min_value": "0.4"
    },
    {
      "proposer": "^Wallet 2/Account 4$",
      "reset_relays": true
    }
  ]
}
```

In the above configuration, any account in "Wallet 1" will receive a different fee recipient as per the first proposer rule, accounts "Wallet 2/Account 1", "Wallet 2/Account 2" and "Wallet 2/Account 3" will receive a different minimum value as per the second proposer rule, and account "Wallet 2/Account 4" will not use MEV relays as per the third proposer rule.

An important note about account specifiers as proposers is that they are regular expressions.  This brings a lot of power to users, however care should be taken that the regular expression matches the validators you think it should match (see below for details on testing).  The rules above are specified with implicit start and end anchors (^ and $, respectively) however if these are not supplied they are added by Vouch to reduce the risk of error.

## Processing and precedence

As mentioned above, the order of selection of configuration is as follows:

1. proposer-specific values in the execution configuration
2. default values in the execution configuration
3. fallback values in Vouch configuration

The process that Vouch undertakes to select the configuration is:

1. start with the fallback values
2. overwrite fallback values with default values
3. overwrite fallback and default values with proposer values

However, it is important to understand that the selection of proposer values stops at the first match.  To give a simple example:

```json
{
  "version": 2,
  "fee_recipient": "0x0123…cdef",
  "proposers": [
    {
      "proposer": "Wallet 1/.*",
      "fee_recipient": "0x1111…1111"
    },
    {
      "proposer": "Wallet 1/Account 2",
      "fee_recipient": "0x2222…2222"
    }
  ]
}
```

This configuration will return `0x1111…1111` as the fee recipient for account "Wallet 1/Account 2".  This is because the account matches the first proposer entry, and once the first matching proposer entry is used no further processing takes place.  Note that this is also relevant for public key proposers, where the same public key could be specified multiple times.  This is also relevant for configurations that use both public keys and accounts, as it is possible for the same validator to be specified in these different ways.

In general, the answer is to ensure that the most specific rules are provided first, and the more general ones later.  For example:

```json
{
  "version": 2,
  "fee_recipient": "0x0123…cdef",
  "proposers": [
    {
      "proposer": "Wallet 1/Account 2",
      "fee_recipient": "0x2222…2222"
    },
    {
      "proposer": "Wallet 1/.*",
      "fee_recipient": "0x1111…1111"
    }
  ]
}
```

This configuration will return `0x2222…2222` as the fee recipient for account "Wallet 1/Account 2".

## Testing
Proposing blocks is a relatively rare event, and as such it is useful for users to be able to understand the execution configuration of a specific proposer before it proposes.  Vouch provides a specific command that can be run to obtain the fully specified proposer configuration for a given public key:

```sh
vouch --proposer-config-check 0x8021…8bbe | jq .
{
  "fee_recipient": "000102030405060708090a0b0c0d0e0f10111213",
  "relays": [
    {
      "address": "https://relay2.com/",
      "public_key": "0xa1d1ad0714035353258038e964ae9675dc0252ee22cea896825c01458e1807bfad2f9969338798548d9858a571f7425c",
      "fee_recipient": "0x131211100f0e0d0c0b0a09080706050403020100",
      "gas_limit": "60000000",
      "min_value": "0.1"
    }
  ]
}
```

(Note that in the above example the output is piped to `jq` to provide formatted output.  This step is unnecessary, and everything at and after the `|` character can be removed from the command if desired, or if `jq` is not installed on the server running Vouch.)

This command should be run as the same user and in the same environment as the active Vouch process itself to ensure that the correct configuration information is used.  Note that this command can be run at the same time that a running Vouch instance is operating without interrupting it.

# Transitioning from version 1 to version 2
Version 2 is designed to provide higher flexibility and clarity than version 1.  Key differences are;
- the default configuration is at the top level of the configuration rather than in a separate `default_config` object
- per-relay configuration allows values such as the fee recipient and gas limit to be set, and provids new values such as minimum acceptable bid value
- proposer overrides are supplied as a list, to make precedence rules clear
- proposer overrides can be set at the wallet and account level

In terms of migrating from version 1 to version 2, it is recommended that a new configuration is created to understand and take advantage of the features that are now available.  However, if a quick migration to version 2 is required the following steps should suffice:
- move values in the `default_config` object to the top level of the configuration
- move the `relays` from the `builder` object to the top level of the configuration
- change each relay entry from being a simple string to an object whose `address` field is the previously mentioned string value
- change the `proposer_config` key to `proposers`
- change the `proposer_config` from an map to a list of objects, moving the existing keys to be the value of the `proposer` key in the subobjects
- update relays in proposer entries the same way as was carried out for the default configuration
- ensure that there is a `"version":2` key at the top level of the configuration
