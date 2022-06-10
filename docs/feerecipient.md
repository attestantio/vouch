# Fee recipients
Fee recipients are the recipients of execution block rewards.  Each block has a fee recipient, and transaction fees and direct payments to this address will be provided to the fee recipient.  The fee recipient can be set on an individual block basis, or

## Default fee recipient
Vouch must have a default fee recipient, or else it will refuse to start.  This can be configured simply with the following lines in your `.vouch.yml` configuration file:

```YAML
feerecipient:
  default-address: '0x0000000000000000000000000000000000000001'
```

This fee recipient will be used for all blocks proposed by Vouch unless more specific information is obtained as per below.

## Static fee recipient
The static fee recipient provider takes fee recipient information from Vouch's configuration file.  A typical configuration may look as follows:

```YAML
feerecipient:
  default-address: '0x0000000000000000000000000000000000000001'
  static:
    validator-addresses:
      11: '0x000000000000000000000000000000000000000a',
      16: '0x000000000000000000000000000000000000000b',
      29: '0x000000000000000000000000000000000000000c'
```

With the above configuration, the validator with index 11 on the beacon chain will use `0x00...0a` as its fee recipient, the validator with index 16 on the beacon chain will use `0x00...0b` as its fee recipient, and the validator with index 29 on the beacon chain will use `0x00...0c` as its fee recipient.  All other validators will use the default address `0x00...01` as their fee recipient.

## Remote fee recipient
The remote fee recipient provider takes fee recipient information from a remote endpoint via a periodic REST request.  A typical configuration may look as follows:

```YAML
feerecipient:
  default-address: '0x0000000000000000000000000000000000000001'
  remote:
    base-url: 'http://provider.example.com/'
```

With the above configuration, Vouch will connect to the URL 'http://provider.example.com/feerecipients' on startup and periodically after that, and obtain a list of fee recipients for each index for which it is validating.  Specifically, it sends a POST request to the aforementioned URL with a body as follows:

``JSON
{
  "indices":
  [
    11,
    16,
    29
  ]
}
``

where in this case `11,16,29` are the consensus indices of the validators for which Vouch is validating.  The response from the endpoint should be of the form:

```JSON
{
  "fee_recipients": [
    "index":11,"fee_recipient":"0x000000000000000000000000000000000000000a",
    "index":16,"fee_recipient":"0x000000000000000000000000000000000000000b",
    "index":29,"fee_recipient":"0x000000000000000000000000000000000000000c",
  ]
}

```

_i.e._ an entry for each requested index with details of the fee recipient address.

Each time Vouch fetches this information it will replace the old data with the information received.  This provides maximum flexibility for situations where the fee recipient may change over time, and can update the fee recipient without requiring a restart of Vouch.

*Note that if both the remote and static fee recipient providers are configured then the remote provider will be used.*

# Which to use?
If you are running Vouch in an environment where you own all validators then you can set a default fee recipient; no further configuration is required.

If you are running Vouch in an environment where each validator has its own fee recipient, for purposes of separation of funds to different end users, then you can use the static fee recipients provider.

If you are running Vouch in an environment where each validator's fee recipient may change, for example if you are providing a service and as part of that service customers may alter their fee recipient address, then you can use the remote fee recipients provider.
