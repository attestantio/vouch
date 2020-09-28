# Majordomo

Vouch uses [majordomo](https://github.com/wealdtech/go-majordomo) for many of its data fetching features.  This document describes the supported confidants, and their configuration options.

## Direct confidant
The direct confidant supplies values directly within the URL.  The format of the URL is `direct://key`.  For example, the URL `direct://Text` would provide the value "Text".

The direct confidant is configured automatically by Vouch.

## File confidant
The file confidant fetches values from the location specified by URL.  The format of the URL is `file://key` For example, the URL `file:///home/me/file.txt` would provide the contents of the file "/home/me/file.txt".

The file confidant is configured automatically by Vouch.

## Google Secret Manager confidant
The Google Secret Manager (GSM) confidant fetches values from [Google Secret Manager](https://cloud.google.com/secret-manager).  The format of the URL is `gsm://id@project/key` For example, the URL `gsm:///me@myproject/mysecret` would provide the contents of the secret labelled "mykey" in the project "myproject".

The GSM confidant has two configuration options.  Credentials are required to allow majordomo to access the secrets.  These are service account credentials in JSON format, available from the Google cloud console.  The path to the credentials file is supplied in the "majordomo.gsm.credentials" configuration parameter.

The second configuration option is the project ID.  This is optional, and can be supplied directly in the majordomo URL if required as seen above.  If the project ID is supplied as a configuration option the majordomo URL can be shorted to the form `gsm://id/key`.

For example, to specify the GSM credentials and project in a YAML configuration file the configuration would be:

```YAML
majordomo:
  gsm:
    credentials: /home/me/gsmcredentials.json
    project: my_project
```

## AWS Secrets Manager confidant
The AWS Secrets Manager (ASM) confidant fetches values from [AWS Secrets Manager](https://aws.amazon.com/secrets-manager/).  The format of the URL is `asm://id:secret@region/key` For example, the URL `asm:///AKIAITXFKX5JWOXJDJKA:8R06MHGKayTFHkuK8@eu-central-1/mysecret` would provide the contents of the secret "mysecret" from the region "eu-central-1".

The ASM confidant has three configuration options.  Region is required to inform majordomo form where to fetch secrets.  This is an Amazon region, such as "us-east-1" or "ap-southeast-2".  The region is supplied in the "majordomo.asm.region" configuration parameter.

The second and third configuration options are the ID and secret of an AWS account that has access to read the secrets.  These values are supplied in the "majordomo.asm.id" and "majordomo.asm.secret" configuration parameters, respectively.

If the parameters are supplied in the configuration they are not required to be supplied in the majordomo URL as well.  If all parameters are supplied in the configuration then the URLs can simply be of the form `asm://key`.

For example, to specify the ASM credentials and region in a YAML configuration file the configuration would be:

```YAML
majordomo:
  asm:
    id: AKIAITXFKX5JWOXJDJKA
    secret: 8R06MHGKayTFHkuK8
    region: eu-central-1
```
