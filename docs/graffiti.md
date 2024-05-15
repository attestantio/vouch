# Graffiti providers

## Static
The static graffiti provider uses the same single value for all proposed blocks.  The graffiti is supplied in the "graffiti.static.value" configuration parameter.  For example, to specify the graffiti "my graffiti" in a YAML configuration file the configuration would be:

```YAML
graffiti:
  static:
    value: my graffiti
```

Note that graffiti is a maximum of 32 bytes in length.

## Dynamic
The dynamic graffiti provider uses a majordomo URL to obtain one or more values for proposed blocks.  The dynamic graffiti provider has a number of additional features.  Firstly, the majordomo URL undergoes variable replacement.  The variables that are available for replacement are:

  - {{SLOT}} the slot of the block being proposed
  - {{VALIDATORINDEX}} the index of the validator proposing the block

For example, if the majordomo URL was `file:///home/me/graffiti-{{VALIDATORINDEX}}.txt` then a block being propopsed by validator 15 would result in the majordomo URL `file:///home/me/graffiti-15.txt` being used to fetch the graffiti.

The graffiti is supplied in the "graffiti.dynamic.location" configuration parameter.  For example, to fetch graffiti from the file "/home/me/{{VALIDATORINDEX}}-graffiti.txt" and, if not present, use graffiti from the file "/home/me/graffiti-default.txt" in a YAML configuration file the configuration  would be:

```YAML
graffiti:
  dynamic:
    location: file:///home/me/graffiti-{{VALIDATORINDEX}}.txt
    fallback-location: file:///home/me/graffiti-default.txt
```

The location and fallback locations are fetched each time a block is proposed, so if in the above example the contents of the file change the graffiti in the next proposed block will alter likewise.

Once the data has been obtained from the supplied location or fallback location the resultant data is separated in to multiple lines (blank lines are removed).  If there is more than one line in the data then one of the lines is picked at random (note that vouch retains no memory of which lines have or have not been selected, so it is possible for the same line to be picked multiple times before another line is picked once).

The graffiti line also undergoes variable replacement for slot and validator index, as per above.  At this point the final result is used as the graffiti for the proposed block.

Note that graffiti is a maximum of 32 bytes in length.  Any resultant graffiti longer than this will be truncated.
