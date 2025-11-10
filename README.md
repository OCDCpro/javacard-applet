# LAYR Javacard Access Control Protocol

This repository contains the Java Card applets that are used for the first iteration of our open-source chip design competition,
which is about the creation of an ASIC to be deployed in an electronic door lock.

The following variants are included:

- `IdentificationApplet`: Implements a basic unauthenticated and unencrypted protocol that simply returns a programmable ID.
This is intended to be used for the lowest challenge level only.

- `AuthenticatedIdentificationApplet`: Implements a challenge-response protocol with mutual authentication and key agreement
based on AES-128. This is intended to be used for all advanced challenge levels.

## Contact and Support

Please contact Niklas Höher ([niklas.hoeher@rub.de](mailto:niklas.hoeher@rub.de)) if you have any questions, comments, or if you found a bug that should be corrected.

## Identification Applet

Simply return the card identifier upon receiving a corresponding request without any authentication or encryption.

### Protocol / Command Summary

| Command     | CLA  | INS  | Description                              |
|-------------|------|------|------------------------------------------|
| `GET_ID`    | 0x80 | 0x12 | Returns the unencrypted 16-byte card ID. |               

For an example sequence, execute the included protocol flow test case.

## Authenticated Identification Applet
    
### Overview

Both parties have knowledge over a long-term shared AES-128 key.
This key is used to perform mutual authentication and key agreement via a
challenge-response protocol to derive an ephemeral AES-128 session key which
is then used to encrypt the exchanged data, which mainly correspond to the
ID of the card.

- **AES Mode**: AES-128 ECB, no padding

### Protocol / Command Summary
| Command     | CLA  | INS  | Description                                                                                                                                                                                         |
|-------------|------|------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `AUTH_INIT` | 0x80 | 0x10 | Card  generates random 8-byte challenge `rc`, computes `AES_psk(rc \|\| 00..00)` using the pre-shared key and returns the ciphertext.                                                               |
| `AUTH`      | 0x80 | 0x11 | Terminal decrypts the ciphertext to recover `rc`, generates its own 8-byte challenge `rt`, and proves possesion of the key to the card by returning `AES_psk(rt \|\| rc)` using the pre-shared key. |
| `GET_ID`    | 0x80 | 0x12 | Derive an ephemeral AES session key as `k_eph = AES_psk(rc \|\| rt)` and returns the 16-byte card ID encrypted using that key if authentication was successful.                                     |

For an example sequence, execute the included protocol flow test case.

## Building

To compile the applets yourself, run the `buildJavaCard` gradle task:

```bash
./gradlew buildJavaCard --info --rerun-tasks
```

The resulting `.cap` file (contains both applets) will be located in `./applet/build/javacard/`.

## Running Tests

To execute all available tests for both applets, execute the following command:
```
./gradlew test --info --rerun-tasks
```

Within the corresponding test classes (`IdentificationAppletTest` and `AuthenticatedIdentificationAppletTest`), you can
also change the `CARD_TYPE` variable to execute tests on a physically connected smart card instead of in the simulator.

Output:

```
> Task :applet:test

AuthenticatedIdentificationAppletTest > testCorrectProtocolFlow() PASSED

IdentificationAppletTest > testCorrectProtocolFlow() PASSED

Deprecated Gradle features were used in this build, making it incompatible with Gradle 9.0.

You can use '--warning-mode all' to show the individual deprecation warnings and determine if they come from your own scripts or plugins.

For more on this, please refer to https://docs.gradle.org/8.8/userguide/command_line_interface.html#sec:command_line_warnings in the Gradle documentation.

BUILD SUCCESSFUL in 745ms
4 actionable tasks: 1 executed, 3 up-to-date

```

## Installation on a Physical Card

To flash the applets onto a physical card, you need the [GlobalPlatformPro](https://github.com/martinpaljak/GlobalPlatformPro) utility.
Follow the provided installation instructions and execute the following commands:

```bash
# Remove old versions of the applets (not required upon initial installation)
gp -uninstall ocdcpro.cap
# Load the .cap file containing both applets onto the card
gp -load ocdcpro.cap
# Install the IdentificationApplet with applet ID "F000000CDC00" and ID "00000000000000000000000000000001"
gp -cap ocdcpro.cap -create F000000CDC00 --applet F000000CDC00  --params 00000000000000000000000000000001
# Install the AuthenticatedIdentificationApplet with applet ID "F000000CDC01", pre-shared AES key "00112233445566778899AABBCCDDEEFF", and ID "00000000000000000000000000000001" 
gp -cap ocdcpro.cap -create F000000CDC01 --applet F000000CDC01  --params 00112233445566778899AABBCCDDEEFF00000000000000000000000000000001
```

## Acknowledgements
This project is based on the [Java Card Gradle Template](https://github.com/ph4r05/javacard-gradle-template) by [ph4r05](https://github.com/ph4r05).
