# PushWarden

PushWarden is a modified version of Bitwarden's open-source client code. It adds a second
encryption level ("level 2") whose passwords are only released after approval on your phone
or with a separate password.

**PushWarden is not affiliated with, endorsed by, or supported by Bitwarden, Inc.**
"Bitwarden" is a trademark of Bitwarden, Inc.; it is used here only to describe compatibility
and the origin of the code. Report PushWarden problems to PushWarden, not to Bitwarden.

## License

This fork is licensed under the GNU General Public License v3.0 (see `LICENSE_GPL.txt` or
`LICENSE.txt`). It is built without any code under the Bitwarden License (the
`bitwarden_license/` directories), which may not be used in production or distributed.

## Changes from upstream

Modified 2026 by PushWarden contributors:

- level 2 encryption, phone approval and pairing (`l2` packages/directories);
- fill, copy and save guards so level 2 values are never filled as ciphertext or saved as
  plaintext;
- new name, package id and icons.

Upstream: https://github.com/bitwarden
