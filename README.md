# bip32

A [BIP32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki) compatible library for Flutter writing by Dart.


## Example
``` dart
import 'package:bip32/bip32.dart' as bip32;
BIP32 node = bip32.fromBase58('xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi')
BIP32 child = node.derivePath('m/0/0')
// ...
```
