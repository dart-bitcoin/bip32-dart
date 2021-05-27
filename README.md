# bip32

A [BIP32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki) compatible library for Flutter writing in Dart.

Inspired by [bitcoinjs](https://github.com/bitcoinjs/bip32)

## Example
```dart

import 'package:bip32/bip32.dart' as bip32;
import 'package:hex/hex.dart';

main() {
  bip32.BIP32 node = bip32.BIP32.fromBase58('xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi');

  print(HEX.encode(node.privateKey));
  // => e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35

  bip32.BIP32 nodeNeutered = node.neutered();
  print(nodeNeutered.isNeutered());
  // => true

  print(HEX.encode(nodeNeutered.publicKey));
  // => 0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2

  print(nodeNeutered.toBase58());
  // => xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8

  bip32.BIP32 child = node.derivePath('m/0/0');
  print(child.toBase58());
  // => xprv9ww7sMFLzJMzur2oEQDB642fbsMS4q6JRraMVTrM9bTWBq7NDS8ZpmsKVB4YF3mZecqax1fjnsPF19xnsJNfRp4RSyexacULXMKowSACTRc

  print(HEX.encode(child.privateKey));
  // => f26cf12f89ab91aeeb8d7324a22e8ba080829db15c9245414b073a8c342322aa

  bip32.BIP32 childNeutered = child.neutered();
  print(childNeutered.isNeutered());
  // => true

  print(HEX.encode(childNeutered.publicKey));
  // => 02756de182c5dd4b717ea87e693006da62dbb3cddaa4a5cad2ed1f5bbab755f0f5

  print(childNeutered.toBase58());
  // => xpub6AvUGrnEpfvJ8L7GLRkBTByQ9uBvUHp9o5VxHrFxhvzV4dSWkySpNaBoLR9FpbnwRmTa69yLHF3QfcaxbWT7gWdwws5k4dpmJvqpEuMWwnj

  bip32.BIP32 nodeFromSeed = bip32.BIP32.fromSeed(HEX.decode("000102030405060708090a0b0c0d0e0f"));
  print(nodeFromSeed.toBase58());
  // => xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi

  bip32.BIP32 nodeFromPub = bip32.BIP32.fromBase58("xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8");
  print(nodeFromPub.toBase58());
  // => xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8

  var message = HEX.decode("0202020202020202020202020202020202020202020202020202020202020202");
  var signature = nodeFromSeed.sign(message);
  print(signature);
  // => [63, 219, 20, 114, 95, 184, 192, 55, 216, 206, 126, 121, 17, 71, 64, 70, 163, 82, 247, 73, 243, 95, 30, 137, 177, 155, 100, 225, 177, 203, 217, 147, 122, 64, 208, 129, 54, 133, 113, 41, 216, 160, 191, 15, 136, 98, 235, 25, 219, 178, 70, 222, 127, 151, 135, 242, 25, 192, 161, 187, 187, 84, 81, 215]

  print(HEX.encode(signature));
  // => 3fdb14725fb8c037d8ce7e7911474046a352f749f35f1e89b19b64e1b1cbd9937a40d08136857129d8a0bf0f8862eb19dbb246de7f9787f219c0a1bbbb5451d7

  print(nodeFromSeed.verify(message, signature));
  // => true
}

```

## Contributor
  * anicdh <anic.dh@gmail.com>
  * p3root 
  * jcramer (null-safety)
