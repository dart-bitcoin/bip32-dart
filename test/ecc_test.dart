import 'package:hex/hex.dart';
import 'package:test/test.dart';
import 'package:bip32/src/utils/ecurve.dart' as ecc;
import 'package:bip32/bip32.dart' as bip32;

final defichain_testnet = bip32.NetworkType(bip32: bip32.Bip32Type(private: 0x04358394, public: 0x043587cf), wif: 0xef);

void main() {
  group("curve test", () {
    test("test private key generation", () {
      // seed
      //55b18e96ce3964ef2c81ad69249eca6d42682c11fbe525df6671fcbf0c2be902 private key

      final hdSeed = bip32.BIP32.fromSeed(
          HEX.decode("6607599b768ce88470b3b20919f9c63bff663e2f1ec3e3072d22fd9da3847784c361d5accc3b411019f5c81dd3e4ccf9fd1fddb232bfc9bfe23864e2e6ee793f"), defichain_testnet);

      final xMasterPriv = bip32.BIP32.fromSeed(hdSeed.privateKey, defichain_testnet);
      final privateKey = xMasterPriv.derivePath("m/0'/0'/0'");

      final privateKeyHex = HEX.encode(privateKey.privateKey);

      expect("55b18e96ce3964ef2c81ad69249eca6d42682c11fbe525df6671fcbf0c2be902", privateKeyHex);
    });

    test("test sign", () {
      ecc.sign(HEX.decode("b11d3d5e4ae12b89d5e3872ccc7d1f96d29b0ab888b67dccf1be5164b811cdbe"), HEX.decode("55b18e96ce3964ef2c81ad69249eca6d42682c11fbe525df6671fcbf0c2be902"));
    });
  });
}
