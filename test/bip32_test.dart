import 'dart:typed_data';
import 'package:bip32/bip32.dart';
import 'package:hex/hex.dart';
import 'package:test/test.dart';
import 'dart:io';
import 'dart:convert';

final LITECOIN = new NetworkType(bip32: new Bip32Type(private: 0x019d9cfe, public: 0x019da462), wif: 0xb0);
List<dynamic> validAll = [];

void main() {
  Map<String, dynamic> fixtures = json.decode(File('./test/fixtures.json').readAsStringSync(encoding: utf8));
  (fixtures['valid'] as List<dynamic>).forEach((f) {
    f['master']['network'] = f['network'];
    f['master']['children'] = f['children'];
    f['master']['comment'] = f['comment'];
    (f['children'] as List<dynamic>).forEach((fc) {
      fc['network'] = f['network'];
      validAll.add(fc);
    });
    validAll.add(f['master']);
    validAll.forEach((ff) {
      group(ff['comment'] ?? ff['base58Priv'], () {
        setUp(() {});
        var network;
        if (ff['network'] == 'litecoin') {
          network = LITECOIN;
        }
        var hdPrv = BIP32.fromBase58(ff['base58Priv'], network);
        test('works for private key -> HD wallet', () {
          verify(hdPrv, true, ff, network);
        });

        var hdPub = BIP32.fromBase58(ff['base58'], network);
        test('works for public key -> HD wallet', () {
          verify(hdPub, false, ff, network);
        });

        if (ff['seed'] != null) {
          var seed = HEX.decode(ff['seed']);
          var hdSeed = BIP32.fromSeed(seed as Uint8List, network);
          test('works for seed -> HD wallet', () {
            verify(hdSeed, true, ff, network);
          });
        }
      });
    });
  });

  test('fromBase58 throws', () {
    (fixtures['invalid']['fromBase58'] as List<dynamic>).forEach((f) {
      var network;
      if (f['network'] != null && f['network'] == 'litecoin') network = LITECOIN;
      BIP32? hd;
      try {
        hd = BIP32.fromBase58(f['string'], network);
      } catch (err) {
        expect((err as ArgumentError).message, f['exception']);
      } finally {
        expect(hd, null);
      }
    });
  });

  test('works for Private -> public (neutered)', () {
    final f = fixtures['valid'][1];
    final c = f['master']['children'][0];
    final master = BIP32.fromBase58(f['master']['base58Priv'] as String);
    final child = master.derive(c['m']).neutered();
    expect(child.toBase58(), c['base58']);
  });

  test('works for Private -> public (neutered, hardened)', () {
    final f = fixtures['valid'][0];
    final c = f['master']['children'][0];
    final master = BIP32.fromBase58(f['master']['base58Priv'] as String);
    final child = master.deriveHardened(c['m']).neutered();
    expect(child.toBase58(), c['base58']);
  });

  test('works for Public -> public', () {
    final f = fixtures['valid'][1];
    final c = f['master']['children'][0];
    final master = BIP32.fromBase58(f['master']['base58'] as String);
    final child = master.derive(c['m']);
    expect(child.toBase58(), c['base58']);
  });

  test('throws on Public -> public (hardened)', () {
    final f = fixtures['valid'][0];
    final c = f['master']['children'][0];
    final master = BIP32.fromBase58(f['master']['base58'] as String);
    BIP32? hd;
    try {
      hd = master.deriveHardened(c['m']);
    } catch (err) {
      expect((err as ArgumentError).message, "Missing private key for hardened child key");
    } finally {
      expect(hd, null);
    }
  });

  test('throws on wrong types', () {
    final f = fixtures['valid'][0];
    final master = BIP32.fromBase58(f['master']['base58'] as String);
    (fixtures['invalid']['derive'] as List<dynamic>).forEach((fx) {
      var hd;
      try {
        hd = master.derive(fx);
      } catch (err) {
        expect((err as ArgumentError).message, "Expected UInt32");
      } finally {
        expect(hd, null);
      }
    });
    (fixtures['invalid']['deriveHardened'] as List<dynamic>).forEach((fx) {
      var hd;
      try {
        hd = master.deriveHardened(fx);
      } catch (err) {
        expect((err as ArgumentError).message, "Expected UInt31");
      } finally {
        expect(hd, null);
      }
    });
    (fixtures['invalid']['derivePath'] as List<dynamic>).forEach((fx) {
      var hd;
      try {
        hd = master.derivePath(fx);
      } catch (err) {
        expect((err as ArgumentError).message, "Expected BIP32 Path");
      } finally {
        expect(hd, null);
      }
    });
    var hdFPrv1, hdFPrv2;
    final ZERO32 = Uint8List.fromList(List.generate(32, (index) => 0));
    final ONE32 = Uint8List.fromList(List.generate(32, (index) => 1));
    try {
      hdFPrv1 = BIP32.fromPrivateKey(new Uint8List(2), ONE32);
    } catch (err) {
      expect((err as ArgumentError).message, "Expected property privateKey of type Buffer(Length: 32)");
    } finally {
      expect(hdFPrv1, null);
    }
    try {
      hdFPrv2 = BIP32.fromPrivateKey(ZERO32, ONE32);
    } catch (err) {
      expect((err as ArgumentError).message, "Private key not in range [1, n]");
    } finally {
      expect(hdFPrv2, null);
    }
  });

  test("works when private key has leading zeros", () {
    const key = "xprv9s21ZrQH143K3ckY9DgU79uMTJkQRLdbCCVDh81SnxTgPzLLGax6uHeBULTtaEtcAvKjXfT7ZWtHzKjTpujMkUd9dDb8msDeAfnJxrgAYhr";
    BIP32 hdkey = BIP32.fromBase58(key);
    expect(HEX.encode(hdkey.privateKey!), "00000055378cf5fafb56c711c674143f9b0ee82ab0ba2924f19b64f5ae7cdbfd");
    BIP32 child = hdkey.derivePath("m/44'/0'/0'/0/0'");
    expect(HEX.encode(child.privateKey!), "3348069561d2a0fb925e74bf198762acc47dce7db27372257d2d959a9e6f8aeb");
  });

  test('derive', () {
    final hd = BIP32.fromBase58('xprv9s21ZrQH143K3Jpuz63XbuGs9CH9xG4sniVBBRVm6AJR57D9arxWz6FkXF3JSxSK7jUmVA11AdWa6ZsUtwGztE4QT5i8Y457RRPvMCc39rY');
    final d = hd.derivePath("m/1'/199007533'/627785449'/1521366139'/1'");
    expect(d.toBase58(), 'xprvA39a1i4ieYqGUQ7G1KGnaGzGwm7v3emjms3QN4jZ3HPeubXjshA3XjD5XFaiNgWFvoyC2NV5jN4eFcsVhkrWkvwR4qjdPbue3kpt6Ur3JRf');
  });

  test("fromSeed", () {
    (fixtures['invalid']['fromSeed'] as List<dynamic>).forEach((f) {
      var hd;
      try {
        hd = BIP32.fromSeed(HEX.decode(f['seed']) as Uint8List);
      } catch (err) {
        expect((err as ArgumentError).message, f['exception']);
      } finally {
        expect(hd, null);
      }
    });
  });

  test("ecdsa", () {
    Uint8List seed = Uint8List.fromList(List.generate(32, (index) => 1));
    Uint8List hash = Uint8List.fromList(List.generate(32, (index) => 2));
    String sigStr = "9636ee2fac31b795a308856b821ebe297dda7b28220fb46ea1fbbd7285977cc04c82b734956246a0f15a9698f03f546d8d96fe006c8e7bd2256ca7c8229e6f5c";
    Uint8List signature = HEX.decode(sigStr) as Uint8List;
    BIP32 node = BIP32.fromSeed(seed);
    expect(HEX.encode(node.sign(hash)), sigStr);
    expect(node.verify(hash, signature), true);
    expect(node.verify(seed, signature), false);
  });
}

void verify(BIP32 hd, prv, f, network) {
  expect(HEX.encode(hd.chainCode), f['chainCode']);
  expect(hd.depth, f['depth'] == null ? 0 : f['depth']);
  expect(hd.index, f['index'] == null ? 0 : f['index']);
  expect(HEX.encode(hd.fingerprint), f['fingerprint']);
  expect(HEX.encode(hd.identifier), f['identifier']);
  expect(HEX.encode(hd.publicKey), f['pubKey']);
  if (prv) {
    expect(hd.toBase58(), f['base58Priv']);
    expect(HEX.encode(hd.privateKey!), f['privKey']);
    expect(hd.toWIF(), f['wif']);
  } else {
    expect(hd.privateKey, null);
  }
  expect(hd.neutered().toBase58(), f['base58']);
  expect(hd.isNeutered(), !prv);

  if (f['children'] == null) return;
  if (!prv && (f['children'] as List<dynamic>).map((fc) => fc['hardened']).contains(true)) return;

  (f['children'] as List<dynamic>).forEach((cf) {
    var chd = hd.derivePath(cf['path']);
    verify(chd, prv, cf, network);
    var chdNoM = hd.derivePath((cf['path'] as String).substring(2)); // no m/
    verify(chdNoM, prv, cf, network);
  });

  // test deriving path from successive children
  var shd = hd;
  (f['children'] as List<dynamic>).forEach((cf) {
    if (cf['m'] == null) return;
    if (cf['hardened'] != null && cf['hardened'] as bool) {
      shd = shd.deriveHardened(cf['m']);
    } else {
      // verify any publicly derived children
      if (cf['base58'] != null) verify(shd.neutered().derive(cf['m']), false, cf, network);
      shd = shd.derive(cf['m']);
      verify(shd, prv, cf, network);
    }
  });
}
