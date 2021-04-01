import "package:bs58check/bs58check.dart" as bs58check;
import "dart:typed_data";
class WIF {
  int version;
  Uint8List privateKey;
  bool compressed;
  WIF({required this.version, required this.privateKey, required this.compressed});
}
WIF decodeRaw(Uint8List buffer, [int? version]) {
  if (version != null && buffer[0] != version) {
    throw new ArgumentError("Invalid network version");
  }
  if (buffer.length == 33) {
    return new WIF(
      version: buffer[0],
      privateKey: buffer.sublist(1, 33),
      compressed: false
    );
  }
  if (buffer.length != 34) {
    throw new ArgumentError("Invalid WIF length");
  }
  if (buffer[33] != 0x01) {
    throw new ArgumentError("Invalid compression flag");
  }
  return new WIF(
      version: buffer[0],
      privateKey: buffer.sublist(1, 33),
      compressed: true
  );
}
Uint8List encodeRaw(int version, Uint8List privateKey, bool compressed) {
  if (privateKey.length != 32) {
    throw new ArgumentError("Invalid privateKey length");
  }
  Uint8List result = new Uint8List(compressed ? 34 : 33);
  ByteData bytes = result.buffer.asByteData();
  bytes.setUint8(0, version);
  result.setRange(1, 33, privateKey);
  if (compressed) {
    result[33] = 0x01;
  }
  return result;
}
WIF decode(String string, [int? version]) {
  return decodeRaw(bs58check.decode(string), version);
}
String encode(WIF wif) {
  return bs58check.encode(
    encodeRaw(
      wif.version,
      wif.privateKey,
      wif.compressed
    )
  );
}