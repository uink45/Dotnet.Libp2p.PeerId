using Org.BouncyCastle.Utilities.Encoders;
using Dotnet.Libp2p.Crypto;
using Multiformats.Hash;
using Multiformats.Base;

namespace Dotnet.Libp2p.PeerId
{
    public class PeerIdExtensions
    {
        public static PeerId GenerateNew(KeyType keyType)
        {
            KeyPair newKeys = KeyPair.Generate(keyType);

            return CreatePeerId(newKeys.PublicKey.Bytes, newKeys.PrivateKey.Bytes);
        }

        public static PeerId CreateFromPrivKey(KeyType keyType, byte[] _privKey)
        {
            switch (keyType)
            {
                case KeyType.RSA:
                    throw new Exception($"Unsupported key type: { keyType }");
                case KeyType.Ed25519:
                    return CreateFromEd25519PrivKey(_privKey);
                case KeyType.Secp256k1:
                    return CreateFromSecp256k1PrivKey(_privKey);
                default:
                    throw new Exception($"Unsupported key type: { keyType }");
            }
        }

        public static PeerId CreateFromPubKey(byte[] _pubKey)
        {
            return CreatePeerId(_pubKey, _pubKey);
        }

        public static PeerId CreateFromBytes(byte[] idBytes)
        {
            return CreatePeerId(idBytes.Skip(2).ToArray());
        }

        public static PeerId CreateFromB58String(string b58String)
        {
            return CreatePeerId(Multibase.DecodeRaw(MultibaseEncoding.Base58Btc, b58String).Skip(2).ToArray());
        }

        public static PeerId CreateFromHexString(string idHexString)
        {
            return CreatePeerId(Hex.Decode(idHexString).Skip(2).ToArray());
        }

        public static PeerId CreateFromCIDV1(string CIDV1)
        {
            CIDV1 = CIDV1.StartsWith("b") ? CIDV1.Substring(1) : throw new Exception("Invalid CID provided. Must start with prefix 'b'.");
            byte[] output = Multibase.DecodeRaw(MultibaseEncoding.Base32Lower, CIDV1).Skip(4).ToArray();
            return CreatePeerId(output);
        }

        public static PeerId CreateFromJson(PeerIdJson peerIdJson)
        {
            if(peerIdJson.privKey == "undefined")
            {
                return CreatePeerId(Multibase.DecodeRaw(MultibaseEncoding.Base58Btc, peerIdJson.id).Skip(2).ToArray());
            }

            return CreatePeerId(Multibase.DecodeRaw(MultibaseEncoding.Base58Btc, peerIdJson.id).Skip(2).ToArray(), Multibase.DecodeRaw(MultibaseEncoding.Base64, peerIdJson.privKey));
        }

        private static PeerId CreateFromEd25519PrivKey(byte[] _privKey)
        {
            Ed25519PrivateKey ed25519PrivateKey = new Ed25519PrivateKey(_privKey);

            return CreatePeerId(ed25519PrivateKey.GetPublic().Bytes, ed25519PrivateKey.Bytes);
        }

        private static PeerId CreateFromSecp256k1PrivKey(byte[] _privKey)
        {
            Secp256k1PrivateKey secp256K1PrivateKey = new Secp256k1PrivateKey(_privKey);
            Secp256k1PublicKey secp256K1PublicKey = new Secp256k1PublicKey(secp256K1PrivateKey.GetPublic().Bytes);           

            return CreatePeerId(secp256K1PublicKey.Bytes, secp256K1PrivateKey.Bytes);
        }

        private static PeerId CreatePeerId(byte[] _pubKey, byte[] _privKey = null)
        {
            byte[] privKey = _privKey == null ? new byte[0] : _privKey.Skip(4).ToArray();
            byte[] pubKey = _pubKey.Skip(4).ToArray();
            byte[] id = ComputeIdFromBytes(_pubKey);

            return new PeerId(privKey, pubKey, id);
        }

        private static byte[] ComputeIdFromBytes(byte[] data)
        {
            return data.Length <= 42 ? Multihash.Encode(data, HashType.ID) : Multihash.Encode(data, HashType.SHA2_256);
        }
    }
}
