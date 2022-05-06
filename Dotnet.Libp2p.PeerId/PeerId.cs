using Multiformats.Hash;
using Multiformats.Base;
using System.Text.Json;
using Dotnet.Libp2p.Crypto;
using Org.BouncyCastle.Utilities.Encoders;

namespace Dotnet.Libp2p.PeerId
{
    public class PeerId 
    {
        private byte[] id;
        private byte[] privKey;
        private byte[] pubKey;
        private KeyType type;

        private const byte CIDv1 = 0x01;
        private const byte LIBP2P_KEY_CODE = 0x72;

        public byte[] Id { get => id; set => throw new Exception("Id is immutable"); }
        public byte[] PrivKey { get => privKey; set => privKey = value; }
        public byte[] PubKey { get => pubKey; set => pubKey = value; }
        public KeyType Type { get => type; }

        public PeerId(byte[] _privKey, byte[] _pubKey, byte[] _id)
        {
            privKey = _privKey;
            pubKey = _pubKey;
            id = _id;
            type = (KeyType)id[3];
        }

        public byte[] MarshalPrivKey() 
        {
            if(privKey != null)
            {
                switch (type)
                {
                    case KeyType.RSA:
                        throw new Exception($"Unsupported key type: { Type }");
                    case KeyType.Ed25519:
                        return new Ed25519PrivateKey(privKey).Bytes;
                    case KeyType.Secp256k1:
                        return new Secp256k1PrivateKey(privKey).Bytes;
                    default:
                        throw new Exception($"Unsupported key type: { Type }");
                }
            }
            else
            {
                throw new Exception("Private key is null");
            }            
        }

        public byte[] MarshalPubKey()
        {
            if(pubKey != null)
            {
                switch (type)
                {
                    case KeyType.RSA:
                        throw new Exception($"Unsupported key type: { Type }");
                    case KeyType.Ed25519:
                        return new Ed25519PublicKey(pubKey).Bytes;
                    case KeyType.Secp256k1:
                        return new Secp256k1PublicKey(pubKey).Bytes;
                    default:
                        throw new Exception($"Unsupported key type: { Type }");
                }
            }
            else
            {
                throw new Exception("Public key is null");
            }           
        }
        
        public byte[] UnMarshalPrivKey() => Hex.Decode(PrivateKey.Unmarshal(MarshalPrivKey()).ToString());
        public byte[] UnMarshalPubKey() => Hex.Decode(PublicKey.Unmarshal(MarshalPubKey()).ToString());
        public string DecodeId() => Multihash.Decode(id).ToString().Remove(0, 4);
        public string ToB58String() => Multibase.Encode(MultibaseEncoding.Base58Btc, id).Remove(0, 1);
        public string ToCIDString() => EncodeToCID();        
        public string ToJson() => ConvertToJson();
        public bool IsEqual(PeerId peer) => id.SequenceEqual(peer.id);
        public bool IsValid() => id.SequenceEqual(Multihash.Encode(MarshalPubKey(), HashType.ID));

        private string EncodeToCID()
        {
            byte[] prefix = { CIDv1, LIBP2P_KEY_CODE };
            byte[] multi = prefix.Concat(id).ToArray();

            return Multibase.Encode(MultibaseEncoding.Base32Lower, multi);
        }

        private string ConvertToJson()
        {
            var peerIdJson = new PeerIdJson()
            {
                id = ToB58String(),
                privKey = "undefined",
                pubKey = Multibase.Encode(MultibaseEncoding.Base64, MarshalPubKey()).Remove(0, 1)
            };

            return JsonSerializer.Serialize(peerIdJson);            
        }
    }
}

