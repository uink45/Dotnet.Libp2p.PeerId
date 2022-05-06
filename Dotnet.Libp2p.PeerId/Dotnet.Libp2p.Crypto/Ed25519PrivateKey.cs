using LibP2P.Utilities.Extensions;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

namespace Dotnet.Libp2p.Crypto
{
    public class Ed25519PrivateKey : PrivateKey
    {
        private readonly byte[] _sk;
        private readonly byte[] _pk;
        private readonly Ed25519Signer _signer; 
        public override KeyType Type => KeyType.Ed25519;
        public override byte[] Bytes => Marshal();
        
        public Ed25519PrivateKey(byte[] sk, byte[] pk = null)
        {
            _sk = sk;
            _pk = pk ?? new Ed25519PrivateKeyParameters(sk, 0).GeneratePublicKey().GetEncoded();
            _signer = new Ed25519Signer();
            _signer.Init(true, new Ed25519PrivateKeyParameters(sk, 0));            
        }

        public new static PrivateKey Unmarshal(byte[] data)
        {
            if (data.Length != 96)
                throw new Exception("invalid length");

            var priv = data.Slice(0, 64);
            var pub = data.Slice(64, 32);

            return new Ed25519PrivateKey(priv, pub);
        }

        public override byte[] Sign(byte[] data) =>  _signer.Sign(data);
        public override PublicKey GetPublic() => new Ed25519PublicKey(_pk);

        protected override byte[] MarshalKey() => _sk.Concat(_pk).ToArray();
    }
}