using System.Diagnostics;
using Secp256k1Net;

namespace Dotnet.Libp2p.Crypto
{
    public class Secp256k1PrivateKey : PrivateKey
    {
        private readonly byte[] _sk;
        private readonly byte[] _pk;

        public override KeyType Type => KeyType.Secp256k1;
        public override byte[] Bytes => Marshal();

        public Secp256k1PrivateKey(byte[] sk, byte[] pk = null)
        {
            _sk = sk;
            if (pk == null)
            {
                _pk = new byte[33];
                byte[] bytes = new byte[64];
                using(var secp256k1 = new Secp256k1())
                {
                    Debug.Assert(secp256k1.PublicKeyCreate(bytes, sk));
                    Debug.Assert(secp256k1.PublicKeySerialize(_pk, bytes, Flags.SECP256K1_EC_COMPRESSED));
                    secp256k1.Dispose();
                }
            }
            else
            {
                _pk = pk;
            }
        }

        public new static PrivateKey Unmarshal(byte[] data)
        {
            return new Secp256k1PrivateKey(data);
        }

        public override byte[] Sign(byte[] data) => SignData(data);
        public override PublicKey GetPublic() => new Secp256k1PublicKey(_pk);

        protected override byte[] MarshalKey() => _sk;

        private byte[] SignData(byte[] data)
        {
            byte[] sig = new byte[33];
            
            using(var secp256k1 = new Secp256k1())
            {
                secp256k1.Sign(sig, data, _sk);
                secp256k1.Dispose();
            }
            return sig;
        }
    }
}
