using LibP2P.Utilities.Extensions;
using Secp256k1Net;

namespace Dotnet.Libp2p.Crypto
{
    public class Secp256k1PublicKey : PublicKey
    {
        private readonly byte[] _k;

        public override KeyType Type => KeyType.Secp256k1;
        public override byte[] Bytes => MarshalKey();

        public Secp256k1PublicKey(byte[] k)
        {
            _k = k;
        }

        public override bool Verify(byte[] data, byte[] signature) => new Secp256k1().Verify(signature, data, _k);

        protected override byte[] MarshalKey() => new PublicKeyContract { Type = Type, Data = _k }.SerializeToBytes();

    }
}
