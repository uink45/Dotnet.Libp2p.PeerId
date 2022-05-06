using LibP2P.Utilities.Extensions;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;


namespace Dotnet.Libp2p.Crypto
{
    public class Ed25519PublicKey : PublicKey
    {
        private readonly byte[] _k;
        private readonly Ed25519Signer _signer;

        public override KeyType Type => KeyType.Ed25519;
        public override byte[] Bytes => MarshalKey();

        public Ed25519PublicKey(byte[] k)
        {
            _k = k;
            _signer = new Ed25519Signer();
            _signer.Init(false, new Ed25519PublicKeyParameters(_k, 0));
        }

        public override bool Verify(byte[] data, byte[] signature) => _signer.Verify(data, signature);

        protected override byte[] MarshalKey() => new PublicKeyContract { Type = Type, Data = _k }.SerializeToBytes();
    }
}