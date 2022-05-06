using System;
using ProtoBuf;

namespace Dotnet.Libp2p.Crypto
{
    [ProtoContract]
    internal class PublicKeyContract
    {
        [ProtoMember(1, IsRequired = true)]
        public KeyType Type { get; set; } = 0;

        [ProtoMember(2, IsRequired = true)]
        public byte[] Data { get; set; } = Array.Empty<byte>();
    }
}