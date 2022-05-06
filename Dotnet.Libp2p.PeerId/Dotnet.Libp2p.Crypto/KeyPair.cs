﻿using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Secp256k1Net;

namespace Dotnet.Libp2p.Crypto
{
    public class KeyPair
    {
        /// <summary>
        /// The Private Key of the Pair
        /// </summary>
        /// <returns>Private Key</returns>
        public PrivateKey PrivateKey { get; }

        /// <summary>
        /// The Public Key of the Pair
        /// </summary>
        /// <returns>Public Key</returns>
        public PublicKey PublicKey { get; }

        protected KeyPair(PrivateKey privateKey, PublicKey publicKey)
        {
            PrivateKey = privateKey;
            PublicKey = publicKey;
        }

        /// <summary>
        /// Generate a new key pair
        /// </summary>
        /// <param name="type">Key type</param>
        /// <param name="bits">Bits (optional)</param>
        /// <returns>A newly generated key pair</returns>
        public static KeyPair Generate(KeyType type, int? bits = null)
        {
            switch (type)
            {
                case KeyType.RSA:
                    return GenerateRsaKeyPair(bits);
                case KeyType.Ed25519:
                    return GenerateEd25519KeyPair();
                case KeyType.Secp256k1:
                    return GenerateSecp256K1KeyPair();
                default:
                    throw new NotSupportedException();
            }
        }

        private static KeyPair GenerateRsaKeyPair(int? bits)
        {
            var generator = new RsaKeyPairGenerator();
            generator.Init(new KeyGenerationParameters(new SecureRandom(), bits ?? 512));
            var pair = generator.GenerateKeyPair();
            var priv = (RsaPrivateCrtKeyParameters)pair.Private;
            var pub = (RsaKeyParameters)pair.Public;
            var pk = new RsaPublicKey(pub);
            var sk = new RsaPrivateKey(priv, pub);

            return new KeyPair(sk, pk);
        }

        private static KeyPair GenerateEd25519KeyPair()
        {
            Ed25519PrivateKeyParameters ed25519PrivateKey = new Ed25519PrivateKeyParameters(new SecureRandom());        
            Ed25519PublicKeyParameters ed25519PublicKey = ed25519PrivateKey.GeneratePublicKey();                
            
            var sk = new Ed25519PrivateKey(ed25519PrivateKey.GetEncoded());                
            var pk = new Ed25519PublicKey(ed25519PublicKey.GetEncoded());
            
            return new KeyPair(sk, pk);                   
        }

        private static KeyPair GenerateSecp256K1KeyPair()
        {
            using (var secp256k1 = new Secp256k1())
            {
                // Private key
                var priv = new byte[32];
                var rnd = System.Security.Cryptography.RandomNumberGenerator.Create();
                do { rnd.GetBytes(priv); }
                while (!secp256k1.SecretKeyVerify(priv));
                var sk = new Secp256k1PrivateKey(priv);

                // Create public key from private key.
                var pk = new Secp256k1PublicKey(sk.GetPublic().Bytes.Skip(4).ToArray());
                
                // Clear unmanaged memory 
                secp256k1.Dispose();
                return new KeyPair(sk, pk);
            }
        }
    }
}