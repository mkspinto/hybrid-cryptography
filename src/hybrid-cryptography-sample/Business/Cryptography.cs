using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace hybrid_cryptography_sample.Business
{
    public class Cryptography
    {
        #region [Cryptography Methods]

        public string EncryptData(string content, out byte[] outKey)
        {
            byte[] SymetricKey = GenerateRandomicKey();
            string Encrypted = Encrypt(content, SymetricKey);

            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            {
                rsa.FromXmlString(SSLCertificate.GetPublicKey());
                outKey = rsa.Encrypt(SymetricKey, true);

                return Encrypted;
            }
        }

        public static byte[] GenerateRandomicKey()
        {
            var rng = new RNGCryptoServiceProvider();
            byte[] sessionKey = new byte[24];

            rng.GetBytes(sessionKey);

            for (var i = 0; i < sessionKey.Length; ++i)
            {
                int keyByte = sessionKey[i] & 0xFE;
                var parity = 0;
                for (var b = keyByte; b != 0; b >>= 1) parity ^= b & 1;
                sessionKey[i] = (byte)(keyByte | (parity == 0 ? 1 : 0));
            }

            return (sessionKey);
        }

        public static string Encrypt(string message, byte[] pswdBytes)
        {
            byte[] messageBytes = Encoding.UTF8.GetBytes(message);

            TripleDESCryptoServiceProvider provider = new TripleDESCryptoServiceProvider();
            ICryptoTransform transform = provider.CreateEncryptor(pswdBytes, pswdBytes);
            CryptoStreamMode mode = CryptoStreamMode.Write;

            MemoryStream memStream = new MemoryStream();
            CryptoStream cryptoStream = new CryptoStream(memStream, transform, mode);
            cryptoStream.Write(messageBytes, 0, messageBytes.Length);
            cryptoStream.FlushFinalBlock();

            byte[] encryptedMessageBytes = new byte[memStream.Length];
            memStream.Position = 0;
            memStream.Read(encryptedMessageBytes, 0, encryptedMessageBytes.Length);

            return Convert.ToBase64String(encryptedMessageBytes);
        }

        #endregion

        #region [Decrypt Methods]

        public static byte[] DecryptSymetricKeyWithCertificatePrivateKey(byte[] key)
        {
            X509Certificate2 Certificate = SSLCertificate.GetValidCertificate();
            var PrivateKey = Certificate.PrivateKey as RSACryptoServiceProvider;

            return PrivateKey.Decrypt(key, true);
        }

        public static byte[] DecryptData(string encryptedMessage, byte[] sessionKey)
        {
            byte[] encryptedMessageBytes = Convert.FromBase64String(encryptedMessage);

            TripleDESCryptoServiceProvider provider = new TripleDESCryptoServiceProvider();
            ICryptoTransform transform = provider.CreateDecryptor(sessionKey, sessionKey);
            CryptoStreamMode mode = CryptoStreamMode.Write;

            MemoryStream memStream = new MemoryStream();
            CryptoStream cryptoStream = new CryptoStream(memStream, transform, mode);
            cryptoStream.Write(encryptedMessageBytes, 0, encryptedMessageBytes.Length);
            cryptoStream.FlushFinalBlock();

            byte[] decryptedMessageBytes = new byte[memStream.Length];
            memStream.Position = 0;
            memStream.Read(decryptedMessageBytes, 0, decryptedMessageBytes.Length);

            return (decryptedMessageBytes);
        }

        #endregion
    }
}
