using System;
using System.IO;
using System.Text;

namespace hybrid_cryptography_sample.Business
{
    public class Manager
    {
        public static string LockPackage(out byte[] encryptedSymetricKey, out string error)
        {
            error = null;

            try
            {
                string Content = "{\"Nome\": \"Marcos Oliveira Pinto\", \"Idade\": \"22\"}";
                return new Cryptography().EncryptData(Content, out encryptedSymetricKey);
            }
            catch (Exception ex)
            {
                error = ex.Message;
                encryptedSymetricKey = null;

                return null;
            }
        }

        public static string OpenPackage(string content, byte[] encryptedSimetricKey)
        {
            try
            {
                byte[] SimetricKey = Cryptography.DecryptSymetricKeyWithCertificatePrivateKey(encryptedSimetricKey);
                byte[] Content = Cryptography.DecryptData(content, SimetricKey);

                return Encoding.UTF8.GetString(Content);
            }
            catch (Exception)
            {

                throw;
            }
        }
    }
}