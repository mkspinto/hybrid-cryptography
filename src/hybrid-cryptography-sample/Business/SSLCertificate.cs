using System;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace hybrid_cryptography_sample.Business
{
    public class SSLCertificate
    {
        /// <summary>
        /// Responsável por recuperar a chave pública do certificado digital
        /// </summary>
        /// <returns>string</returns>
        public static string GetPublicKey()
        {
            var certificate = GetValidCertificate();
            var publicKey = ((RSACryptoServiceProvider)certificate.PublicKey.Key);

            return (publicKey.ToXmlString(false));
        }

        /// <summary>
        /// Responsável por procurar na store do Windows o Certificado Digital
        /// baseado no "Serial Number" informado
        /// </summary>
        /// <returns>X509Certificate2</returns>
        /// <remarks>
        /// O certificado digital do serial informado deve estar instalado
        /// corretamente na store do computador que rodar o programa
        /// </remarks>
        public static X509Certificate2 GetValidCertificate()
        {
            using (X509Store store = new X509Store(StoreName.Root, StoreLocation.LocalMachine))
            {
                store.Open(OpenFlags.ReadOnly);

                try
                {
                    X509Certificate2Collection certificate = store.Certificates.Find(X509FindType.FindBySerialNumber, "6a83b48e3d985495484c8c09c7ab0d6d", false);

                    if (certificate.Count > 0)
                        return (certificate[0]);

                    throw new SecurityException("Certificado não encontrado");
                }
                catch (Exception)
                {
                    throw;
                }
            }
        }
    }
}