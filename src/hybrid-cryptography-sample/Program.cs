using hybrid_cryptography_sample.Business;
using System;

namespace hybrid_cryptography_sample
{
    class Program
    {
        Manager manager;

        public Program()
        {
            manager = new Manager();
        }

        static void Main(string[] args)
        {
            byte[] EncryptedSimetricKey;
            string Error = null;

            string LockedResult = Manager.LockPackage(out EncryptedSimetricKey, out Error);

            Console.WriteLine(String.Format("Criptografia:    {0}", LockedResult));
            Console.WriteLine(String.Format("Chave Simétrica: {0}", Convert.ToBase64String(EncryptedSimetricKey)));
            Console.WriteLine();

            string OpenPackage = Manager.OpenPackage(LockedResult, EncryptedSimetricKey);
            Console.WriteLine(String.Format("Conteudo:        {0}", OpenPackage));

            Console.ReadLine();

        }
    }
}
