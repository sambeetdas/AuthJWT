using Auth.JWT.Common;
using Model;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Common
{
    class Util
    {
        public static string ErrorMessage { get; set; }
        internal static string EncryptStringToBytesAes(string plainText, string strKey, string strBytesIv)
        {

            byte[] Key = hexStringToByte(strKey);

            byte[] IV = hexStringToByte(strBytesIv);
            //Array.Resize(ref IV, 16);

            // Check arguments.
            if (plainText == null || plainText.Length <= 0)
                throw new ArgumentNullException("plainText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");
            byte[] encrypted;
            // Create an Aes object
            // with the specified key and IV.
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;

                // Create a decrytor to perform the stream transform.
                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for encryption.
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {

                            //Write all data to the stream.
                            swEncrypt.Write(plainText);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }

            return Convert.ToBase64String(encrypted);

        }

        internal static string DecryptStringFromBytesAes(string strCipherText, string strKey, string strBytesIv)
        {
            //byte[] cipherText = hexStringToByte(strCipherText);
            byte[] cipherText = Convert.FromBase64String(strCipherText);

            byte[] Key = hexStringToByte(strKey);

            byte[] IV = hexStringToByte(strBytesIv);
            //Array.Resize(ref IV, 16);

            // Check arguments.
            if (cipherText == null || cipherText.Length <= 0)
                throw new ArgumentNullException("cipherText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");

            // Declare the string used to hold
            // the decrypted text.
            string plaintext = null;

            // Create an Aes object
            // with the specified key and IV.
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;

                // Create a decrytor to perform the stream transform.
                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for decryption.
                using (MemoryStream msDecrypt = new MemoryStream(cipherText))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {

                            // Read the decrypted bytes from the decrypting stream
                            // and place them in a string.
                            plaintext = srDecrypt.ReadToEnd();
                        }
                    }
                }

            }

            return plaintext;

        }

        private static byte[] hexStringToByte(String hex)
        {
            int len = (hex.Length / 2);
            byte[] result = new byte[len];
            char[] achar = hex.ToCharArray();
            for (int i = 0; i < len; i++)
            {
                int pos = i * 2;
                result[i] = (byte)(toByte(achar[pos]) << 4 | toByte(achar[pos + 1]));
            }
            return result;
        }

        private static byte toByte(char c)
        {
            byte b = (byte)"0123456789ABCDEF".IndexOf(c);
            return b;
        }

        internal static string Base64Encode(string plainText)
        {
            var plainTextBytes = System.Text.Encoding.UTF8.GetBytes(plainText);
            return System.Convert.ToBase64String(plainTextBytes);
        }

        internal static string Base64Decode(string base64EncodedData)
        {
            var base64EncodedBytes = System.Convert.FromBase64String(base64EncodedData);
            return System.Text.Encoding.UTF8.GetString(base64EncodedBytes);
        }

        internal static string ComputeSha1Hash(string str, string key)
        {
            var encoding = new ASCIIEncoding();
            byte[] signature;
            using (var crypto = new HMACSHA1(encoding.GetBytes(key)))
            {
                signature = crypto.ComputeHash(encoding.GetBytes(str));
            }

            return System.Convert.ToBase64String(signature);
        }

        internal static string ComputeSha256Hash(string str, string key)
        {
            var encoding = new ASCIIEncoding();
            byte[] signature;
            using (var crypto = new HMACSHA256(encoding.GetBytes(key)))
            {
                signature = crypto.ComputeHash(encoding.GetBytes(str));
            }

            return System.Convert.ToBase64String(signature);
        }

        internal static string ComputeSha384Hash(string str, string key)
        {
            var encoding = new ASCIIEncoding();
            byte[] signature;
            using (var crypto = new HMACSHA384(encoding.GetBytes(key)))
            {
                signature = crypto.ComputeHash(encoding.GetBytes(str));
            }

            return System.Convert.ToBase64String(signature);
        }

        internal static string ComputeSha512Hash(string str, string key)
        {
            var encoding = new ASCIIEncoding();
            byte[] signature;
            using (var crypto = new HMACSHA512(encoding.GetBytes(key)))
            {
                signature = crypto.ComputeHash(encoding.GetBytes(str));
            }

            return System.Convert.ToBase64String(signature);
        }

        internal static void ErrorBuilder(string error)
        {
            if (String.IsNullOrWhiteSpace(Util.ErrorMessage))
            {
                Util.ErrorMessage += error;
            }
            else
            {
                Util.ErrorMessage += ", " + error;
            }
            
        }

        internal static void ComputeAlgorithm(string algoritmType, ref Handler.Implementation.JwtHandler.AlgorithDelegate algoritmFunction)
        {
            switch (algoritmType)
            {
                case AlgorithmType.SHA1:
                    algoritmFunction = ComputeSha1Hash;
                    break;
                case AlgorithmType.SHA256:
                    algoritmFunction = ComputeSha256Hash;
                    break;
                case AlgorithmType.SHA384:
                    algoritmFunction = ComputeSha384Hash;
                    break;
                case AlgorithmType.SHA512:
                    algoritmFunction = ComputeSha512Hash;
                    break;
                default:
                    break;
            }
        }
    }
}
