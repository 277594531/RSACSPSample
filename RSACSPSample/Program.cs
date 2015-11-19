using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.Cryptography;

namespace RSACSPSample
{
    class Program
    {
        static void Main(string[] args)
        {
            try
            {
                //Create a UnicodeEncoder to convert between byte array and string.
                UnicodeEncoding ByteConverter = new UnicodeEncoding();

                //Create byte arrays to hold original, encrypted, and decrypted data. 
                byte[] dataToEncrypt = ByteConverter.GetBytes("Data to Encrypt");
                byte[] encryptedData;
                byte[] decryptedData;

                //Create a new instance of RSACryptoServiceProvider to generate 
                //public and private key data. 

                string KeyContainerName = "MyKeyContainer";

                //Create a new key and persist it in  
                //the key container.
                RSAPersistKeyInCSP(KeyContainerName);
                
                using (RSACryptoServiceProvider RSA = new RSACryptoServiceProvider())
                {
                    //System.IO.StringWriter sw = new System.IO.StringWriter();
                    System.IO.StreamWriter st = System.IO.File.CreateText(@"D:\temp\publicKey.xml");
                    st.Write(RSA.ToXmlString(false));
                    st.Close();

                    System.IO.StreamWriter st1 = System.IO.File.CreateText(@"D:\temp\privateKey.xml");
                    st1.Write(RSA.ToXmlString(true));
                    st1.Close();

                    System.IO.StreamReader sr = new System.IO.StreamReader(@"D:\temp\publicKey.xml");
                    string publicKey = sr.ReadLine();
                    RSA.FromXmlString(publicKey);

                    Console.WriteLine(RSA.ToXmlString(false));
                    Console.WriteLine(RSA.ToXmlString(true));

                    //Pass the data to ENCRYPT, the public key information  
                    //(using RSACryptoServiceProvider.ExportParameters(false), 
                    //and a boolean flag specifying no OAEP padding.
                    encryptedData = RSAEncrypt(dataToEncrypt, RSA.ExportParameters(false), false);

                    //Pass the data to DECRYPT, the private key information  
                    //(using RSACryptoServiceProvider.ExportParameters(true), 
                    //and a boolean flag specifying no OAEP padding.
                    decryptedData = RSADecrypt(encryptedData, RSA.ExportParameters(true), false);

                    //Display the decrypted plaintext to the console. 
                    Console.WriteLine("Decrypted plaintext: {0}", ByteConverter.GetString(decryptedData));
                }
            }
            catch (ArgumentNullException)
            {
                //Catch this exception in case the encryption did 
                //not succeed.
                Console.WriteLine("Encryption failed.");

            }
        }

        static public byte[] RSAEncrypt(byte[] DataToEncrypt, RSAParameters RSAKeyInfo, bool DoOAEPPadding)
        {
            try
            {
                byte[] encryptedData;
                //Create a new instance of RSACryptoServiceProvider. 
                using (RSACryptoServiceProvider RSA = new RSACryptoServiceProvider())
                {

                    //Import the RSA Key information. This only needs 
                    //toinclude the public key information.
                    RSA.ImportParameters(RSAKeyInfo);

                    //Encrypt the passed byte array and specify OAEP padding.   
                    //OAEP padding is only available on Microsoft Windows XP or 
                    //later.  
                    encryptedData = RSA.Encrypt(DataToEncrypt, DoOAEPPadding);
                }
                return encryptedData;
            }
            //Catch and display a CryptographicException   
            //to the console. 
            catch (CryptographicException e)
            {
                Console.WriteLine(e.Message);

                return null;
            }

        }

        static public byte[] RSADecrypt(byte[] DataToDecrypt, RSAParameters RSAKeyInfo, bool DoOAEPPadding)
        {
            try
            {
                byte[] decryptedData;
                //Create a new instance of RSACryptoServiceProvider. 
                using (RSACryptoServiceProvider RSA = new RSACryptoServiceProvider())
                {
                    //Import the RSA Key information. This needs 
                    //to include the private key information.
                    RSA.ImportParameters(RSAKeyInfo);

                    //Decrypt the passed byte array and specify OAEP padding.   
                    //OAEP padding is only available on Microsoft Windows XP or 
                    //later.  
                    decryptedData = RSA.Decrypt(DataToDecrypt, DoOAEPPadding);
                }
                return decryptedData;
            }
            //Catch and display a CryptographicException   
            //to the console. 
            catch (CryptographicException e)
            {
                Console.WriteLine(e.ToString());

                return null;
            }

        }

        public static void RSAPersistKeyInCSP(string ContainerName)
        {
            try
            {
                // Create a new instance of CspParameters.  Pass 
                // 13 to specify a DSA container or 1 to specify 
                // an RSA container.  The default is 1.
                CspParameters cspParams = new CspParameters();

                // Specify the container name using the passed variable.
                cspParams.KeyContainerName = ContainerName;

                //Create a new instance of RSACryptoServiceProvider to generate 
                //a new key pair.  Pass the CspParameters class to persist the  
                //key in the container.
                RSACryptoServiceProvider RSAalg = new RSACryptoServiceProvider(cspParams);

                //Indicate that the key was persisted.
                Console.WriteLine("The RSA key was persisted in the container, \"{0}\".", ContainerName);
            }
            catch (CryptographicException e)
            {
                Console.WriteLine(e.Message);

            }
        }

        public static void RSADeleteKeyInCSP(string ContainerName)
        {
            try
            {
                // Create a new instance of CspParameters.  Pass 
                // 13 to specify a DSA container or 1 to specify 
                // an RSA container.  The default is 1.
                CspParameters cspParams = new CspParameters();

                // Specify the container name using the passed variable.
                cspParams.KeyContainerName = ContainerName;

                //Create a new instance of RSACryptoServiceProvider.  
                //Pass the CspParameters class to use the  
                //key in the container.
                RSACryptoServiceProvider RSAalg = new RSACryptoServiceProvider(cspParams);

                //Delete the key entry in the container.
                RSAalg.PersistKeyInCsp = false;

                //Call Clear to release resources and delete the key from the container.
                RSAalg.Clear();

                //Indicate that the key was persisted.
                Console.WriteLine("The RSA key was deleted from the container, \"{0}\".", ContainerName);
            }
            catch (CryptographicException e)
            {
                Console.WriteLine(e.Message);

            }
        }






    }
}
