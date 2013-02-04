/******************************************************************************
*	Copyright 2013 Prospective Software Inc.
*	Licensed under the Apache License, Version 2.0 (the "License");
*	you may not use this file except in compliance with the License.
*	You may obtain a copy of the License at
*
*		http://www.apache.org/licenses/LICENSE-2.0
*
*	Unless required by applicable law or agreed to in writing, software
*	distributed under the License is distributed on an "AS IS" BASIS,
*	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*	See the License for the specific language governing permissions and
*	limitations under the License.
******************************************************************************/

using System;
using System.Collections.Generic;
using System.IO;
using Windows.Security.Cryptography;
using Windows.Security.Cryptography.Core;

namespace System.Utilities.Cryptography
{
	/// <summary>
	/// Provides encryption and decryption capabilites using 128-bit, 192-bit, and 256-bit AES encryption methods.
	/// This implementation is FIPS compliant.
	/// </summary>
	public static class Encryption
	{
		private const int Bits128 = 16;
		private const int Bits192 = 24;
		private const int Bits256 = 32;

		#region - Key Generation Functions -

		private struct KeyData
		{
			public byte[] Key;
			public byte[] IV;
		}

		//Computes an 128-bit Initialization Vector
		private static KeyData GenerateKeyIV128(byte[] Key)
		{
			// Generate the Initialization Vector.
			byte[] IVH = Hash.Compute512Byte(Key);
			var IV = new byte[Bits128];
			for (int i = 0; i < Bits128; i++)
				IV[i] = IVH[i];

			//Make sure the key is the proper length and fix it if needed.
			if (Key.Length != Bits128)
			{
				var TempKey = new List<byte>(Key);
				int c = Bits128;
				while (TempKey.Count != Bits128)
				{
					if (TempKey.Count < Bits128)
						TempKey.Add(IVH[c++]);
					else if (TempKey.Count > Bits128)
						TempKey.RemoveAt(0);
					else
						break;
					if (c > IVH.Length - 1) c = Bits128;
				}
				Key = TempKey.ToArray();
			}

			var NK = new KeyData { Key = Key, IV = IV };
			return NK;
		}

		//Computes an 192-bit Initialization Vector
		private static KeyData GenerateKeyIV192(byte[] Key)
		{
			// Generate the Initialization Vector.
			byte[] IVH = Hash.Compute512Byte(Key);
			var IV = new byte[Bits192];
			for (int i = 0; i < Bits192; i++)
				IV[i] = IVH[i];

			//Make sure the key is the proper length and fix it if needed.
			if (Key.Length != Bits192)
			{
				var TempKey = new List<byte>(Key);
				int c = Bits192;
				while (TempKey.Count != Bits192)
				{
					if (TempKey.Count < Bits192)
						TempKey.Add(IVH[c++]);
					else if (TempKey.Count > Bits192)
						TempKey.RemoveAt(0);
					else
						break;
					if (c > IVH.Length - 1) c = Bits192;
				}
				Key = TempKey.ToArray();
			}

			var NK = new KeyData { Key = Key, IV = IV };
			return NK;
		}

		//Computes an 256-bit Initialization Vector
		private static KeyData GenerateKeyIV256(byte[] Key)
		{
			// Generate the Initialization Vector.
			byte[] IVH = Hash.Compute512Byte(Key);
			var IV = new byte[Bits256];
			for (int i = 0; i < Bits256; i++)
				IV[i] = IVH[i];

			//Make sure the key is the proper length and fix it if needed.
			if (Key.Length != Bits256)
			{
				var TempKey = new List<byte>(Key);
				int c = Bits256;
				while (TempKey.Count != Bits256)
				{
					if (TempKey.Count < Bits256)
						TempKey.Add(IVH[c++]);
					else if (TempKey.Count > Bits256)
						TempKey.RemoveAt(0);
					else
						break;
					if (c > IVH.Length - 1) c = Bits256;
				}
				Key = TempKey.ToArray();
			}

			var NK = new KeyData{ Key = Key, IV = IV };
			return NK;
		}

		#endregion

		#region - 128-Bit Functions -

		/// <summary>
		/// Encrypts the specified data using a 128-bit cipher. The key can be any length.
		/// </summary>
		/// <param name="Data">The data to be encrypted.</param>
		/// <param name="Key">The key used to encrypt the data.</param>
		/// <returns>A Base-64 string containing the encoded data.</returns>
		public static string Encrypt128Base64(string Data, byte[] Key)
		{
			KeyData KeyData = GenerateKeyIV128(Key);
			SymmetricKeyAlgorithmProvider AES = SymmetricKeyAlgorithmProvider.OpenAlgorithm(SymmetricAlgorithmNames.AesCbcPkcs7);
			return CryptographicBuffer.EncodeToBase64String(CryptographicEngine.Encrypt(AES.CreateSymmetricKey(CryptographicBuffer.CreateFromByteArray(KeyData.Key)), CryptographicBuffer.ConvertStringToBinary(Data, BinaryStringEncoding.Utf8), CryptographicBuffer.CreateFromByteArray(KeyData.IV)));
		}

		/// <summary>
		/// Encrypts the specified data using a 128-bit cipher. The key can be any length.
		/// </summary>
		/// <param name="Data">The data to be encrypted.</param>
		/// <param name="Key">The key used to encrypt the data.</param>
		/// <returns>A byte array containing the encoded data.</returns>
		public static byte[] Encrypt128Byte(string Data, byte[] Key)
		{
			KeyData KeyData = GenerateKeyIV128(Key);
			SymmetricKeyAlgorithmProvider AES = SymmetricKeyAlgorithmProvider.OpenAlgorithm(SymmetricAlgorithmNames.AesCbcPkcs7);
			byte[] ret;
			CryptographicBuffer.CopyToByteArray(CryptographicEngine.Encrypt(AES.CreateSymmetricKey(CryptographicBuffer.CreateFromByteArray(KeyData.Key)), CryptographicBuffer.ConvertStringToBinary(Data, BinaryStringEncoding.Utf8), CryptographicBuffer.CreateFromByteArray(KeyData.IV)), out ret);
			return ret;
		}

		/// <summary>
		/// Encrypts the specified data using a 128-bit cipher. The key can be any length.
		/// </summary>
		/// <param name="Data">The data to be encrypted.</param>
		/// <param name="Key">The key used to encrypt the data.</param>
		/// <returns>A Base-64 string containing the encoded data.</returns>
		public static string Encrypt128Base64(byte[] Data, byte[] Key)
		{
			KeyData KeyData = GenerateKeyIV128(Key);
			SymmetricKeyAlgorithmProvider AES = SymmetricKeyAlgorithmProvider.OpenAlgorithm(SymmetricAlgorithmNames.AesCbcPkcs7);
			return CryptographicBuffer.EncodeToBase64String(CryptographicEngine.Encrypt(AES.CreateSymmetricKey(CryptographicBuffer.CreateFromByteArray(KeyData.Key)), CryptographicBuffer.CreateFromByteArray(Data), CryptographicBuffer.CreateFromByteArray(KeyData.IV)));
		}

		/// <summary>
		/// Encrypts the specified data using a 128-bit cipher. The key can be any length.
		/// </summary>
		/// <param name="Data">The data to be encrypted.</param>
		/// <param name="Key">The key used to encrypt the data.</param>
		/// <returns>A byte array containing the encoded data.</returns>
		public static byte[] Encrypt128Byte(byte[] Data, byte[] Key)
		{
			KeyData KeyData = GenerateKeyIV128(Key);
			SymmetricKeyAlgorithmProvider AES = SymmetricKeyAlgorithmProvider.OpenAlgorithm(SymmetricAlgorithmNames.AesCbcPkcs7);
			byte[] ret;
			CryptographicBuffer.CopyToByteArray(CryptographicEngine.Encrypt(AES.CreateSymmetricKey(CryptographicBuffer.CreateFromByteArray(KeyData.Key)), CryptographicBuffer.CreateFromByteArray(Data), CryptographicBuffer.CreateFromByteArray(KeyData.IV)), out ret);
			return ret;
		}

		/// <summary>
		/// Decrypts the specified data using a 128-bit cipher. The key can be any length.
		/// </summary>
		/// <param name="Data">The data to be decrypted.</param>
		/// <param name="Key">The key used to decrypt the data.</param>
		/// <returns>A string containing the decoded data.</returns>
		public static string Decrypt128String(byte[] Data, byte[] Key)
		{
			KeyData KeyData = GenerateKeyIV128(Key);
			SymmetricKeyAlgorithmProvider AES = SymmetricKeyAlgorithmProvider.OpenAlgorithm(SymmetricAlgorithmNames.AesCbcPkcs7);
			return CryptographicBuffer.ConvertBinaryToString(BinaryStringEncoding.Utf8, CryptographicEngine.Decrypt(AES.CreateSymmetricKey(CryptographicBuffer.CreateFromByteArray(KeyData.Key)), CryptographicBuffer.CreateFromByteArray(Data), CryptographicBuffer.CreateFromByteArray(KeyData.IV)));
		}

		/// <summary>
		/// Decrypts the specified data using a 128-bit cipher. The key can be any length.
		/// </summary>
		/// <param name="Data">The data to be decrypted.</param>
		/// <param name="Key">The key used to decrypt the data.</param>
		/// <returns>A string containing the decoded data.</returns>
		public static byte[] Decrypt128Byte(byte[] Data, byte[] Key)
		{
			KeyData KeyData = GenerateKeyIV128(Key);
			SymmetricKeyAlgorithmProvider AES = SymmetricKeyAlgorithmProvider.OpenAlgorithm(SymmetricAlgorithmNames.AesCbcPkcs7);
			byte[] ret;
			CryptographicBuffer.CopyToByteArray(CryptographicEngine.Decrypt(AES.CreateSymmetricKey(CryptographicBuffer.CreateFromByteArray(KeyData.Key)), CryptographicBuffer.CreateFromByteArray(Data), CryptographicBuffer.CreateFromByteArray(KeyData.IV)), out ret);
			return ret;
		}

		#endregion

		#region - 192-Bit Functions -

		/// <summary>
		/// Encrypts the specified data using a 192-bit cipher. The key can be any length.
		/// </summary>
		/// <param name="Data">The data to be encrypted.</param>
		/// <param name="Key">The key used to encrypt the data.</param>
		/// <returns>A Base-64 string containing the encoded data.</returns>
		public static string Encrypt192Base64(string Data, byte[] Key)
		{
			KeyData KeyData = GenerateKeyIV192(Key);
			SymmetricKeyAlgorithmProvider AES = SymmetricKeyAlgorithmProvider.OpenAlgorithm(SymmetricAlgorithmNames.AesCbcPkcs7);
			return CryptographicBuffer.EncodeToBase64String(CryptographicEngine.Encrypt(AES.CreateSymmetricKey(CryptographicBuffer.CreateFromByteArray(KeyData.Key)), CryptographicBuffer.ConvertStringToBinary(Data, BinaryStringEncoding.Utf8), CryptographicBuffer.CreateFromByteArray(KeyData.IV)));
		}

		/// <summary>
		/// Encrypts the specified data using a 192-bit cipher. The key can be any length.
		/// </summary>
		/// <param name="Data">The data to be encrypted.</param>
		/// <param name="Key">The key used to encrypt the data.</param>
		/// <returns>A byte array containing the encoded data.</returns>
		public static byte[] Encrypt192Byte(string Data, byte[] Key)
		{
			KeyData KeyData = GenerateKeyIV192(Key);
			SymmetricKeyAlgorithmProvider AES = SymmetricKeyAlgorithmProvider.OpenAlgorithm(SymmetricAlgorithmNames.AesCbcPkcs7);
			byte[] ret;
			CryptographicBuffer.CopyToByteArray(CryptographicEngine.Encrypt(AES.CreateSymmetricKey(CryptographicBuffer.CreateFromByteArray(KeyData.Key)), CryptographicBuffer.ConvertStringToBinary(Data, BinaryStringEncoding.Utf8), CryptographicBuffer.CreateFromByteArray(KeyData.IV)), out ret);
			return ret;
		}

		/// <summary>
		/// Encrypts the specified data using a 192-bit cipher. The key can be any length.
		/// </summary>
		/// <param name="Data">The data to be encrypted.</param>
		/// <param name="Key">The key used to encrypt the data.</param>
		/// <returns>A Base-64 string containing the encoded data.</returns>
		public static string Encrypt192Base64(byte[] Data, byte[] Key)
		{
			KeyData KeyData = GenerateKeyIV192(Key);
			SymmetricKeyAlgorithmProvider AES = SymmetricKeyAlgorithmProvider.OpenAlgorithm(SymmetricAlgorithmNames.AesCbcPkcs7);
			return CryptographicBuffer.EncodeToBase64String(CryptographicEngine.Encrypt(AES.CreateSymmetricKey(CryptographicBuffer.CreateFromByteArray(KeyData.Key)), CryptographicBuffer.CreateFromByteArray(Data), CryptographicBuffer.CreateFromByteArray(KeyData.IV)));
		}

		/// <summary>
		/// Encrypts the specified data using a 192-bit cipher. The key can be any length.
		/// </summary>
		/// <param name="Data">The data to be encrypted.</param>
		/// <param name="Key">The key used to encrypt the data.</param>
		/// <returns>A byte array containing the encoded data.</returns>
		public static byte[] Encrypt192Byte(byte[] Data, byte[] Key)
		{
			KeyData KeyData = GenerateKeyIV192(Key);
			SymmetricKeyAlgorithmProvider AES = SymmetricKeyAlgorithmProvider.OpenAlgorithm(SymmetricAlgorithmNames.AesCbcPkcs7);
			byte[] ret;
			CryptographicBuffer.CopyToByteArray(CryptographicEngine.Encrypt(AES.CreateSymmetricKey(CryptographicBuffer.CreateFromByteArray(KeyData.Key)), CryptographicBuffer.CreateFromByteArray(Data), CryptographicBuffer.CreateFromByteArray(KeyData.IV)), out ret);
			return ret;
		}

		/// <summary>
		/// Decrypts the specified data using a 192-bit cipher. The key can be any length.
		/// </summary>
		/// <param name="Data">The data to be decrypted.</param>
		/// <param name="Key">The key used to decrypt the data.</param>
		/// <returns>A string containing the decoded data.</returns>
		public static string Decrypt192String(byte[] Data, byte[] Key)
		{
			KeyData KeyData = GenerateKeyIV192(Key);
			SymmetricKeyAlgorithmProvider AES = SymmetricKeyAlgorithmProvider.OpenAlgorithm(SymmetricAlgorithmNames.AesCbcPkcs7);
			return CryptographicBuffer.ConvertBinaryToString(BinaryStringEncoding.Utf8, CryptographicEngine.Decrypt(AES.CreateSymmetricKey(CryptographicBuffer.CreateFromByteArray(KeyData.Key)), CryptographicBuffer.CreateFromByteArray(Data), CryptographicBuffer.CreateFromByteArray(KeyData.IV)));
		}

		/// <summary>
		/// Decrypts the specified data using a 192-bit cipher. The key can be any length.
		/// </summary>
		/// <param name="Data">The data to be decrypted.</param>
		/// <param name="Key">The key used to decrypt the data.</param>
		/// <returns>A string containing the decoded data.</returns>
		public static byte[] Decrypt192Byte(byte[] Data, byte[] Key)
		{
			KeyData KeyData = GenerateKeyIV192(Key);
			SymmetricKeyAlgorithmProvider AES = SymmetricKeyAlgorithmProvider.OpenAlgorithm(SymmetricAlgorithmNames.AesCbcPkcs7);
			byte[] ret;
			CryptographicBuffer.CopyToByteArray(CryptographicEngine.Decrypt(AES.CreateSymmetricKey(CryptographicBuffer.CreateFromByteArray(KeyData.Key)), CryptographicBuffer.CreateFromByteArray(Data), CryptographicBuffer.CreateFromByteArray(KeyData.IV)), out ret);
			return ret;
		}

		#endregion

		#region - 256-Bit Functions -

		/// <summary>
		/// Encrypts the specified data using a 256-bit cipher. The key can be any length.
		/// </summary>
		/// <param name="Data">The data to be encrypted.</param>
		/// <param name="Key">The key used to encrypt the data.</param>
		/// <returns>A Base-64 string containing the encoded data.</returns>
		public static string Encrypt256Base64(string Data, byte[] Key)
		{
			KeyData KeyData = GenerateKeyIV256(Key);
			SymmetricKeyAlgorithmProvider AES = SymmetricKeyAlgorithmProvider.OpenAlgorithm(SymmetricAlgorithmNames.AesCbcPkcs7);
			return CryptographicBuffer.EncodeToBase64String(CryptographicEngine.Encrypt(AES.CreateSymmetricKey(CryptographicBuffer.CreateFromByteArray(KeyData.Key)), CryptographicBuffer.ConvertStringToBinary(Data, BinaryStringEncoding.Utf8), CryptographicBuffer.CreateFromByteArray(KeyData.IV)));
		}

		/// <summary>
		/// Encrypts the specified data using a 256-bit cipher. The key can be any length.
		/// </summary>
		/// <param name="Data">The data to be encrypted.</param>
		/// <param name="Key">The key used to encrypt the data.</param>
		/// <returns>A byte array containing the encoded data.</returns>
		public static byte[] Encrypt256Byte(string Data, byte[] Key)
		{
			KeyData KeyData = GenerateKeyIV256(Key);
			SymmetricKeyAlgorithmProvider AES = SymmetricKeyAlgorithmProvider.OpenAlgorithm(SymmetricAlgorithmNames.AesCbcPkcs7);
			byte[] ret;
			CryptographicBuffer.CopyToByteArray(CryptographicEngine.Encrypt(AES.CreateSymmetricKey(CryptographicBuffer.CreateFromByteArray(KeyData.Key)), CryptographicBuffer.ConvertStringToBinary(Data, BinaryStringEncoding.Utf8), CryptographicBuffer.CreateFromByteArray(KeyData.IV)), out ret);
			return ret;
		}

		/// <summary>
		/// Encrypts the specified data using a 256-bit cipher. The key can be any length.
		/// </summary>
		/// <param name="Data">The data to be encrypted.</param>
		/// <param name="Key">The key used to encrypt the data.</param>
		/// <returns>A Base-64 string containing the encoded data.</returns>
		public static string Encrypt256Base64(byte[] Data, byte[] Key)
		{
			KeyData KeyData = GenerateKeyIV256(Key);
			SymmetricKeyAlgorithmProvider AES = SymmetricKeyAlgorithmProvider.OpenAlgorithm(SymmetricAlgorithmNames.AesCbcPkcs7);
			return CryptographicBuffer.EncodeToBase64String(CryptographicEngine.Encrypt(AES.CreateSymmetricKey(CryptographicBuffer.CreateFromByteArray(KeyData.Key)), CryptographicBuffer.CreateFromByteArray(Data), CryptographicBuffer.CreateFromByteArray(KeyData.IV)));
		}

		/// <summary>
		/// Encrypts the specified data using a 256-bit cipher. The key can be any length.
		/// </summary>
		/// <param name="Data">The data to be encrypted.</param>
		/// <param name="Key">The key used to encrypt the data.</param>
		/// <returns>A byte array containing the encoded data.</returns>
		public static byte[] Encrypt256Byte(byte[] Data, byte[] Key)
		{
			KeyData KeyData = GenerateKeyIV256(Key);
			SymmetricKeyAlgorithmProvider AES = SymmetricKeyAlgorithmProvider.OpenAlgorithm(SymmetricAlgorithmNames.AesCbcPkcs7);
			byte[] ret;
			CryptographicBuffer.CopyToByteArray(CryptographicEngine.Encrypt(AES.CreateSymmetricKey(CryptographicBuffer.CreateFromByteArray(KeyData.Key)), CryptographicBuffer.CreateFromByteArray(Data), CryptographicBuffer.CreateFromByteArray(KeyData.IV)), out ret);
			return ret;
		}

		/// <summary>
		/// Decrypts the specified data using a 256-bit cipher. The key can be any length.
		/// </summary>
		/// <param name="Data">The data to be decrypted.</param>
		/// <param name="Key">The key used to decrypt the data.</param>
		/// <returns>A string containing the decoded data.</returns>
		public static string Decrypt256String(byte[] Data, byte[] Key)
		{
			KeyData KeyData = GenerateKeyIV256(Key);
			SymmetricKeyAlgorithmProvider AES = SymmetricKeyAlgorithmProvider.OpenAlgorithm(SymmetricAlgorithmNames.AesCbcPkcs7);
			return CryptographicBuffer.ConvertBinaryToString(BinaryStringEncoding.Utf8, CryptographicEngine.Decrypt(AES.CreateSymmetricKey(CryptographicBuffer.CreateFromByteArray(KeyData.Key)), CryptographicBuffer.CreateFromByteArray(Data), CryptographicBuffer.CreateFromByteArray(KeyData.IV)));
		}

		/// <summary>
		/// Decrypts the specified data using a 256-bit cipher. The key can be any length.
		/// </summary>
		/// <param name="Data">The data to be decrypted.</param>
		/// <param name="Key">The key used to decrypt the data.</param>
		/// <returns>A string containing the decoded data.</returns>
		public static byte[] Decrypt256Byte(byte[] Data, byte[] Key)
		{
			KeyData KeyData = GenerateKeyIV256(Key);
			SymmetricKeyAlgorithmProvider AES = SymmetricKeyAlgorithmProvider.OpenAlgorithm(SymmetricAlgorithmNames.AesCbcPkcs7);
			byte[] ret;
			CryptographicBuffer.CopyToByteArray(CryptographicEngine.Decrypt(AES.CreateSymmetricKey(CryptographicBuffer.CreateFromByteArray(KeyData.Key)), CryptographicBuffer.CreateFromByteArray(Data), CryptographicBuffer.CreateFromByteArray(KeyData.IV)), out ret);
			return ret;
		}

		#endregion
	}
}