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
using Windows.Security.Cryptography;
using Windows.Security.Cryptography.Core;

namespace System.Utilities.Cryptography
{
	/// <summary>
	/// Provides hash computation services using the SHA-2 family of algorithms. It supports 256-bit, 384-bit, and 512-bit hashes.
	/// This implementation is FIPS compliant.
	/// The functions are named in the following fashion:
	/// The first section indicates the operation being performed.
	/// The second section indicates the bit length of the hash.
	/// The third section notes the formatted return value of the hash.
	/// </summary>
	public static class Hash
	{
		private readonly static HashAlgorithmProvider SHA256;
		private readonly static HashAlgorithmProvider SHA384;
		private readonly static HashAlgorithmProvider SHA512;

		static Hash()
		{
			SHA256 = HashAlgorithmProvider.OpenAlgorithm("SHA256");
			SHA384 = HashAlgorithmProvider.OpenAlgorithm("SHA384");
			SHA512 = HashAlgorithmProvider.OpenAlgorithm("SHA512");
		}

		/// <summary>
		/// Generates a 256-bit hash for the given data and returns the generated results as a Base-64 string.
		/// </summary>
		/// <param name="Data">The data to be hashed. Takes a string.</param>
		/// <returns>Hash value formatted as a Base-64 string.</returns>
		public static string Compute256Base64(string Data)
		{
			return CryptographicBuffer.EncodeToBase64String(SHA256.HashData(CryptographicBuffer.ConvertStringToBinary(Data, BinaryStringEncoding.Utf8)));
		}

		/// <summary>
		/// Generates a 256-bit hash for the given data and returns the generated results as a Base-64 string.
		/// </summary>
		/// <param name="Data">The data to be hashed. Takes an array of bytes.</param>
		/// <returns>Hash value formatted as a Base-64 string.</returns>
		public static string Compute256Base64(byte[] Data)
		{
			return CryptographicBuffer.EncodeToBase64String(SHA256.HashData(CryptographicBuffer.CreateFromByteArray(Data)));
		}

		/// <summary>
		/// Generates a 256-bit hash for the given data using the specified Salt value and returns the generated results as an Base-64 string.
		/// </summary>
		/// <param name="Data">The data to be hashed. Takes an array of bytes.</param>
		/// <param name="Salt">The salt value used to help prevent dictionary attacks. Takes an array of bytes.</param>
		/// <returns>Hash value formatted as a Base-64 string.</returns>
		public static string Compute256Base64(IEnumerable<byte> Data, IEnumerable<byte> Salt)
		{
			var TD = new List<byte>(Data);
			var TS = new List<byte>(Salt);

			//The Salt Algorithm
			TD.AddRange(TS);
			foreach (byte b in TS)
			{
				TD.Insert(0, b);
				TD.Insert(TD.Count - 1, b);
			}

			return CryptographicBuffer.EncodeToBase64String(SHA256.HashData(CryptographicBuffer.CreateFromByteArray(TD.ToArray())));
		}

		/// <summary>
		/// Generates a 256-bit hash for the given data and returns the generated results as a hexadecimal string.
		/// </summary>
		/// <param name="Data">The data to be hashed. Takes a string.</param>
		/// <returns>Hash value formatted as a hexadecimal string.</returns>
		public static string Compute256Hex(string Data)
		{
			return CryptographicBuffer.EncodeToHexString(SHA256.HashData(CryptographicBuffer.ConvertStringToBinary(Data, BinaryStringEncoding.Utf8)));
		}

		/// <summary>
		/// Generates a 256-bit hash for the given data and returns the generated results as a hexadecimal string.
		/// </summary>
		/// <param name="Data">The data to be hashed. Takes an array of bytes.</param>
		/// <returns>Hash value formatted as a hexadecimal string.</returns>
		public static string Compute256Hex(byte[] Data)
		{
			return CryptographicBuffer.EncodeToHexString(SHA256.HashData(CryptographicBuffer.CreateFromByteArray(Data)));
		}

		/// <summary>
		/// Generates a 256-bit hash for the given data using the specified Salt value and returns the generated results as a hexadecimal string.
		/// </summary>
		/// <param name="Data">The data to be hashed. Takes an array of bytes.</param>
		/// <param name="Salt">The salt value used to help prevent dictionary attacks. Takes an array of bytes.</param>
		/// <returns>Hash value formatted as a hexadecimal string.</returns>
		public static string Compute256Hex(IEnumerable<byte> Data, IEnumerable<byte> Salt)
		{
			var TD = new List<byte>(Data);
			var TS = new List<byte>(Salt);

			//The Salt Algorithm
			TD.AddRange(TS);
			foreach (byte b in TS)
			{
				TD.Insert(0, b);
				TD.Insert(TD.Count - 1, b);
			}

			return CryptographicBuffer.EncodeToHexString(SHA256.HashData(CryptographicBuffer.CreateFromByteArray(TD.ToArray())));
		}

		/// <summary>
		/// Generates a 256-bit hash for the given data and returns the generated results as an array of bytes.
		/// </summary>
		/// <param name="Data">The data to be hashed. Takes a string.</param>
		/// <returns>Hash value formatted as a byte array.</returns>
		public static byte[] Compute256Byte(string Data)
		{
			byte[] ret;
			CryptographicBuffer.CopyToByteArray(SHA256.HashData(CryptographicBuffer.ConvertStringToBinary(Data, BinaryStringEncoding.Utf8)), out ret);
			return ret;
		}

		/// <summary>
		/// Generates a 256-bit hash for the given data and returns the generated results as an array of bytes.
		/// </summary>
		/// <param name="Data">The data to be hashed. Takes an array of bytes.</param>
		/// <returns>Hash value formatted as a byte array.</returns>
		public static byte[] Compute256Byte(byte[] Data)
		{
			byte[] ret;
			CryptographicBuffer.CopyToByteArray(SHA256.HashData(CryptographicBuffer.CreateFromByteArray(Data)), out ret);
			return ret;
		}

		/// <summary>
		/// Generates a 256-bit hash for the given data using the specified Salt value and returns the generated results as an array of bytes.
		/// </summary>
		/// <param name="Data">The data to be hashed. Takes an array of bytes.</param>
		/// <param name="Salt">The salt value used to help prevent dictionary attacks. Takes an array of bytes.</param>
		/// <returns>Hash value formatted as a byte array.</returns>
		public static byte[] Compute256Byte(IEnumerable<byte> Data, IEnumerable<byte> Salt)
		{
			var TD = new List<byte>(Data);
			var TS = new List<byte>(Salt);

			//The Salt Algorithm
			TD.AddRange(TS);
			foreach (byte b in TS)
			{
				TD.Insert(0, b);
				TD.Insert(TD.Count - 1, b);
			}

			byte[] ret;
			CryptographicBuffer.CopyToByteArray(SHA256.HashData(CryptographicBuffer.CreateFromByteArray(TD.ToArray())), out ret);
			return ret;
		}

		/// <summary>
		/// Generates a 384-bit hash for the given data and returns the generated results as a Base-64 string.
		/// </summary>
		/// <param name="Data">The data to be hashed. Takes a string.</param>
		/// <returns>Hash value formatted as a Base-64 string.</returns>
		public static string Compute384Base64(string Data)
		{
			return CryptographicBuffer.EncodeToBase64String(SHA384.HashData(CryptographicBuffer.ConvertStringToBinary(Data, BinaryStringEncoding.Utf8)));
		}

		/// <summary>
		/// Generates a 384-bit hash for the given data and returns the generated results as a Base-64 string.
		/// </summary>
		/// <param name="Data">The data to be hashed. Takes an array of bytes.</param>
		/// <returns>Hash value formatted as a Base-64 string.</returns>
		public static string Compute384Base64(byte[] Data)
		{
			return CryptographicBuffer.EncodeToBase64String(SHA384.HashData(CryptographicBuffer.CreateFromByteArray(Data)));
		}

		/// <summary>
		/// Generates a 384-bit hash for the given data using the specified Salt value and returns the generated results as an Base-64 string.
		/// </summary>
		/// <param name="Data">The data to be hashed. Takes an array of bytes.</param>
		/// <param name="Salt">The salt value used to help prevent dictionary attacks. Takes an array of bytes.</param>
		/// <returns>Hash value formatted as a Base-64 string.</returns>
		public static string Compute384Base64(IEnumerable<byte> Data, IEnumerable<byte> Salt)
		{
			var TD = new List<byte>(Data);
			var TS = new List<byte>(Salt);

			//The Salt Algorithm
			TD.AddRange(TS);
			foreach (byte b in TS)
			{
				TD.Insert(0, b);
				TD.Insert(TD.Count - 1, b);
			}

			return CryptographicBuffer.EncodeToBase64String(SHA384.HashData(CryptographicBuffer.CreateFromByteArray(TD.ToArray())));
		}

		/// <summary>
		/// Generates a 384-bit hash for the given data and returns the generated results as a hexadecimal string.
		/// </summary>
		/// <param name="Data">The data to be hashed. Takes a string.</param>
		/// <returns>Hash value formatted as a hexadecimal string.</returns>
		public static string Compute384Hex(string Data)
		{
			return CryptographicBuffer.EncodeToHexString(SHA384.HashData(CryptographicBuffer.ConvertStringToBinary(Data, BinaryStringEncoding.Utf8)));
		}

		/// <summary>
		/// Generates a 384-bit hash for the given data and returns the generated results as a hexadecimal string.
		/// </summary>
		/// <param name="Data">The data to be hashed. Takes an array of bytes.</param>
		/// <returns>Hash value formatted as a hexadecimal string.</returns>
		public static string Compute384Hex(byte[] Data)
		{
			return CryptographicBuffer.EncodeToHexString(SHA384.HashData(CryptographicBuffer.CreateFromByteArray(Data)));
		}

		/// <summary>
		/// Generates a 384-bit hash for the given data using the specified Salt value and returns the generated results as a hexadecimal string.
		/// </summary>
		/// <param name="Data">The data to be hashed. Takes an array of bytes.</param>
		/// <param name="Salt">The salt value used to help prevent dictionary attacks. Takes an array of bytes.</param>
		/// <returns>Hash value formatted as a hexadecimal string.</returns>
		public static string Compute384Hex(IEnumerable<byte> Data, IEnumerable<byte> Salt)
		{
			var TD = new List<byte>(Data);
			var TS = new List<byte>(Salt);

			//The Salt Algorithm
			TD.AddRange(TS);
			foreach (byte b in TS)
			{
				TD.Insert(0, b);
				TD.Insert(TD.Count - 1, b);
			}

			return CryptographicBuffer.EncodeToHexString(SHA384.HashData(CryptographicBuffer.CreateFromByteArray(TD.ToArray())));
		}

		/// <summary>
		/// Generates a 384-bit hash for the given data and returns the generated results as an array of bytes.
		/// </summary>
		/// <param name="Data">The data to be hashed. Takes a string.</param>
		/// <returns>Hash value formatted as a byte array.</returns>
		public static byte[] Compute384Byte(string Data)
		{
			byte[] ret;
			CryptographicBuffer.CopyToByteArray(SHA384.HashData(CryptographicBuffer.ConvertStringToBinary(Data, BinaryStringEncoding.Utf8)), out ret);
			return ret;
		}

		/// <summary>
		/// Generates a 384-bit hash for the given data and returns the generated results as an array of bytes.
		/// </summary>
		/// <param name="Data">The data to be hashed. Takes an array of bytes.</param>
		/// <returns>Hash value formatted as a byte array.</returns>
		public static byte[] Compute384Byte(byte[] Data)
		{
			byte[] ret;
			CryptographicBuffer.CopyToByteArray(SHA384.HashData(CryptographicBuffer.CreateFromByteArray(Data)), out ret);
			return ret;
		}

		/// <summary>
		/// Generates a 384-bit hash for the given data using the specified Salt value and returns the generated results as an array of bytes.
		/// </summary>
		/// <param name="Data">The data to be hashed. Takes an array of bytes.</param>
		/// <param name="Salt">The salt value used to help prevent dictionary attacks. Takes an array of bytes.</param>
		/// <returns>Hash value formatted as a byte array.</returns>
		public static byte[] Compute384Byte(IEnumerable<byte> Data, IEnumerable<byte> Salt)
		{
			var TD = new List<byte>(Data);
			var TS = new List<byte>(Salt);

			//The Salt Algorithm
			TD.AddRange(TS);
			foreach (byte b in TS)
			{
				TD.Insert(0, b);
				TD.Insert(TD.Count - 1, b);
			}

			byte[] ret;
			CryptographicBuffer.CopyToByteArray(SHA384.HashData(CryptographicBuffer.CreateFromByteArray(TD.ToArray())), out ret);
			return ret;
		}

		/// <summary>
		/// Generates a 512-bit hash for the given data and returns the generated results as a Base-64 string.
		/// </summary>
		/// <param name="Data">The data to be hashed. Takes a string.</param>
		/// <returns>Hash value formatted as a Base-64 string.</returns>
		public static string Compute512Base64(string Data)
		{
			return CryptographicBuffer.EncodeToBase64String(SHA512.HashData(CryptographicBuffer.ConvertStringToBinary(Data, BinaryStringEncoding.Utf8)));
		}

		/// <summary>
		/// Generates a 512-bit hash for the given data and returns the generated results as a Base-64 string.
		/// </summary>
		/// <param name="Data">The data to be hashed. Takes an array of bytes.</param>
		/// <returns>Hash value formatted as a Base-64 string.</returns>
		public static string Compute512Base64(byte[] Data)
		{
			return CryptographicBuffer.EncodeToBase64String(SHA512.HashData(CryptographicBuffer.CreateFromByteArray(Data)));
		}

		/// <summary>
		/// Generates a 512-bit hash for the given data using the specified Salt value and returns the generated results as an Base-64 string.
		/// </summary>
		/// <param name="Data">The data to be hashed. Takes an array of bytes.</param>
		/// <param name="Salt">The salt value used to help prevent dictionary attacks. Takes an array of bytes.</param>
		/// <returns>Hash value formatted as a Base-64 string.</returns>
		public static string Compute512Base64(IEnumerable<byte> Data, IEnumerable<byte> Salt)
		{
			var TD = new List<byte>(Data);
			var TS = new List<byte>(Salt);

			//The Salt Algorithm
			TD.AddRange(TS);
			foreach (byte b in TS)
			{
				TD.Insert(0, b);
				TD.Insert(TD.Count - 1, b);
			}

			return CryptographicBuffer.EncodeToBase64String(SHA512.HashData(CryptographicBuffer.CreateFromByteArray(TD.ToArray())));
		}

		/// <summary>
		/// Generates a 512-bit hash for the given data and returns the generated results as a hexadecimal string.
		/// </summary>
		/// <param name="Data">The data to be hashed. Takes a string.</param>
		/// <returns>Hash value formatted as a hexadecimal string.</returns>
		public static string Compute512Hex(string Data)
		{
			return CryptographicBuffer.EncodeToHexString(SHA512.HashData(CryptographicBuffer.ConvertStringToBinary(Data, BinaryStringEncoding.Utf8)));
		}

		/// <summary>
		/// Generates a 512-bit hash for the given data and returns the generated results as a hexadecimal string.
		/// </summary>
		/// <param name="Data">The data to be hashed. Takes an array of bytes.</param>
		/// <returns>Hash value formatted as a hexadecimal string.</returns>
		public static string Compute512Hex(byte[] Data)
		{
			return CryptographicBuffer.EncodeToHexString(SHA512.HashData(CryptographicBuffer.CreateFromByteArray(Data)));
		}

		/// <summary>
		/// Generates a 512-bit hash for the given data using the specified Salt value and returns the generated results as a hexadecimal string.
		/// </summary>
		/// <param name="Data">The data to be hashed. Takes an array of bytes.</param>
		/// <param name="Salt">The salt value used to help prevent dictionary attacks. Takes an array of bytes.</param>
		/// <returns>Hash value formatted as a hexadecimal string.</returns>
		public static string Compute512Hex(IEnumerable<byte> Data, IEnumerable<byte> Salt)
		{
			var TD = new List<byte>(Data);
			var TS = new List<byte>(Salt);

			//The Salt Algorithm
			TD.AddRange(TS);
			foreach (byte b in TS)
			{
				TD.Insert(0, b);
				TD.Insert(TD.Count - 1, b);
			}

			return CryptographicBuffer.EncodeToHexString(SHA256.HashData(CryptographicBuffer.CreateFromByteArray(TD.ToArray())));
		}

		/// <summary>
		/// Generates a 512-bit hash for the given data and returns the generated results as an array of bytes.
		/// </summary>
		/// <param name="Data">The data to be hashed. Takes a string.</param>
		/// <returns>Hash value formatted as a byte array.</returns>
		public static byte[] Compute512Byte(string Data)
		{
			byte[] ret;
			CryptographicBuffer.CopyToByteArray(SHA512.HashData(CryptographicBuffer.ConvertStringToBinary(Data, BinaryStringEncoding.Utf8)), out ret);
			return ret;
		}

		/// <summary>
		/// Generates a 512-bit hash for the given data and returns the generated results as an array of bytes.
		/// </summary>
		/// <param name="Data">The data to be hashed. Takes an array of bytes.</param>
		/// <returns>Hash value formatted as a byte array.</returns>
		public static byte[] Compute512Byte(byte[] Data)
		{
			byte[] ret;
			CryptographicBuffer.CopyToByteArray(SHA512.HashData(CryptographicBuffer.CreateFromByteArray(Data)), out ret);
			return ret;
		}

		/// <summary>
		/// Generates a 512-bit hash for the given data using the specified Salt value and returns the generated results as an array of bytes.
		/// </summary>
		/// <param name="Data">The data to be hashed. Takes an array of bytes.</param>
		/// <param name="Salt">The salt value used to help prevent dictionary attacks. Takes an array of bytes.</param>
		/// <returns>Hash value formatted as a byte array.</returns>
		public static byte[] Compute512Byte(IEnumerable<byte> Data, IEnumerable<byte> Salt)
		{
			var TD = new List<byte>(Data);
			var TS = new List<byte>(Salt);

			//The Salt Algorithm
			TD.AddRange(TS);
			foreach (byte b in TS)
			{
				TD.Insert(0, b);
				TD.Insert(TD.Count - 1, b);
			}

			byte[] ret;
			CryptographicBuffer.CopyToByteArray(SHA256.HashData(CryptographicBuffer.CreateFromByteArray(TD.ToArray())), out ret);
			return ret;
		}
	}
}