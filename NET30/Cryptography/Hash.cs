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
using System.Security.Cryptography;

namespace System.Utilities.Cryptography
{
	/// <summary>
	/// Provides hash computation services using the SHA-2 family of algorithms. It supports 256-bit, 384-bit, and 512-bit hashes.
	/// This implementation is NOT FIPS compliant.
	/// The functions are named in the following fashion:
	/// The first section indicates the operation being performed.
	/// The second section indicates the bit length of the hash.
	/// The third section notes the formatted return value of the hash.
	/// </summary>
	public static class Hash
	{
		private readonly static SHA256Managed SHA256 = new SHA256Managed();
		private readonly static SHA384Managed SHA384 = new SHA384Managed();
		private readonly static SHA512Managed SHA512 = new SHA512Managed();

		/// <summary>
		/// Generates a 256-bit hash for the given data and returns the generated results as a Base-64 string.
		/// </summary>
		/// <param name="Data">The data to be hashed. Takes a string.</param>
		/// <returns>Hash value formatted as a Base-64 string.</returns>
		public static string Compute256Base64(string Data)
		{
			return Convert.ToBase64String(SHA256.ComputeHash(System.Text.Encoding.Default.GetBytes(Data)));
		}

		/// <summary>
		/// Generates a 256-bit hash for the given data and returns the generated results as a Base-64 string.
		/// </summary>
		/// <param name="Data">The data to be hashed. Takes an array of bytes.</param>
		/// <returns>Hash value formatted as a Base-64 string.</returns>
		public static string Compute256Base64(byte[] Data)
		{
			return Convert.ToBase64String(SHA256.ComputeHash(Data));
		}

		/// <summary>
		/// Generates a 256-bit hash for the given data and returns the generated results as a Base-64 string.
		/// </summary>
		/// <param name="Data">The data to be hashed. Takes an IO Stream.</param>
		/// <returns>Hash value formatted as a Base-64 string.</returns>
		public static string Compute256Base64(System.IO.Stream Data)
		{
			return Convert.ToBase64String(SHA256.ComputeHash(Data));
		}

		/// <summary>
		/// Generates a 256-bit hash for the given data using the specified Salt value and returns the generated results as an Base-64 string.
		/// If no salt value is given one is automatically used. (NOTE: The default salt value is static and should not be considered secure!)
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

			return Convert.ToBase64String(SHA256.ComputeHash(TD.ToArray()));
		}

		/// <summary>
		/// Generates a 256-bit hash for the given data and returns the generated results as a hexadecimal string.
		/// </summary>
		/// <param name="Data">The data to be hashed. Takes a string.</param>
		/// <returns>Hash value formatted as a hexadecimal string.</returns>
		public static string Compute256Hex(string Data)
		{
			return BitConverter.ToString(SHA256.ComputeHash(System.Text.Encoding.Default.GetBytes(Data))).Replace("-", "");
		}

		/// <summary>
		/// Generates a 256-bit hash for the given data and returns the generated results as a hexadecimal string.
		/// </summary>
		/// <param name="Data">The data to be hashed. Takes an array of bytes.</param>
		/// <returns>Hash value formatted as a hexadecimal string.</returns>
		public static string Compute256Hex(byte[] Data)
		{
			return BitConverter.ToString(SHA256.ComputeHash(Data)).Replace("-", "");
		}

		/// <summary>
		/// Generates a 256-bit hash for the given data and returns the generated results as a hexadecimal string.
		/// </summary>
		/// <param name="Data">The data to be hashed. Takes an IO Stream.</param>
		/// <returns>Hash value formatted as a hexadecimal string.</returns>
		public static string Compute256Hex(System.IO.Stream Data)
		{
			return BitConverter.ToString(SHA256.ComputeHash(Data)).Replace("-", "");
		}

		/// <summary>
		/// Generates a 256-bit hash for the given data using the specified Salt value and returns the generated results as a hexadecimal string.
		/// If no salt value is given one is automatically used. (NOTE: The default salt value is static and should not be considered secure!)
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

			return BitConverter.ToString(SHA256.ComputeHash(TD.ToArray())).Replace("-", "");
		}

		/// <summary>
		/// Generates a 256-bit hash for the given data and returns the generated results as an array of bytes.
		/// </summary>
		/// <param name="Data">The data to be hashed. Takes a string.</param>
		/// <returns>Hash value formatted as a byte array.</returns>
		public static byte[] Compute256Byte(string Data)
		{
			return SHA256.ComputeHash(System.Text.Encoding.Default.GetBytes(Data));
		}

		/// <summary>
		/// Generates a 256-bit hash for the given data and returns the generated results as an array of bytes.
		/// </summary>
		/// <param name="Data">The data to be hashed. Takes an array of bytes.</param>
		/// <returns>Hash value formatted as a byte array.</returns>
		public static byte[] Compute256Byte(byte[] Data)
		{
			return SHA256.ComputeHash(Data);
		}

		/// <summary>
		/// Generates a 256-bit hash for the given data and returns the generated results as an array of bytes.
		/// </summary>
		/// <param name="Data">The data to be hashed.</param>
		/// <returns>Hash value formatted as a byte array.</returns>
		public static byte[] Compute256Byte(System.IO.Stream Data)
		{
			return SHA256.ComputeHash(Data);
		}

		/// <summary>
		/// Generates a 256-bit hash for the given data using the specified Salt value and returns the generated results as an array of bytes.
		/// If no salt value is given one is automatically used. (NOTE: The default salt value is static and should not be considered secure!)
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

			return SHA256.ComputeHash(TD.ToArray());
		}

		/// <summary>
		/// Generates a 384-bit hash for the given data and returns the generated results as a Base-64 string.
		/// </summary>
		/// <param name="Data">The data to be hashed. Takes a string.</param>
		/// <returns>Hash value formatted as a Base-64 string.</returns>
		public static string Compute384Base64(string Data)
		{
			return Convert.ToBase64String(SHA384.ComputeHash(System.Text.Encoding.Default.GetBytes(Data)));
		}

		/// <summary>
		/// Generates a 384-bit hash for the given data and returns the generated results as a Base-64 string.
		/// </summary>
		/// <param name="Data">The data to be hashed. Takes an array of bytes.</param>
		/// <returns>Hash value formatted as a Base-64 string.</returns>
		public static string Compute384Base64(byte[] Data)
		{
			return Convert.ToBase64String(SHA384.ComputeHash(Data));
		}

		/// <summary>
		/// Generates a 384-bit hash for the given data and returns the generated results as a Base-64 string.
		/// </summary>
		/// <param name="Data">The data to be hashed. Takes an IO Stream.</param>
		/// <returns>Hash value formatted as a Base-64 string.</returns>
		public static string Compute384Base64(System.IO.Stream Data)
		{
			return Convert.ToBase64String(SHA384.ComputeHash(Data));
		}

		/// <summary>
		/// Generates a 384-bit hash for the given data using the specified Salt value and returns the generated results as an Base-64 string.
		/// If no salt value is given one is automatically used. (NOTE: The default salt value is static and should not be considered secure!)
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

			return Convert.ToBase64String(SHA384.ComputeHash(TD.ToArray()));
		}

		/// <summary>
		/// Generates a 384-bit hash for the given data and returns the generated results as a hexadecimal string.
		/// </summary>
		/// <param name="Data">The data to be hashed. Takes a string.</param>
		/// <returns>Hash value formatted as a hexadecimal string.</returns>
		public static string Compute384Hex(string Data)
		{
			return BitConverter.ToString(SHA384.ComputeHash(System.Text.Encoding.Default.GetBytes(Data))).Replace("-", "");
		}

		/// <summary>
		/// Generates a 384-bit hash for the given data and returns the generated results as a hexadecimal string.
		/// </summary>
		/// <param name="Data">The data to be hashed. Takes an array of bytes.</param>
		/// <returns>Hash value formatted as a hexadecimal string.</returns>
		public static string Compute384Hex(byte[] Data)
		{
			return BitConverter.ToString(SHA384.ComputeHash(Data)).Replace("-", "");
		}

		/// <summary>
		/// Generates a 384-bit hash for the given data and returns the generated results as a hexadecimal string.
		/// </summary>
		/// <param name="Data">The data to be hashed. Takes an IO Stream.</param>
		/// <returns>Hash value formatted as a hexadecimal string.</returns>
		public static string Compute384Hex(System.IO.Stream Data)
		{
			return BitConverter.ToString(SHA384.ComputeHash(Data)).Replace("-", "");
		}

		/// <summary>
		/// Generates a 384-bit hash for the given data using the specified Salt value and returns the generated results as a hexadecimal string.
		/// If no salt value is given one is automatically used. (NOTE: The default salt value is static and should not be considered secure!)
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

			return BitConverter.ToString(SHA384.ComputeHash(TD.ToArray())).Replace("-", "");
		}

		/// <summary>
		/// Generates a 384-bit hash for the given data and returns the generated results as an array of bytes.
		/// </summary>
		/// <param name="Data">The data to be hashed. Takes a string.</param>
		/// <returns>Hash value formatted as a byte array.</returns>
		public static byte[] Compute384Byte(string Data)
		{
			return SHA384.ComputeHash(System.Text.Encoding.Default.GetBytes(Data));
		}

		/// <summary>
		/// Generates a 384-bit hash for the given data and returns the generated results as an array of bytes.
		/// </summary>
		/// <param name="Data">The data to be hashed. Takes an array of bytes.</param>
		/// <returns>Hash value formatted as a byte array.</returns>
		public static byte[] Compute384Byte(byte[] Data)
		{
			return SHA384.ComputeHash(Data);
		}

		/// <summary>
		/// Generates a 384-bit hash for the given data and returns the generated results as an array of bytes.
		/// </summary>
		/// <param name="Data">The data to be hashed.</param>
		/// <returns>Hash value formatted as a byte array.</returns>
		public static byte[] Compute384Byte(System.IO.Stream Data)
		{
			return SHA384.ComputeHash(Data);
		}

		/// <summary>
		/// Generates a 384-bit hash for the given data using the specified Salt value and returns the generated results as an array of bytes.
		/// If no salt value is given one is automatically used. (NOTE: The default salt value is static and should not be considered secure!)
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

			return SHA384.ComputeHash(TD.ToArray());
		}

		/// <summary>
		/// Generates a 512-bit hash for the given data and returns the generated results as a Base-64 string.
		/// </summary>
		/// <param name="Data">The data to be hashed. Takes a string.</param>
		/// <returns>Hash value formatted as a Base-64 string.</returns>
		public static string Compute512Base64(string Data)
		{
			return Convert.ToBase64String(SHA512.ComputeHash(System.Text.Encoding.Default.GetBytes(Data)));
		}

		/// <summary>
		/// Generates a 512-bit hash for the given data and returns the generated results as a Base-64 string.
		/// </summary>
		/// <param name="Data">The data to be hashed. Takes an array of bytes.</param>
		/// <returns>Hash value formatted as a Base-64 string.</returns>
		public static string Compute512Base64(byte[] Data)
		{
			return Convert.ToBase64String(SHA512.ComputeHash(Data));
		}

		/// <summary>
		/// Generates a 512-bit hash for the given data and returns the generated results as a Base-64 string.
		/// </summary>
		/// <param name="Data">The data to be hashed. Takes an IO Stream.</param>
		/// <returns>Hash value formatted as a Base-64 string.</returns>
		public static string Compute512Base64(System.IO.Stream Data)
		{
			return Convert.ToBase64String(SHA512.ComputeHash(Data));
		}

		/// <summary>
		/// Generates a 512-bit hash for the given data using the specified Salt value and returns the generated results as an Base-64 string.
		/// If no salt value is given one is automatically used. (NOTE: The default salt value is static and should not be considered secure!)
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

			return Convert.ToBase64String(SHA512.ComputeHash(TD.ToArray()));
		}

		/// <summary>
		/// Generates a 512-bit hash for the given data and returns the generated results as a hexadecimal string.
		/// </summary>
		/// <param name="Data">The data to be hashed. Takes a string.</param>
		/// <returns>Hash value formatted as a hexadecimal string.</returns>
		public static string Compute512Hex(string Data)
		{
			return BitConverter.ToString(SHA512.ComputeHash(System.Text.Encoding.Default.GetBytes(Data))).Replace("-", "");
		}

		/// <summary>
		/// Generates a 512-bit hash for the given data and returns the generated results as a hexadecimal string.
		/// </summary>
		/// <param name="Data">The data to be hashed. Takes an array of bytes.</param>
		/// <returns>Hash value formatted as a hexadecimal string.</returns>
		public static string Compute512Hex(byte[] Data)
		{
			return BitConverter.ToString(SHA512.ComputeHash(Data)).Replace("-", "");
		}

		/// <summary>
		/// Generates a 512-bit hash for the given data and returns the generated results as a hexadecimal string.
		/// </summary>
		/// <param name="Data">The data to be hashed. Takes an IO Stream.</param>
		/// <returns>Hash value formatted as a hexadecimal string.</returns>
		public static string Compute512Hex(System.IO.Stream Data)
		{
			return BitConverter.ToString(SHA512.ComputeHash(Data)).Replace("-", "");
		}

		/// <summary>
		/// Generates a 512-bit hash for the given data using the specified Salt value and returns the generated results as a hexadecimal string.
		/// If no salt value is given one is automatically used. (NOTE: The default salt value is static and should not be considered secure!)
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

			return BitConverter.ToString(SHA512.ComputeHash(TD.ToArray())).Replace("-", "");
		}

		/// <summary>
		/// Generates a 512-bit hash for the given data and returns the generated results as an array of bytes.
		/// </summary>
		/// <param name="Data">The data to be hashed. Takes a string.</param>
		/// <returns>Hash value formatted as a byte array.</returns>
		public static byte[] Compute512Byte(string Data)
		{
			return SHA512.ComputeHash(System.Text.Encoding.Default.GetBytes(Data));
		}

		/// <summary>
		/// Generates a 512-bit hash for the given data and returns the generated results as an array of bytes.
		/// </summary>
		/// <param name="Data">The data to be hashed. Takes an array of bytes.</param>
		/// <returns>Hash value formatted as a byte array.</returns>
		public static byte[] Compute512Byte(byte[] Data)
		{
			return SHA512.ComputeHash(Data);
		}

		/// <summary>
		/// Generates a 512-bit hash for the given data and returns the generated results as an array of bytes.
		/// </summary>
		/// <param name="Data">The data to be hashed.</param>
		/// <returns>Hash value formatted as a byte array.</returns>
		public static byte[] Compute512Byte(System.IO.Stream Data)
		{
			return SHA512.ComputeHash(Data);
		}

		/// <summary>
		/// Generates a 512-bit hash for the given data using the specified Salt value and returns the generated results as an array of bytes.
		/// If no salt value is given one is automatically used. (NOTE: The default salt value is static and should not be considered secure!)
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

			return SHA512.ComputeHash(TD.ToArray());
		}
	}
}