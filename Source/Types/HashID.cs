﻿/******************************************************************************
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

using System.Globalization;
using System.Runtime.Serialization;
using System.Text;
using System.Utilities.Cryptography;
using System.Xml;
using System.Xml.Serialization;

namespace System
{
	[Serializable]
	public struct HashID : ISerializable, IXmlSerializable
	{
		private ulong first;
		private ulong second;
		private ulong third;
		private ulong fourth;

		public HashID(byte[] hash)
		{
			if(hash.Length != 32) throw new ArgumentException("Hash value length is incorrect. Length must be 32 bytes.", "hash");

			first = BitConverter.ToUInt64(hash, 0);
			second = BitConverter.ToUInt64(hash, 8);
			third = BitConverter.ToUInt64(hash, 16);
			fourth = BitConverter.ToUInt64(hash, 24);
		}

		public HashID(string hash)
		{
			if (hash.Length != 64) throw new ArgumentException("Hash value length is incorrect. Length must be 64 characters.", "hash");

			var harr = new byte[32];
			for (int i = 0; i < 32; i++)
				harr[i] = byte.Parse(hash.Substring(i*2, 2), NumberStyles.HexNumber);

			first = BitConverter.ToUInt64(harr, 0);
			second = BitConverter.ToUInt64(harr, 8);
			third = BitConverter.ToUInt64(harr, 16);
			fourth = BitConverter.ToUInt64(harr, 24);
		}
		
		public byte[] ToByteArray()
		{
			var arr = new byte[32];

			BitConverter.GetBytes(first).CopyTo(arr, 0);
			BitConverter.GetBytes(second).CopyTo(arr, 8);
			BitConverter.GetBytes(third).CopyTo(arr, 16);
			BitConverter.GetBytes(fourth).CopyTo(arr, 24);

			return arr;
		}

		public string ToHexString()
		{
			var arr = new byte[32];

			BitConverter.GetBytes(first).CopyTo(arr, 0);
			BitConverter.GetBytes(second).CopyTo(arr, 8);
			BitConverter.GetBytes(third).CopyTo(arr, 16);
			BitConverter.GetBytes(fourth).CopyTo(arr, 24);

			return BitConverter.ToString(arr).Replace("-", "");
		}

		public override bool Equals(object obj)
		{
			if (obj.GetType() != typeof (HashID)) return base.Equals(obj);
			var hid = (HashID) obj;
			return (hid.first == first && hid.second == second && hid.third == third && hid.fourth == fourth);
		}

		public override int GetHashCode()
		{
			return Convert.ToInt32(first ^ second ^ third ^ fourth);
		}

		public override string ToString()
		{
			return ToHexString();
		}

		public static bool operator ==(HashID a, HashID b)
		{
			return (a.first == b.first && a.second == b.second && a.third == b.third && a.fourth == b.fourth);
		}

		public static bool operator !=(HashID a, HashID b)
		{
			return !(a == b);
		}

		public static HashID GenerateHashID(byte[] data)
		{
			return new HashID(Hash.Compute256Byte(data));
		}

		public static HashID GenerateHashID(string data)
		{
			return new HashID(Hash.Compute256Byte(data));
		}

		public static HashID GenerateHashID()
		{
			return new HashID(Hash.Compute256Byte(Guid.NewGuid().ToByteArray()));
		}

		#region - Serialization -

		public HashID(SerializationInfo info, StreamingContext context)
		{
			first = info.GetUInt64("first");
			second = info.GetUInt64("second");
			third = info.GetUInt64("third");
			fourth = info.GetUInt64("fourth");
		}

		public void GetObjectData(SerializationInfo info, StreamingContext context)
		{
			info.AddValue("first", first);
			info.AddValue("second", second);
			info.AddValue("third", third);
			info.AddValue("fourth", fourth);
		}

		public Xml.Schema.XmlSchema GetSchema()
		{
			return null;
		}

		public void ReadXml(Xml.XmlReader reader)
		{
			reader.MoveToContent();
			reader.ReadStartElement();
			reader.MoveToAttribute("first");
			first = Convert.ToUInt64(reader.Value);
			reader.MoveToAttribute("second");
			second = Convert.ToUInt64(reader.Value);
			reader.MoveToAttribute("third");
			third = Convert.ToUInt64(reader.Value);
			reader.MoveToAttribute("fourth");
			fourth = Convert.ToUInt64(reader.Value);
			reader.ReadEndElement();
		}

		public void WriteXml(Xml.XmlWriter writer)
		{
			writer.WriteAttributeString("first", first.ToString(CultureInfo.InvariantCulture));
			writer.WriteAttributeString("second", second.ToString(CultureInfo.InvariantCulture));
			writer.WriteAttributeString("third", third.ToString(CultureInfo.InvariantCulture));
			writer.WriteAttributeString("fourth", fourth.ToString(CultureInfo.InvariantCulture));
		}
	
		#endregion
	}
}