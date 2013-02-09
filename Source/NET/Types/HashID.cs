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
		[NonSerialized]private ulong first;
		[NonSerialized]private ulong second;
		[NonSerialized]private ulong third;
		[NonSerialized]private ulong fourth;

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

		public Guid ToGUID()
		{
			ulong a = first ^ second;
			ulong b = third ^ fourth;
			var arr = new byte[16];

			BitConverter.GetBytes(a).CopyTo(arr, 0);
			BitConverter.GetBytes(b).CopyTo(arr, 8);

			return new Guid(arr);
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
			var barr = new byte[64];
			Guid.NewGuid().ToByteArray().CopyTo(barr, 0);
			Guid.NewGuid().ToByteArray().CopyTo(barr, 16);
			Guid.NewGuid().ToByteArray().CopyTo(barr, 32);
			Guid.NewGuid().ToByteArray().CopyTo(barr, 48);
			return new HashID(Hash.Compute256Byte(barr));
		}

		#region - Serialization -

		public HashID(SerializationInfo info, StreamingContext context)
		{
			string t = info.GetString("value");
			
			var harr = new byte[32];
			for (int i = 0; i < 32; i++)
				harr[i] = byte.Parse(t.Substring(i * 2, 2), NumberStyles.HexNumber);

			first = BitConverter.ToUInt64(harr, 0);
			second = BitConverter.ToUInt64(harr, 8);
			third = BitConverter.ToUInt64(harr, 16);
			fourth = BitConverter.ToUInt64(harr, 24);
		}

		public void GetObjectData(SerializationInfo info, StreamingContext context)
		{
			info.AddValue("value", ToHexString());
		}

		public Xml.Schema.XmlSchema GetSchema()
		{
			return null;
		}

		public void ReadXml(Xml.XmlReader reader)
		{
			reader.MoveToContent();
			reader.ReadStartElement();
			reader.MoveToAttribute("value");
			string t = Convert.ToString(reader.Value);
			reader.ReadEndElement();

			var harr = new byte[32];
			for (int i = 0; i < 32; i++)
				harr[i] = byte.Parse(t.Substring(i * 2, 2), NumberStyles.HexNumber);

			first = BitConverter.ToUInt64(harr, 0);
			second = BitConverter.ToUInt64(harr, 8);
			third = BitConverter.ToUInt64(harr, 16);
			fourth = BitConverter.ToUInt64(harr, 24);
		}

		public void WriteXml(Xml.XmlWriter writer)
		{
			writer.WriteAttributeString("value", ToHexString());
		}
	
		#endregion
	}
}