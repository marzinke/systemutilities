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

namespace System
{

#pragma warning disable 1591
	public enum Base2ParseMode
	{
		Binary,
		Scientific
	}

	internal enum Base2StorageMode
	{
		Bits,
		Bytes,
		Kibibits, 
		Kibibytes,
		Kilobits, 
		Kilobytes,	
		Mebibits, 
		Mebibytes,
		Megabits, 
		Megabytes,	
		Gibibits, 
		Gibibytes,
		Gigabits, 
		Gigabytes,	
		Tebibits, 
		Tebibytes,
		Terabits, 
		Terabytes,	
		Pebibits, 
		Pebibytes,
		Petabits, 
		Petabytes
	}
	
	public struct Base2
	{
		internal Base2StorageMode storeMode;
		internal Base2ParseMode parseMode;

		internal ulong bits;
		public ulong Bits { get { return bits; } private set { bits = value; storeMode = Base2StorageMode.Bits; } }

		public decimal Bytes { get { return Convert.ToDecimal(Bits / 8); } set { Bits = Convert.ToUInt64(Decimal.Round(value * 8)); storeMode = Base2StorageMode.Bytes; } }
		public long BytesNormalized { get { return Convert.ToInt64(Decimal.Round(Bits / 8)); } }

		public decimal Kibibits { get { return Convert.ToDecimal(Bits / 1024); } set { Bits = Convert.ToUInt64(value * 1024); storeMode = Base2StorageMode.Kibibits; } }
		public decimal Kibibytes { get { return Convert.ToDecimal(Bytes / 1024); } set { Bytes = Convert.ToInt64(value * 1024); storeMode = Base2StorageMode.Kibibytes; } }
		public decimal Kilobits { get { return Convert.ToDecimal(Bits / 1000); } set { Bits = Convert.ToUInt64(value * 1000); storeMode = Base2StorageMode.Kilobits; } }
		public decimal Kilobytes { get { return Convert.ToDecimal(Bytes / 1000); } set { Bytes = Convert.ToInt64(value * 1000); storeMode = Base2StorageMode.Kilobytes; } }

		public decimal Mebibits { get { return Convert.ToDecimal(Bits / (1024 ^ 2)); } set { Bits = Convert.ToUInt64(value * (1024 ^ 2)); storeMode = Base2StorageMode.Mebibits; } }
		public decimal Mebibytes { get { return Convert.ToDecimal(Bytes / (1024 ^ 2)); } set { Bytes = Convert.ToInt64(value * (1024 ^ 2)); storeMode = Base2StorageMode.Mebibytes; } }
		public decimal Megabits { get { return Convert.ToDecimal(Bits / (1000 ^ 2)); } set { Bits = Convert.ToUInt64(value * (1000 ^ 2)); storeMode = Base2StorageMode.Megabits; } }
		public decimal Megabytes { get { return Convert.ToDecimal(Bytes / (1000 ^ 2)); } set { Bytes = Convert.ToInt64(value * (1000 ^ 2)); storeMode = Base2StorageMode.Megabytes; } }

		public decimal Gibibits { get { return Convert.ToDecimal(Bits / (1024 ^ 3)); } set { Bits = Convert.ToUInt64(value * (1024 ^ 3)); storeMode = Base2StorageMode.Gibibits; } }
		public decimal Gibibytes { get { return Convert.ToDecimal(Bytes / (1024 ^ 3)); } set { Bytes = Convert.ToInt64(value * (1024 ^ 3)); storeMode = Base2StorageMode.Gibibytes; } }
		public decimal Gigabits { get { return Convert.ToDecimal(Bits / (1000 ^ 3)); } set { Bits = Convert.ToUInt64(value * (1000 ^ 3)); storeMode = Base2StorageMode.Gigabits; } }
		public decimal Gigabytes { get { return Convert.ToDecimal(Bytes / (1000 ^ 3)); } set { Bytes = Convert.ToInt64(value * (1000 ^ 3)); storeMode = Base2StorageMode.Gigabytes; } }

		public decimal Tebibits { get { return Convert.ToDecimal(Bits / (1024 ^ 4)); } set { Bits = Convert.ToUInt64(value * (1024 ^ 4)); storeMode = Base2StorageMode.Tebibits; } }
		public decimal Tebibytes { get { return Convert.ToDecimal(Bytes / (1024 ^ 4)); } set { Bytes = Convert.ToInt64(value * (1024 ^ 4)); storeMode = Base2StorageMode.Tebibytes; } }
		public decimal Terabits { get { return Convert.ToDecimal(Bits / (1000 ^ 4)); } set { Bits = Convert.ToUInt64(value * (1000 ^ 4)); storeMode = Base2StorageMode.Terabits; } }
		public decimal Terabytes { get { return Convert.ToDecimal(Bytes / (1000 ^ 4)); } set { Bytes = Convert.ToInt64(value * (1000 ^ 4)); storeMode = Base2StorageMode.Terabytes; } }

		public decimal Pebibits { get { return Convert.ToDecimal(Bits / (1024 ^ 5)); } set { Bits = Convert.ToUInt64(value * (1024 ^ 5)); storeMode = Base2StorageMode.Pebibits; } }
		public decimal Pebibytes { get { return Convert.ToDecimal(Bytes / (1024 ^ 5)); } set { Bytes = Convert.ToInt64(value * (1024 ^ 5)); storeMode = Base2StorageMode.Pebibytes; } }
		public decimal Petabits { get { return Convert.ToDecimal(Bits / (1000 ^ 5)); } set { Bits = Convert.ToUInt64(value * (1000 ^ 5)); storeMode = Base2StorageMode.Petabits; } }
		public decimal Petabytes { get { return Convert.ToDecimal(Bytes / (1000 ^ 5)); } set { Bytes = Convert.ToInt64(value * (1000 ^ 5)); storeMode = Base2StorageMode.Petabytes; } }

		public string ValueBinary { get { return ToString(); } set { Base2 t; if (TryParse(value, Base2ParseMode.Binary, false, out t)) { bits = t.bits; storeMode = t.storeMode; } else { throw new ArgumentException("Base2 was unable to parse the value you specified."); } } }
		public string ValueScientific { get { return ToString(); } set { Base2 t; if (TryParse(value, Base2ParseMode.Scientific, false, out t)) { bits = t.bits; storeMode = t.storeMode; } else { throw new ArgumentException("Base2 was unable to parse the value you specified."); } } }
		public string ValueRoundedBinary { get { return ToString(); } set { Base2 t; if (TryParse(value, Base2ParseMode.Binary, true, out t)) { bits = t.bits; storeMode = t.storeMode; } else { throw new ArgumentException("Base2 was unable to parse the value you specified."); } } }
		public string ValueRoundedScientific { get { return ToString(); } set { Base2 t; if (TryParse(value, Base2ParseMode.Scientific, true, out t)) { bits = t.bits; storeMode = t.storeMode; } else { throw new ArgumentException("Base2 was unable to parse the value you specified."); } } }
		
		public Base2(ulong Bits)
		{
			bits = Bits;
			storeMode = Base2StorageMode.Bits;
			parseMode = Base2ParseMode.Binary;
		}

		public Base2(decimal Bytes)
		{
			bits = 0;
			storeMode = Base2StorageMode.Bytes;
			parseMode = Base2ParseMode.Binary;
			this.Bytes = Bytes;
		}
		
		public static bool TryParse(string Value, Base2ParseMode ParseMode, bool Round, out Base2 Return)
		{
			try
			{
				Return = Parse(Value, ParseMode, Round);
			}
			catch
			{
				Return = new Base2(0);
				return false;
			}
			return true;
		}

		public static Base2 Parse(string Value, Base2ParseMode ParseMode, bool Round)
		{
			var ret = new Base2();
			var r = new System.Text.RegularExpressions.Regex(@"[A-Za-z]*$");

			if (Value.EndsWith("bit", StringComparison.CurrentCultureIgnoreCase))
			{
				ret.Bits = Convert.ToUInt64(r.Replace(Value, ""));
			}
			if (Value.EndsWith("B", StringComparison.CurrentCultureIgnoreCase))
			{
				try { ret.Bytes = Convert.ToInt64(r.Replace(Value, "")); }
				catch { Value += "B"; }
			}

			if (ParseMode == Base2ParseMode.Binary)
			{
				if (Value.EndsWith("KBIT", StringComparison.CurrentCultureIgnoreCase))
				{
					if (Round)
						ret.Kibibits = Decimal.Round(Convert.ToDecimal(r.Replace(Value, "")));
					else
						ret.Kibibits = Convert.ToDecimal(r.Replace(Value, ""));
				}
				if (Value.EndsWith("KB", StringComparison.CurrentCultureIgnoreCase))
				{
					if (Round)
						ret.Kibibytes = Decimal.Round(Convert.ToDecimal(r.Replace(Value, "")));
					else
						ret.Kibibytes = Convert.ToDecimal(r.Replace(Value, ""));
				}
				if (Value.EndsWith("MBIT", StringComparison.CurrentCultureIgnoreCase))
				{
					if (Round)
						ret.Mebibits = Decimal.Round(Convert.ToDecimal(r.Replace(Value, "")));
					else
						ret.Mebibits = Convert.ToDecimal(r.Replace(Value, ""));
				}
				if (Value.EndsWith("MB", StringComparison.CurrentCultureIgnoreCase))
				{
					if (Round)
						ret.Mebibytes = Decimal.Round(Convert.ToDecimal(r.Replace(Value, "")));
					else
						ret.Mebibytes = Convert.ToDecimal(r.Replace(Value, ""));
				}
				if (Value.EndsWith("GBIT", StringComparison.CurrentCultureIgnoreCase))
				{
					if (Round)
						ret.Gibibits = Decimal.Round(Convert.ToDecimal(r.Replace(Value, "")));
					else
						ret.Gibibits = Convert.ToDecimal(r.Replace(Value, ""));
				}
				if (Value.EndsWith("GB", StringComparison.CurrentCultureIgnoreCase))
				{
					if (Round)
						ret.Gibibytes = Decimal.Round(Convert.ToDecimal(r.Replace(Value, "")));
					else
						ret.Gibibytes = Convert.ToDecimal(r.Replace(Value, ""));
				}
				if (Value.EndsWith("TBIT", StringComparison.CurrentCultureIgnoreCase))
				{
					if (Round)
						ret.Tebibits = Decimal.Round(Convert.ToDecimal(r.Replace(Value, "")));
					else
						ret.Tebibits = Convert.ToDecimal(r.Replace(Value, ""));
				}
				if (Value.EndsWith("TB", StringComparison.CurrentCultureIgnoreCase))
				{
					if (Round)
						ret.Tebibytes = Decimal.Round(Convert.ToDecimal(r.Replace(Value, "")));
					else
						ret.Tebibytes = Convert.ToDecimal(r.Replace(Value, ""));
				}
				if (Value.EndsWith("PBIT", StringComparison.CurrentCultureIgnoreCase))
				{
					if (Round)
						ret.Pebibits = Decimal.Round(Convert.ToDecimal(r.Replace(Value, "")));
					else
						ret.Pebibits = Convert.ToDecimal(r.Replace(Value, ""));
				}
				if (Value.EndsWith("PB", StringComparison.CurrentCultureIgnoreCase))
				{
					if (Round)
						ret.Pebibytes = Decimal.Round(Convert.ToDecimal(r.Replace(Value, "")));
					else
						ret.Pebibytes = Convert.ToDecimal(r.Replace(Value, ""));
				}
			}

			if (ParseMode == Base2ParseMode.Scientific)
			{
				if (Value.EndsWith("KIBIT", StringComparison.CurrentCultureIgnoreCase))
				{
					if (Round)
						ret.Kibibits = Decimal.Round(Convert.ToDecimal(r.Replace(Value, "")));
					else
						ret.Kibibits = Convert.ToDecimal(r.Replace(Value, ""));
				}
				if (Value.EndsWith("KIB", StringComparison.CurrentCultureIgnoreCase))
				{
					if (Round)
						ret.Kibibytes = Decimal.Round(Convert.ToDecimal(r.Replace(Value, "")));
					else
						ret.Kibibytes = Convert.ToDecimal(r.Replace(Value, ""));
				}
				if (Value.EndsWith("MIBIT", StringComparison.CurrentCultureIgnoreCase))
				{
					if (Round)
						ret.Mebibits = Decimal.Round(Convert.ToDecimal(r.Replace(Value, "")));
					else
						ret.Mebibits = Convert.ToDecimal(r.Replace(Value, ""));
				}
				if (Value.EndsWith("MIB", StringComparison.CurrentCultureIgnoreCase))
				{
					if (Round)
						ret.Mebibytes = Decimal.Round(Convert.ToDecimal(r.Replace(Value, "")));
					else
						ret.Mebibytes = Convert.ToDecimal(r.Replace(Value, ""));
				}
				if (Value.EndsWith("GIBIT", StringComparison.CurrentCultureIgnoreCase))
				{
					if (Round)
						ret.Gibibits = Decimal.Round(Convert.ToDecimal(r.Replace(Value, "")));
					else
						ret.Gibibits = Convert.ToDecimal(r.Replace(Value, ""));
				}
				if (Value.EndsWith("GIB", StringComparison.CurrentCultureIgnoreCase))
				{
					if (Round)
						ret.Gibibytes = Decimal.Round(Convert.ToDecimal(r.Replace(Value, "")));
					else
						ret.Gibibytes = Convert.ToDecimal(r.Replace(Value, ""));
				}
				if (Value.EndsWith("TIBIT", StringComparison.CurrentCultureIgnoreCase))
				{
					if (Round)
						ret.Tebibits = Decimal.Round(Convert.ToDecimal(r.Replace(Value, "")));
					else
						ret.Tebibits = Convert.ToDecimal(r.Replace(Value, ""));
				}
				if (Value.EndsWith("TIB", StringComparison.CurrentCultureIgnoreCase))
				{
					if (Round)
						ret.Tebibytes = Decimal.Round(Convert.ToDecimal(r.Replace(Value, "")));
					else
						ret.Tebibytes = Convert.ToDecimal(r.Replace(Value, ""));
				}
				if (Value.EndsWith("PIBIT", StringComparison.CurrentCultureIgnoreCase))
				{
					if (Round)
						ret.Pebibits = Decimal.Round(Convert.ToDecimal(r.Replace(Value, "")));
					else
						ret.Pebibits = Convert.ToDecimal(r.Replace(Value, ""));
				}
				if (Value.EndsWith("PIB", StringComparison.CurrentCultureIgnoreCase))
				{
					if (Round)
						ret.Pebibytes = Decimal.Round(Convert.ToDecimal(r.Replace(Value, "")));
					else
						ret.Pebibytes = Convert.ToDecimal(r.Replace(Value, ""));
				}
				if (Value.EndsWith("KBIT", StringComparison.CurrentCultureIgnoreCase))
				{
					if (Round)
						ret.Kilobits = Decimal.Round(Convert.ToDecimal(r.Replace(Value, "")));
					else
						ret.Kilobits = Convert.ToDecimal(r.Replace(Value, ""));
				}
				if (Value.EndsWith("KB", StringComparison.CurrentCultureIgnoreCase))
				{
					if (Round)
						ret.Kilobytes = Decimal.Round(Convert.ToDecimal(r.Replace(Value, "")));
					else
						ret.Kilobytes = Convert.ToDecimal(r.Replace(Value, ""));
				}
				if (Value.EndsWith("MBIT", StringComparison.CurrentCultureIgnoreCase))
				{
					if (Round)
						ret.Megabits = Decimal.Round(Convert.ToDecimal(r.Replace(Value, "")));
					else
						ret.Megabits = Convert.ToDecimal(r.Replace(Value, ""));
				}
				if (Value.EndsWith("MB", StringComparison.CurrentCultureIgnoreCase))
				{
					if (Round)
						ret.Megabytes = Decimal.Round(Convert.ToDecimal(r.Replace(Value, "")));
					else
						ret.Megabytes = Convert.ToDecimal(r.Replace(Value, ""));
				}
				if (Value.EndsWith("GBIT", StringComparison.CurrentCultureIgnoreCase))
				{
					if (Round)
						ret.Gigabits = Decimal.Round(Convert.ToDecimal(r.Replace(Value, "")));
					else
						ret.Gigabits = Convert.ToDecimal(r.Replace(Value, ""));
				}
				if (Value.EndsWith("GB", StringComparison.CurrentCultureIgnoreCase))
				{
					if (Round)
						ret.Gigabytes = Decimal.Round(Convert.ToDecimal(r.Replace(Value, "")));
					else
						ret.Gigabytes = Convert.ToDecimal(r.Replace(Value, ""));
				}
				if (Value.EndsWith("TBIT", StringComparison.CurrentCultureIgnoreCase))
				{
					if (Round)
						ret.Terabits = Decimal.Round(Convert.ToDecimal(r.Replace(Value, "")));
					else
						ret.Terabits = Convert.ToDecimal(r.Replace(Value, ""));
				}
				if (Value.EndsWith("TB", StringComparison.CurrentCultureIgnoreCase))
				{
					if (Round)
						ret.Terabytes = Decimal.Round(Convert.ToDecimal(r.Replace(Value, "")));
					else
						ret.Terabytes = Convert.ToDecimal(r.Replace(Value, ""));
				}
				if (Value.EndsWith("PBIT", StringComparison.CurrentCultureIgnoreCase))
				{
					if (Round)
						ret.Petabits = Decimal.Round(Convert.ToDecimal(r.Replace(Value, "")));
					else
						ret.Petabits = Convert.ToDecimal(r.Replace(Value, ""));
				}
				if (Value.EndsWith("PB", StringComparison.CurrentCultureIgnoreCase))
				{
					if (Round)
						ret.Petabytes = Decimal.Round(Convert.ToDecimal(r.Replace(Value, "")));
					else
						ret.Petabytes = Convert.ToDecimal(r.Replace(Value, ""));
				}
			}

			ret.parseMode = ParseMode;
			return ret;
		}

		public override string ToString()
		{
			if (parseMode == Base2ParseMode.Scientific)
			{
				if (storeMode == Base2StorageMode.Bits) return Bits.ToString() + "bit";
				if (storeMode == Base2StorageMode.Bytes) return Bytes.ToString() + "B";
				if (storeMode == Base2StorageMode.Kibibits) return Kibibits.ToString() + "kibit";
				if (storeMode == Base2StorageMode.Kibibytes) return Kibibytes.ToString() + "KiB";
				if (storeMode == Base2StorageMode.Kilobits) return Kilobits.ToString() + "kbit";
				if (storeMode == Base2StorageMode.Kilobytes) return Kilobytes.ToString() + "KB";
				if (storeMode == Base2StorageMode.Mebibits) return Mebibits.ToString() + "Mibit";
				if (storeMode == Base2StorageMode.Mebibytes) return Mebibytes.ToString() + "MiB";
				if (storeMode == Base2StorageMode.Megabits) return Megabits.ToString() + "Mbit";
				if (storeMode == Base2StorageMode.Megabytes) return Megabytes.ToString() + "MB";
				if (storeMode == Base2StorageMode.Gibibits) return Gibibits.ToString() + "Gibit";
				if (storeMode == Base2StorageMode.Gibibytes) return Gibibytes.ToString() + "GiB";
				if (storeMode == Base2StorageMode.Gigabits) return Gigabits.ToString() + "Gbit";
				if (storeMode == Base2StorageMode.Gigabytes) return Gigabytes.ToString() + "GB";
				if (storeMode == Base2StorageMode.Tebibits) return Tebibits.ToString() + "Tebit";
				if (storeMode == Base2StorageMode.Tebibytes) return Tebibytes.ToString() + "TiB";
				if (storeMode == Base2StorageMode.Terabits) return Terabits.ToString() + "Tbit";
				if (storeMode == Base2StorageMode.Terabytes) return Terabytes.ToString() + "TB";
				if (storeMode == Base2StorageMode.Pebibits) return Pebibits.ToString() + "Pibit";
				if (storeMode == Base2StorageMode.Pebibytes) return Pebibytes.ToString() + "PiB";
				if (storeMode == Base2StorageMode.Petabits) return Petabits.ToString() + "Pbit";
				if (storeMode == Base2StorageMode.Petabytes) return Petabytes.ToString() + "PB";
			}

			if (parseMode == Base2ParseMode.Binary)
			{
				if (storeMode == Base2StorageMode.Bits) return Bits.ToString() + "bit";
				if (storeMode == Base2StorageMode.Bytes) return Bytes.ToString() + "B";
				if (storeMode == Base2StorageMode.Kibibits) return Kibibits.ToString() + "kbit";
				if (storeMode == Base2StorageMode.Kibibytes) return Kibibytes.ToString() + "KB";
				if (storeMode == Base2StorageMode.Kilobits) return Kilobits.ToString() + "kbit";
				if (storeMode == Base2StorageMode.Kilobytes) return Kilobytes.ToString() + "KB";
				if (storeMode == Base2StorageMode.Mebibits) return Mebibits.ToString() + "Mbit";
				if (storeMode == Base2StorageMode.Mebibytes) return Mebibytes.ToString() + "MB";
				if (storeMode == Base2StorageMode.Megabits) return Megabits.ToString() + "Mbit";
				if (storeMode == Base2StorageMode.Megabytes) return Megabytes.ToString() + "MB";
				if (storeMode == Base2StorageMode.Gibibits) return Gibibits.ToString() + "Gbit";
				if (storeMode == Base2StorageMode.Gibibytes) return Gibibytes.ToString() + "GB";
				if (storeMode == Base2StorageMode.Gigabits) return Gigabits.ToString() + "Gbit";
				if (storeMode == Base2StorageMode.Gigabytes) return Gigabytes.ToString() + "GB";
				if (storeMode == Base2StorageMode.Tebibits) return Tebibits.ToString() + "Tbit";
				if (storeMode == Base2StorageMode.Tebibytes) return Tebibytes.ToString() + "TB";
				if (storeMode == Base2StorageMode.Terabits) return Terabits.ToString() + "Tbit";
				if (storeMode == Base2StorageMode.Terabytes) return Terabytes.ToString() + "TB";
				if (storeMode == Base2StorageMode.Pebibits) return Pebibits.ToString() + "Pbit";
				if (storeMode == Base2StorageMode.Pebibytes) return Pebibytes.ToString() + "PB";
				if (storeMode == Base2StorageMode.Petabits) return Petabits.ToString() + "Pbit";
				if (storeMode == Base2StorageMode.Petabytes) return Petabytes.ToString() + "PB";
			}
			return "";
		}
	}
#pragma warning restore 1591
}