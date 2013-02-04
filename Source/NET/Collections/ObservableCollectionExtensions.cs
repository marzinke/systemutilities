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
using System.Collections.ObjectModel;
using System.Linq;
using System.Text;

namespace System.Collections.ObjectModel
{
	/// <summary>
	/// Extension methods for ObservableCollection.
	/// </summary>
	public static class ObservableCollectionExtensions
	{
		/// <summary>
		/// Extends ObservableCollection with an AddRange method.
		/// </summary>
		/// <param name="col">The extended collection.</param>
		/// <param name="range">The range of elements to add.</param>
		public static void AddRange<T>(this ObservableCollection<T> col, IEnumerable<T> range)
		{
			foreach(T t in range)
				col.Add(t);
		}

		/// <summary>
		/// Extends ObservableCollection with an AddRange method.
		/// </summary>
		/// <param name="col">The extended collection.</param>
		/// <param name="index">The index to begin inserting elements.</param>
		/// <param name="range">The range of elements to insert.</param>
		public static void InsertRange<T>(this ObservableCollection<T> col, int index, IEnumerable<T> range)
		{
			int i = 0;
			foreach (T t in range)
				col.Insert(index + i++, t);
		}

		/// <summary>
		/// Extends ObservableCollection with a RemoveRange method.
		/// </summary>
		/// <param name="col">The extended collection.</param>
		/// <param name="range">The range of elements to remove.</param>
		public static void RemoveRange<T>(this ObservableCollection<T> col, IEnumerable<T> range)
		{
			foreach (T t in range)
				col.Remove(t);
		}

		/// <summary>
		/// Provides sort capabilities in a specified direction using a generic selector.
		/// </summary>
		/// <typeparam name="T"></typeparam>
		/// <typeparam name="TKey"></typeparam>
		/// <param name="col">The extended collection.</param>
		/// <param name="keySelector"></param>
		/// <param name="direction"></param>
		public static void Sort<T, TKey>(this ObservableCollection<T> col, Func<T, TKey> keySelector, System.ComponentModel.ListSortDirection direction)
		{
			switch (direction)
			{
				case System.ComponentModel.ListSortDirection.Ascending:
					{
						ApplySort(col, col.OrderBy(keySelector));
						break;
					}
				case System.ComponentModel.ListSortDirection.Descending:
					{
						ApplySort(col, col.OrderByDescending(keySelector));
						break;
					}
			}
		}

		/// <summary>
		/// Provides sort capabilities in a specified direction using a generic selector and a comparer.
		/// </summary>
		/// <typeparam name="T"></typeparam>
		/// <typeparam name="TKey"></typeparam>
		/// <param name="col">The extended collection.</param>
		/// <param name="keySelector"></param>
		/// <param name="comparer"></param>
		/// <param name="direction"></param>
		public static void Sort<T, TKey>(this ObservableCollection<T> col, Func<T, TKey> keySelector, IComparer<TKey> comparer, System.ComponentModel.ListSortDirection direction)
		{
			switch (direction)
			{
				case System.ComponentModel.ListSortDirection.Ascending:
					{
						ApplySort(col, col.OrderBy(keySelector, comparer));
						break;
					}
				case System.ComponentModel.ListSortDirection.Descending:
					{
						ApplySort(col, col.OrderByDescending(keySelector, comparer));
						break;
					}
			}
		}

		/// <summary>
		/// Provides an ascending sort using a generic selector and a comparer.
		/// </summary>
		/// <typeparam name="T"></typeparam>
		/// <typeparam name="TKey"></typeparam>
		/// <param name="col">The extended collection.</param>
		/// <param name="keySelector"></param>
		/// <param name="comparer"></param>
		public static void Sort<T, TKey>(this ObservableCollection<T> col, Func<T, TKey> keySelector, IComparer<TKey> comparer)
		{
			ApplySort(col, col.OrderBy(keySelector, comparer));
		}

		/// <summary>
		/// Provides an ascending sort using a generic selector
		/// </summary>
		/// <typeparam name="T"></typeparam>
		/// <typeparam name="TKey"></typeparam>
		/// <param name="col">The extended collection.</param>
		/// <param name="keySelector"></param>
		public static void Sort<T, TKey>(this ObservableCollection<T> col, Func<T, TKey> keySelector)
		{
			ApplySort(col, col.OrderBy(keySelector));
		}

		private static void ApplySort<T>(this ObservableCollection<T> col, IEnumerable<T> sortedItems)
		{
			var sortedItemsList = sortedItems.ToList();
			foreach (var item in sortedItemsList)
			{
				if (col.IndexOf(item) == sortedItemsList.IndexOf(item)) continue;
				col.Move(col.IndexOf(item), sortedItemsList.IndexOf(item));
			}
		}
	}
}