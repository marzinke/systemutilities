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
using System.Collections;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Text;
#if !NET30
using System.Linq;
#endif

namespace System.Collections.ObjectModel
{
	/// <summary>
	/// The delegate for the ElementPropertyChanged event.
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	public delegate void ElementPropertyChangedHandler(object sender, PropertyChangedEventArgs e);

	/// <summary>
	/// Adds sorting and item property change notification services to a standard ObservableCollection.
	/// </summary>
	/// <typeparam name="T"></typeparam>
	public class ObservableCollectionEx<T> : ObservableCollection<T> where T : INotifyPropertyChanged
	{
		/// <summary>
		/// Notifies the user of any changes to the properties of items stored in the collection.
		/// </summary>
		public event ElementPropertyChangedHandler ElementPropertyChanged;

		/// <summary>
		/// Basic constructor
		/// </summary>
		public ObservableCollectionEx()
			: base()
		{
		}

		/// <summary>
		/// Constructor that takes a List(Of T).
		/// </summary>
		/// <param name="list"></param>
		public ObservableCollectionEx(List<T> list)
			: base(list)
		{
		}

		/// <summary>
		/// Constructor that takes an IEnumerable(Of T).
		/// </summary>
		/// <param name="collection"></param>
		public ObservableCollectionEx(IEnumerable<T> collection)
			: base(collection)
		{
		}

		/// <summary>
		/// Calls the CollectionChanged event and updates ElementPropertyChanged event bindings.
		/// </summary>
		/// <param name="e"></param>
		protected override void OnCollectionChanged(System.Collections.Specialized.NotifyCollectionChangedEventArgs e)
		{
			Unsubscribe(e.OldItems);
			Subscribe(e.NewItems);
			base.OnCollectionChanged(e);
		}

		/// <summary>
		/// Removes all items from the collection.
		/// </summary>
		protected override void ClearItems()
		{
			foreach (T element in this)
				element.PropertyChanged -= ContainedElementChanged;

			base.ClearItems();
		}

		private void Subscribe(System.Collections.IList iList)
		{
			if (iList != null)
			{
				foreach (T element in iList)
					element.PropertyChanged += ContainedElementChanged;
			}
		}

		private void Unsubscribe(System.Collections.IList iList)
		{
			if (iList != null)
			{
				foreach (T element in iList)
					element.PropertyChanged -= ContainedElementChanged;
			}
		}

		private void ContainedElementChanged(object sender, PropertyChangedEventArgs e)
		{
			OnPropertyChanged(e);
			ElementPropertyChanged(sender, e);
		}
	}
}