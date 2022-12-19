using PustokDb2022.Models;
using System.Collections.Generic;

namespace PustokDb2022.ViewModels
{
    public class HomeViewModel
    {
        public List<Book> SpecialBooks { get; set; }
        public List<Book> NewBooks { get; set; }
        public List<Book> DiscountedBooks { get; set; }
        public List<Slider> Sliders { get; set; }
        public List<Feature> Features { get; set; }
        public List<BookImage> BookImages { get; set; }
        public Dictionary<string, string> Settings { get; set; }
    }
}
