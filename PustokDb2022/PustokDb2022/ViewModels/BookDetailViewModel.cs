using PustokDb2022.Models;

namespace PustokDb2022.ViewModels
{
    public class BookDetailViewModel
    {
        public Book Book { get; set; }
        public List<Book> RelatedBooks { get; set; }
        public ReviewCreateViewModel ReviewVM { get; set; }
        public bool HasReview { get; set; }
    }
}
