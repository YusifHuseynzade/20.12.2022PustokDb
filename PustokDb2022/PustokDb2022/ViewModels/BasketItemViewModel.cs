using PustokDb2022.Models;

namespace PustokDb2022.ViewModels
{
    public class BasketItemViewModel
    {
        public int Id { get; set; }
        public int Count { get; set; }
        public Book Book { get; set; }
    }
}
