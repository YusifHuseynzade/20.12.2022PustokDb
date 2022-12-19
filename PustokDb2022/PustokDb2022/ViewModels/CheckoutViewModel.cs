using PustokDb2022.Models;

namespace PustokDb2022.ViewModels
{
    public class CheckoutViewModel
    {
        public Order Order { get; set; }
        public List<CheckoutItemViewModel> CheckoutItems { get; set; } = new List<CheckoutItemViewModel>();
        public decimal Total { get; set; }
    }
}
