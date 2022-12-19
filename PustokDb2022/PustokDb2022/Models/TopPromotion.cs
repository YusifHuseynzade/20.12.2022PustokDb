using PustokDb2022.Models;
using System.ComponentModel.DataAnnotations;

namespace PustokDb2022.Models
{
    public class TopPromotion : BaseEntity
    {
        [Required]
        [MaxLength(75)]
        public string Image { get; set; }
        [Required]
        [MaxLength(100)]
        public string RedirectUrl { get; set; }
    }
}
