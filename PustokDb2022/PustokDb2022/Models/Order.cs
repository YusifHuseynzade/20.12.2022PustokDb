
using PustokDb2022.Enums;
using System.ComponentModel.DataAnnotations;

namespace PustokDb2022.Models
{
    public class Order: BaseEntity
    {
        public string? AppUserId { get; set; }
        [MaxLength(25)]
        public string Fullname { get; set; }
        [MaxLength(100)]
        public string Email { get; set; }
        [MaxLength(250)]
        public string Address1 { get; set; }
        [MaxLength(250)]
        public string? Address2 { get; set; }
        [MaxLength(20)]
        public string City { get; set; }
        [MaxLength(10)]
        public string ZipCode { get; set; }
        [MaxLength(500)]
        public string? Note { get; set; }
        public AppUser? AppUser { get; set; }
        public List<OrderItem>?OrderItems { get; set; }
        public OrderStatus Status { get; set; }
    }
}
