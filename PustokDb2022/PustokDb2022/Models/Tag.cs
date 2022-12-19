using System.ComponentModel.DataAnnotations;

namespace PustokDb2022.Models
{
    public class Tag : BaseEntity
    {
        [MaxLength(30)]
        public string Name { get; set; }
        public List<BookTag> BookTags { get; set; } 
    }
}
