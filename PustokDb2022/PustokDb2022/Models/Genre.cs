using PustokDb2022.Models;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;

namespace PustokDb2022.Models
{
    public class Genre : BaseEntity
    {
        [Required]
        [MaxLength(50)]
        public string Name { get; set; }
        public List<Book>? Books { get; set; }
    }
}
