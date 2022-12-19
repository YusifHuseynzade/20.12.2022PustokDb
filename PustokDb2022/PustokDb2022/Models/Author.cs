using PustokDb2022.Models;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;

namespace PustokDb2022.Models
{
    public class Author : BaseEntity
    {
        [Required]
        [MaxLength(35)]
        public string FullName { get; set; }
        public List<Book>? Books { get; set; }
    }
}
