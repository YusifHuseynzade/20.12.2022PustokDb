using System.ComponentModel.DataAnnotations;

namespace PustokDb2022.Models
{
    public class Feature
    {
        public int Id { get; set; }
        [Required]
        [MaxLength(75)]
        public string Icon { get; set; }
        [Required]
        [MaxLength(100)]
        public string Text1 { get; set; }
        [Required]
        [MaxLength(100)]
        public string Text2 { get; set; }
    }
}
