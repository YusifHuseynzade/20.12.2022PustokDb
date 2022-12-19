using Microsoft.EntityFrameworkCore.Metadata.Internal;
using PustokDb2022.Attributes.ValidationAttributes;
using PustokDb2022.Models;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace PustokDb2022.Models
{
    public class Slider : BaseEntity
    {
        [MaxLength(30)]
        public string? Title1 { get; set; }
        [MaxLength(50)]
        public string? Title2 { get; set; }
        [MaxLength(250)]
        public string? Desc { get; set; }
        [MaxLength(100)]
        public string? Image { get; set; }
        [MaxLength(30)]
        public string BtnText { get; set; }
        [MaxLength(100)]
        public string RedirectUrl { get; set; }
        public int Order { get; set; }
        [NotMapped]
        [MaxFileSize(2)]
        [AllowedFileTypes("image/png", "image/jpeg")]
        public IFormFile? ImageFile { get; set; }

    }

}
