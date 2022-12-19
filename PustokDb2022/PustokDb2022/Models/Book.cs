using Microsoft.EntityFrameworkCore.Metadata.Internal;
using PustokDb2022.Attributes.ValidationAttributes;
using PustokDb2022.Models;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace PustokDb2022.Models
{
    public class Book : BaseEntity
    {
        public int GenreId { get; set; }
        public int AuthorId { get; set; }
        [MaxLength(100)]
        public string Name { get; set; }
        public byte AvgRate { get; set; }
        public bool StockStatus { get; set; }
        [Column(TypeName = "decimal(18,2)")]
        public decimal SalePrice { get; set; }
        [Column(TypeName = "decimal(18,2)")]
        public decimal DisCountPercent { get; set; }
        [Column(TypeName = "decimal(18,2)")]
        public decimal CostPrice { get; set; }
        public bool IsDeleted { get; set; }
        public bool IsSpecial { get; set; }
        public bool IsNew { get; set; }
        [NotMapped]
        [MaxFileSize(2)]
        [AllowedFileTypes("image/jpeg", "image/png")]
        public IFormFile? PosterFile { get; set; }
        [NotMapped]
        [MaxFileSize(2)]
        [AllowedFileTypes("image/jpeg", "image/png")]
        public IFormFile? HoverPosterFile { get; set; }
        [NotMapped]
        [MaxFileSize(2)]
        public List<IFormFile>? ImageFiles { get; set; } = new List<IFormFile>();
        [NotMapped]
        public List<int>? BookImageIds { get; set; } = new List<int>();
        [NotMapped]
        public List<int>? TagIds { get; set; } = new List<int>();
        public Genre? Genres { get; set; }
        public Author? Authors { get; set; }
        public List<BookImage>? BookImages { get; set; }
        public List<BookTag>? BookTags { get; set; }
        public List<Review>? Reviews { get; set; }

    }
}
