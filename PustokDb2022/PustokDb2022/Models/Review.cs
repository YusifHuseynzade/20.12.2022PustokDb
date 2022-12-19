namespace PustokDb2022.Models
{
    public class Review : BaseEntity
    {
        public int BookId { get; set; }
        public string AppUserId { get; set; }
        public byte Rate { get; set; }
        public string Text { get; set; }
        public Book Book { get; set; }
        public AppUser AppUser { get; set; }
    }
}
