using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using PustokDb2022.Models;
using System.Collections.Generic;

namespace PustokDb2022.DAL
{
    public class PustokDbContext : IdentityDbContext
    {
        public PustokDbContext(DbContextOptions<PustokDbContext> options) : base(options)
        {

        }
        public DbSet<Slider> Sliders { get; set; }
        public DbSet<Genre> Genres { get; set; }
        public DbSet<BookImage> BookImages { get; set; }
        public DbSet<Book> Books { get; set; }
        public DbSet<Author> Authors { get; set; }
        public DbSet<BtmPromotion> BtmPromotions { get; set; }
        public DbSet<TopPromotion> TopPromotions { get; set; }
        public DbSet<Setting> Settings { get; set; }
        public DbSet<Feature> Features { get; set; }
        public DbSet<Tag> Tags { get; set; }
        public DbSet<BookTag> BookTags { get; set; }
        public DbSet<AppUser> AppUsers { get; set; }
        public DbSet<Review> Reviews { get; set; }
        public DbSet<BasketItem> BasketItems { get; set; }
        public DbSet<Order> Orders { get; set; }
        public DbSet<OrderItem> OrderItems { get; set; }
    }
}
