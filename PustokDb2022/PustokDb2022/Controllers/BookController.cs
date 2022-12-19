using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using PustokDb2022.DAL;
using PustokDb2022.Models;
using PustokDb2022.ViewModels;
using Newtonsoft.Json;

namespace PustokDb2022.Controllers
{
    public class BookController : Controller
    {
        private readonly PustokDbContext _context;
        private readonly UserManager<AppUser> _userManager;

        public BookController(PustokDbContext context, UserManager<AppUser> userManager)
        {
            _context = context;
            _userManager = userManager;

        }

        public IActionResult GetBook(int id)
        {
            Book book = _context.Books.Include(x => x.Genres).Include(x => x.BookImages).FirstOrDefault(x => x.Id == id);

            return PartialView("_BookModalPartial", book);
        }
        public async Task<IActionResult> Detail(int id)
        {
            Book book = _context.Books
                .Include(x => x.Genres)
                .Include(x => x.Authors)
                .Include(x => x.BookImages)
                .Include(x => x.Reviews).ThenInclude(x => x.AppUser)
                .Include(x => x.BookTags).ThenInclude(x => x.Tag)
                .FirstOrDefault(x => x.Id == id);

            BookDetailViewModel detailVM = new BookDetailViewModel
            {
                Book = book,
                ReviewVM = new ReviewCreateViewModel { BookId = id },
                RelatedBooks = _context.Books.Include(x => x.BookImages).Include(x => x.Authors).Where(x => x.GenreId == book.GenreId || x.AuthorId == book.AuthorId).Take(8).ToList()
            };

            if (User.Identity.IsAuthenticated)
            {
                AppUser user = await _userManager.FindByNameAsync(User.Identity.Name);

                if (user != null)
                {
                    detailVM.HasReview = book.Reviews.Any(x => x.AppUserId == user.Id);
                }
            }

            if (book == null)
                return NotFound();

            return View(detailVM);
        }

        [Authorize(Roles = "Member")]
        [HttpPost]
        public async Task<IActionResult> Review(ReviewCreateViewModel reviewVM)
        {
            AppUser user = await _userManager.FindByNameAsync(User.Identity.Name);

            Book book = await _context.Books
              .Include(x => x.Genres)
              .Include(x => x.Authors)
              .Include(x => x.BookImages)
              .Include(x => x.Reviews).ThenInclude(x => x.AppUser)
              .Include(x => x.BookTags).ThenInclude(x => x.Tag)
              .FirstOrDefaultAsync(x => x.Id == reviewVM.BookId);

            if (book == null)
                return NotFound();

            if (!ModelState.IsValid)
            {

                BookDetailViewModel detailVM = new BookDetailViewModel
                {
                    Book = book,
                    RelatedBooks = _context.Books.Include(x => x.BookImages).Include(x => x.Authors).Where(x => x.GenreId == book.GenreId || x.AuthorId == book.AuthorId).Take(8).ToList(),
                    ReviewVM = reviewVM
                };

                return View("detail", detailVM);
            }

            Review newReview = new Review
            {
                Rate = reviewVM.Rate,
                Text = reviewVM.Text,
                AppUserId = user.Id,
            };

            book.Reviews.Add(newReview);
            book.AvgRate = (byte)Math.Ceiling(book.Reviews.Average(x => x.Rate));
            await _context.SaveChangesAsync();

            return RedirectToAction("detail", new { id = book.Id });
        }

        public async Task<IActionResult> AddToBasket(int bookId, int count = 1)
        {
            AppUser user = null;


            if (User.Identity.IsAuthenticated)
            {
                user = await _userManager.FindByNameAsync(User.Identity.Name);
            }


            if (!_context.Books.Any(x => x.Id == bookId && x.StockStatus))
            {
                return NotFound();
            }

            BasketViewModel basket = new BasketViewModel();


            if (user != null)
            {
                BasketItem basketItem = _context.BasketItems.FirstOrDefault(x => x.BookId == bookId && x.AppUserId == user.Id);

                if (basketItem == null)
                {
                    basketItem = new BasketItem
                    {
                        AppUserId = user.Id,
                        BookId = bookId,
                        Count = 1

                    };

                    _context.BasketItems.Add(basketItem);
                }
                else
                {
                    basketItem.Count++;
                }

                _context.SaveChanges();
               

                var model = _context.BasketItems.Include(x => x.Book).ThenInclude(x => x.BookImages).Where(x => x.AppUserId==user.Id).ToList();


                foreach (var item in model)
                {
                    BasketItemViewModel itemVM = new BasketItemViewModel
                    {
                        Book = item.Book,
                        Count = item.Count,
                        Id = item.Id
                    };

                    basket.Items.Add(itemVM);
                    basket.TotalPrice += item.Count * (item.Book.SalePrice * (100 - item.Book.DisCountPercent) / 100);
                }
            }
            else
            {
                var basketStr = HttpContext.Request.Cookies["basket"];

                List<BasketItemCookieViewModel> basketCookieItems = null;
                if (basketStr == null)
                {
                    basketCookieItems = new List<BasketItemCookieViewModel>();
                }
                else
                {
                    basketCookieItems = JsonConvert.DeserializeObject<List<BasketItemCookieViewModel>>(basketStr);
                }


                BasketItemCookieViewModel basketCookieItem = basketCookieItems.FirstOrDefault(x => x.BookId == bookId);

                if (basketCookieItem == null)
                {
                    basketCookieItem = new BasketItemCookieViewModel
                    {
                        BookId = bookId,
                        Count = 1
                    };

                    basketCookieItems.Add(basketCookieItem);
                }
                else
                {
                    basketCookieItem.Count++;
                }


                var jsonStr = JsonConvert.SerializeObject(basketCookieItems);
                HttpContext.Response.Cookies.Append("basket", jsonStr);



                foreach (var item in basketCookieItems)
                {
                    Book book = _context.Books.Include(x => x.BookImages).FirstOrDefault(x => x.Id == item.BookId);

                    BasketItemViewModel itemVM = new BasketItemViewModel
                    {
                        Book = book,
                        Count = item.Count,
                        Id = 0
                    };

                    basket.Items.Add(itemVM);
                    basket.TotalPrice += item.Count * (itemVM.Book.SalePrice * (100 - itemVM.Book.DisCountPercent) / 100);
                }
            }
            return RedirectToAction("index", "home");
        }

        public IActionResult GetBasket()
        {
            var basketStr = HttpContext.Request.Cookies["basket"];

            var basket = JsonConvert.DeserializeObject<List<BasketItemCookieViewModel>>(basketStr);

            return Ok(basket);
        }
    }
    
}
