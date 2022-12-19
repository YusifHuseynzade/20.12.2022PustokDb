using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using PustokDb2022.Areas.Manage.ViewModels;
using PustokDb2022.DAL;
using PustokDb2022.Helpers;
using PustokDb2022.Models;
using System.Data;

namespace PustokDb2022.Areas.Manage.Controllers
{
    [Area("manage")]
    [Authorize(Roles = "SuperAdmin,Admin,Editor")]
    public class BookController : Controller
    {
        private readonly PustokDbContext _context;
        private readonly IWebHostEnvironment _env;
        public BookController(PustokDbContext context, IWebHostEnvironment env)
        {
            _context = context;
            _env = env;
        }
        public IActionResult Index(int page = 1)
        {
            var query = _context.Books
                .Include(x => x.Genres)
                .Include(x => x.Authors)
                .Include(x => x.BookImages);


            var model = PaginationList<Book>.Create(query, page, 4);
            return View(model);
        }
        public IActionResult Create()
        {
            ViewBag.Genres = _context.Genres.ToList();
            ViewBag.Authors = _context.Authors.ToList();
            ViewBag.Tags = _context.Tags.ToList();


            return View();
        }

        [HttpPost]
        public IActionResult Create(Book book)
        {
            if (!_context.Authors.Any(x => x.Id == book.AuthorId))
                ModelState.AddModelError("AuthorId", "Author not found");

            if (!_context.Genres.Any(x => x.Id == book.GenreId))
                ModelState.AddModelError("GenreId", "Genre not found");

            _checkImageFiles(book.ImageFiles, book.PosterFile, book.HoverPosterFile);

            if (!ModelState.IsValid)
            {
                ViewBag.Genres = _context.Genres.ToList();
                ViewBag.Authors = _context.Authors.ToList();
                ViewBag.Tags = _context.Tags.ToList();

                return View();
            }

            book.BookImages = new List<BookImage>();

            BookImage poster = new BookImage
            {
                Image = FileManager.Save(book.PosterFile, _env.WebRootPath, "uploads/books"),
                PosterStatus = true,
            };

            book.BookImages.Add(poster);

            BookImage hoverPoster = new BookImage
            {
                Image = FileManager.Save(book.HoverPosterFile, _env.WebRootPath, "uploads/books"),
                PosterStatus = false
            };
            book.BookImages.Add(hoverPoster);


            foreach (var imgFile in book.ImageFiles)
            {
                BookImage bookImage = new BookImage
                {
                    Image = FileManager.Save(imgFile, _env.WebRootPath, "uploads/books"),
                };
                book.BookImages.Add(bookImage);
            }

            book.BookTags = new List<BookTag>();

            foreach (var tagId in book.TagIds)
            {
                if (!_context.Tags.Any(x => x.Id == tagId))
                {
                    ViewBag.Genres = _context.Genres.ToList();
                    ViewBag.Authors = _context.Authors.ToList();
                    ViewBag.Tags = _context.Tags.ToList();

                    ModelState.AddModelError("TagIds", "Tag not found");
                    return View();
                }

                BookTag bookTag = new BookTag
                {
                    TagId = tagId
                };
                book.BookTags.Add(bookTag);
            }

            _context.Books.Add(book);
            _context.SaveChanges();

            return RedirectToAction("index");
        }

        private void _checkImageFiles(List<IFormFile> images, IFormFile posterFile, IFormFile hoverPosterFile)
        {
            if (posterFile == null)
                ModelState.AddModelError("PosterFile", "PosterFile is required");
            else if (posterFile.ContentType != "image/png" && posterFile.ContentType != "image/jpeg")
                ModelState.AddModelError("PosterFile", "Content type must be image/png or image/jpeg!");
            else if (posterFile != null && posterFile.Length > 2097152)
                ModelState.AddModelError("PosterFile", "File size must be less than 2MB!");

            if (hoverPosterFile == null)
                ModelState.AddModelError("hoverPosterFile", "hoverPosterFile is required");
            else if (hoverPosterFile != null && hoverPosterFile.ContentType != "image/png" && hoverPosterFile.ContentType != "image/jpeg")
                ModelState.AddModelError("HoverPosterFile", "Content type must be image/png or image/jpeg!");
            else if (hoverPosterFile != null && hoverPosterFile.Length > 2097152)
                ModelState.AddModelError("HoverPosterFile", "File size must be less than 2MB!");

            if (images != null)
            {
                foreach (var imgFile in images)
                {
                    if (imgFile.ContentType != "image/png" && imgFile.ContentType != "image/jpeg")
                        ModelState.AddModelError("ImageFiles", "Content type must be image/png or image/jpeg!");

                    if (imgFile.Length > 2097152)
                        ModelState.AddModelError("ImageFiles", "File size must be less than 2MB!");
                }
            }
        }

        public IActionResult Edit(int id)
        {
            Book book = _context.Books.Include(x => x.BookTags).Include(x => x.BookImages).FirstOrDefault(x => x.Id == id);

            if (book == null)
                return RedirectToAction("error", "dashboard");
            ViewBag.Genres = _context.Genres.ToList();
            ViewBag.Authors = _context.Authors.ToList();
            ViewBag.Tags = _context.Tags.ToList();

            foreach (var bt in book.BookTags)
            {
                book.TagIds.Add(bt.TagId);
            }

            //book.TagIds = book.BookTags.Select(x => x.TagId).ToList();

            return View(book);
        }

        [HttpPost]
        public IActionResult Edit(Book book)
        {
            Book existBook = _context.Books.Include(x => x.BookTags).Include(x => x.BookImages).FirstOrDefault(x => x.Id == book.Id);

            if (existBook == null)
                return RedirectToAction("error", "dashboard");

            if (existBook.GenreId != book.GenreId && !_context.Genres.Any(x => x.Id == book.GenreId))
                ModelState.AddModelError("GenreId", "Genre not found!");

            if (existBook.AuthorId != book.AuthorId && !_context.Authors.Any(x => x.Id == book.AuthorId))
                ModelState.AddModelError("AuthorId", "Author not found!");

            if (!ModelState.IsValid)
            {
                ViewBag.Genres = _context.Genres.ToList();
                ViewBag.Authors = _context.Authors.ToList();
                ViewBag.Tags = _context.Tags.ToList();

                 foreach(var bt in existBook.BookTags)
                {
                    book.TagIds.Add(bt.TagId);
                }

                //existBook.TagIds = book.BookTags.Select(x => x.TagId).ToList();

                return View(existBook);
            }

            if (book.PosterFile != null)
            {
                var poster = existBook.BookImages.FirstOrDefault(x => x.PosterStatus == true);
                var newPosterName = FileManager.Save(book.PosterFile, _env.WebRootPath, "uploads/books");
                FileManager.Delete(_env.WebRootPath, "uploads/books", poster.Image);
                poster.Image = newPosterName;
            }

            if (book.HoverPosterFile != null)
            {
                var hoverPoster = existBook.BookImages.FirstOrDefault(x => x.PosterStatus == false);
                var newHoverPosterName = FileManager.Save(book.HoverPosterFile, _env.WebRootPath, "uploads/books");
                FileManager.Delete(_env.WebRootPath, "uploads/books", hoverPoster.Image);
                hoverPoster.Image = newHoverPosterName;
            }

            var removedFiles = existBook.BookImages.FindAll(x => x.PosterStatus == null && !book.BookImageIds.Contains(x.Id));

            foreach (var item in removedFiles)
            {
                FileManager.Delete(_env.WebRootPath, "uploads/books", item.Image);
            }

            existBook.BookImages.RemoveAll(x => removedFiles.Contains(x));

            foreach (var imgFile in book.ImageFiles)
            {
                BookImage bookImage = new BookImage
                {
                    Image = FileManager.Save(imgFile, _env.WebRootPath, "uploads/books"),
                };
                existBook.BookImages.Add(bookImage);
            }

            existBook.BookTags.RemoveAll(x => !book.TagIds.Contains(x.TagId));

            foreach (var tagId in book.TagIds.Where(x => !existBook.BookTags.Any(bt => bt.TagId==x)))
            {
                if (!_context.Tags.Any(x => x.Id == tagId))
                {
                    ViewBag.Genres = _context.Genres.ToList();
                    ViewBag.Authors = _context.Authors.ToList();
                    ViewBag.Tags = _context.Tags.ToList();

                    foreach (var bt in existBook.BookTags)
                    {
                        book.TagIds.Add(bt.TagId);
                    }

                    //book.TagIds = existBook.BookTags.Select(x => x.TagId).ToList();

                    ModelState.AddModelError("TagIds", "Tag not found");
                    return View(existBook);
                }

                BookTag bookTag = new BookTag
                {
                    TagId = tagId
                };
                existBook.BookTags.Add(bookTag);
            }


            existBook.GenreId = book.GenreId;
            existBook.AuthorId = book.AuthorId;
            existBook.Name = book.Name;
            existBook.SalePrice = book.SalePrice;
            existBook.DisCountPercent = book.DisCountPercent;
            existBook.CostPrice = book.CostPrice;
            existBook.IsNew = book.IsNew;
            existBook.IsSpecial = book.IsSpecial;
            existBook.StockStatus = book.StockStatus;

            _context.SaveChanges();

            return RedirectToAction("index");
        }
    }
}
