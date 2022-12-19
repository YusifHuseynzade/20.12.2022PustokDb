using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using PustokDb2022.DAL;
using PustokDb2022.Models;
using System.Data;

namespace PustokDb2022.Areas.Manage.Controllers
{
    [Area("manage")]
    [Authorize(Roles = "SuperAdmin,Admin,Editor")]
    public class GenreController : Controller
    {
        private readonly PustokDbContext _context;

        public GenreController(PustokDbContext context)
        {
            _context = context;
        }
       
        public IActionResult Index(int page = 1)
        {
            var model = _context.Genres.Include(x => x.Books).Skip((page-1)*2).Take(2).ToList();
            ViewBag.Page = page;
            ViewBag.TotalPage = (int)Math.Ceiling(_context.Genres.Count() / 2d);

            return View(model);
        }

        public IActionResult Create()
        {
            return View();
        }

        [HttpPost]
        public IActionResult Create(Genre genre)
        {
            if (!ModelState.IsValid)
            {
                return View();
            }

            if (_context.Genres.Any(x => x.Name == genre.Name))
            {
                ModelState.AddModelError("Name", "This name has been taken");
                return View();
            }

            _context.Genres.Add(genre);
            _context.SaveChanges();

            return RedirectToAction("Index");
        }

        public IActionResult Edit(int id)
        {
            Genre genre = _context.Genres.FirstOrDefault(x => x.Id == id);
            if (genre == null)
            return RedirectToAction("error", "dashboard");


            return View(genre);
        }



        [HttpPost]
        public IActionResult Edit(Genre genre)
        {
            if (!ModelState.IsValid)
            {
                return View();
            }


            if (_context.Genres.Any(x => x.Name == genre.Name && x.Id!=genre.Id))
            {
                ModelState.AddModelError("Name", "This name has been taken");
                return View();
            }

            Genre existGenre = _context.Genres.FirstOrDefault(x => x.Id == genre.Id);

            existGenre.Name = genre.Name;
            _context.SaveChanges();

            return RedirectToAction("index");
        }

        public IActionResult Delete(int id)
        {
            Genre genre = _context.Genres.Include(x => x.Books).FirstOrDefault(x => x.Id == id);

            return View(genre);
        }

        [HttpPost]
        public IActionResult Delete(Genre genre)
        {
            Genre existGenre = _context.Genres.FirstOrDefault(x => x.Id == genre.Id);

            if (!_context.Books.Any(x => x.GenreId == genre.Id))
            {
                _context.Genres.Remove(existGenre);
                _context.SaveChanges();
            }


            return RedirectToAction("index");
        }
    }
}
