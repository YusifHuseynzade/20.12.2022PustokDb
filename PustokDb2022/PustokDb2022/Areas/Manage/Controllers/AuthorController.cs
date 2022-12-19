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
    public class AuthorController : Controller
    {
        private readonly PustokDbContext _context;

        public AuthorController(PustokDbContext context)
        {
            _context = context;
        }
        public IActionResult Index(int page = 1)
        {
            var model = _context.Authors.Include(x => x.Books).Skip((page-1)*2).Take(2).ToList();
            ViewBag.Page = page;
            ViewBag.TotalPage = (int)Math.Ceiling(_context.Authors.Count() / 2d);
            
            return View(model);
        }

        public IActionResult Create()
        {
            return View();
        }

        [HttpPost]
        public IActionResult Create(Author author)
        {
            if (!ModelState.IsValid)
            {
                return View();
            }

            if (_context.Authors.Any(x => x.FullName == author.FullName))
            {
                ModelState.AddModelError("FullName", "This Fullname has been taken");
                return View();
            }

            _context.Authors.Add(author);
            _context.SaveChanges();

            return RedirectToAction("Index");
        }

        public IActionResult Edit(int id)
        {
            Author author = _context.Authors.FirstOrDefault(x => x.Id == id);
            if (author == null)
            return RedirectToAction("error", "dashboard");

            return View(author);
        }



        [HttpPost]
        public IActionResult Edit(Author author)
        {
            if (!ModelState.IsValid)
            {
                return View();
            }


            if (_context.Authors.Any(x => x.FullName == author.FullName && x.Id!=author.Id))
            {
                ModelState.AddModelError("FullName", "This Fullname has been taken");
                return View();
            }

            Author existAuthor = _context.Authors.FirstOrDefault(x => x.Id == author.Id);

            existAuthor.FullName = author.FullName;
            _context.SaveChanges();

            return RedirectToAction("index");
        }

        public IActionResult Delete(int id)
        {
            Author author = _context.Authors.Include(x => x.Books).FirstOrDefault(x => x.Id == id);

            return View(author);
        }

        [HttpPost]
        public IActionResult Delete(Author author)
        {
            Author existAuthor = _context.Authors.FirstOrDefault(x => x.Id == author.Id);

            if (!_context.Books.Any(x => x.AuthorId == author.Id))
            {
                _context.Authors.Remove(existAuthor);
                _context.SaveChanges();
            }


            return RedirectToAction("index");
        }
    }
}
