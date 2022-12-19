using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using PustokDb2022.DAL;
using PustokDb2022.Helpers;
using PustokDb2022.Models;
using System.Data;

namespace PustokDb2022.Areas.Manage.Controllers
{
    [Area("manage")]
    [Authorize(Roles = "SuperAdmin,Admin,Editor")]
    public class SliderController : Controller
    {
        private readonly PustokDbContext _context;
        private readonly IWebHostEnvironment _env;

        public SliderController(PustokDbContext context, IWebHostEnvironment env)
        {
            _context = context;
            _env = env;
        }
        public IActionResult Index()
        {
            var model = _context.Sliders.OrderBy(x => x.Order).ToList();

            return View(model);
        }

        public IActionResult Create()
        {

            var slider = _context.Sliders.OrderByDescending(x => x.Order).FirstOrDefault();
            int order = slider == null ? 1 : slider.Order + 1;


            ViewBag.Order = order;
            return View();
        }

        [HttpPost]
        public IActionResult Create(Slider slider)
        {
            if (slider.ImageFile!=null && slider.ImageFile.ContentType != "image/png" && slider.ImageFile.ContentType != "image/jpeg")
                ModelState.AddModelError("ImageFile", "Content type must be image/png or image/jpeg!");

            if (slider.ImageFile!=null && slider.ImageFile.Length > 2097152)
                ModelState.AddModelError("ImageFile", "File size must be less than 2MB!");
            if (!ModelState.IsValid)
            {
                return View();
            }

            slider.Image = FileManager.Save(slider.ImageFile, _env.WebRootPath, "uploads/sliders");


            _context.Sliders.Add(slider);
            _context.SaveChanges();

            return RedirectToAction("index");
        }

        [HttpPost]
        public IActionResult Edit(Slider slider)
        {
            if (!ModelState.IsValid)
            {
                return View();
            }

            if (slider.ImageFile!=null && slider.ImageFile.ContentType != "image/png" && slider.ImageFile.ContentType != "image/jpeg")
                ModelState.AddModelError("ImageFile", "Content type must be image/png or image/jpeg!");

            if (slider.ImageFile!=null && slider.ImageFile.Length > 2097152)
                ModelState.AddModelError("ImageFile", "File size must be less than 2MB!");

            Slider existSlider = _context.Sliders.FirstOrDefault(x => x.Id == slider.Id);
            if (existSlider == null)
            {
                return RedirectToAction("error", "dashboard");
            }

            if (slider.ImageFile != null)
            {
                var newImageName = FileManager.Save(slider.ImageFile, _env.WebRootPath, "uploads/sliders");

                FileManager.Delete(_env.WebRootPath, "uploads/sliders", existSlider.Image);
                existSlider.Image = newImageName;
            }

            
            existSlider.Order = slider.Order;
            existSlider.Desc = slider.Desc;
            existSlider.RedirectUrl = slider.RedirectUrl;
            existSlider.BtnText = slider.BtnText;
            existSlider.Title1 = slider.Title1;
            existSlider.Title2 = slider.Title2;
            _context.SaveChanges();

            return RedirectToAction("index");
        }

        public IActionResult Edit(int id)
        {
            Slider slider = _context.Sliders.FirstOrDefault(x => x.Id == id);

            return View(slider);
        }


        public IActionResult Delete(int id)
        {
            Slider slider = _context.Sliders.FirstOrDefault(x => x.Id == id);

            if (slider == null)
                return NotFound();

            FileManager.Delete(_env.WebRootPath, "uploads/sliders", slider.Image);

            _context.Sliders.Remove(slider);
            _context.SaveChanges();

            return Ok();
        }
    }
}
