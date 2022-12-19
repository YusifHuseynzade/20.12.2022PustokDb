using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using PustokDb2022.DAL;
using PustokDb2022.Models;
using PustokDb2022.ViewModels;
using System.Data;

namespace PustokDb2022.Controllers
{
    public class AccountController : Controller
    {
        private readonly PustokDbContext _pustokcontext;
        private readonly UserManager<AppUser> _userManager;
        private readonly SignInManager<AppUser> _signInManager;
      

        public AccountController(PustokDbContext pustokContext, UserManager<AppUser> userManager, SignInManager<AppUser> signInManager)
        {
            _pustokcontext = pustokContext;
            _userManager= userManager;
            _signInManager=signInManager;
        }
        public IActionResult Login()
        {
            return View();
        }

        public IActionResult Register()
        {
            return View();
        }
        [HttpPost]
        public async Task<IActionResult> RegisterAsync(MemberRegisterViewModel memberVM)
        {
            if(!ModelState.IsValid)
                return View();
            //AppUser user = _pustokdbcontext.AppUsers.FirstOrDefault(x=>x.NormalizedUserName == memberVM.UserName.ToUpper());

            if (await _userManager.FindByNameAsync(memberVM.UserName) != null)
            {
                ModelState.AddModelError("Username", "This Username already exist!");
                return View();
            }
            else if (await _userManager.FindByEmailAsync(memberVM.Email) != null)
            {
                ModelState.AddModelError("Email", "This Email already exist!");
                return View();
            }

            AppUser user = new AppUser
            {
                UserName = memberVM.UserName,
                Email = memberVM.Email,
                FullName= memberVM.FullName,
            };

            var result = await _userManager.CreateAsync(user, memberVM.Password);

           if(!result.Succeeded)
            {
                foreach(var error in result.Errors)
                {
                    ModelState.AddModelError("", error.Description);
                }
                return View();
            }

            await _userManager.AddToRoleAsync(user, "Member");
            return RedirectToAction("login");
        }

        [HttpPost]
        public async Task<IActionResult> Login(MemberLoginViewModel memberVM, string returnUrl)
        {
            AppUser user = await _userManager.FindByNameAsync(memberVM.Username);

            if (user == null)
            {
                ModelState.AddModelError("", "Username or Password is incorrect!");
                return View();
            }

            var roles = await _userManager.GetRolesAsync(user);

            if (!roles.Contains("Member"))
            {
                ModelState.AddModelError("", "Username or Passwrod is incorrect!");
                return View();
            }

            var result = await _signInManager.PasswordSignInAsync(user, memberVM.Password, false, true);

            if (result.IsLockedOut)
            {
                ModelState.AddModelError("", "5 dəqiqə sonra təkrar yoxlayın!");
                return View();
            }

            if (!result.Succeeded)
            {
                ModelState.AddModelError("", "Username or Password is incorrect!");
                return View();
            }

            if (returnUrl != null)
                return Redirect(returnUrl);

            return RedirectToAction("index", "home");
        }

        public async Task<IActionResult> LogOut()
        {
            await _signInManager.SignOutAsync();
            return RedirectToAction("login", "account");
        }
        public async Task<IActionResult> Show()
        {
            if (User.Identity.IsAuthenticated)

            {
                AppUser user = await _userManager.FindByNameAsync(User.Identity.Name);
                return Content(user.FullName);
            }
            return Content("logged out");
        }

        [Authorize(Roles = "Member")]
        public async Task<IActionResult> Profile()
        {
            AppUser user = await _userManager.FindByNameAsync(User.Identity.Name);

            MemberUpdateViewModel memberVM = new MemberUpdateViewModel
            {
                Username = user.UserName,
                Fullname = user.FullName,
                Email = user.Email,
            };
            return View(memberVM);
        }

        [Authorize(Roles = "Member")]
        [HttpPost]
        public async Task<IActionResult> Profile(MemberUpdateViewModel memberVM)
        {
            AppUser user = await _userManager.FindByNameAsync(User.Identity.Name);

            if (user == null)
                return RedirectToAction("login");

            if (memberVM.Username.ToUpper()!= user.NormalizedUserName && _pustokcontext.Users.Any(x => x.NormalizedUserName == memberVM.Username.ToUpper()))
                ModelState.AddModelError("Username", "Username has already taken");

            if (memberVM.Email.ToUpper() != user.NormalizedEmail && _pustokcontext.Users.Any(x => x.NormalizedEmail == memberVM.Email.ToUpper()))
                ModelState.AddModelError("Email", "Email has already  taken");

            if (!ModelState.IsValid)
                return View();

            if (memberVM.Password != null)
            {
                if (memberVM.CurrentPassword==null || !await _userManager.CheckPasswordAsync(user, memberVM.CurrentPassword))
                {
                    ModelState.AddModelError("CurrentPassword", "CurrentPassword is not correct!");
                    return View();
                }

                var restult = await _userManager.ChangePasswordAsync(user, memberVM.CurrentPassword, memberVM.Password);

                if (!restult.Succeeded)
                {
                    foreach (var err in restult.Errors)
                    {
                        ModelState.AddModelError("", err.Description);
                    }
                    return View();
                }
            }

            user.UserName = memberVM.Username;
            user.FullName = memberVM.Fullname;
            user.Email = memberVM.Email;

            var result = await _userManager.UpdateAsync(user);
            await _signInManager.SignInAsync(user, false);
            return RedirectToAction("profile");

        }
    }
}
