using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace PustokDb2022.Controllers
{
    public class BaseController : Controller
    {
        protected string UserId => User.FindFirstValue(ClaimTypes.NameIdentifier);
    }
}
