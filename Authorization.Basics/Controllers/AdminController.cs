using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Security.Claims;
using System.Threading.Tasks;

namespace Authorization.Basics.Controllers
{
    [Authorize]
    public class AdminController : Controller
    {
        public IActionResult Index()
        {
            return View();
        }

        [AllowAnonymous]
        public IActionResult Login(string returnUrl)
        {
            return View();
        }

        [HttpPost]
        [AllowAnonymous]
        public async Task<IActionResult> LoginAsync(LoginViewModel model)
        {
            if (!ModelState.IsValid)
                return View(model);

            var claims = new List<Claim>
            {
                new Claim("Demo", "Value")
            };
            var claimIdentity = new ClaimsIdentity(claims, "Cookie");
            var claimPrincipal = new ClaimsPrincipal(claimIdentity);
            await HttpContext.SignInAsync("Cookie", claimPrincipal);

            HttpResponse resp = HttpContext.Response;
            string cookie = GetCookieValueFromResponse(resp, ".AspNetCore.Cookie");

            return Redirect(model.ReturnUrl);
        }

        /// <summary>
        /// Получение токена из Cookie
        /// </summary>
        /// <param name="response"></param>
        /// <param name="cookieName"></param>
        /// <returns></returns>
        private string GetCookieValueFromResponse(HttpResponse response, string cookieName)
        {
            foreach (var headers in response.Headers.Values)
                foreach (var header in headers)
                    if (header.StartsWith($"{cookieName}="))
                    {
                        var p1 = header.IndexOf('=');
                        var p2 = header.IndexOf(';');
                        return header.Substring(p1 + 1, p2 - p1 - 1);
                    }
            return null;
        }

        public IActionResult LogOff()
        {
            HttpContext.SignOutAsync("Cookie");
            return Redirect("/Home/Index");
        }
    }

    public class LoginViewModel
    {
        [Required]
        public string UserName { get; set; }
        [Required]
        public string Password { get; set; }
        [Required]
        public string ReturnUrl { get; set; }
    }
}
