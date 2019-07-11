using Microsoft.AspNetCore.Mvc;
using System.Threading.Tasks;
using WebAdvert.Web.Models.Accounts;
using Amazon.AspNetCore.Identity.Cognito;
using Amazon.Extensions.CognitoAuthentication;

namespace WebAdvert.Web.Controllers
{

    public class AccountsController : Controller
    {
        private readonly CognitoUserPool _pool;
        private readonly CognitoUserManager<CognitoUser> _userManager;
        private readonly CognitoSignInManager<CognitoUser> _signInManager;
        public AccountsController(CognitoUserPool pool, CognitoUserManager<CognitoUser> userManager, CognitoSignInManager<CognitoUser> signInManager)
        {
            _pool = pool;
            _userManager = userManager;
            _signInManager = signInManager;
        }
        [HttpGet]
        public IActionResult SignUP()
        {
            var model = new SignUpModel();
            return View(model);
        }

        [HttpPost]
        public async Task<IActionResult> SignUP(SignUpModel model)
        {
            if (ModelState.IsValid)
            {
                var user = _pool.GetUser(model.Email);
                if (user.Status != null)
                {
                    ModelState.AddModelError("UserExists", "User with this email already exists");
                }
                user.Attributes.Add(CognitoAttributesConstants.Name, model.Email);
                var createdUser = await _userManager.CreateAsync(user, model.Passsword).ConfigureAwait(false);
                if (createdUser.Succeeded)
                    RedirectToAction("Confirm");
            }

            return View(model);
        }
        [HttpGet]
        public IActionResult Confirm(ConfirmModel model)
        {
            return View(model);
        }
        [HttpPost]
        [ActionName("Confirm")]
        public async Task<IActionResult> ConfirmPost(ConfirmModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByEmailAsync(model.Email).ConfigureAwait(false);
                if (user == null)
                {
                    ModelState.AddModelError("NotFound", "A user with given email address was not found");
                    return View();
                }
                var result = await ((CognitoUserManager<CognitoUser>)_userManager).ConfirmSignUpAsync(user, model.Code, true).ConfigureAwait(false);
                if (result.Succeeded) return RedirectToAction("Index", "Home");
                foreach (var item in result.Errors) ModelState.AddModelError(item.Code, item.Description);

                return View(model);
            }
            return View(model);
        }
        [HttpGet]
        public IActionResult Login(LoginModel model)
        {
            return View(model);
        }
        [HttpPost]
        [ActionName("Login")]
        public async Task<IActionResult> LoginPost(LoginModel model)
        {
            if (ModelState.IsValid)
            {
                var result = await _signInManager.PasswordSignInAsync(model.Email, model.Password, model.RememberMe, false).ConfigureAwait(false);
                if (result.Succeeded)
                    return RedirectToAction("Index", "Home");
            }
            return View(model);
        }
        public async Task<IActionResult> Signout()
        {
            if (User.Identity.IsAuthenticated) await _signInManager.SignOutAsync().ConfigureAwait(false);
            return RedirectToAction("Login");
        }
    }
}