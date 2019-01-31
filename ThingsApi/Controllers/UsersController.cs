using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using ThingsApi.Models;
using ThingsApi.Services;
using ThingsApi.ViewModels;

namespace ThingsApi.Controllers
{
    [Authorize]
    [ApiController]
    [Route("api/[controller]")]
    public class UsersController : ControllerBase
    {
        private readonly IUserService userService;
        private readonly UserManager<ApplicationUser> userManager;
        private readonly SignInManager<ApplicationUser> signInManager;
        private readonly ILogger<UsersController> logger;
        private readonly IConfiguration config;

        public UsersController(
            IUserService userService,
            UserManager<ApplicationUser> userManager,
            SignInManager<ApplicationUser> signInManager,
            ILogger<UsersController> logger,
            IConfiguration config
        )
        {
            this.userService = userService;
            this.userManager = userManager;
            this.signInManager = signInManager;
            this.logger = logger;
            this.config = config;
        }

        [HttpGet]
        [Authorize(Roles = ApplicationRole.Admin)]
        public async Task<ActionResult<List<UserViewModel>>> GetAllUsers()
        {
            var users = await this.userService.GetAllUsersAsync();

            var result = new List<UserViewModel>();

            foreach (var user in users)
            {
                result.Add(new UserViewModel
                {
                    Id = user.Id,
                    UserName = user.UserName,
                    Email = user.Email
                });
            }

            return result;
        }

        [HttpGet("{id}")]
        public async Task<ActionResult<UserViewModel>> GetUser(string id)
        {
            var user = await this.userService.GetUserByIdAsync(id);

            var currentUserId = User.Identity.Name;

            if (user == null)
            {
                return NotFound();
            }
            else if (id != currentUserId && !User.IsInRole(ApplicationRole.Admin))
            {
                return Forbid();
            }
            else
            {
                return new UserViewModel
                {
                    Id = user.Id,
                    UserName = user.UserName,
                    Email = user.Email
                };
            }
        }

        [AllowAnonymous]
        [HttpPost]
        public async Task<IActionResult> Register([FromBody]NewUserViewModel newUser)
        {
            var user = new ApplicationUser
            {
                UserName = newUser.Username,
                Email = newUser.Username,
                Bio = newUser.Bio
            };

            this.logger.LogInformation($"Creating new user {newUser.Username}");
            var result = await this.userManager.CreateAsync(user, newUser.Password);
            this.logger.LogInformation($"Successfully created new user {user.UserName} with id {user.Id}");

            if (result.Succeeded)
            {
                return Ok(new UserViewModel
                {
                    Id = user.Id,
                    Email = user.Email,
                    UserName = user.UserName
                });
            }
            else
            {
                return BadRequest(result.Errors);
            }
        }

        [AllowAnonymous]
        [HttpPost("token")]
        public async Task<ActionResult<TokenResponse>> Authenticate([FromBody]UserCredentials uc)
        {
            // authenticate user
            var authSuccessful = await this.AuthenticateUserAsync(uc.Username, uc.Password);
            if (!authSuccessful)
            {
                return Unauthorized();
            }

            var user = await this.userManager.FindByNameAsync(uc.Username);
            if (user == null)
            {
                throw new InvalidOperationException("Could not load user");
            }

            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(this.config.GetValue<string>("JwtSigningKey"));
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new Claim[]
                {
                    new Claim(ClaimTypes.Name, uc.Username.ToString()),
                    new Claim(ClaimTypes.Role, this.userService.UserIsInRole(user, ApplicationRole.Admin).Result ? ApplicationRole.Admin : ApplicationRole.User)
                }),
                Expires = DateTime.UtcNow.AddDays(7),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };
            var token = tokenHandler.CreateToken(tokenDescriptor);
            var response = new TokenResponse
            {
                Id = user.Id,
                Username = uc.Username,
                Token = tokenHandler.WriteToken(token)
            };

            return Ok(response);
        }

        private async Task<bool> AuthenticateUserAsync(string username, string password)
        {
            var user = await this.userManager.FindByNameAsync(username);
            return await this.userManager.CheckPasswordAsync(user, password);
        }
    }

    public class NewUserViewModel
    {
        public string Username { get; set; }
        public string Password { get; set; }
        public string Bio { get; set; }
    }

    public class TokenResponse
    {
        public string Id { get; set; }
        public string Username { get; set; }
        public string Token { get; set; }
    }

    public class UserCredentials
    {
        public string Username { get; set; }
        public string Password { get; set; }
    }
}