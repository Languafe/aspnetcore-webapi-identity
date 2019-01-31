using System;
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

namespace ThingsApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UsersController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> userManager;
        private readonly SignInManager<ApplicationUser> signInManager;
        private readonly ILogger<UsersController> logger;
        private readonly IConfiguration config;

        public UsersController(
            UserManager<ApplicationUser> userManager,
            SignInManager<ApplicationUser> signInManager,
            ILogger<UsersController> logger,
            IConfiguration config
        )
        {
            this.userManager = userManager;
            this.signInManager = signInManager;
            this.logger = logger;
            this.config = config;
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
                return Ok(user);
            }
            else
            {
                throw new Exception("Could not create user");
            }
        }

        [AllowAnonymous]
        [HttpPost("token")]
        public async Task<ActionResult<TokenResponse>> GetToken([FromBody]UserCredentials uc)
        {
            // authenticate user
            var authSuccessful = await this.AuthenticateUserAsync(uc.Username, uc.Password);
            if (!authSuccessful)
            {
                return Unauthorized();
            }

            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(this.config.GetValue<string>("JwtSigningKey"));
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new Claim[]
                {
                    new Claim(ClaimTypes.Name, uc.Username.ToString())
                }),
                Expires = DateTime.UtcNow.AddDays(7),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };
            var token = tokenHandler.CreateToken(tokenDescriptor);
            var response = new TokenResponse
            {
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
        public string Username { get; set; }
        public string Token { get; set; }
    }

    public class UserCredentials
    {
        public string Username { get; set; }
        public string Password { get; set; }
    }
}