using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using ThingsApi.Data;
using ThingsApi.Models;

namespace ThingsApi.Services
{
    public interface IUserService
    {
        Task<IEnumerable<ApplicationUser>> GetAllUsersAsync();
        Task<ApplicationUser> GetUserByIdAsync(string id);
        Task<bool> UserIsInRole(ApplicationUser user, string role);
    }

    public class UserService : IUserService
    {
        private readonly ApplicationDbContext dbContext;
        private readonly UserManager<ApplicationUser> userManager;
        private readonly SignInManager<ApplicationUser> signInManager;
        private readonly RoleManager<IdentityRole> roleManager;
        private readonly ILogger<UserService> logger;

        public UserService(
            ApplicationDbContext dbContext,
            UserManager<ApplicationUser> userManager, 
            SignInManager<ApplicationUser> signInManager,
            RoleManager<IdentityRole> roleManager,
            ILogger<UserService> logger)
        {
            this.dbContext = dbContext;
            this.userManager = userManager;
            this.signInManager = signInManager;
            this.roleManager = roleManager;
            this.logger = logger;
        }
        public async Task<IEnumerable<ApplicationUser>> GetAllUsersAsync()
        {
            return await this.dbContext.Users.ToListAsync();
        }

        public async Task<ApplicationUser> GetUserByIdAsync(string id)
        {
            return await this.userManager.FindByIdAsync(id);
        }

        public async Task<bool> UserIsInRole(ApplicationUser user, string role)
        {
            var roles = await this.userManager.GetRolesAsync(user);

            return roles.Contains(role);
        }
    }

}