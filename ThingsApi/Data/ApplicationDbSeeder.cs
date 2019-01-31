using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using ThingsApi.Models;

namespace ThingsApi.Data
{
    public class ApplicationDbSeeder
    {
        private static readonly string AdminEmail = "admin@api.things.com";
        private static readonly string AdminPassword = "P@ssword1!";

        public static void SeedUsers(UserManager<ApplicationUser> userManager)
        {
            if (userManager.FindByEmailAsync(AdminEmail).Result == null)
            {
                ApplicationUser admin = new ApplicationUser
                {
                    UserName = AdminEmail,
                    Email = AdminEmail
                };

                var result = userManager.CreateAsync(admin, AdminPassword).Result;

                if (result.Succeeded)
                {
                    userManager.AddToRoleAsync(admin, ApplicationRole.Admin);
                }
            }
        }
    }
}