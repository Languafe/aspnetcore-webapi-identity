using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using ThingsApi.Models;

namespace ThingsApi.Data
{
    public class ApplicationDbContext : IdentityDbContext<ApplicationUser>
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
            : base(options)
        {
            
        }

        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);

            const string ADMIN_ROLE = "Administrator";
            const string USER_ROLE = "User";

            // new technique for seeding data as of .NET Core 2.1
            builder.Entity<IdentityRole>()
                .HasData(
                    new IdentityRole { Name = ADMIN_ROLE, NormalizedName = ADMIN_ROLE.ToUpper() },
                    new IdentityRole { Name = USER_ROLE, NormalizedName = USER_ROLE.ToUpper() }
                );
        }
    }
}