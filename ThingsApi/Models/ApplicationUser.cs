using Microsoft.AspNetCore.Identity;

namespace ThingsApi.Models
{
    public class ApplicationUser : IdentityUser
    {
        public string Bio { get; set; }
    }
}