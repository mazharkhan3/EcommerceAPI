using Microsoft.AspNetCore.Identity;

namespace EcommerceAPI.Entities;

// Todo: Define limits for the properties
public class ApplicationUser : IdentityUser
{
    public string FirstName { get; set; }
    public string LastName { get; set; }
}