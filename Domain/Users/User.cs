using Microsoft.AspNetCore.Identity;
using System;

namespace Domain.Users
{
    public class User : IdentityUser
    {
        public string FirstName { get; set; } = string.Empty;
        public string LastName { get; set; } = string.Empty;
        public string? RefreshToken { get; set; }
        public DateTime? RefreshTokenExpiery { get; set; }

    }

    /**
     * HAVE TO ADD VALIDATION OF SOME SORT
     */
}
