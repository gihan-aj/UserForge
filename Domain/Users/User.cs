using Microsoft.AspNetCore.Identity;
using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Domain.Users
{
    public class User : IdentityUser
    {
        [Required]
        [PersonalData]
        [Column(TypeName = "nvarchar(255)")]
        public string FirstName { get; set; } = string.Empty;

        [Required]
        [PersonalData]
        [Column(TypeName = "nvarchar(255)")]
        public string LastName { get; set; } = string.Empty;

        [ProtectedPersonalData]
        public DateTime? DateOfBirth { get; set; }

        [ProtectedPersonalData]
        [Column(TypeName = "nvarchar(255)")]
        public string? RefreshToken { get; set; }

        [ProtectedPersonalData]
        public DateTime? RefreshTokenExpiery { get; set; }

    }

    /**
     * HAVE TO ADD VALIDATION OF SOME SORT
     */
}
