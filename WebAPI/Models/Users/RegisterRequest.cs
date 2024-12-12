using System;

namespace WebAPI.Models.Users
{
    public record RegisterRequest(
        string FirstName,
        string LastName,
        string Email,
        string? PhoneNumber,
        DateTime? DateOfBirth,
        string Password);
}
