using System;

namespace WebAPI.Models.Users
{
    public record UpdateUserRequest(string FirstName, string LastName, string? PhoneNumber, DateTime? DateOfBirth);
}
