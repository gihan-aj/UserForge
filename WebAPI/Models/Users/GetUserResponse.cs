using System;

namespace WebAPI.Models.Users
{
    public record GetUserResponse(
        string Id, 
        string Email, 
        string FirstName, 
        string LastName,
        string? PhoneNumber,
        DateTime? DateOfBirth);
}
