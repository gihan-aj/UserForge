namespace Application.Users.Queries.Get
{
    public record GetUsersResponse(
        string Id,
        string Email,
        string FirstName,
        string LastName,
        string? PhoneNumber,
        bool EmailConfirmed,
        bool IsActive);
}
