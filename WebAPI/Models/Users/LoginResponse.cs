namespace WebAPI.Models.Users
{
    public record LoginResponse(
        string Id, 
        string Email, 
        string FirstName, 
        string LastName, 
        string AccessToken,
        string? RefreshToken = null);
}
