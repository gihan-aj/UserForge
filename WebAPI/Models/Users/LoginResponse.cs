namespace WebAPI.Models.Users
{
    public record LoginResponse(string UserName, string FirstName, string LastName, string AccessToken);
}
