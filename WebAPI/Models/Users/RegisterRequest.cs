namespace WebAPI.Models.Users
{
    public record RegisterRequest(
        string FirstName, 
        string LastName, 
        string Email, 
        string Password);
}
