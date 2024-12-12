namespace WebAPI.Models.Users
{
    public record LoginResponse( 
        string AccessToken,
        string RefreshToken,
        UserResponse User);
}
