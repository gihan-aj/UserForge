namespace WebAPI.Models.Users
{
    public record ResetPasswordRequest(string UserId, string Token, string NewPassword);
}
