namespace WebAPI.Models.Users
{
    public record ChangePasswordRequest(
        string CurrentPassowrd, 
        string NewPassword, 
        string ConfirmNewPassword);
}
