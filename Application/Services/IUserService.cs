using Domain.Users;
using SharedKernal;
using System.Threading.Tasks;

namespace Application.Services
{
    public interface IUserService
    {
        Task<Result<User>> CreateAsync(string firstName, string lastName, string email, string password);
        Task<Result> AddToRoleAsync(User user, string role);
        Task<Result<string>> GenerateEmailConfirmationTokenAsync(User user);
        Task<Result<User>> FindByIdAsync(string id);
        Task<Result> ConfirmEmailAsync(string userId, string token);
        Task<Result<User>> FindByEmailAsync(string email);
        Task<Result<User>> LoginAsync(string username, string password);
        Task<Result<string[]>> GetRolesAsync(User user);
        Task<Result> PersistRefreshToken(User user, string refreshToken);
        Task<Result<User>> GetByRefreshToken(string refreshToken);
        Task<Result> ChangePasswordAsync(string userId, string oldPassword, string newPassword, string confirmNewPassword);
        Task<Result<string>> GeneratePasswordResetTokenAsync(User user);
        Task<Result> ResetPasswordAsync(string userId, string token, string newPassword);
        Task<Result> UpdateUserAsync(string userId, string firstName, string lastName, string phoneNumber);
    }
}
