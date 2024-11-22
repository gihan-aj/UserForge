using Domain.Users;
using SharedKernal;
using System.Threading.Tasks;

namespace Application.Services
{
    public interface IAuthService
    {
        Task<ServiceResult<User>> CreateUserAsync(string firstName, string lastName, string email, string password);

        Task<ServiceResult<string>> GenerateEmailConfirmationTokenAsync(User user);

        Task<ServiceResult<User>> ConfirmEmailAsync(string userId, string token);

        Task<ServiceResult<User>> LoginAsync(string userName, string password);

        Task<ServiceResult<User>> AddToRolesAsync(User user, string role);

        Task<ServiceResult<string[]>> GetRolesAsync(User user);

        Task<ServiceResult<User>> GetUserByEmailAsync(string email);

        Task<ServiceResult<string>> GenerateRefreshTokenAsync(User user);

        Task<ServiceResult<User>> RefreshTokenAsync(string refreshToken);
    }
}
