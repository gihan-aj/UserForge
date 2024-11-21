using Domain.Users;
using SharedKernal;
using System.Threading.Tasks;

namespace Application.Services
{
    public interface IUserService
    {
        Task<ServiceResult<User>> CreateUserAsync(string firstName, string lastName, string email, string password);

        Task<ServiceResult<string>> GenerateEmailConfirmationTokenAsync(User user);

        Task<ServiceResult<User>> ConfirmEmailAsync(string userId, string token);

        Task<Result<User>> FindByEmailAsync(string email);
        Task<Result> ActivateUserAsync(string userId, string token);
        Task<Result> LoginAsync(string userName, string password);
    }
}
