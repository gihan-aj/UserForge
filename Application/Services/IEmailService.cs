using Domain.Users;
using SharedKernal;
using System.Threading.Tasks;

namespace Application.Services
{
    public interface IEmailService
    {
        Task<Result> SendConfirmationEmailAsync(User user, string token);
        Task<Result> SendPasswordResetEmailAsync(User user, string token);
    }
}
