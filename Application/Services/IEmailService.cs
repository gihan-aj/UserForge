using Domain.Users;
using System.Threading.Tasks;

namespace Application.Services
{
    public interface IEmailService
    {
        Task SendConfirmationEmailAsync(User user, string token);
    }
}
