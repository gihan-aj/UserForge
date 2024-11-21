using Domain.Users;
using System.Threading.Tasks;

namespace Application.Services
{
    public interface IEmailService
    {
        Task SendEmailAsync (User user, string token);
    }
}
