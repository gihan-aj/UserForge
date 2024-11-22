using Domain.Users;

namespace Application.Services
{
    public interface ITokenService
    {
        string CreateJwtToken(User user, string[] roles);
        string GenerateRefreshToken();
    }
}
