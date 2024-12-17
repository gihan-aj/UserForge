using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace Domain.Users
{
    public interface IUsersRepository
    {
        Task<List<User>> GetRangeAsync(List<string> ids, CancellationToken cancellationToken = default);
        void Update(User user); 
    }
}
