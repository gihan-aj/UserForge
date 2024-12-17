using Application.Common.Pagination;
using Application.Users.Queries.Get;
using System.Threading;
using System.Threading.Tasks;

namespace Application.Services
{
    public interface IUsersService
    {
        Task<PaginatedList<GetUsersResponse>> GetUsersAsync(
        string? searchTerm,
        string? sortColumn,
        string? sortOrder,
        int page,
        int pageSize,
        CancellationToken cancellationToken);
    }
}
