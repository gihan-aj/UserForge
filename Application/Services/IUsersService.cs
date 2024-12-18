using Application.Common.Pagination;
using Application.Users.Queries.Get;
using SharedKernal;
using System.Collections.Generic;
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

        Task<Result> ActivateUsers(List<string> ids, CancellationToken cancellationToken);

        Task<Result> DeactivateUsers(List<string> ids, CancellationToken cancellationToken);
    }
}
