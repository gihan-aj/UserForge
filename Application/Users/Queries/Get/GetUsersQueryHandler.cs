using Application.Abstractions.Messaging;
using Application.Common.Pagination;
using Application.Data;
using Application.Services;
using Domain.Users;
using SharedKernal;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace Application.Users.Queries.Get
{
    internal sealed class GetUsersQueryHandler 
        : ICommandHandler<GetUsersQuery, PaginatedList<GetUsersResponse>>
    {
        private readonly IUsersService _usersService;

        public GetUsersQueryHandler(IUsersService usersService)
        {
            _usersService = usersService;
        }
        public async Task<Result<PaginatedList<GetUsersResponse>>> Handle(GetUsersQuery request, CancellationToken cancellationToken)
        {
            var users = await _usersService.GetUsersAsync(
                request.SearchTerm,
                request.SortColumn,
                request.SortOrder,
                request.Page,
                request.PageSize,
                cancellationToken);

            return users;
        }
    }
}
