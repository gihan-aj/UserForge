using Application.Abstractions.Messaging;
using Application.Common.Pagination;

namespace Application.Users.Queries.Get
{
    public record GetUsersQuery(
        string? SearchTerm,
        string? SortColumn,
        string? SortOrder,
        int Page,
        int PageSize): ICommand<PaginatedList<GetUsersResponse>>;
}
