using Application.Common.Pagination;
using Application.Users.Queries.Get;
using Domain.Users;
using MediatR;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using SharedKernal;
using System.Threading.Tasks;

namespace WebAPI.Endpoints.v1
{
    public static class UsersEndpoints
    {
        public static void MapUsersEndpoints(this IEndpointRouteBuilder app)
        {
            var group = app
                .MapGroup("users")
                .WithTags("Admin");

            group.MapGet("", GetUsers)
                .RequireAuthorization(policy => policy.RequireRole(UserRoles.Admin))
                .WithName("GetUsers");

            static async Task<IResult> GetUsers(
                string? searchTerm,
                string? sortColumn,
                string? sortOrder,
                int page,
                int pageSize,
                ISender sender)
            {
                var query = new GetUsersQuery(searchTerm, sortColumn, sortOrder, page, pageSize);

                Result<PaginatedList<GetUsersResponse>> result = await sender.Send(query);

                return Results.Ok(result.Value);
            }
        }
    }
}
