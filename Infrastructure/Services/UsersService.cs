using Application.Common.Pagination;
using Application.Services;
using Application.Users.Queries.Get;
using Domain.Users;
using Microsoft.AspNetCore.Identity;
using System;
using System.Linq;
using System.Linq.Expressions;
using System.Threading;
using System.Threading.Tasks;

namespace Infrastructure.Services
{
    public class UsersService : IUsersService
    {
        private readonly UserManager<User> _userManager;

        public UsersService(UserManager<User> userManager)
        {
            _userManager = userManager;
        }

        public async Task<PaginatedList<GetUsersResponse>> GetUsersAsync(
            string? searchTerm, 
            string? sortColumn, 
            string? sortOrder, 
            int page, 
            int pageSize,
            CancellationToken cancellationToken)
        {
            IQueryable<User> usersQuery = _userManager.Users.AsQueryable();

            // Filtering
            if(!string.IsNullOrWhiteSpace(searchTerm) )
            {
                usersQuery = usersQuery
                    .Where(u => 
                    u.FirstName.Contains(searchTerm) ||
                    u.LastName.Contains(searchTerm) ||
                    u.Email!.Contains(searchTerm));
            }

            // Sorting
            if(sortOrder?.ToLower() == "desc")
            {
                usersQuery = usersQuery
                    .OrderByDescending(GetSortProperty(sortColumn));
            }
            else
            {
                usersQuery = usersQuery
                    .OrderBy(GetSortProperty(sortColumn));
            }

            // Selecting
            var usersResponsQuery = usersQuery
                .Select(u => new GetUsersResponse(
                    u.Id,
                    u.Email!,
                    u.FirstName,
                    u.LastName,
                    u.PhoneNumber,
                    u.EmailConfirmed,
                    u.IsActive));

            var users = await PaginatedList<GetUsersResponse>.CreateAsync(
                usersResponsQuery,
                page,
                pageSize,
                cancellationToken);

            return users;
        }

        private static Expression<Func<User, object>> GetSortProperty(string? sortColumn)
        {
            return sortColumn?.ToLower() switch
            {
                "firstname" => user => user.FirstName,
                "lastname" => user => user.LastName,
                "email" => user => user.Email!,
                _ => user => user.Id
            };
        }
    }
}
