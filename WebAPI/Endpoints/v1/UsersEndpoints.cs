using Application.Common.Pagination;
using Application.Common.Requests;
using Application.Users.Commands.Activate;
using Application.Users.Commands.Deactivate;
using Application.Users.Queries.Get;
using Domain.Users;
using MediatR;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using SharedKernal;
using System;
using System.Linq;
using System.Threading.Tasks;
using WebAPI.Infrastructure;

namespace WebAPI.Endpoints.v1
{
    public static class UsersEndpoints
    {
        public static void MapUsersEndpoints(this IEndpointRouteBuilder app)
        {
            var group = app
                .MapGroup("users")
                .RequireAuthorization(policy => policy.RequireRole(UserRoles.Admin))
                .WithTags("Admin");

            group.MapGet("", GetUsers)
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

            group.MapPut("activate", ActivateUsers).WithName("Activate");

            static async Task<IResult> ActivateUsers(BulkIdsRequest<string> request, ISender sender)
            {
                if (request is null)
                {
                    throw new ArgumentNullException(nameof(request));
                }
                if(request.Ids.Count() == 0)
                {
                    return HandleFailure(UserErrors.NotFound.Users);
                }

                var command = new ActivateUsersCommand(request.Ids.ToList());
                var result = await sender.Send(command);
                if (result.IsFailure)
                {
                    return HandleFailure(result);
                }

                return Results.NoContent();
            }
            
            group.MapPut("deactivate", DeactivateUsers).WithName("Deactivate");

            static async Task<IResult> DeactivateUsers(BulkIdsRequest<string> request, ISender sender)
            {
                if (request is null)
                {
                    throw new ArgumentNullException(nameof(request));
                }
                if(request.Ids.Count() == 0)
                {
                    return HandleFailure(UserErrors.NotFound.Users);
                }

                var command = new DeactivateUsersCommand(request.Ids.ToList());
                var result = await sender.Send(command);
                if (result.IsFailure)
                {
                    return HandleFailure(result);
                }

                return Results.NoContent();
            }

        }

        private static IResult HandleFailure(Result result) =>
            result switch
            {
                { IsSuccess: true } => throw new InvalidOperationException(),

                { Error: { Code: "ValidationError" } } =>
                Results.BadRequest(ResultCreationHandler.CreateProblemDetails(
                    "Validation Errors",
                    StatusCodes.Status400BadRequest,
                    result.Error,
                    result.Error.SubErrors.ToArray())),

                { Error: { Code: "IdentityError" } } =>
                Results.BadRequest(ResultCreationHandler.CreateProblemDetails(
                    "Validation Errors",
                    StatusCodes.Status400BadRequest,
                    result.Error,
                    result.Error.SubErrors.ToArray())),

                { Error: { Code: "EmailAlreadyExists" } } =>
                Results.Problem(ResultCreationHandler.CreateProblemDetails(
                    "Email Already Exists",
                    StatusCodes.Status409Conflict,
                    result.Error)),

                { Error: { Code: "UserNotFound" } } =>
                Results.NotFound(ResultCreationHandler.CreateProblemDetails(
                    "User Not Found",
                    StatusCodes.Status404NotFound,
                    result.Error)),

                { Error: { Code: "EmailNotFound" } } =>
                Results.Problem(ResultCreationHandler.CreateProblemDetails(
                    "Email Not Found",
                    StatusCodes.Status404NotFound,
                    result.Error)),

                { Error: { Code: "EmailAlreadyConfirmed" } } =>
                Results.Problem(ResultCreationHandler.CreateProblemDetails(
                    "Email Already Confirmed",
                    StatusCodes.Status409Conflict,
                    result.Error)),

                { Error: { Code: "EmailNotConfirmed" } } =>
                Results.Problem(ResultCreationHandler.CreateProblemDetails(
                    "Email Not Confirmed",
                    StatusCodes.Status400BadRequest,
                    result.Error)),

                { Error: { Code: "InvalidCredentials" } } =>
                Results.BadRequest(ResultCreationHandler.CreateProblemDetails(
                    "Invalid Credentials",
                    StatusCodes.Status400BadRequest,
                    result.Error)),

                { Error: { Code: "MissingRefreshToken" } } =>
                Results.Problem(ResultCreationHandler.CreateProblemDetails(
                    "Token Error",
                    StatusCodes.Status401Unauthorized,
                    result.Error)),

                { Error: { Code: "InvalidRefreshToken" } } =>
                Results.Problem(ResultCreationHandler.CreateProblemDetails(
                    "Token Error",
                    StatusCodes.Status401Unauthorized,
                    result.Error)),

                { Error: { Code: "InvalidAccessToken" } } =>
                Results.Problem(ResultCreationHandler.CreateProblemDetails(
                    "Token Error",
                    StatusCodes.Status401Unauthorized,
                    result.Error)),

                { Error: { Code: "PasswordMismatch" } } =>
                Results.BadRequest(ResultCreationHandler.CreateProblemDetails(
                    "Password Mismatch",
                    StatusCodes.Status400BadRequest,
                    result.Error)),

                _ => Results.Problem(ResultCreationHandler.CreateProblemDetails(
                    "Internal server error",
                    StatusCodes.Status500InternalServerError,
                    result.Error))
            };
    }
}
