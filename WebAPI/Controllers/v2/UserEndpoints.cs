using Application.Configurations;
using Application.Services;
using Azure.Core;
using Domain.Users;
using Infrastructure.Services;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using SharedKernal;
using System;
using System.Security.Claims;
using System.Threading.Tasks;
using WebAPI.Infrastructure;
using WebAPI.Models.Users;

namespace WebAPI.Controllers.v2
{
    public static class UserEndpoints
    {
        public static void MapUserEndpoints(this IEndpointRouteBuilder app)
        {
            app.MapPost("user/login", Login).AllowAnonymous();

            static async Task<IResult> Login(
                LoginRequest request,
                IUserService userService,
                ITokenService tokenService)
            {
                if (request is null)
                {
                    throw new ArgumentNullException(nameof(request));
                }

                var validator = new LoginRequestValidator();
                var validationResult = ValidationHandler.Handle(validator.Validate(request));
                if (validationResult.IsFailure)
                {
                    return HandleFailure(validationResult);
                }

                var loginResult = await userService.LoginAsync(request.Email.ToLower(), request.Password);
                if (loginResult.IsFailure)
                {
                    return HandleFailure(loginResult);
                }

                var user = loginResult.Value;

                // User roles
                var rolesResult = await userService.GetRolesAsync(user);

                // JWT
                string accessToken = tokenService.CreateJwtToken(user, rolesResult.Value);

                // Refresh token
                string refreshToken = tokenService.GenerateRefreshToken();

                // Save refresh token
                var persistRefreshTokenResult = await userService.PersistRefreshToken(user, refreshToken);
                if (persistRefreshTokenResult.IsFailure)
                {
                    return HandleFailure(persistRefreshTokenResult);
                }

                return Results.Ok(new LoginResponse(user.Id, user.Email!, user.FirstName, user.LastName, accessToken, refreshToken));
            }

            app.MapPost("user/refresh", Refresh).AllowAnonymous();

            static async Task<IResult> Refresh(
                RefreshTokenRequest request,
                IUserService userService,
                ITokenService tokenService)
            {
                if (string.IsNullOrWhiteSpace(request.RefreshToken))
                {
                    return HandleFailure(Result.Failure(UserErrors.Token.MissingRefreshToken));
                }

                var userResult = await userService.GetByRefreshToken(request.RefreshToken);
                if (userResult.IsFailure)
                {
                    return HandleFailure(userResult);
                }

                var user = userResult.Value;

                // Refresh token
                string newRefreshToken = tokenService.GenerateRefreshToken();

                // Save refresh token
                var persistRefreshTokenResult = await userService.PersistRefreshToken(user, newRefreshToken);
                if (persistRefreshTokenResult.IsFailure)
                {
                    return HandleFailure(persistRefreshTokenResult);
                }

                // User roles
                var rolesResult = await userService.GetRolesAsync(user);

                // JWT
                string accessToken = tokenService.CreateJwtToken(user, rolesResult.Value);

                return Results.Ok(new LoginResponse(user.Id, user.Email!, user.FirstName, user.LastName, accessToken, newRefreshToken));
            }

            app.MapGet("user", GetUserDetails).RequireAuthorization();

            static async Task<IResult> GetUserDetails(
                ClaimsPrincipal user, 
                IUserService userService)
            {
                var id = user.FindFirstValue(ClaimTypes.NameIdentifier);
                var result = await userService.FindByIdAsync(id);
                if (result.IsFailure)
                {
                    return HandleFailure(result);
                }

                var userDetails = result.Value;

                var userResponse = new GetUserResponse(
                    id, 
                    userDetails.UserName!, 
                    userDetails.FirstName, 
                    userDetails.LastName);

                return Results.Ok(userResponse);
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
                    "Identity Errors",
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

                { Error: { Code: "EmailAlreadyConfirmed" } } =>
                Results.Problem(ResultCreationHandler.CreateProblemDetails(
                    "Email Already Confirmed",
                    StatusCodes.Status409Conflict,
                    result.Error)),

                { Error: { Code: "InvalidCredentials" } } =>
                Results.BadRequest(ResultCreationHandler.CreateProblemDetails(
                    "Invalid Credentials",
                    StatusCodes.Status400BadRequest,
                    result.Error)),

                { Error: { Code: "MissingRefreshToken" } } =>
                Results.Problem(ResultCreationHandler.CreateProblemDetails(
                    "User Validation Error",
                    StatusCodes.Status401Unauthorized,
                    result.Error)),

                { Error: { Code: "InvalidRefreshToken" } } =>
                Results.Problem(ResultCreationHandler.CreateProblemDetails(
                    "User Validation Error",
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
