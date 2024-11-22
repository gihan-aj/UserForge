using Application.Services;
using Domain.Users;
using FluentValidation;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using SharedKernal;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using WebAPI.Extensions;
using WebAPI.Models.Users;

namespace WebAPI.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly IConfiguration _configuration;
        private readonly IEmailService _emailService;
        private readonly IAuthService _authService;
        private readonly ITokenService _tokenService;

        public AuthController(IConfiguration configuration, IEmailService emailService, IAuthService authService, ITokenService tokenService)
        {
            _configuration = configuration;
            _emailService = emailService;
            _authService = authService;
            _tokenService = tokenService;
        }

        [HttpPost("register")]
        [AllowAnonymous]
        public async Task<IResult> Register([FromBody] RegisterRequest request)
        {
            var validator = new RegisterRequestValidator();
            var validationResult = validator.Validate(request);
            if(!validationResult.IsValid)
            {
                return HandleFailure(ResultExtensions.CreateProblemDetailsFromValidationErrors<RegisterRequest>(validationResult));
            }

            var result = await _authService.CreateUserAsync(
                request.FirstName.ToLower(), 
                request.LastName.ToLower(), 
                request.Email.ToLower(), 
                request.Password);

            if (result.IsFailure)
            {
                return HandleFailure(result);
            }

            var user = result.Value;

            // Add user role
            var addRoleResult = await _authService.AddToRolesAsync(user, UserRoles.User);
            if (addRoleResult.IsFailure)
            {
                return HandleFailure(result);
            }

            // Generate confirmation token
            var tokenResult = await _authService.GenerateEmailConfirmationTokenAsync(user);
            if(tokenResult.IsFailure)
            {
                return HandleFailure(result);
            }

            var token = tokenResult.Value;

            // Send activation link
            await _emailService.SendConfirmationEmailAsync(user, token);

            var location = Url.Action(nameof(Register), new { id = user.Id }) ?? $"/{user.Id}";
            return Results.Created(location, user);
        }

        [HttpPut("confirm-email")]
        [AllowAnonymous]
        public async Task<IResult> ConfirmEmail(string userId, string token)
        {
            var result = await _authService.ConfirmEmailAsync(userId, token);
            if (result.IsFailure)
            {
                return HandleFailure(result);
            }

            return Results.NoContent();
        }

        [HttpPost("login")]
        [AllowAnonymous]
        public async Task<IResult> Login([FromBody] LoginRequest request)
        {
            var validator = new LoginRequestValidator();
            var validationResult = validator.Validate(request);
            if (!validationResult.IsValid)
            {
                return HandleFailure(ResultExtensions.CreateProblemDetailsFromValidationErrors<LoginRequest>(validationResult));
            }

            var userResult = await _authService.LoginAsync(request.Email.ToLower(), request.Password);
            if (userResult.IsFailure)
            {
                return HandleFailure(userResult);
            }

            var user = userResult.Value;

            var rolesResult = await _authService.GetRolesAsync(user);

            // Generate JWT
            string token = _tokenService.CreateJwtToken(user, rolesResult.Value);

            // Generate refresh token
            var refreshTokenResult = await _authService.GenerateRefreshTokenAsync(user);
            if (refreshTokenResult.IsFailure)
            {
                return HandleFailure(refreshTokenResult);
            }

            var refreshToken = refreshTokenResult.Value;

            // Store refresh token in httponly cookie
            HttpContext.Response.Cookies.Append("refreshToken", refreshToken, new CookieOptions
            {
                HttpOnly = true,
                Secure = true, // For production , HTTPS
                SameSite = SameSiteMode.Strict,
                Expires = DateTime.UtcNow.AddDays(7)
            });

            return Results.Ok(new LoginResponse(user.UserName, user.FirstName, user.LastName, token));
        }

        [HttpGet("resend-email-confirmation-link/{email}")]
        [AllowAnonymous]
        public async Task<IResult> ResendEmailConfirmationLink(string email)
        {
            var result = await _authService.GetUserByEmailAsync(email);
            if (result.IsFailure)
            {
                return HandleFailure(result);
            }

            var user = result.Value;

            var tokenResult = await _authService.GenerateEmailConfirmationTokenAsync(user);
            if (tokenResult.IsFailure)
            {
                return HandleFailure(tokenResult);
            }

            var token = tokenResult.Value;

            await _emailService.SendConfirmationEmailAsync(user, token);

            return Results.NoContent();
        }

        [HttpPost("refresh-token")]
        [AllowAnonymous]
        public async Task<IResult> RefreshToken()
        {
            // Retrieve refresh token from cookies
            if(!HttpContext.Request.Cookies.TryGetValue("refreshToken", out var refreshToken))
            {
                return HandleFailure(ServiceResult<User>.WithError(UserErrors.MissingRefreshToken));
            }

            var refreshTokenResult = await _authService.RefreshTokenAsync(refreshToken);
            if (refreshTokenResult.IsFailure)
            {
                return HandleFailure(refreshTokenResult);
            }

            User user = refreshTokenResult.Value;

            HttpContext.Response.Cookies.Append("refreshToken", user.RefreshToken, new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.Strict,
                Expires = DateTime.UtcNow.AddDays(7)
            });

            var rolesResult = await _authService.GetRolesAsync(user);

            var accessToken = _tokenService.CreateJwtToken(user, rolesResult.Value);

            return Results.Ok(new LoginResponse(user.UserName, user.FirstName, user.LastName, accessToken));
        }

        //[HttpPost]
        //[Authorize(Roles = "Admin")]
        //public async Task<IActionResult> CreateUser([FromBody] CreateUserRequest request)
        //{
        //    if (await _userManager.FindByEmailAsync(request.Email) != null)
        //    {
        //        return BadRequest($"A user with email {request.Email}, already exists.");
        //    }

        //    var user = new User
        //    {
        //        UserName = request.Email,
        //        Email = request.Email,
        //        FirstName = request.FirstName,
        //        LastName = request.LastName,
        //    };

        //    var result = await _userManager.CreateAsync(user, request.Password);
        //    if (!result.Succeeded)
        //    {
        //        return BadRequest(result.Errors);
        //    }

        //    if (!string.IsNullOrEmpty(request.Role) && await _roleManager.RoleExistsAsync(request.Role))
        //    {
        //        await _userManager.AddToRoleAsync(user, request.Role);
        //    }

        //    return Ok("User created successfully.");
        //}

        /**
         * Helpers
         */
        private IResult HandleFailure<T>(ServiceResult<T> result) =>
            result switch
            {
                { IsSuccess: true } => throw new InvalidOperationException(),

                { Error: { Code: "User.NotValid" } } => 
                Results.Problem(ResultExtensions.CreateProblemDetails(
                    "Invalid",
                    StatusCodes.Status401Unauthorized,
                    result.Error)),
                
                { Error: { Code: "User.NotFound" } } => 
                Results.NotFound(ResultExtensions.CreateProblemDetails(
                    "Not Found",
                    StatusCodes.Status404NotFound,
                    result.Error)),

                { Error: { Code: "User.EmailNotFound" } } =>
                Results.NotFound(ResultExtensions.CreateProblemDetails(
                    "Email Not Found",
                    StatusCodes.Status404NotFound,
                    result.Error)),
                
                { Error: { Code: "User.EmailNotConfirmed" } } =>
                Results.BadRequest(ResultExtensions.CreateProblemDetails(
                    "Email Not Confirmed",
                    StatusCodes.Status400BadRequest,
                    result.Error)),
                
                { Error: { Code: "User.AlreadyExists" } } =>
                Results.Problem(ResultExtensions.CreateProblemDetails(
                    "User Already Exists",
                    StatusCodes.Status406NotAcceptable,
                    result.Error)),
                
                { Error: { Code: "User.EmailAlreadyConfirmed" } } =>
                Results.BadRequest(ResultExtensions.CreateProblemDetails(
                    "Email Already Confirmed",
                    StatusCodes.Status400BadRequest,
                    result.Error)),

                { Error: { Code: "User.RefreshTokenInvalid" } } =>
                Results.Problem(ResultExtensions.CreateProblemDetails(
                    "User Validation Error",
                    StatusCodes.Status401Unauthorized,
                    result.Error,
                    result.Errors)),
                
                { Error: { Code: "User.RefreshTokenMissing" } } =>
                Results.Problem(ResultExtensions.CreateProblemDetails(
                    "User Validation Error",
                    StatusCodes.Status401Unauthorized,
                    result.Error,
                    result.Errors)),
                
                { Error: { Code: "ValidationError" } } =>
                Results.BadRequest(ResultExtensions.CreateProblemDetails(
                    "Validation Error",
                    StatusCodes.Status400BadRequest,
                    result.Error,
                    result.Errors)),

                _ => Results.Problem(ResultExtensions.CreateProblemDetails(
                    "Internal server error", 
                    StatusCodes.Status500InternalServerError, 
                    result.Error))
            };
        
    }
}
