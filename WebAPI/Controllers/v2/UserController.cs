using Application.Services;
using Asp.Versioning;
using Domain.Users;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using SharedKernal;
using System;
using System.Threading.Tasks;
using WebAPI.Infrastructure;
using WebAPI.Models.Users;

namespace WebAPI.Controllers
{
    [ApiController]
    [Route("api/v{apiVersion:apiVersion}/[controller]")]
    [ApiVersion("2", Deprecated = true)]
    public class UserController : ControllerBase
    {
        private readonly IConfiguration _configuration;
        private readonly IEmailService _emailService;
        private readonly IUserService _userService;
        private readonly ITokenService _tokenService;

        public UserController(IConfiguration configuration, IEmailService emailService, IUserService userService, ITokenService tokenService)
        {
            _configuration = configuration;
            _emailService = emailService;
            _userService = userService;
            _tokenService = tokenService;
        }

        [HttpPost("register")]
        [AllowAnonymous]
        public async Task<IResult> Register([FromBody] RegisterRequest request)
        {
            if (request is null)
            {
                throw new ArgumentNullException(nameof(request));
            }

            var validator = new RegisterRequestValidator();
            var validationResult = ValidationHandler.Handle(validator.Validate(request));
            if (validationResult.IsFailure)
            {
                return HandleFailure(validationResult);
            }

            var result = await _userService.CreateAsync(
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
            var addToRoleResult = await _userService.AddToRoleAsync(user, UserRoles.User);
            if (addToRoleResult.IsFailure)
            {
                return HandleFailure(result);
            }

            // Email confirmation token
            var emailConfirmationTokenResult = await _userService.GenerateEmailConfirmationTokenAsync(user);
            if (emailConfirmationTokenResult.IsFailure)
            {
                return HandleFailure(emailConfirmationTokenResult);
            }

            var emailConfirmationToken = emailConfirmationTokenResult.Value;

            // Confirm link via email
            var emailResult = await _emailService.SendConfirmationEmailAsync(user, emailConfirmationToken);
            if (emailResult.IsFailure)
            {
                return HandleFailure(emailResult);
            }

            var location = Url.Action(nameof(GetById), new { id = user.Id }) ?? $"/{user.Id}";
            return Results.CreatedAtRoute(location);
        }

        [HttpGet("{id}")]
        public async Task<IResult> GetById(string id)
        {
            var result = await _userService.FindByIdAsync(id);
            if (result.IsFailure)
            {
                return HandleFailure(result);
            }

            var user = result.Value;

            var userResponse = new GetUserResponse(id, user.UserName, user.FirstName, user.LastName);

            return Results.Ok(userResponse);
        }

        [HttpPut("confirm-email")]
        [AllowAnonymous]
        public async Task<IResult> ConfirmEmail(string userId, string token)
        {
            var result = await _userService.ConfirmEmailAsync(userId, token);
            if(result.IsFailure)
            {
                return HandleFailure(result);
            }

            return Results.NoContent();
        }

        [HttpPost("resend-email-confirmation-link/{email}")]
        [AllowAnonymous]
        public async Task<IResult> ResendEmailConfirmationLink(string email)
        {
            var userResult = await _userService.FindByEmailAsync(email);
            if (userResult.IsFailure)
            {
                return HandleFailure(userResult);
            }
            var user = userResult.Value;

            var tokenResult = await _userService.GenerateEmailConfirmationTokenAsync(user);
            if (tokenResult.IsFailure)
            {
                return HandleFailure(tokenResult);
            }

            var token = tokenResult.Value;
            var emailResult = await _emailService.SendConfirmationEmailAsync(user, token);
            if (emailResult.IsFailure)
            {
                return HandleFailure(emailResult);
            }

            return Results.NoContent();
        }

        [HttpPost("login")]
        [AllowAnonymous]
        public async Task<IResult> Login([FromBody]LoginRequest request)
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

            var loginResult = await _userService.LoginAsync(request.Email.ToLower(), request.Password);
            if(loginResult.IsFailure)
            {
                return HandleFailure(loginResult);
            }

            var user = loginResult.Value;

            // User roles
            var rolesResult = await _userService.GetRolesAsync(user);

            // JWT
            string accessToken = _tokenService.CreateJwtToken(user, rolesResult.Value);

            // Refresh token
            string refreshToken = _tokenService.GenerateRefreshToken();

            // Save refresh token
            var persistRefreshTokenResult = await _userService.PersistRefreshToken(user, refreshToken);
            if(persistRefreshTokenResult.IsFailure)
            {
                return HandleFailure(persistRefreshTokenResult);
            }

            // Store refresh token in httpOnly cookie
            HttpContext.Response.Cookies.Append("refreshToken", refreshToken, new CookieOptions
            {
                HttpOnly = true,
                Secure = true, // For production , HTTPS
                SameSite = SameSiteMode.Strict,
                Expires = DateTime.UtcNow.AddDays(7)
            });

            return Results.Ok(new LoginResponse(user.UserName, user.FirstName, user.LastName, accessToken));
        }

        [HttpPost("refresh")]
        [AllowAnonymous]
        public async Task<IResult> Refresh()
        {
            // Retrieve refresh token from cookies
            if (!HttpContext.Request.Cookies.TryGetValue("refreshToken", out var refreshToken))
            {
                return HandleFailure(Result.Failure(UserErrors.Token.MissingRefreshToken));
            }

            var userResult = await _userService.GetByRefreshToken(refreshToken);
            if (userResult.IsFailure)
            {
                return HandleFailure(userResult);
            }

            var user = userResult.Value;

            // Refresh token
            string newRefreshToken = _tokenService.GenerateRefreshToken();

            // Save refresh token
            var persistRefreshTokenResult = await _userService.PersistRefreshToken(user, newRefreshToken);
            if (persistRefreshTokenResult.IsFailure)
            {
                return HandleFailure(persistRefreshTokenResult);
            }

            // Store refresh token in httpOnly cookie
            HttpContext.Response.Cookies.Append("refreshToken", refreshToken, new CookieOptions
            {
                HttpOnly = true,
                Secure = true, // For production , HTTPS
                SameSite = SameSiteMode.Strict,
                Expires = DateTime.UtcNow.AddDays(7)
            });

            // User roles
            var rolesResult = await _userService.GetRolesAsync(user);

            // JWT
            string accessToken = _tokenService.CreateJwtToken(user, rolesResult.Value);

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
        private IResult HandleFailure(Result result) =>
            result switch
            {
                { IsSuccess: true } => throw new InvalidOperationException(),

                { Error : { Code: "ValidationError"} } => 
                Results.BadRequest(ResultCreationHandler.CreateProblemDetails(
                    "Validation Errors",
                    StatusCodes.Status400BadRequest,
                    result.Error,
                    result.Error.SubErrors.ToArray())),
                
                { Error : { Code: "IdentityError"} } => 
                Results.BadRequest(ResultCreationHandler.CreateProblemDetails(
                    "Identity Errors",
                    StatusCodes.Status400BadRequest,
                    result.Error,
                    result.Error.SubErrors.ToArray())),
                
                { Error : { Code: "EmailAlreadyExists" } } => 
                Results.Problem(ResultCreationHandler.CreateProblemDetails(
                    "Email Already Exists",
                    StatusCodes.Status409Conflict,
                    result.Error)),
                
                { Error : { Code: "UserNotFound" } } => 
                Results.NotFound(ResultCreationHandler.CreateProblemDetails(
                    "User Not Found",
                    StatusCodes.Status404NotFound,
                    result.Error)),
                
                { Error : { Code: "EmailAlreadyConfirmed" } } => 
                Results.Problem(ResultCreationHandler.CreateProblemDetails(
                    "Email Already Confirmed",
                    StatusCodes.Status409Conflict,
                    result.Error)),
                
                { Error : { Code: "InvalidCredentials" } } => 
                Results.BadRequest(ResultCreationHandler.CreateProblemDetails(
                    "Invalid Credentials",
                    StatusCodes.Status400BadRequest,
                    result.Error)),
                
                { Error : { Code: "MissingRefreshToken" } } => 
                Results.Problem(ResultCreationHandler.CreateProblemDetails(
                    "User Validation Error",
                    StatusCodes.Status400BadRequest,
                    result.Error)),
                
                { Error : { Code: "InvalidRefreshToken" } } => 
                Results.Problem(ResultCreationHandler.CreateProblemDetails(
                    "User Validation Error",
                    StatusCodes.Status400BadRequest,
                    result.Error)),
                
                { Error : { Code: "PasswordMismatch" } } => 
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
