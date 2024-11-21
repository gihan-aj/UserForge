using Application.Services;
using Domain.Users;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
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
    public class UserController : ControllerBase
    {
        private readonly UserManager<User> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _configuration;
        private readonly IEmailService _emailService;
        private readonly IUserService _userService;

        public UserController(RoleManager<IdentityRole> roleManager, UserManager<User> userManager, IConfiguration configuration, IEmailService emailService, IUserService userService)
        {
            _roleManager = roleManager;
            _userManager = userManager;
            _configuration = configuration;
            _emailService = emailService;
            _userService = userService;
        }

        [HttpPost("register")]
        [AllowAnonymous]
        public async Task<IResult> Register([FromBody] RegisterRequest request)
        {
            var result = await _userService.CreateUserAsync(
                request.FirstName.ToLower(), 
                request.LastName.ToLower(), 
                request.Email.ToLower(), 
                request.Password);

            if (result.IsFailure)
            {
                return HandleFailure(result);
            }

            var user = result.Value;

            // Generate confirmation token
            var tokenResult = await _userService.GenerateEmailConfirmationTokenAsync(user);
            if(tokenResult.IsFailure)
            {
                return HandleFailure(result);
            }

            var token = tokenResult.Value;

            // Send activation link
            await _emailService.SendEmailAsync(user, token);

            var location = Url.Action(nameof(Register), new { id = user.Id }) ?? $"/{user.Id}";
            return Results.Created(location, user);
        }

        [HttpPut("confirm-email")]
        [AllowAnonymous]
        public async Task<IResult> ConfirmEmail(string userId, string token)
        {
            var result = await _userService.ConfirmEmailAsync(userId, token);
            if (result.IsFailure)
            {
                return HandleFailure(result);
            }

            return Results.NoContent();
        }

        [HttpPost("login")]
        [AllowAnonymous]
        public async Task<IActionResult> Login([FromBody] LoginRequest request)
        {
            var user = await _userManager.FindByEmailAsync(request.Email);
            if (user == null || !await _userManager.CheckPasswordAsync(user, request.Password))
            {
                return Unauthorized("Invalid email or password.");
            }

            if (!user.EmailConfirmed)
            {
                return BadRequest("Email not confirmed.");
            }

            // Generate JWT
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.UTF8.GetBytes(_configuration["JWT:Key"]);
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[]
                {
                    new Claim(ClaimTypes.Name, user.Id),
                    new Claim(ClaimTypes.Email, user.Email)
                }),
                Expires = DateTime.UtcNow.AddDays(7),
                Issuer = _configuration["JWT:Issuer"],
                Audience = _configuration["JWT:ClientUrl"],
                SigningCredentials = new SigningCredentials(
                    new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);
            var jwt = tokenHandler.WriteToken(token);

            return Ok(new { Token = jwt });
        }

        [HttpPost]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> CreateUser([FromBody] CreateUserRequest request)
        {
            if (await _userManager.FindByEmailAsync(request.Email) != null)
            {
                return BadRequest($"A user with email {request.Email}, already exists.");
            }

            var user = new User
            {
                UserName = request.Email,
                Email = request.Email,
                FirstName = request.FirstName,
                LastName = request.LastName,
            };

            var result = await _userManager.CreateAsync(user, request.Password);
            if (!result.Succeeded)
            {
                return BadRequest(result.Errors);
            }

            if (!string.IsNullOrEmpty(request.Role) && await _roleManager.RoleExistsAsync(request.Role))
            {
                await _userManager.AddToRoleAsync(user, request.Role);
            }

            return Ok("User created successfully.");
        }

        /**
         * Helpers
         */
        private IResult HandleFailure(ServiceResult<User> result) =>
            result switch
            {
                { IsSuccess: true } => throw new InvalidOperationException(),

                { Error: { Code: "User.NotFound" } } => 
                Results.NotFound(ResultExtensions.CreateProblemDetails(
                    "Not Found",
                    StatusCodes.Status404NotFound,
                    result.Error)),

                { Error: { Code: "User.AlreadyExists" } } =>
                Results.Problem(ResultExtensions.CreateProblemDetails(
                    "Email Already Exists",
                    StatusCodes.Status406NotAcceptable,
                    result.Error)),

                { Error: { Code: "ServiceError" } } =>
                Results.BadRequest(ResultExtensions.CreateProblemDetails(
                    "User Service Error",
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
