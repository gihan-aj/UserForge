using Application.Services;
using Domain.Users;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using SharedKernal;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Infrastructure.Services
{
    public class AuthService : IAuthService
    {
        private readonly UserManager<User> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly ITokenService _tokenService;

        public AuthService(RoleManager<IdentityRole> roleManager, UserManager<User> userManager, ITokenService tokenService)
        {
            _roleManager = roleManager;
            _userManager = userManager;
            _tokenService = tokenService;
        }
        public async Task<ServiceResult<User>> CreateUserAsync(string firstName, string lastName, string email, string password)
        {
            if(await _userManager.FindByEmailAsync(email) != null)
            {
                return ServiceResult<User>.WithError(UserErrors.AlreadyExists(email));
            }

            var user = new User
            {
                UserName = email,
                Email = email,
                FirstName = firstName,
                LastName = lastName,
                EmailConfirmed = false // Email confirmation is required
            };

            var result = await _userManager.CreateAsync(user, password);
            if (!result.Succeeded)
            {
                return CreateServiceError<User>(result.Errors);
            }

            return ServiceResult<User>.WithoutErrors(user);
        }

        public async Task<ServiceResult<string>> GenerateEmailConfirmationTokenAsync(User user)
        {
            if (user.EmailConfirmed)
            {
                return ServiceResult<string>.WithError(UserErrors.EmailAlreadyConfirmed(user.Email));
            }

            var result = await _userManager.GenerateEmailConfirmationTokenAsync(user);

            return ServiceResult<string>.WithoutErrors(result);
        }

        public async Task<ServiceResult<User>> ConfirmEmailAsync(string userId, string token)
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user is null)
            {
                return ServiceResult<User>.WithError(UserErrors.NotFound(userId));
            }

            if (user.EmailConfirmed)
            {
                return ServiceResult<User>.WithError(UserErrors.EmailAlreadyConfirmed(user.Email));
            }

            var decodedTokenBytes = WebEncoders.Base64UrlDecode(token);
            var decodedToken = Encoding.UTF8.GetString(decodedTokenBytes);

            var result = await _userManager.ConfirmEmailAsync(user, decodedToken);
            if(!result.Succeeded)
            {
                return CreateServiceError<User>(result.Errors);
            }

            return ServiceResult<User>.WithoutErrors(user);
        }

        public async Task<ServiceResult<User>> LoginAsync(string email, string password)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user is null)
            {
                return ServiceResult<User>.WithError(UserErrors.NotValid);
            }

            if (!await _userManager.CheckPasswordAsync(user, password))
            {
                return ServiceResult<User>.WithError(UserErrors.NotValid);
            }

            if (!user.EmailConfirmed)
            {
                return ServiceResult<User>.WithError(UserErrors.EmailNotConfirmed(user.Email));
            }

            return ServiceResult<User>.WithoutErrors(user);
        }

        public async Task<ServiceResult<User>> AddToRolesAsync(User user , string role)
        {
            var result = await _userManager.AddToRoleAsync(user, role);
            if (!result.Succeeded)
            {
                return CreateServiceError<User>(result.Errors);
            }

            return ServiceResult<User>.WithoutErrors(user);
        }

        public async Task<ServiceResult<string[]>> GetRolesAsync(User user)
        {
            var result = await _userManager.GetRolesAsync(user);
            return ServiceResult<string[]>.WithoutErrors(result.ToArray());
        }

        public async Task<ServiceResult<User>> GetUserByEmailAsync(string email)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if(user is null)
            {
                return ServiceResult<User>.WithError(UserErrors.EmailNotFound(email));
            }

            if (user.EmailConfirmed)
            {
                return ServiceResult<User>.WithError(UserErrors.EmailAlreadyConfirmed(email)); 
            }

            return ServiceResult<User>.WithoutErrors(user);
        }

        public async Task<ServiceResult<string>> GenerateRefreshTokenAsync(User user)
        {
            var refreshToken = _tokenService.GenerateRefreshToken();
            user.RefreshToken = refreshToken;
            user.RefreshTokenExpiery = DateTime.UtcNow.AddDays(7);

            var updatedResult = await _userManager.UpdateAsync(user);
            if(!updatedResult.Succeeded)
            {
                return CreateServiceError<string>(updatedResult.Errors);
            }

            return ServiceResult<string>.WithoutErrors(refreshToken);
        }

        public async Task<ServiceResult<User>> RefreshTokenAsync(string refreshToken)
        {
            var user = await _userManager.Users.FirstOrDefaultAsync(u => u.RefreshToken == refreshToken);
            if(user is null || user.RefreshTokenExpiery < DateTime.UtcNow )
            {
                return ServiceResult<User>.WithError(UserErrors.InvaildRefreshToken);
            }

            var newRefreshToken = _tokenService.GenerateRefreshToken();
            user.RefreshToken = newRefreshToken;
            user.RefreshTokenExpiery = DateTime.UtcNow.AddDays(7);

            var updatedResult = await _userManager.UpdateAsync(user);
            if (!updatedResult.Succeeded)
            {
                return CreateServiceError<User>(updatedResult.Errors);
            }

            return ServiceResult<User>.WithoutErrors(user);
        }

        private ServiceResult<T> CreateServiceError<T>(IEnumerable<IdentityError> errors)
        {
            Error[] validationErrors = errors
                        .Select(identityError => new Error(
                            identityError.Code,
                            identityError.Description))
                        .ToArray();

            return ServiceResult<T>.WithErrors(validationErrors);
        }


    }
}
