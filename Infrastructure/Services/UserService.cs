using Application.Configurations;
using Application.Services;
using Domain.Users;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using SharedKernal;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Infrastructure.Services
{
    public class UserService : IUserService
    {
        private readonly UserManager<User> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly JwtSettings _jwtSettings;

        public UserService(RoleManager<IdentityRole> roleManager, UserManager<User> userManager, IOptions<JwtSettings> jwtSettings)
        {
            _roleManager = roleManager;
            _userManager = userManager;
            _jwtSettings = jwtSettings.Value;
        }

        public async Task<Result<User>> CreateAsync(string firstName, string lastName, string email, string password)
        {
            if(await _userManager.FindByEmailAsync(email) != null)
            {
                return Result.Failure<User>(UserErrors.Conflict.EmailAlreadyExists(email));
            }

            var user = new User
            {
                FirstName = firstName,
                LastName = lastName,
                Email = email,
                UserName = email,
                EmailConfirmed = false,
            };

            var result = await _userManager.CreateAsync(user, password);
            if (!result.Succeeded)
            {
                return CreateIdentityError<User>(result.Errors);
            }

            return Result.Success(user);
        }

        public async Task<Result> AddToRoleAsync(User user, string role)
        {
            var result = await _userManager.AddToRoleAsync(user, role);
            if (!result.Succeeded)
            {
                return CreateIdentityError(result.Errors);
            }

            return Result.Success();
        }

        public async Task<Result<string>> GenerateEmailConfirmationTokenAsync(User user)
        {
            if (user.EmailConfirmed)
            {
                return Result.Failure<string>(UserErrors.Conflict.EmailAlreadyConfirmed(user.Email));
            }

            var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
            return Result.Success(token);
        }

        public async Task<Result<User>> FindByIdAsync(string id)
        {
            var user = await _userManager.FindByIdAsync(id);
            if(user is null)
            {
                return Result.Failure<User>(UserErrors.NotFound.User(id));
            }

            return Result.Success(user);
        }

        public async Task<Result> ConfirmEmailAsync(string userId, string token)
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user is null)
            {
                return Result.Failure(UserErrors.NotFound.User(userId));
            }

            if (user.EmailConfirmed)
            {
                return Result.Failure(UserErrors.Conflict.EmailAlreadyConfirmed(userId));
            }

            var decodedTokenBytes = WebEncoders.Base64UrlDecode(token);
            var decodedToken = Encoding.UTF8.GetString(decodedTokenBytes);

            var result = await _userManager.ConfirmEmailAsync(user, decodedToken);
            if (!result.Succeeded)
            {
                return CreateIdentityError(result.Errors);
            }

            return Result.Success();
        }

        public async Task<Result<User>> FindByEmailAsync(string email)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user is null)
            {
                return Result.Failure<User>(UserErrors.NotFound.Email(email));
            }

            return user;
        }

        public async Task<Result<User>> LoginAsync(string username, string password)
        {
            var user = await _userManager.FindByNameAsync(username);
            if(user is null)
            {
                return Result.Failure<User>(UserErrors.Validation.InvalidCredentials);
            }

            if(!await _userManager.CheckPasswordAsync(user, password))
            {
                return Result.Failure<User>(UserErrors.Validation.InvalidCredentials);
            }

            return user;
        }

        public async Task<Result<string[]>> GetRolesAsync(User user)
        {
            var result = await _userManager.GetRolesAsync(user);
            return result.ToArray();
        }

        public async Task<Result> PersistRefreshToken(User user, string refreshToken)
        {
            user.RefreshToken = refreshToken;
            user.RefreshTokenExpiery = DateTime.UtcNow.AddDays(_jwtSettings.RefreshTokenExpiresInDays);

            var result = await _userManager.UpdateAsync(user);
            if (!result.Succeeded)
            {
                return CreateIdentityError(result.Errors);
            }

            return Result.Success();
        }

        public async Task<Result<User>> GetByRefreshToken(string refreshToken)
        {
            var user = await _userManager.Users.FirstOrDefaultAsync(u => u.RefreshToken == refreshToken);
            if(user is null || user.RefreshTokenExpiery < DateTime.UtcNow)
            {
                return Result.Failure<User>(UserErrors.Token.InvalidRefreshToken);
            }

            return user;
        }

        public async Task<Result> ChangePasswordAsync(string userId, string oldPassword, string newPassword, string confirmNewPassword)
        {
            var user = await _userManager.FindByIdAsync(userId);
            if(user is null)
            {
                return Result.Failure(UserErrors.NotFound.User(userId));
            }

            if(newPassword != confirmNewPassword)
            {
                return Result.Failure(UserErrors.Validation.PasswordMismatch);
            }

            var result = await _userManager.ChangePasswordAsync(user, oldPassword, newPassword);
            if (!result.Succeeded)
            {
                return CreateIdentityError(result.Errors);
            }

            return Result.Success();
        }

        public async Task<Result<string>> GeneratePasswordResetTokenAsync(User user)
        {
            var token = await _userManager.GeneratePasswordResetTokenAsync(user);

            return token;
        }

        public async Task<Result> ResetPasswordAsync(string userId, string token, string newPassword)
        {
            var user = await _userManager.FindByIdAsync(userId);
            if(user is null)
            {
                return Result.Failure(UserErrors.NotFound.User(userId));
            }

            var decodedTokenBytes = WebEncoders.Base64UrlDecode(token);
            var decodedToken = Encoding.UTF8.GetString(decodedTokenBytes);

            var result = await _userManager.ResetPasswordAsync(user, decodedToken, newPassword);
            if (!result.Succeeded)
            {
                return CreateIdentityError(result.Errors);
            }

            return Result.Success();
        }

        public async Task<Result> UpdateUserAsync(string userId, string firstName, string lastName, string phoneNumber)
        {
            var user = await _userManager.FindByIdAsync(userId);
            if(user is null)
            {
                return Result.Failure(UserErrors.NotFound.User(userId));
            }

            user.FirstName = firstName;
            user.LastName = lastName;
            if(!string.IsNullOrEmpty(phoneNumber))
                user.PhoneNumber = phoneNumber;

            var updatedResult = await _userManager.UpdateAsync(user);
            if (!updatedResult.Succeeded)
            {
                return CreateIdentityError(updatedResult.Errors);
            }

            return Result.Success();
        }

        public async Task<Result<string>> GenerateChangeEmailTokenAsync(string userId, string newEmail, string password)
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user is null)
            {
                return Result.Failure<string>(UserErrors.NotFound.User(userId));
            }

            var isPasswordValid = await _userManager.CheckPasswordAsync(user, password);
            if (!isPasswordValid)
            {
                return Result.Failure<string>(UserErrors.Validation.InvalidPassword);
            }

            var token = await _userManager.GenerateChangeEmailTokenAsync(user, newEmail);

            return token;
        }

        public async Task<Result> DeactivateAccountAsync(string userId)
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user is null)
            {
                return Result.Failure(UserErrors.NotFound.User(userId));
            }

            user.EmailConfirmed = false;
            var updateResult = await _userManager.UpdateAsync(user);
            if (!updateResult.Succeeded)
            {
                return CreateIdentityError(updateResult.Errors);
            }

            return Result.Success();
        }

        public async Task<Result> ChangeEmailAsync(string userId, string newEmail, string token)
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user is null)
            {
                return Result.Failure(UserErrors.NotFound.User(userId));
            }

            var decodedTokenBytes = WebEncoders.Base64UrlDecode(token);
            var decodedToken = Encoding.UTF8.GetString(decodedTokenBytes);

            var emailChangeResult = await _userManager.ChangeEmailAsync(user, newEmail, decodedToken);
            if (!emailChangeResult.Succeeded)
            {
                return CreateIdentityError(emailChangeResult.Errors);
            }

            user.NormalizedEmail = _userManager.NormalizeEmail(user.Email);
            user.UserName = newEmail;
            user.EmailConfirmed = true;
            var updateResult = await _userManager.UpdateAsync(user);
            if (!updateResult.Succeeded)
            {
                return CreateIdentityError(updateResult.Errors);
            }

            return Result.Success();
        }

        /**
         * Helper methods
         */
        private Result<T> CreateIdentityError<T>(IEnumerable<IdentityError> errors)
        {
            var subErrors = errors
                .Select(identityError => new Error(identityError.Code, identityError.Description))
                .ToList();

            var error = new Error("IdentityError", "Identity Error Occured.", subErrors);

            return Result.Failure<T>(error);
        }        
        
        private Result CreateIdentityError(IEnumerable<IdentityError> errors)
        {
            var subErrors = errors
                .Select(identityError => new Error(identityError.Code, identityError.Description))
                .ToList();

            var error = new Error("IdentityError", "Identity Error Occured.", subErrors);

            return Result.Failure(error);
        }    

    }
}
