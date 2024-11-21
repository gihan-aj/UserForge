using Application.Services;
using Domain.Users;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.WebUtilities;
using SharedKernal;
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

        public UserService(RoleManager<IdentityRole> roleManager, UserManager<User> userManager)
        {
            _roleManager = roleManager;
            _userManager = userManager;
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
                return CreateServiceError(result.Errors);
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
                return CreateServiceError(result.Errors);
            }

            return ServiceResult<User>.WithoutErrors(user);
        }

        public async Task<Result<User>> FindByEmailAsync(string email)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user == null)
            {
                return Result.Failure<User>(UserErrors.NotFound(email));
            }

            return user;
        }

        public Task<Result> ActivateUserAsync(string userId, string token)
        {
            throw new System.NotImplementedException();
        }

        public Task<Result> LoginAsync(string userName, string password)
        {
            throw new System.NotImplementedException();
        }

        private ServiceResult<User> CreateServiceError(IEnumerable<IdentityError> errors)
        {
            Error[] validationErrors = errors
                        .Select(identityError => new Error(
                            identityError.Code,
                            identityError.Description))
                        .ToArray();

            return ServiceResult<User>.WithErrors(validationErrors);
        }

    }
}
