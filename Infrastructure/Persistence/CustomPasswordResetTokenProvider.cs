using Application.Configurations;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using System;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Infrastructure.Persistence
{
    public class CustomPasswordResetTokenProvider<TUser> : IUserTwoFactorTokenProvider<TUser>
        where TUser : class
    {
        private readonly string _hmacKey;
        private readonly int _tokenExpieryInMinutes;

        public CustomPasswordResetTokenProvider(IOptions<TokenSettings> tokenSetings)
        {
            _hmacKey = tokenSetings.Value.PasswordResetToken.HmacSecretKey
                ?? throw new ArgumentNullException(nameof(tokenSetings.Value.PasswordResetToken.HmacSecretKey));
            _tokenExpieryInMinutes = tokenSetings.Value.PasswordResetToken.ExpiresInMinutes;
        }

        public async Task<bool> CanGenerateTwoFactorTokenAsync(UserManager<TUser> manager, TUser user)
        {
            var email = await manager.GetEmailAsync(user).ConfigureAwait(false);

            return !string.IsNullOrEmpty(email) && await manager.IsEmailConfirmedAsync(user).ConfigureAwait(false);
        }

        public async Task<string> GenerateAsync(string purpose, UserManager<TUser> manager, TUser user)
        {
            var email = await manager.GetEmailAsync(user).ConfigureAwait(false);

            return GenerateHmacToken(email!, purpose, _hmacKey);
        }

        public async Task<bool> ValidateAsync(string purpose, string token, UserManager<TUser> manager, TUser user)
        {
            var parts = token.Split(':');

            if(parts.Length != 4)
            {
                return false;
            }

            var email = parts[0];
            var tokenPurpose = parts[1];
            var timestamp = long.Parse(parts[2]);
            var signature = parts[3];

            var currentTime = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            var tokenValidityDuration = TimeSpan.FromMinutes(_tokenExpieryInMinutes).TotalSeconds;

            if(currentTime - timestamp > tokenValidityDuration)
            {
                return false;
            }

            var secretKey = _hmacKey;
            var rawToken = $"{email}:{tokenPurpose}:{timestamp}";

            using(var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(secretKey)))
            {
                var computedSignature = Convert.ToBase64String(hmac.ComputeHash(Encoding.UTF8.GetBytes(rawToken)));
                if(signature != computedSignature)
                {
                    return false;
                }
            }

            var userEmail = await manager.GetEmailAsync(user).ConfigureAwait(false);

            return email == userEmail && purpose == tokenPurpose;
        }

        private string GenerateHmacToken(string email, string purpose, string secretKey)
        {
            var timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            var rawToken = $"{email}:{purpose}:{timestamp}";

            using (var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(secretKey)))
            {
                var signature = Convert.ToBase64String(hmac.ComputeHash(Encoding.UTF8.GetBytes(rawToken)));
                return $"{rawToken}:{signature}";
            }
        }
    }
}
