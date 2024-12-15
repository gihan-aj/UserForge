using Application.Configurations;
using Application.Services;
using Domain.Users;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace Infrastructure.Services
{
    public class TokenService : ITokenService
    {
        private readonly TokenSettings _tokenSettings;
        private readonly SymmetricSecurityKey _key;

        public TokenService(IOptions<TokenSettings> tokenSettings)
        {
            _tokenSettings = tokenSettings.Value;
            _key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_tokenSettings.JWT.HmacSha256SecretKey));
        }

        public string CreateJwtToken(User user, string[] roles)
        {
            var userClaims = new List<Claim>
            {
                new Claim(ClaimTypes.NameIdentifier, user.Id),
                new Claim(ClaimTypes.Email, user.Email!),
                //new Claim(ClaimTypes.GivenName, user.FirstName),
                //new Claim(ClaimTypes.Surname, user.LastName),
            };

            userClaims.AddRange(
                roles.Select(
                    role => new Claim(ClaimTypes.Role, role)));

            var credentials = new SigningCredentials(_key, SecurityAlgorithms.HmacSha256Signature);
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(userClaims),
                Expires = DateTime.UtcNow.AddMinutes(_tokenSettings.JWT.ExpiresInMinutes),
                SigningCredentials = credentials,
                Issuer = _tokenSettings.JWT.Issuer,
                Audience = _tokenSettings.JWT.ClientUrl
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            var jwt = tokenHandler.CreateToken(tokenDescriptor);

            return tokenHandler.WriteToken(jwt);
        }

        public string GenerateRefreshToken()
        {
            var randomBytes = new byte[32];
            using(var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(randomBytes);
            }

            return Convert.ToBase64String(randomBytes);
        }
    }
}
