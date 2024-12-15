using Application.Configurations;
using Application.Services;
using Domain.Users;
using Infrastructure.Persistence;
using Infrastructure.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using System;

namespace Infrastructure
{
    public static class DependencyInjection
    {
        public static IServiceCollection AddInfrastructure(this IServiceCollection services, IConfiguration configuration)
        {
            var connection = configuration.GetConnectionString("DefaultConnection");

            services.AddDbContext<ApplicationDbContext>(options =>
                options.UseSqlServer(connection));

            services.AddIdentityCore<User>(options =>
            {
                options.SignIn.RequireConfirmedAccount = false;
                options.SignIn.RequireConfirmedPhoneNumber = false;
                options.SignIn.RequireConfirmedEmail = true;

                options.Password.RequiredLength = 6;
                options.Password.RequireDigit = true;
                options.Password.RequireLowercase = true;
                options.Password.RequireUppercase = true;
                options.Password.RequireNonAlphanumeric = true;

                options.Tokens.AuthenticatorTokenProvider = TokenOptions.DefaultAuthenticatorProvider;
                options.Tokens.ChangeEmailTokenProvider = TokenOptions.DefaultEmailProvider;
                options.Tokens.ChangePhoneNumberTokenProvider = TokenOptions.DefaultPhoneProvider;
                options.Tokens.EmailConfirmationTokenProvider = TokenOptions.DefaultEmailProvider;
                options.Tokens.PasswordResetTokenProvider = TokenOptions.DefaultProvider;
            })
                .AddRoles<IdentityRole>()
                .AddRoleManager<RoleManager<IdentityRole>>()
                .AddEntityFrameworkStores<ApplicationDbContext>()
                .AddPasswordValidator<PasswordValidator<User>>()
                .AddTokenProvider<EmailTokenProvider<User>>(TokenOptions.DefaultEmailProvider)
                .AddTokenProvider<CustomPasswordResetTokenProvider<User>>(TokenOptions.DefaultProvider);

            services.AddTransient<IEmailService, EmailService>();
            services.AddTransient<IUserService, UserService>();
            services.AddTransient<ITokenService, TokenService>();

            return services;
        }
    }
}
