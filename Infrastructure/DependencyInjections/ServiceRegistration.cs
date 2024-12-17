using Application.Services;
using Domain.Users;
using Infrastructure.Repositories;
using Infrastructure.Services;
using Microsoft.Extensions.DependencyInjection;

namespace Infrastructure.DependencyInjection.DependencyInjection
{
    public static class ServiceRegistration
    {
        public static IServiceCollection AddServiceRegistrations(this IServiceCollection services)
        {
            // Register Services
            services.AddTransient<IEmailService, EmailService>();
            services.AddTransient<IUserService, UserService>();
            services.AddTransient<ITokenService, TokenService>();
            services.AddTransient<IUsersService, UsersService>();

            // Register Repositories
            services.AddTransient<IUsersRepository, UsersRepository>();

            return services;
        }
    }
}
