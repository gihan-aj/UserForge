using Application.Services;
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

            return services;
        }
    }
}
