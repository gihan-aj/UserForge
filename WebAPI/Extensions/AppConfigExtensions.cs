using Application.Configurations;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace WebAPI.Extensions
{
    public static class AppConfigExtensions
    {
        public static IServiceCollection ConfigureAppSettings(this IServiceCollection services, IConfiguration configuration)
        {
            services.Configure<SmtpSettings>(configuration.GetSection("Email:SMTP"))
                .Configure<TokenSettings>(configuration.GetSection("Authentication:TokenSettings"));

            return services;
        }
        public static WebApplication ConfigureCORS(this WebApplication app, IConfiguration configuration)
        {
            app.UseCors(options =>
            {
                options.WithOrigins("http://localhost:4200") 
                    .AllowAnyMethod()
                    .AllowAnyHeader();
            });

            return app;
        }
    }
}
