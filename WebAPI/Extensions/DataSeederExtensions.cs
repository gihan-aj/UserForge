using Infrastructure.Persistence;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using System.Threading.Tasks;

namespace WebAPI.Extensions
{
    public static class DataSeederExtensions
    {
        public static async Task<WebApplication> SeedInitialDataAsync(this WebApplication app)
        {
            using (var scope = app.Services.CreateScope())
            {
                var services = scope.ServiceProvider;
                await DataSeeder.SeedRolesAndUserAsync(services);
            }

            return app;
        }
    }
}
