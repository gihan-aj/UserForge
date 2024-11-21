using Infrastructure.Persistence;
using Microsoft.AspNetCore.Builder;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace WebAPI.Extensions
{

        public static class MigrationExtensions
        {
            public static void ApplyMigrations(this IApplicationBuilder app)
            {
                using IServiceScope scope = app.ApplicationServices.CreateScope();

                using ApplicationDbContext context = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();

                context.Database.Migrate();
            }
        }

}
