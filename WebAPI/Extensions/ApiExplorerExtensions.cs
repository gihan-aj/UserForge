using Asp.Versioning;
using Asp.Versioning.ApiExplorer;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using System.Collections.Generic;
using WebAPI.OpenApi;

namespace WebAPI.Extensions
{
    public static class ApiExplorerExtensions
    {
        public static IServiceCollection AddSwaggerExplorerWithApiVersioning(this IServiceCollection services)
        {
            services.AddApiVersioning(options =>
            {
                options.DefaultApiVersion = new ApiVersion(2);
                options.ReportApiVersions = true;
                options.ApiVersionReader = new UrlSegmentApiVersionReader();
            })
                .AddMvc()
                .AddApiExplorer(options =>
                {
                    options.GroupNameFormat = "'v'V";
                    options.SubstituteApiVersionInUrl = true;
                });
            services.ConfigureOptions<ConfigureSwaggerGenOptions>();

            services.AddEndpointsApiExplorer();
            services.AddSwaggerGen();

            return services;
        }

        public static WebApplication ConfigureSwaggerExplorer(this WebApplication app)
        {
            app.UseSwagger();
            app.UseSwaggerUI(options =>
            {
                IReadOnlyList<ApiVersionDescription> descriptions = app.DescribeApiVersions();

                foreach (ApiVersionDescription desc in descriptions)
                {
                    string url = $"/swagger/{desc.GroupName}/swagger.json";
                    string name = desc.GroupName.ToUpperInvariant();

                    options.SwaggerEndpoint(url, name);
                }
            });

            return app;
        }
    }
}
