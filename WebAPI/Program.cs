using Application.Configurations;
using Asp.Versioning;
using Asp.Versioning.ApiExplorer;
using Infrastructure;
using Infrastructure.Persistence;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using System.Collections.Generic;
using WebAPI.Extensions;
using WebAPI.Infrastructure;
using WebAPI.OpenApi;

var builder = WebApplication.CreateBuilder(args);

// Settings
builder.Services.Configure<SmtpSettings>(builder.Configuration.GetSection("Smtp"))
    .Configure<JwtSettings>(builder.Configuration.GetSection("JWT"))
    .Configure<TokenSettings>(builder.Configuration.GetSection("TokenSettings"));

builder.Services.AddInfrastructure(builder.Configuration);

builder.Services.AddJWTAuthentication(builder.Configuration)
    .AddAuthorization();

builder.Services.AddControllers();

// Global Exception handling
builder.Services.AddExceptionHandler<GlobalExceptionHandler>()
    .AddProblemDetails();

builder.Services.AddApiVersioning(options =>
{
    options.DefaultApiVersion = new ApiVersion(1);
    options.ReportApiVersions = true;
    options.ApiVersionReader = new UrlSegmentApiVersionReader();
})
    .AddMvc()
    .AddApiExplorer(options =>
    {
        options.GroupNameFormat = "'v'V";
        options.SubstituteApiVersionInUrl = true;
    });
builder.Services.ConfigureOptions<ConfigureSwaggerGenOptions>();

// swagger
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var devOrigin = "angular_front";
builder.Services.AddCors(
    options =>
    {
        options.AddPolicy(name: devOrigin,
            policy =>
            {
                policy.WithOrigins("http://localhost:4200")
                .AllowAnyHeader()
                .AllowAnyMethod(); ;
            });
    });

var app = builder.Build();

// Seed data
using (var scope = app.Services.CreateScope())
{
    var services = scope.ServiceProvider;
    await DataSeeder.SeedRolesAndUserAsync(services);
}

app.MapControllers();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI(options =>
    {
        IReadOnlyList<ApiVersionDescription> descriptions = app.DescribeApiVersions();

        foreach(ApiVersionDescription desc in descriptions)
        {
            string url = $"/swagger/{desc.GroupName}/swagger.json";
            string name = desc.GroupName.ToUpperInvariant();

            options.SwaggerEndpoint(url, name);
        }
    });

    app.ApplyMigrations();
}

app.UseHttpsRedirection();

app.UseExceptionHandler();

app.UseCors(devOrigin);

app.UseAuthentication();

app.UseAuthorization();

app.Run();
