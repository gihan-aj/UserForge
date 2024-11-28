using Application.Configurations;
using Asp.Versioning;
using Asp.Versioning.ApiExplorer;
using FluentValidation.AspNetCore;
using Infrastructure;
using Infrastructure.Persistence;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using System.Collections.Generic;
using System.Text;
using WebAPI.Extensions;
using WebAPI.Infrastructure;
using WebAPI.OpenApi;
using WebAPI.ServiceRegistrar;

var builder = WebApplication.CreateBuilder(args);

// SMTP server settings
builder.Services.Configure<SmtpSettings>(builder.Configuration.GetSection("Smtp"));

// JWT
builder.Services.Configure<JwtSettings>(builder.Configuration.GetSection("JWT"));

// Token setings
builder.Services.Configure<TokenSettings>(builder.Configuration.GetSection("TokenSettings"));

// Infrastructure
builder.Services.AddInfrastructure(builder.Configuration);

// Authentication with JWT
builder.Services.AddJWTAuthentication(builder.Configuration);

builder.Services.AddAuthorization();

builder.Services.AddControllers();

// Global Exception handling
builder.Services.AddExceptionHandler<GlobalExceptionHandler>();
builder.Services.AddProblemDetails();

// Api versioning
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

app.UseAuthentication();

app.UseAuthorization();

app.Run();
