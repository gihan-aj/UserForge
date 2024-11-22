using Application.Configurations;
using FluentValidation.AspNetCore;
using Infrastructure;
using Infrastructure.Persistence;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using System.Text;
using WebAPI.Extensions;
using WebAPI.Infrastructure;
using WebAPI.ServiceRegistrar;

var builder = WebApplication.CreateBuilder(args);

// SMTP server settings
builder.Services.Configure<SmtpSettings>(builder.Configuration.GetSection("Smtp"));

// JWT
builder.Services.Configure<JwtSettings>(builder.Configuration.GetSection("JWT"));

// Infrastructure
builder.Services.AddInfrastructure(builder.Configuration);

// Authentication with JWT
builder.Services.AddJWTAuthentication(builder.Configuration);

builder.Services.AddAuthorization();

builder.Services.AddControllers();

// Global Exception handling
builder.Services.AddExceptionHandler<GlobalExceptionHandler>();
builder.Services.AddProblemDetails();

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

// Seed data
using (var scope = app.Services.CreateScope())
{
    var services = scope.ServiceProvider;
    await DataSeeder.SeedRolesAndUserAsync(services);
}

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();

    app.ApplyMigrations();
}

app.UseHttpsRedirection();

app.UseExceptionHandler();

app.UseAuthentication();

app.UseAuthorization();

app.MapControllers();

app.Run();
