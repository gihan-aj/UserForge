using Infrastructure;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using WebAPI.Extensions;
using WebAPI.Infrastructure;

var builder = WebApplication.CreateBuilder(args);
var configuration = builder.Configuration;

builder.Services.ConfigureAppSettings(configuration);

builder.Services.AddInfrastructure(configuration);

builder.Services.AddJWTAuthentication(configuration)
                .AddAuthorization();

builder.Services.AddControllers();

builder.Services.AddExceptionHandler<GlobalExceptionHandler>();
builder.Services.AddProblemDetails();

builder.Services.AddSwaggerExplorerWithApiVersioning();

var app = builder.Build();

await app.SeedInitialDataAsync();

app.MapControllers();

if (app.Environment.IsDevelopment())
{
    app.ConfigureSwaggerExplorer();

    app.ApplyMigrations();
}

app.UseHttpsRedirection();

app.UseExceptionHandler();

app.ConfigureCORS(configuration);

app.UseAuthentication();

app.UseAuthorization();

app.Run();
