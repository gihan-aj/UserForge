using Asp.Versioning.Builder;
using Infrastructure;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using WebAPI.Endpoints.v1;
using WebAPI.Extensions;
using WebAPI.Infrastructure;

var builder = WebApplication.CreateBuilder(args);
var configuration = builder.Configuration;

builder.Services.ConfigureAppSettings(configuration);

builder.Services.AddInfrastructure(configuration);

builder.Services.AddJWTAuth(configuration);

builder.Services.AddControllers();

builder.Services.AddExceptionHandler<GlobalExceptionHandler>();
builder.Services.AddProblemDetails();

builder.Services.AddSwaggerExplorerWithApiVersioning();

var app = builder.Build();

await app.SeedInitialDataAsync();

app.MapControllers();

ApiVersionSet apiVersionSet = app.NewApiVersionSet()
    .HasApiVersion(new Asp.Versioning.ApiVersion(2))
    .ReportApiVersions()
    .Build();

RouteGroupBuilder versionedGroup = app.MapGroup("api/v{apiVersion:apiVersion}")
    .WithApiVersionSet(apiVersionSet);

versionedGroup.MapUserEndpoints();


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
