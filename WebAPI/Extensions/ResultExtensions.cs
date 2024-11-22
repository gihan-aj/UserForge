using Microsoft.AspNetCore.Mvc;
using SharedKernal;
using System.Linq;

namespace WebAPI.Extensions
{
    public static class ResultExtensions
    {
        public static ProblemDetails CreateProblemDetails(
            string title,
            int status,
            Error error,
            Error[]? errors = null) =>
            new()
            {
                Title = title,
                Type = error.Code,
                Detail = error.Description,
                Status = status,
                Extensions = { { nameof(errors), errors } }
            };

        public static ServiceResult<T> CreateProblemDetailsFromValidationErrors<T>(FluentValidation.Results.ValidationResult validationResult)
        {
            var errors = validationResult.Errors
                .Select(failure => new Error(failure.ErrorCode, failure.ErrorMessage))
                .ToArray();

            return ServiceResult<T>.WithErrors(errors);

        }
    }
}
