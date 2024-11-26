using SharedKernal;
using System.Linq;

namespace WebAPI.Infrastructure
{
    public static class ValidationHandler
    {
        public static Result Handle(FluentValidation.Results.ValidationResult validationResult)
        {
            if(validationResult.IsValid)
            {
                return Result.Success();
            }

            var errors = validationResult.Errors
                .Select(failure => new Error(failure.ErrorCode, failure.ErrorMessage))
                .ToList();

            Error validationError = new("ValidationError", "One or more validation errors occured.", errors);

            return Result.Failure(validationError);
        }
    }
}
