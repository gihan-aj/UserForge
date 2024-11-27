using FluentValidation;

namespace WebAPI.Models.Users
{
    public class UpdateUserRequestValidator : AbstractValidator<UpdateUserRequest>
    {
        public UpdateUserRequestValidator()
        {
            RuleFor(x => x.FirstName)
                .NotEmpty().WithMessage("First Name is required.");

            RuleFor(x => x.LastName)
                .NotEmpty().WithMessage("Last Name is required.");

        }
    }
}
