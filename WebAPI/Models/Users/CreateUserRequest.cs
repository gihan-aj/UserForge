﻿using FluentValidation;

namespace WebAPI.Models.Users
{
    public record CreateUserRequest(
        string FirstName,
        string LastName,
        string Email,
        string Password,
        string Role);

    public class CreateUserRequestValidator : AbstractValidator<CreateUserRequest>
    {
        public CreateUserRequestValidator()
        {
            RuleFor(x => x.Email)
                .NotEmpty().WithMessage("Email is required.")
                .EmailAddress().WithMessage("Invalid email format.");

            RuleFor(x => x.Password)
                .NotEmpty().WithMessage("Password is required.")
                .MinimumLength(6).WithMessage("Password must be at least 6 characters long.");

            RuleFor(x => x.FirstName)
                .NotEmpty().WithMessage("First Name is required.");

            RuleFor(x => x.LastName)
                .NotEmpty().WithMessage("Last Name is required.");
        }
    }
}
