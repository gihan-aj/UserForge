using FluentValidation;
using System.Text.RegularExpressions;
using System;

namespace WebAPI.Models.Users
{
    public class UpdateUserRequestValidator : AbstractValidator<UpdateUserRequest>
    {
        public UpdateUserRequestValidator()
        {
            RuleFor(x => x.FirstName)
                .Cascade(CascadeMode.Stop)
                .NotEmpty().WithMessage("First Name is required.")
                .MinimumLength(3).WithMessage("First Name must be at least 3 characters long.")
                .MaximumLength(255).WithMessage("First Name must not exceed 255 characters.")
                .Matches("^[a-zA-Z]+$").WithMessage("First Name can only contain alphabetic characters.");

            RuleFor(x => x.LastName)
                .NotEmpty().WithMessage("Last Name is required.")
                .MinimumLength(3).WithMessage("Last Name must be at least 3 characters long.")
                .MaximumLength(255).WithMessage("Last Name must not exceed 255 characters.")
                .Matches("^[a-zA-Z]+$").WithMessage("Last Name can only contain alphabetic characters.");

            RuleFor(x => x.PhoneNumber)
               .Cascade(CascadeMode.Stop)
                .Must(BeAValidPhoneNumber).When(x => !string.IsNullOrWhiteSpace(x.PhoneNumber))
                .WithMessage("Please provide a valid phone number.");

            RuleFor(x => x.DateOfBirth)
                .Must(BeAValidAge)
                .WithMessage("You must be at least 16 years old.")
                .When(x => x.DateOfBirth.HasValue);

        }

        private bool BeAValidPhoneNumber(string? phoneNumber)
        {
            if (string.IsNullOrWhiteSpace(phoneNumber)) return false;
            return Regex.IsMatch(phoneNumber, @"^\+?[1-9]\d{1,14}$"); // E.164 format
        }

        private bool BeAValidAge(DateTime? dateOfBirth)
        {
            if (!dateOfBirth.HasValue)
            {
                return false;
            }

            var age = DateTime.Now.Year - dateOfBirth.Value.Year;
            if (dateOfBirth.Value.Date > DateTime.Now.AddYears(-age))
            {
                age--;
            }

            return age >= 16;
        }
    }
}
