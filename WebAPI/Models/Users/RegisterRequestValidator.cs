using FluentValidation;
using System;
using System.Text.RegularExpressions;

namespace WebAPI.Models.Users
{
    public class RegisterRequestValidator : AbstractValidator<RegisterRequest>
    {
        public RegisterRequestValidator()
        {
            RuleFor(x => x.Email)
                .Cascade(CascadeMode.Stop)
                .NotEmpty().WithMessage("Email is required.")
                .EmailAddress().WithMessage("Please provide a valid email address.");

            RuleFor(x => x.Password)
                .Cascade(CascadeMode.Stop)
                .NotEmpty().WithMessage("Password is required.")
                .MinimumLength(6).WithMessage("Password must be at least 6 characters long.")
                .Matches("[A-Z]").WithMessage("Password must contain at least one uppercase letter.")
                .Matches("[a-z]").WithMessage("Password must contain at least one lowercase letter.")
                .Matches("[0-9]").WithMessage("Password must contain at least one numeric digit.")
                .Matches("[^a-zA-Z0-9]").WithMessage("Password must contain at least one special character.");

            RuleFor(x => x.FirstName)
                .Cascade(CascadeMode.Stop)
                .NotEmpty().WithMessage("First Name is required.")
                .MaximumLength(255).WithMessage("First Name cannot exceed 255 characters.")
                .Matches("^[a-zA-Z]+$").WithMessage("First Name can only contain alphabetic characters.");

            RuleFor(x => x.LastName)
                .Cascade(CascadeMode.Stop)
                .NotEmpty().WithMessage("Last Name is required.")
                .MaximumLength(255).WithMessage("Last Name cannot exceed 255 characters.")
                .Matches("^[a-zA-Z]+$").WithMessage("Last Name can only contain alphabetic characters.");

            RuleFor(x => x.PhoneNumber)
               .Cascade(CascadeMode.Stop)
                .Must(BeAValidPhoneNumber).When(x => !string.IsNullOrWhiteSpace(x.PhoneNumber))
                .WithMessage("Please provide a valid phone number.");

            RuleFor(x => x.DateOfBirth)
                .Must(BeAValidAge).When(x => x.DateOfBirth.HasValue)
                .WithMessage("You must be at least 18 years old.");
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
            if(dateOfBirth.Value.Date > DateTime.Now.AddYears(-age))
            {
                age--;
            }

            return age >= 18;
        }
    }
}
