using SharedKernal;

namespace Domain.Users
{
    public static class UserErrors
    {
        public static class Validation
        {
            public static Error InvalidCredentials => new("InvalidCredentials", "The provided username or password is incorrect.");
            public static Error InvalidPassword => new("InvalidPassword", "The provided password is incorrect.");
            public static Error PasswordMismatch => new("PasswordMismatch", "The new password and confirmation do not match.");
            public static Error WeakPassword => new("WeakPassword", "The password does not meet the required complexity.");
            public static Error InvalidEmailFormat => new("InvalidEmailFormat", "The provided email format is invalid.");
            public static Error MissingRequiredField(string fieldName) => new("MissingRequiredField", $"{fieldName} is required.");
        }

        public static class NotFound
        {
            public static Error User(string userId) => new("UserNotFound", $"No user found with ID: {userId}.");
            public static Error Email(string email) => new("EmailNotFound", $"No account found with email: {email}.");
            public static Error Resource(string resourceName) => new("ResourceNotFound", $"{resourceName} was not found.");
        }

        public static class Conflict
        {
            public static Error EmailAlreadyExists(string email) => new("EmailAlreadyExists", $"An account with email: {email} already exists.");
            public static Error UsernameAlreadyExists(string username) => new("UsernameAlreadyExists", $"An account with username: {username} already exists.");
            public static Error EmailAlreadyConfirmed(string email) => new("EmailAlreadyConfirmed", $"The email: {email} is already confirmed. You can log in.");
        }

        public static class Token
        {
            public static Error InvalidRefreshToken => new("InvalidRefreshToken", "The refresh token is invalid or expired. Please log in again.");
            public static Error InvalidAccessToken => new("InvalidAccessToken", "The access token is invalid or expired. Please log in again.");
            public static Error MissingRefreshToken => new("MissingRefreshToken", "The refresh token is missing. Please log in again.");
            public static Error ExpiredToken => new("ExpiredToken", "The token has expired. Please request a new one.");
        }

        public static class Authorization
        {
            public static Error EmailNotConfirmed(string email) => new("EmailNotConfirmed", $"The email: {email} is not confirmed. Confirm you email to activate your account");
            public static Error AccessDenied => new("AccessDenied", "You do not have permission to perform this action.");
            public static Error RoleNotAssigned => new("RoleNotAssigned", "The user does not have the required role for this action.");
        }

        public static class General
        {
            public static Error OperationFailed(string reason) => new("OperationFailed", $"The operation failed. Reason: {reason}.");
            public static Error UnexpectedError => new("UnexpectedError", "An unexpected error occurred. Please try again later.");
        }
    }
}
