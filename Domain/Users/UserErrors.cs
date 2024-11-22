using SharedKernal;

namespace Domain.Users
{
    public static class UserErrors
    {
        public static Error NotValid => new("User.NotValid", $"Username or password is not valid.");
        public static Error NotFound(string id) => new("User.NotFound", $"The user ({id}), is not found.");
        public static Error EmailNotFound(string email) => new("User.EmailNotFound", $"The email ({email}), is not registered.");
        public static Error EmailNotConfirmed(string email) => new("User.EmailNotConfirmed", $"The email ({email}), is not confirmed.");
        public static Error AlreadyExists(string email) => new("User.AlreadyExists", $"A user with email ({email}), is already exists.");
        public static Error EmailAlreadyConfirmed(string email) => new("User.EmailAlreadyConfirmed", $"The user email ({email}), is already confirmed. You can login.");
        public static Error InvaildRefreshToken => new("User.RefreshTokenInvalid", "The token is invalid or expired. Please login again");
        public static Error MissingRefreshToken => new("User.RefreshTokenMissing", "The token is missing. Please login again");
    }
}
