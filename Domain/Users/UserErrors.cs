using SharedKernal;

namespace Domain.Users
{
    public static class UserErrors
    {
        public static Error NotFound(string id) => new("User.NotFound", $"The user - {id}, is not found.");
        public static Error AlreadyExists(string email) => new("User.AlreadyExists", $"A user with email - {email}, is already exists.");
        public static Error EmailAlreadyConfirmed(string email) => new("User.EmailAlreadyConfirmed", $"The user email - {email}, is already confirmed. You can login.");
    }
}
