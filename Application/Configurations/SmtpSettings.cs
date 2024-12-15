namespace Application.Configurations
{
    public class SmtpSettings
    {
        public string Host { get; set; } = string.Empty;
        public int Port { get; set; }
        public string Username { get; set; } = string.Empty ;
        public string Password { get; set; } = string.Empty;
        public string ApplicationName { get; set; } = string.Empty;
        public SmtpRoutes Routes { get; set; } = new();
    }

    public class SmtpRoutes
    {
        public string ConfirmEmailPath { get; set; } = string.Empty;
        public string ResetPasswordPath { get; set; } = string.Empty;
        public string ChangeEmailPath { get; set; } = string.Empty;
    }
}
