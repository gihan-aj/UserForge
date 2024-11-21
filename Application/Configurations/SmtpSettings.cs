namespace Application.Configurations
{
    public class SmtpSettings
    {
        public string Host { get; set; }
        public int Port { get; set; }
        public string Username { get; set; }
        public string Password { get; set; }
        public string ApplicationName { get; set; }
        public string ConfirmEmailPath { get; set; }
        public string ResetPasswordPath { get; set; }
    }
}
