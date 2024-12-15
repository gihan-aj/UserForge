namespace Application.Configurations
{
    public class TokenSettings
    {
        public JwtSettings JWT { get; set; } = new();
        public RefreshTokenSettings RefreshToken { get; set; } = new();
        public PasswordResetTokenSettings PasswordResetToken { get; set; } = new();
    }
}
