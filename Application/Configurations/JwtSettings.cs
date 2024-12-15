namespace Application.Configurations
{
    public class JwtSettings
    {
        public string HmacSha256SecretKey { get; set; } = string.Empty;
        public int ExpiresInMinutes { get; set; }
        public string Issuer { get; set; } = string.Empty;
        public string ClientUrl { get; set; } = string.Empty;
    }
}
