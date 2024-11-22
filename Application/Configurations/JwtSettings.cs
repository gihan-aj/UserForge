namespace Application.Configurations
{
    public class JwtSettings
    {
        public string Key { get; set; }
        public int ExpiresInMinutes { get; set; }
        public int RefreshTokenExpiresInDays { get; set; }
        public string Issuer { get; set; }
        public string ClientUrl { get; set; }
    }
}
