using Application.Configurations;
using Application.Services;
using Domain.Users;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Options;
using SharedKernal;
using System;
using System.Net;
using System.Net.Mail;
using System.Text;
using System.Threading.Tasks;

namespace Infrastructure.Services
{
    public class EmailService : IEmailService
    {
        private readonly SmtpSettings _smtpSettings;
        private readonly JwtSettings _jwtSettings;

        public EmailService(IOptions<SmtpSettings> smtpSettings, IOptions<JwtSettings> jwtSettings)
        {
            _smtpSettings = smtpSettings.Value;
            _jwtSettings = jwtSettings.Value;
        }

        public async Task<Result> SendConfirmationEmailAsync(User user, string token)
        {
            try
            {
                token = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(token));

                var clientUrl = _jwtSettings.ClientUrl;
                var confirmEmailPath = _smtpSettings.ConfirmEmailPath;
                var url = $"{clientUrl}/{confirmEmailPath}?token={token}&userId={user.Id}";

                var appName = _smtpSettings.ApplicationName;

                var body = CreateEmailBody(
                    "Email Confirmation",
                    user.FirstName,
                    "Please confirm your email address by clicking the button below:",
                    "Confirm Email",
                    url,
                    appName);

                using var smtpClient = new SmtpClient(_smtpSettings.Host, _smtpSettings.Port)
                {
                    Credentials = new NetworkCredential(_smtpSettings.Username, _smtpSettings.Password),
                    EnableSsl = true
                };

                var mailMessage = new MailMessage
                {
                    From = new MailAddress(_smtpSettings.Username, appName),
                    Subject = "Confirm your email",
                    Body = body,
                    IsBodyHtml = true
                };

                mailMessage.To.Add(user.Email);

                await smtpClient.SendMailAsync(mailMessage);

                return Result.Success();
            }
            catch (Exception ex)
            {
                return Result.Failure(new("EmailServerError", ex.Message));
            }
            
        }

        private string CapitalizeFirstLetter(string name)
        {
            if (string.IsNullOrEmpty(name))
            {
                return name;
            }

            return char.ToUpper(name[0]) + name.Substring(1);
        }

        private string CreateEmailBody(string header, string name, string instructions, string action, string url, string appName)
        {
            var firstName = CapitalizeFirstLetter(name);
            int year = DateTime.UtcNow.Year;

            var containerStyle = "font-family: Arial, sans-serif; width: 100%; max-width: 576px; margin: 0 auto; background-color: #ffffff; padding: 20px; box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);";
            var headerStyle = "text-align: center; padding: 20px 0; border-bottom: 1px solid #dddddd;";
            var h1Style = "margin: 0; color: #333333;";
            var contentStyle = "padding: 20px;";
            var pStyle = " line-height: 1.5; color: #666666;";
            var aStyle = "display: inline-block; padding: 10px 20px; background-color: #007bff; color: #ffffff; text-decoration: none; border-radius: 8px;";
            var footerStyle = "text-align: center; padding: 20px; border-top: 1px solid #dddddd; color: #999999; font-size: 12px;";

            var body = $"<div style=\"{containerStyle}\">" +
                $"<div style=\"{headerStyle}\">" +
                $"<h1 style=\"{h1Style}\">{header}</h1>" +
                "</div>" +
                $"<div style=\"{contentStyle}\">" +
                $"<p style=\"{pStyle}\">Hi {firstName},</p>" +
                $"<p style=\"{pStyle}\">{instructions}</p>" +
                $"<a style=\"{aStyle}\" href=\"{url}\">{action}</a>" +
                $"<p style=\"{pStyle}\">If you did not sign up for this account, you can ignore this email.</p>" +
                $"<p style=\"{pStyle}\">Thanks,<br>The {appName} Team</p>" +
                "</div>" +
                $"<div style=\"{footerStyle}\">" +
                $"<p>&copy; {year} {appName}. All rights reserved.</p>" +
                "</div>";

            return body;
        }
    }
}
