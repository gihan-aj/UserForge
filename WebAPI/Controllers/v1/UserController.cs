using Application.Services;
using Asp.Versioning;
using Domain.Users;
using Infrastructure.Settings;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using SharedKernal;
using System;
using System.Security.Claims;
using System.Threading.Tasks;
using WebAPI.Infrastructure;
using WebAPI.Models.Users;

namespace WebAPI.Controllers.v1
{
    [ApiController]
    [Route("api/v{apiVersion:apiVersion}/[controller]")]
    [ApiVersion("1")]
    public class UserController : ControllerBase
    {
        private readonly IEmailService _emailService;
        private readonly IUserService _userService;
        private readonly ITokenService _tokenService;
        private readonly TokenSettings _tokenSettings;

        public UserController(IEmailService emailService, IUserService userService, ITokenService tokenService, IOptions<TokenSettings> tokenSettings)
        {
            _emailService = emailService;
            _userService = userService;
            _tokenService = tokenService;
            _tokenSettings = tokenSettings.Value;
        }

        /// <summary>
        /// Registers a new user account.
        /// </summary>
        /// <remarks>
        /// **Endpoint Purpose**:  
        /// This endpoint allows anonymous users to register a new account in the system.  
        ///
        /// **Sample Request:**
        ///
        ///     POST api/Users/register
        ///     {
        ///         "firstName": "John",
        ///         "lastName": "Doe",
        ///         "email": "john.doe@example.com",
        ///         "password": "Password1234!"
        ///     }
        ///
        /// **Validation Notes:**
        /// - The `firstName` and `lastName` fields must not be empty.
        /// - The `email` field must be a valid email address.
        /// - The `password` must meet the defined complexity requirements.
        ///
        /// **Possible Errors:**
        /// - **400 Bad Request**: If the input validation fails.
        /// - **500 Internal Server Error**: If an unexpected error occurs.
        ///
        /// Upon successful registration:
        /// - The user will be added to the `User` role.
        /// - An email confirmation token will be sent to the user's email address.
        /// </remarks>
        /// <param name="request">The registration details for the new user.</param>
        /// <returns>
        /// A 201 Created response with the location of the new user resource.  
        /// If the registration fails, returns a problem details object with error information.
        /// </returns>
        /// <response code="201">Returns the location of the created resource.</response>
        /// <response code="400">If the request contains invalid data.</response>
        /// <response code="500">If an unexpected error occurs on the server.</response>
        [HttpPost("register")]
        [AllowAnonymous]
        [ProducesResponseType(StatusCodes.Status201Created)]
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status400BadRequest)]
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status500InternalServerError)]
        public async Task<IResult> Register([FromBody] RegisterRequest request)
        {
            if (request is null)
            {
                throw new ArgumentNullException(nameof(request));
            }

            var validator = new RegisterRequestValidator();
            var validationResult = ValidationHandler.Handle(validator.Validate(request));
            if (validationResult.IsFailure)
            {
                return HandleFailure(validationResult);
            }

            var result = await _userService.CreateAsync(
                request.FirstName.ToLower(),
                request.LastName.ToLower(),
                request.Email.ToLower(),
                request.PhoneNumber,
                request.DateOfBirth,
                request.Password);

            if (result.IsFailure)
            {
                return HandleFailure(result);
            }

            var user = result.Value;

            // Add user role
            var addToRoleResult = await _userService.AddToRoleAsync(user, UserRoles.User);
            if (addToRoleResult.IsFailure)
            {
                return HandleFailure(result);
            }

            // Email confirmation token
            var emailConfirmationTokenResult = await _userService.GenerateEmailConfirmationTokenAsync(user);
            if (emailConfirmationTokenResult.IsFailure)
            {
                return HandleFailure(emailConfirmationTokenResult);
            }

            var emailConfirmationToken = emailConfirmationTokenResult.Value;

            // Confirm link via email
            var emailResult = await _emailService.SendConfirmationEmailAsync(user, emailConfirmationToken);
            if (emailResult.IsFailure)
            {
                return HandleFailure(emailResult);
            }

            //var location = Url.Action(nameof(GetUser), new { id = user.Id }) ?? $"/{user.Id}";
            return Results.CreatedAtRoute();
        }

        /// <summary>
        /// Retrieves the details of the currently logged-in user.
        /// </summary>
        /// <remarks>
        /// This endpoint retrieves the details of the authenticated user based on their token.  
        /// The user must be logged in and authorized to access this resource.
        ///
        /// **Sample Request:**
        ///
        ///     GET api/Users/logged-in-user-details
        ///     
        /// **Authorization Header:**
        ///
        ///     Authorization: Bearer {token}
        ///
        /// **Possible Responses:**
        /// 
        /// - **200 OK**: Returns the user's details.
        /// - **401 Unauthorized**: If the request does not include a valid authorization token.
        /// - **404 Not Found**: If the user is not found.
        /// - **500 Internal Server Error**: If an unexpected error occurs.
        /// </remarks>
        /// <returns>
        /// The details of the logged-in user.  
        /// Returns a <see cref="GetUserResponse"/> object containing the user's ID, username, first name, and last name.
        /// </returns>
        /// <exception cref="UnauthorizedAccessException">
        /// Thrown if the user is not authorized to access this resource.
        /// </exception>
        /// <response code="200">Returns the details of the authenticated user.</response>
        /// <response code="401">If the user is not authenticated or the token is invalid.</response>
        /// <response code="404">If the user details cannot be found in the system.</response>
        /// <response code="500">If an internal server error occurs.</response>
        [HttpGet]
        [Authorize(Roles = UserRoles.User)]
        [ProducesResponseType(typeof(GetUserResponse), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status401Unauthorized)]
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status404NotFound)]
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status500InternalServerError)]
        public async Task<IResult> GetUser()
        {
            var id = User.FindFirstValue(ClaimTypes.NameIdentifier);
            var result = await _userService.FindByIdAsync(id);
            if (result.IsFailure)
            {
                return HandleFailure(result);
            }

            var user = result.Value;

            var userResponse = new GetUserResponse(
                id, 
                user.Email!, 
                user.FirstName, 
                user.LastName,
                user.PhoneNumber,
                user.DateOfBirth);

            return Results.Ok(userResponse);
        }

        /// <summary>
        /// Confirms a user's email address using a token.
        /// </summary>
        /// <remarks>
        /// **Endpoint Purpose**:  
        /// This endpoint is used to verify a user's email address by providing the user ID and a confirmation token.
        ///
        /// **How it Works:**
        /// - The user receives an email with a confirmation link containing the `userId` and `token`.
        /// - Upon clicking the link, this endpoint is called to verify the token and activate the user's email.
        ///
        /// **Possible Errors:**
        /// - **400 Bad Request**: If the token or userId is invalid.
        /// - **500 Internal Server Error**: If an unexpected error occurs during processing.
        ///
        /// **Sample Request:**
        /// 
        ///     PUT api/Users/confirm-email?userId=12345&amp;token=abc123xyz
        ///
        /// </remarks>
        /// <param name="userId">The ID of the user whose email is being confirmed.</param>
        /// <param name="token">The confirmation token sent to the user's email.</param>
        /// <returns>
        /// A 204 No Content response if the email is successfully confirmed.
        /// If the confirmation fails, returns a problem details object with error information.
        /// </returns>
        /// <response code="204">Email successfully confirmed.</response>
        /// <response code="400">If the `userId` or `token` is invalid.</response>
        /// <response code="500">If an unexpected error occurs.</response>
        [HttpPut("confirm-email")]
        [AllowAnonymous]
        [ProducesResponseType(StatusCodes.Status204NoContent)]
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status400BadRequest)]
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status500InternalServerError)]
        public async Task<IResult> ConfirmEmail(string userId, string token)
        {
            var result = await _userService.ConfirmEmailAsync(userId, token);
            if (result.IsFailure)
            {
                return HandleFailure(result);
            }

            return Results.NoContent();
        }

        /// <summary>
        /// Resends the email confirmation link to a user's registered email address.
        /// </summary>
        /// <remarks>
        /// **Endpoint Purpose**:  
        /// This endpoint allows a user to request a new email confirmation link if they have not yet confirmed their email.
        ///
        /// **How it Works:**
        /// - The user provides their email address.
        /// - The system verifies if the email belongs to a registered user.
        /// - If the user exists, a new confirmation token is generated and emailed to the user.
        ///
        /// **Possible Errors:**
        /// - **400 Bad Request**: If the email format is invalid or the user does not exist.
        /// - **500 Internal Server Error**: If an unexpected error occurs while generating the token or sending the email.
        ///
        /// **Sample Request:**
        /// 
        ///     POST api/Users/resend-email-confirmation-link/john.doe@email.com
        ///
        /// **Sample Response for Success:**
        /// - **204 No Content**: The confirmation email was successfully resent.
        ///
        /// **Common Scenarios:**
        /// - If the user enters an unregistered email, a `400 Bad Request` is returned.
        /// - If there is a system error, a `500 Internal Server Error` is returned.
        ///
        /// </remarks>
        /// <param name="email">The email address of the user requesting a new confirmation link.</param>
        /// <returns>
        /// A 204 No Content response if the email was successfully sent.  
        /// If an error occurs, a problem details object is returned with relevant error information.
        /// </returns>
        /// <response code="204">Confirmation email successfully resent.</response>
        /// <response code="400">If the email is invalid or not associated with any user.</response>
        /// <response code="500">If an unexpected error occurs during processing.</response>
        [HttpPost("resend-email-confirmation-link/{email}")]
        [AllowAnonymous]
        [ProducesResponseType(StatusCodes.Status204NoContent)]
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status400BadRequest)]
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status500InternalServerError)]
        public async Task<IResult> ResendEmailConfirmationLink(string email)
        {
            var userResult = await _userService.FindByEmailAsync(email);
            if (userResult.IsFailure)
            {
                return HandleFailure(userResult);
            }
            var user = userResult.Value;

            var tokenResult = await _userService.GenerateEmailConfirmationTokenAsync(user);
            if (tokenResult.IsFailure)
            {
                return HandleFailure(tokenResult);
            }

            var token = tokenResult.Value;
            var emailResult = await _emailService.SendConfirmationEmailAsync(user, token);
            if (emailResult.IsFailure)
            {
                return HandleFailure(emailResult);
            }

            return Results.NoContent();
        }

        /// <summary>
        /// Authenticates a user and generates access and refresh tokens.
        /// </summary>
        /// <remarks>
        /// **Endpoint Purpose:**  
        /// This endpoint allows users to log in with their credentials (email and password) and receive a JWT access token and a refresh token.
        ///
        /// **How it Works:**
        /// - Validates the email and password provided in the request.
        /// - Authenticates the user against the database.
        /// - Generates a JWT access token for authorization.
        /// - Generates a refresh token, stores it securely, and sends it to the user as an HTTP-only cookie.
        ///
        /// **Response:**  
        /// On successful login:
        /// - The user's details and the JWT access token are included in the response.
        /// - The refresh token is sent as an HTTP-only cookie for secure storage.
        ///
        /// **Sample Request:**
        /// 
        ///     POST api/Users/login
        ///     {
        ///         "email": "user@example.com",
        ///         "password": "Password1234"
        ///     }
        ///
        /// **Sample Response for Success:**
        /// ```json
        /// {
        ///     "id": "john.doe",
        ///     "email": "john.doe",
        ///     "firstName": "John",
        ///     "lastName": "Doe",
        ///     "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
        /// }
        /// ```
        ///
        /// **Possible Errors:**
        /// - **400 Bad Request**: Validation errors in the request.
        /// - **401 Unauthorized**: Invalid credentials.
        /// - **500 Internal Server Error**: Unexpected issues during the login process.
        ///
        /// </remarks>
        /// <param name="request">The user's login credentials (email and password).</param>
        /// <returns>
        /// A 200 OK response with the user's details and JWT token if login is successful.  
        /// Errors are returned with appropriate HTTP status codes.
        /// </returns>
        /// <response code="200">The user was successfully authenticated and tokens were generated.</response>
        /// <response code="400">The request is invalid (e.g., missing or improperly formatted fields).</response>
        /// <response code="401">Invalid login credentials.</response>
        /// <response code="500">An unexpected error occurred.</response>
        [HttpPost("login")]
        [AllowAnonymous]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status400BadRequest)]
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status401Unauthorized)]
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status500InternalServerError)]
        public async Task<IResult> Login([FromBody] LoginRequest request)
        {
            if (request is null)
            {
                throw new ArgumentNullException(nameof(request));
            }

            var validator = new LoginRequestValidator();
            var validationResult = ValidationHandler.Handle(validator.Validate(request));
            if (validationResult.IsFailure)
            {
                return HandleFailure(validationResult);
            }

            var loginResult = await _userService.LoginAsync(request.Email.ToLower(), request.Password);
            if (loginResult.IsFailure)
            {
                return HandleFailure(loginResult);
            }

            var user = loginResult.Value;

            // User roles
            var rolesResult = await _userService.GetRolesAsync(user);

            // JWT
            string accessToken = _tokenService.CreateJwtToken(user, rolesResult.Value);

            // Refresh token
            string refreshToken = _tokenService.GenerateRefreshToken();

            // Save refresh token
            var persistRefreshTokenResult = await _userService.PersistRefreshToken(user, refreshToken);
            if (persistRefreshTokenResult.IsFailure)
            {
                return HandleFailure(persistRefreshTokenResult);
            }

            // Store refresh token in httpOnly cookie
            HttpContext.Response.Cookies.Append("refreshToken", refreshToken, new CookieOptions
            {
                HttpOnly = true,
                Secure = false, // For production , HTTPS
                SameSite = SameSiteMode.None,
                Expires = DateTime.UtcNow.AddDays(_tokenSettings.RefreshToken.ExpiresInDays)
            });

            return Results.Ok(new LoginResponse(
                    accessToken,
                    refreshToken,
                    new UserResponse(
                        user.Id,
                        user.FirstName,
                        user.LastName)));
        }

        /// <summary>
        /// Refreshes the JWT access token using a valid refresh token.
        /// </summary>
        /// <remarks>
        /// **Endpoint Purpose:**  
        /// This endpoint allows users to obtain a new access token when the existing one expires, using a valid refresh token stored in an HTTP-only cookie.
        ///
        /// **How it Works:**
        /// - Retrieves the refresh token from the user's cookies.
        /// - Verifies the refresh token and fetches the associated user.
        /// - Generates a new JWT access token and a new refresh token.
        /// - Saves the new refresh token and replaces the existing one in the user's cookies.
        ///
        /// **Response:**  
        /// On success:
        /// - A new JWT access token is returned in the response body.
        /// - A new refresh token is stored in the user's cookies.
        ///
        /// **Sample Request:**  
        /// The request does not require a body as the refresh token is sent automatically in cookies.
        ///
        /// **Sample Response for Success:**
        /// ```json
        /// {
        ///     "userName": "john.doe",
        ///     "firstName": "John",
        ///     "lastName": "Doe",
        ///     "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
        /// }
        /// ```
        ///
        /// **Possible Errors:**
        /// - **400 Bad Request**: Missing or invalid refresh token.
        /// - **401 Unauthorized**: Refresh token is invalid or expired.
        /// - **500 Internal Server Error**: Issues during token processing.
        ///
        /// </remarks>
        /// <returns>
        /// A 200 OK response with a new JWT access token if successful.  
        /// Errors are returned with appropriate HTTP status codes.
        /// </returns>
        /// <response code="200">A new access token was successfully generated.</response>
        /// <response code="400">The refresh token is missing or invalid.</response>
        /// <response code="401">Unauthorized access due to an invalid or expired refresh token.</response>
        /// <response code="500">An unexpected error occurred.</response>
        [HttpPost("refresh")]
        [AllowAnonymous]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status400BadRequest)]
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status401Unauthorized)]
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status500InternalServerError)]
        public async Task<IResult> Refresh()
        {
            // Retrieve refresh token from cookies
            if (!HttpContext.Request.Cookies.TryGetValue("refreshToken", out var refreshToken))
            {
                return HandleFailure(Result.Failure(UserErrors.Token.MissingRefreshToken));
            }

            var userResult = await _userService.GetByRefreshToken(refreshToken);
            if (userResult.IsFailure)
            {
                return HandleFailure(userResult);
            }

            var user = userResult.Value;

            // Refresh token
            string newRefreshToken = _tokenService.GenerateRefreshToken();

            // Save refresh token
            var persistRefreshTokenResult = await _userService.PersistRefreshToken(user, newRefreshToken);
            if (persistRefreshTokenResult.IsFailure)
            {
                return HandleFailure(persistRefreshTokenResult);
            }

            // Store refresh token in httpOnly cookie
            HttpContext.Response.Cookies.Append("refreshToken", newRefreshToken, new CookieOptions
            {
                HttpOnly = true,
                Secure = false, // For production , HTTPS
                SameSite = SameSiteMode.None,
                Expires = DateTime.UtcNow.AddDays(_tokenSettings.RefreshToken.ExpiresInDays)
            });

            // User roles
            var rolesResult = await _userService.GetRolesAsync(user);

            // JWT
            string accessToken = _tokenService.CreateJwtToken(user, rolesResult.Value);

            return Results.Ok(new LoginResponse(
                    accessToken,
                    refreshToken,
                    new UserResponse(
                        user.Id,
                        user.FirstName,
                        user.LastName)));
        }

        /// <summary>
        /// Changes the password for the currently authenticated user.
        /// </summary>
        /// <remarks>
        /// **Endpoint Purpose:**  
        /// This endpoint allows authenticated users to change their password. The request requires a valid access token and provides the current password, new password, and confirmation of the new password.
        ///
        /// **How it Works:**
        /// - The request is validated using a request validator.
        /// - The user's identity is retrieved from the access token claims.
        /// - The current password is verified, and the new password is validated and set if valid.
        ///
        /// **Sample Request:**
        /// ```json
        /// {
        ///     "currentPassword": "currentPassword123",
        ///     "newPassword": "newPassword456",
        ///     "confirmNewPassword": "newPassword456"
        /// }
        /// ```
        ///
        /// **Sample Response for Success:**  
        /// Status 204 No Content (password changed successfully).
        ///
        /// **Possible Errors:**
        /// - **400 Bad Request**: Validation errors, such as mismatched passwords or missing fields.
        /// - **401 Unauthorized**: Invalid or expired access token.
        /// - **500 Internal Server Error**: Errors during password change processing.
        ///
        /// </remarks>
        /// <param name="request">The request payload containing the current password, new password, and confirmation of the new password.</param>
        /// <returns>
        /// A 204 No Content response on successful password change.
        /// </returns>
        /// <response code="204">Password was successfully changed.</response>
        /// <response code="400">The request was invalid, such as mismatched passwords or missing data.</response>
        /// <response code="401">Unauthorized access due to an invalid or expired token.</response>
        /// <response code="500">An unexpected error occurred while changing the password.</response>
        [HttpPut("change-password")]
        [Authorize]
        [ProducesResponseType(StatusCodes.Status204NoContent)]
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status400BadRequest)]
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status401Unauthorized)]
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status500InternalServerError)]
        public async Task<IResult> ChangePassword(ChangePasswordRequest request)
        {
            if (request is null)
            {
                throw new ArgumentNullException(nameof(request));
            }

            var validator = new ChangePasswordRequestValidator();
            var validationResult = ValidationHandler.Handle(validator.Validate(request));
            if (validationResult.IsFailure)
            {
                return HandleFailure(validationResult);
            }

            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            if(userId is null)
            {
                return HandleFailure(Result.Failure(UserErrors.Token.InvalidAccessToken));
            }

            var result = await _userService.ChangePasswordAsync(userId,request.CurrentPassowrd, request.NewPassword, request.ConfirmNewPassword);
            if(result.IsFailure)
            {
                return HandleFailure(result);
            }

            return Results.NoContent();
        }

        /// <summary>
        /// Requests a password reset for the specified user by sending a password reset email.
        /// </summary>
        /// <remarks>
        /// **Endpoint Purpose:**  
        /// This endpoint allows authenticated users to request a password reset by providing their email. The request generates a password reset token and sends it via email.
        ///
        /// **How it Works:**
        /// - The request is validated using a request validator.
        /// - The user's email is used to look up their record in the database.
        /// - A password reset token is generated and sent to the user via an email service.
        ///
        /// **Sample Request:**
        /// ```json
        /// {
        ///     "email": "user@example.com"
        /// }
        /// ```
        ///
        /// **Sample Response for Success:**  
        /// Status 204 No Content (password reset email sent successfully).
        ///
        /// **Possible Errors:**
        /// - **400 Bad Request**: Validation errors, such as invalid email format or missing email.
        /// - **401 Unauthorized**: The request is made without a valid authentication token.
        /// - **404 Not Found**: User with the provided email address does not exist.
        /// - **500 Internal Server Error**: Issues while generating the password reset token or sending the email.
        ///
        /// </remarks>
        /// <param name="request">The request payload containing the email for password reset.</param>
        /// <returns>
        /// A 204 No Content response indicating that the password reset email was sent successfully.
        /// </returns>
        /// <response code="204">Password reset email was successfully sent.</response>
        /// <response code="400">The request was invalid, such as validation errors.</response>
        /// <response code="401">Unauthorized access due to an invalid or expired token.</response>
        /// <response code="404">User not found for the provided email address.</response>
        /// <response code="500">An unexpected error occurred while processing the password reset request.</response>
        [HttpPost("forgot-password")]
        [Authorize]
        [ProducesResponseType(StatusCodes.Status204NoContent)]
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status400BadRequest)]
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status401Unauthorized)]
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status404NotFound)]
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status500InternalServerError)]
        public async Task<IResult> RequestPasswordReset([FromBody]ForgotPasswordRequest request)
        {
            if (request is null)
            {
                throw new ArgumentNullException(nameof(request));
            }

            var validator = new ForgotPasswordRequestValidator();
            var validationResult = ValidationHandler.Handle(validator.Validate(request));
            if (validationResult.IsFailure)
            {
                return HandleFailure(validationResult);
            }

            var userResult = await _userService.FindByEmailAsync(request.Email.ToLower());
            if (userResult.IsFailure)
            {
                return HandleFailure(userResult);
            }

            var user = userResult.Value;

            var tokenResult = await _userService.GeneratePasswordResetTokenAsync(user);
            if (tokenResult.IsFailure)
            {
                return HandleFailure(tokenResult);
            }

            var token = tokenResult.Value;

            var emailResult = await _emailService.SendPasswordResetEmailAsync(user, token);
            if(emailResult.IsFailure)
            {
                return HandleFailure(emailResult);
            }

            return Results.NoContent();
        }

        /// <summary>
        /// Resets the user's password using a provided token and new password.
        /// </summary>
        /// <remarks>
        /// **Endpoint Purpose:**  
        /// This endpoint allows authenticated users to reset their password using a valid token and a new password.
        ///
        /// **How it Works:**
        /// - The request must include the user's ID, the token for verification, and the new password.
        /// - The token is validated, and if valid, the password is reset.
        ///
        /// **Sample Request:**
        /// ```json
        /// {
        ///     "userId": "12345",
        ///     "token": "reset-token-value",
        ///     "newPassword": "NewPassword123!"
        /// }
        /// ```
        ///
        /// **Sample Response for Success:**  
        /// Status 204 No Content (password reset was successful).
        ///
        /// **Possible Errors:**
        /// - **400 Bad Request**: Validation errors, such as an invalid or expired token, or weak password format.
        /// - **401 Unauthorized**: The request is made without a valid authentication token.
        /// - **404 Not Found**: User not found for the provided user ID.
        /// - **500 Internal Server Error**: Issues while processing the password reset.
        ///
        /// </remarks>
        /// <param name="request">The request payload containing the user ID, token, and new password.</param>
        /// <returns>
        /// A 204 No Content response indicating that the password was successfully reset.
        /// </returns>
        /// <response code="204">Password was successfully reset.</response>
        /// <response code="400">The request was invalid, such as validation errors or token issues.</response>
        /// <response code="401">Unauthorized access due to an invalid or expired token.</response>
        /// <response code="404">User not found for the provided user ID.</response>
        /// <response code="500">An unexpected error occurred while resetting the password.</response>
        [HttpPut("reset-password")]
        [Authorize]
        [ProducesResponseType(StatusCodes.Status204NoContent)]
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status400BadRequest)]
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status401Unauthorized)]
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status404NotFound)]
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status500InternalServerError)]
        public async Task<IResult> ResetPassword([FromBody]ResetPasswordRequest request)
        {
            var result = await _userService.ResetPasswordAsync(request.UserId, request.Token, request.NewPassword);
            if (result.IsFailure)
            {
                return HandleFailure(result);
            }

            return Results.NoContent();
        }

        /// <summary>
        /// Updates the user's profile information, such as first name, last name, and phone number.
        /// </summary>
        /// <remarks>
        /// **Endpoint Purpose:**  
        /// This endpoint allows an authenticated user to update their profile details, including first name, last name, and phone number.
        ///
        /// **How it Works:**
        /// - The request must include the user's updated profile information.
        /// - The request is validated before proceeding to update the details in the database.
        /// - The update is performed only if the user is authenticated and authorized.
        ///
        /// **Sample Request:**
        /// ```json
        /// {
        ///     "firstName": "John",
        ///     "lastName": "Doe",
        ///     "phoneNumber": "123-456-7890"
        /// }
        /// ```
        ///
        /// **Sample Response for Success:**  
        /// Status 204 No Content (user information was successfully updated).
        ///
        /// **Possible Errors:**
        /// - **400 Bad Request**: Validation errors with the request payload.
        /// - **401 Unauthorized**: The request is made without a valid authentication token.
        /// - **404 Not Found**: User not found for the provided user ID.
        /// - **500 Internal Server Error**: Issues while updating user information.
        ///
        /// </remarks>
        /// <param name="request">The request payload containing the user's new profile information.</param>
        /// <returns>
        /// A 204 No Content response indicating that the profile update was successful.
        /// </returns>
        /// <response code="204">User profile updated successfully.</response>
        /// <response code="400">Invalid request or validation errors.</response>
        /// <response code="401">Unauthorized access due to an invalid or expired token.</response>
        /// <response code="404">User not found for the provided user ID.</response>
        /// <response code="500">An unexpected error occurred while updating the profile.</response>
        [HttpPut("update")]
        [Authorize]
        [ProducesResponseType(StatusCodes.Status204NoContent)]
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status400BadRequest)]
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status401Unauthorized)]
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status404NotFound)]
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status500InternalServerError)]
        public async Task<IResult> UpdateUser(UpdateUserRequest request)
        {
            if (request is null)
            {
                throw new ArgumentNullException(nameof(request));
            }

            var validator = new UpdateUserRequestValidator();
            var validationResult = ValidationHandler.Handle(validator.Validate(request));
            if (validationResult.IsFailure)
            {
                return HandleFailure(validationResult);
            }

            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            if(userId == null)
            {
                return HandleFailure(Result.Failure(UserErrors.Token.InvalidAccessToken));
            }

            var result = await _userService.UpdateUserAsync(
                userId, 
                request.FirstName.ToLower(), 
                request.LastName.ToLower(), 
                request.PhoneNumber,
                request.DateOfBirth);

            if (result.IsFailure)
            {
                return HandleFailure(result);
            }

            return Results.NoContent();
        }

        /// <summary>
        /// Requests an email change for the authenticated user by generating a token and sending a confirmation email.
        /// </summary>
        /// <remarks>
        /// **Endpoint Purpose:**  
        /// This endpoint allows an authenticated user to request an email change. It validates the request, generates a token for email change, 
        /// and sends an email to the user with instructions to complete the change.
        ///
        /// **How it Works:**
        /// - The user must be authenticated and provide their current password to authorize the email change.
        /// - The request is validated before proceeding.
        /// - A token is generated and sent to the user's new email address.
        /// - The current account is deactivated until the new email is verified.
        ///
        /// **Sample Request:**
        /// ```json
        /// {
        ///     "newEmail": "new.email@example.com",
        ///     "password": "CurrentPassword123"
        /// }
        /// ```
        /// </remarks>
        /// <param name="request">The request payload containing the new email and user password for verification.</param>
        /// <returns>
        /// A 204 No Content response indicating that the email change request was successful.
        /// </returns>
        /// <response code="204">Email change request processed successfully.</response>
        /// <response code="400">Validation errors in the request payload.</response>
        /// <response code="401">Unauthorized due to an invalid or expired token.</response>
        /// <response code="404">User not found for the provided user ID.</response>
        /// <response code="500">An unexpected error occurred while processing the request.</response>
        [HttpPut("request-email-change")]
        [Authorize]
        [ProducesResponseType(StatusCodes.Status204NoContent)]
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status400BadRequest)]
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status401Unauthorized)]
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status404NotFound)]
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status500InternalServerError)]
        public async Task<IResult> RequestEmailChange(ChangeEmailRequest request)
        {
            if (request is null)
            {
                throw new ArgumentNullException(nameof(request));
            }

            var validator = new ChangeEmailRequestValidator();
            var validationResult = ValidationHandler.Handle(validator.Validate(request));
            if (validationResult.IsFailure)
            {
                return HandleFailure(validationResult);
            }

            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (userId == null)
            {
                return HandleFailure(Result.Failure(UserErrors.Token.InvalidAccessToken));
            }

            var userResult = await _userService.FindByIdAsync(userId);
            if (userResult.IsFailure)
            {
                return HandleFailure(userResult);
            }

            var user = userResult.Value;

            var tokenResult = await _userService.GenerateChangeEmailTokenAsync(userId, request.NewEmail, request.Password);
            if(tokenResult.IsFailure)
            {
                return HandleFailure(tokenResult);
            }

            var token = tokenResult.Value;

            var emailResult = await _emailService.SendEmailChangeEmailAsync(user, token, request.NewEmail);
            if (emailResult.IsFailure)
            {
                return HandleFailure(emailResult);
            }

            var deactivateResult = await _userService.DeactivateAccountAsync(userId);
            if (deactivateResult.IsFailure)
            {
                return HandleFailure(deactivateResult);
            }

            return Results.NoContent();
        }

        /// <summary>
        /// Confirms an email change request by verifying the token and updating the user's email.
        /// </summary>
        /// <remarks>
        /// This endpoint accepts a user ID, the new email, and a token as query parameters. It validates the token and updates the user's email if the token is valid.
        ///
        /// **Sample Request:**
        /// ```
        /// PUT /api/user/confirm-email-change?userId=123&amp;newEmail=new.email@example.com&amp;token=abcdef1234
        /// ```
        /// </remarks>
        /// <param name="userId">The ID of the user whose email is being changed.</param>
        /// <param name="newEmail">The new email address the user wants to change to.</param>
        /// <param name="token">The token for verifying the email change request.</param>
        /// <returns>
        /// A 204 No Content response indicating that the email change was successful.
        /// </returns>
        /// <response code="204">Email change confirmed successfully.</response>
        /// <response code="400">Invalid token or request parameters.</response>
        /// <response code="404">User not found.</response>
        /// <response code="500">An unexpected error occurred while processing the request.</response>
        [HttpPut("confirm-email-change")]
        [AllowAnonymous]
        [ProducesResponseType(StatusCodes.Status204NoContent)]
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status400BadRequest)]
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status404NotFound)]
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status500InternalServerError)]
        public async Task<IResult> ConfirmEmailChange([FromQuery] string userId, [FromQuery] string newEmail, [FromQuery] string token)
        {
            var result = await _userService.ChangeEmailAsync(userId, newEmail.ToLower(), token);
            if (result.IsFailure)
            {
                return HandleFailure(result);
            }

            return Results.NoContent();
        }

        //[HttpPost]
        //[Authorize(Roles = "Admin")]
        //public async Task<IActionResult> CreateUser([FromBody] CreateUserRequest request)
        //{
        //    if (await _userManager.FindByEmailAsync(request.Email) != null)
        //    {
        //        return BadRequest($"A user with email {request.Email}, already exists.");
        //    }

        //    var user = new User
        //    {
        //        UserName = request.Email,
        //        Email = request.Email,
        //        FirstName = request.FirstName,
        //        LastName = request.LastName,
        //    };

        //    var result = await _userManager.CreateAsync(user, request.Password);
        //    if (!result.Succeeded)
        //    {
        //        return BadRequest(result.Errors);
        //    }

        //    if (!string.IsNullOrEmpty(request.Role) && await _roleManager.RoleExistsAsync(request.Role))
        //    {
        //        await _userManager.AddToRoleAsync(user, request.Role);
        //    }

        //    return Ok("User created successfully.");
        //}

        /**
         * Helpers
         */
        private IResult HandleFailure(Result result) =>
            result switch
            {
                { IsSuccess: true } => throw new InvalidOperationException(),

                { Error: { Code: "ValidationError" } } =>
                Results.BadRequest(ResultCreationHandler.CreateProblemDetails(
                    "Validation Errors",
                    StatusCodes.Status400BadRequest,
                    result.Error,
                    result.Error.SubErrors.ToArray())),

                { Error: { Code: "IdentityError" } } =>
                Results.BadRequest(ResultCreationHandler.CreateProblemDetails(
                    "Validation Errors",
                    StatusCodes.Status400BadRequest,
                    result.Error,
                    result.Error.SubErrors.ToArray())),

                { Error: { Code: "EmailAlreadyExists" } } =>
                Results.Problem(ResultCreationHandler.CreateProblemDetails(
                    "Email Already Exists",
                    StatusCodes.Status409Conflict,
                    result.Error)),

                { Error: { Code: "UserNotFound" } } =>
                Results.NotFound(ResultCreationHandler.CreateProblemDetails(
                    "User Not Found",
                    StatusCodes.Status404NotFound,
                    result.Error)),

                { Error: { Code: "EmailAlreadyConfirmed" } } =>
                Results.Problem(ResultCreationHandler.CreateProblemDetails(
                    "Email Already Confirmed",
                    StatusCodes.Status409Conflict,
                    result.Error)),
                
                { Error: { Code: "EmailNotConfirmed" } } =>
                Results.Problem(ResultCreationHandler.CreateProblemDetails(
                    "Email Not Confirmed",
                    StatusCodes.Status401Unauthorized,
                    result.Error)),

                { Error: { Code: "InvalidCredentials" } } =>
                Results.BadRequest(ResultCreationHandler.CreateProblemDetails(
                    "Invalid Credentials",
                    StatusCodes.Status400BadRequest,
                    result.Error)),

                { Error: { Code: "MissingRefreshToken" } } =>
                Results.Problem(ResultCreationHandler.CreateProblemDetails(
                    "User Validation Error",
                    StatusCodes.Status400BadRequest,
                    result.Error)),

                { Error: { Code: "InvalidRefreshToken" } } =>
                Results.Problem(ResultCreationHandler.CreateProblemDetails(
                    "User Validation Error",
                    StatusCodes.Status400BadRequest,
                    result.Error)),

                { Error: { Code: "PasswordMismatch" } } =>
                Results.BadRequest(ResultCreationHandler.CreateProblemDetails(
                    "Password Mismatch",
                    StatusCodes.Status400BadRequest,
                    result.Error)),
                
                { Error: { Code: "InvalidAccessToken" } } =>
                Results.Problem(ResultCreationHandler.CreateProblemDetails(
                    "Invalid Access Token",
                    StatusCodes.Status401Unauthorized,
                    result.Error)),
                
                { Error: { Code: "InvalidPassword" } } =>
                Results.BadRequest(ResultCreationHandler.CreateProblemDetails(
                    "Invalid Password",
                    StatusCodes.Status400BadRequest,
                    result.Error)),

                _ => Results.Problem(ResultCreationHandler.CreateProblemDetails(
                    "Internal server error",
                    StatusCodes.Status500InternalServerError,
                    result.Error))
            };

    }
}
