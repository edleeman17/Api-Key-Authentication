using System;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;

namespace ApiKeyAuthentication.Authentication
{
    public class ApiKeyAuthenticationHandler : AuthenticationHandler<ApiKeyAuthenticationOptions>
    {
        public ApiKeyAuthenticationHandler(IOptionsMonitor<ApiKeyAuthenticationOptions> options, ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock) : base(options, logger, encoder, clock) { }

        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            if (!Request.Headers.TryGetValue("X-API-KEY", out var apiKeyHeaderValue)) return AuthenticateResult.Fail("Authorisation Failure.");

            var allowedKeys = new [] { "my-valid-api-key-value" };

            if (!allowedKeys.Any(k => k.Equals(apiKeyHeaderValue)))
            {
                return AuthenticateResult.Fail("Authorisation Failure.");
            }

            var identity = new ClaimsIdentity( new[]{ new Claim(ClaimTypes.Name, Guid.NewGuid().ToString()) }, Scheme.Name);
            var principal = new System.Security.Principal.GenericPrincipal(identity, null);

            await Task.Yield();

            return AuthenticateResult.Success(new AuthenticationTicket(principal, ApiKeyAuthenticationOptions.Scheme));
        }

        protected override async Task HandleChallengeAsync(AuthenticationProperties properties)
        {
            Response.StatusCode = 401;
            Response.ContentType = "application/problem+json";
            var problemDetails = new UnauthorisedProblemDetails();

            await Response.WriteAsync(JsonSerializer.Serialize(problemDetails));
        }
    }
}

