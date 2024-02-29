using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Text.Json;

namespace WeatherAsssistant
{
    public class CustomAuthenticationHandler : AuthenticationHandler<AuthenticationSchemeOptions>
    {
        public CustomAuthenticationHandler(
            IOptionsMonitor<AuthenticationSchemeOptions> options,
            ILoggerFactory logger,
            UrlEncoder encoder) : base(options, logger, encoder)
        {

        }

        protected override Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            // Try to get the token from the header
            if (!Request.Headers.TryGetValue("x-forwarded-access-token", out var token))
            {
                return Task.FromResult(AuthenticateResult.Fail("Header Not Found."));
            }

            try
            {
                // Attempt to decode the JWT token
                var tokenHandler = new JwtSecurityTokenHandler();
                var jwtToken = tokenHandler.ReadJwtToken(token);
                var claims = jwtToken.Claims.Select(claim => new Claim(claim.Type, claim.Value)).ToList();

                var identity = new ClaimsIdentity(claims, Scheme.Name);

                var resourceAccessClaim = jwtToken.Claims.FirstOrDefault(c => c.Type == "resource_access")?.Value;
                if (resourceAccessClaim != null)
                {
                    var resourceAccessData = JsonSerializer.Deserialize<Dictionary<string, object>>(resourceAccessClaim);
                    if (resourceAccessData != null && resourceAccessData.TryGetValue("express-middleware", out var expressMiddlewareData))
                    {
                        var expressMiddlewareDict = JsonSerializer.Deserialize<Dictionary<string, object>>(expressMiddlewareData.ToString());
                        if (expressMiddlewareDict != null && expressMiddlewareDict.TryGetValue("roles", out var roles))
                        {
                            var parsedRoles = JsonSerializer.Deserialize<List<string>>(roles.ToString());
                            if (parsedRoles != null)
                            {
                                foreach (var role in parsedRoles)
                                {
                                    identity.AddClaim(new Claim(ClaimTypes.Role, role));
                                }
                            }
                        }
                    }
                }

                var principal = new ClaimsPrincipal(identity);
                var ticket = new AuthenticationTicket(principal, Scheme.Name);
                return Task.FromResult(AuthenticateResult.Success(ticket));
            }
            catch
            {
                return Task.FromResult(AuthenticateResult.Fail("Invalid Token."));
            }
        }
    }
}
