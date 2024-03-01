using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Principal;
using System.Text.Encodings.Web;
using System.Text.Json;

namespace WeatherAsssistant
{
    public static class OAuth2ProxyDefaults
    {
        public const string AuthenticationScheme = "x-forwarded-access-token";
    }

    public class OAuth2ProxyOptions : AuthenticationSchemeOptions
    {
        public Func<JwtSecurityToken, ClaimsIdentity, ClaimsIdentity> HandleClaimsIdentity { get; set; }
    }

    public class KeycloakConfiguration
    {
        public string Resource { get; set; }
    }

    public class KeycloakOAuth2ProxyOptions : OAuth2ProxyOptions
    {
        public KeycloakConfiguration Configuration { get; set; }

        public KeycloakOAuth2ProxyOptions(KeycloakConfiguration configuration)
        {
            Configuration = configuration;
            HandleClaimsIdentity = (jwtToken, claimsIdentity) =>
            {
                var resourceAccessClaim = jwtToken.Claims.FirstOrDefault(c => c.Type == "resource_access")?.Value;
                if (resourceAccessClaim != null)
                {
                    var resourceAccessData = JsonSerializer.Deserialize<Dictionary<string, object>>(resourceAccessClaim);
                    if (resourceAccessData != null && resourceAccessData.TryGetValue(Configuration.Resource, out var resourceData))
                    {
                        var expressMiddlewareDict = JsonSerializer.Deserialize<Dictionary<string, object>>(resourceData.ToString());
                        if (expressMiddlewareDict != null && expressMiddlewareDict.TryGetValue("roles", out var roles))
                        {
                            var parsedRoles = JsonSerializer.Deserialize<List<string>>(roles.ToString());
                            if (parsedRoles != null)
                            {
                                foreach (var role in parsedRoles)
                                {
                                    claimsIdentity.AddClaim(new Claim(ClaimTypes.Role, role));
                                }
                            }
                        }
                    }
                }
                return claimsIdentity;
            };
        }
    }

    public class OAuth2ProxyAuthenticationHandler : AuthenticationHandler<OAuth2ProxyOptions>
    {
        public OAuth2ProxyAuthenticationHandler(
            IOptionsMonitor<OAuth2ProxyOptions> options,
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

                if (Options.HandleClaimsIdentity != null)
                {
                    identity = Options.HandleClaimsIdentity.Invoke(jwtToken, identity);
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

    public static class OAuth2ProxyAuthExtenstions
    {
        public static AuthenticationBuilder AddOAuth2ProxyAuthentication(this IServiceCollection services, Action<OAuth2ProxyOptions>? configureOptions)
        {
            return services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = OAuth2ProxyDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = OAuth2ProxyDefaults.AuthenticationScheme;
            }).AddScheme<OAuth2ProxyOptions, OAuth2ProxyAuthenticationHandler>(OAuth2ProxyDefaults.AuthenticationScheme, options =>
            {
                if (configureOptions != null)
                    configureOptions(options);
            });
        }

        public static AuthenticationBuilder AddKeycloakOAuth2ProxyAuthentication(this IServiceCollection services,
            ConfigurationManager configuration)
        {
            var keycloakConfiguration = configuration.GetSection("Keycloak").Get<KeycloakConfiguration>();
            ArgumentNullException.ThrowIfNull(keycloakConfiguration);
            var keycloakOptions = new KeycloakOAuth2ProxyOptions(keycloakConfiguration);
            return services.AddOAuth2ProxyAuthentication(options =>
            {
                options.HandleClaimsIdentity = keycloakOptions.HandleClaimsIdentity;
            });
        }
    }
}
