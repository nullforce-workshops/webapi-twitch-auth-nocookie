using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Security.Principal;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Threading.Tasks;

namespace WebApiTwitchAuth.Authorization
{
    public class TwitchAuthenticationHandler : AuthenticationHandler<TwitchAuthenticationOptions>
    {
        private readonly IHttpClientFactory _clientFactory;

        public TwitchAuthenticationHandler(
            IOptionsMonitor<TwitchAuthenticationOptions> options,
            ILoggerFactory logger,
            UrlEncoder encoder,
            ISystemClock clock,
            IHttpClientFactory clientFactory)
            : base(options, logger, encoder, clock)
        {
            _clientFactory = clientFactory;
        }

        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            // If there's no Authorization header fail
            if (!Request.Headers.ContainsKey("Authorization"))
            {
                return AuthenticateResult.Fail("Unauthorized");
            }

            string authorizationHeader = Request.Headers["Authorization"];

            if (string.IsNullOrEmpty(authorizationHeader))
            {
                return AuthenticateResult.NoResult();
            }

            // The Authorization header value should start with Bearer
            if (!authorizationHeader.StartsWith("bearer", StringComparison.OrdinalIgnoreCase))
            {
                return AuthenticateResult.Fail("Unauthorized");
            }

            // Get the token portion of the Authorization header value
            var token = authorizationHeader.Substring("bearer".Length).Trim();

            if (string.IsNullOrEmpty(token))
            {
                return AuthenticateResult.Fail("Unauthorized");
            }

            try
            {
                return await ValidateToken(token);
            }
            catch (Exception ex)
            {
                return AuthenticateResult.Fail(ex.Message);
            }
        }

        private async Task<AuthenticateResult> ValidateToken(string token)
        {
            // Validate the token with Twitch via User Information Endpoint
            using var request = new HttpRequestMessage(HttpMethod.Get, Options.UserInformationEndpoint);
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

            // Don't actually need the ClientId
            //request.Headers.Add("Client-ID", Options.ClientId);

            var client = _clientFactory.CreateClient();
            var response = await client.SendAsync(request);

            if (!response.IsSuccessStatusCode)
            {
                Logger.LogError(
                    "An error occurred while retrieving the user profile: the remote server " +
                    "returned a {Status} response with the following payload: {Header} {Body}.",
                    response.StatusCode,
                    response.Headers.ToString(),
                    await response.Content.ReadAsStringAsync());

                throw new HttpRequestException("An error occurred while retrieving the user profile.");
            }

            var userinfo = await JsonSerializer.DeserializeAsync<TwitchGetUserInfoResponse>(await response.Content.ReadAsStreamAsync());
            var audience = userinfo.Audience;
            var issuer = userinfo.Issuer;

            if (Options.ValidateAudience && Options.ValidAudience != audience)
            {
                return AuthenticateResult.Fail("Unauthorized");
            }

            if (Options.ValidateIssuer && Options.ValidIssuer != issuer)
            {
                return AuthenticateResult.Fail("Unauthorized");
            }

            var userid = userinfo.UserId;
            var username = userinfo.PreferredUsername;

            // Get token scopes with Twitch via the Token Validation Endpoint
            using var tokenValidationRequest = new HttpRequestMessage(HttpMethod.Get, Options.TokenValidationEndpoint);
            tokenValidationRequest.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            tokenValidationRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

            var tokenValidationResponse = await client.SendAsync(tokenValidationRequest);

            var scopes = new string[] { };

            if (tokenValidationResponse.IsSuccessStatusCode)
            {
                var tokeninfo = await JsonSerializer.DeserializeAsync<TwitchValidationResponse>(
                    await tokenValidationResponse.Content.ReadAsStreamAsync());
                scopes = tokeninfo.Scopes;
            }

            // Extract the UserInfo from the Twitch UserInformation endpoint and create a principal
            var claims = new List<Claim>()
            {
                new Claim(ClaimTypes.Name, username),
                new Claim(ClaimTypes.NameIdentifier, userid),
            };

            claims.AddRange(scopes.Select(s => new Claim("TwitchScope", s)));

            var identity = new ClaimsIdentity(claims, Scheme.Name);
            var principal = new GenericPrincipal(identity, null);
            var ticket = new AuthenticationTicket(principal, Scheme.Name);

            return AuthenticateResult.Success(ticket);
        }
    }
}
