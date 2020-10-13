using Microsoft.AspNetCore.Authentication;

namespace WebApiTwitchAuth.Authorization
{
    public class TwitchAuthenticationOptions : AuthenticationSchemeOptions
    {
        public string ClientId { get; set; }
        public string UserInformationEndpoint { get; set; } = "https://id.twitch.tv/oauth2/userinfo";

        public string TokenValidationEndpoint { get; set; } = "https://id.twitch.tv/oauth2/validate";

        public bool ValidateAudience { get; set; }
        public string ValidAudience { get; set; }

        public bool ValidateIssuer { get; set; } = true;
        public string ValidIssuer { get; set; } = "https://id.twitch.tv/oauth2";
    }
}
