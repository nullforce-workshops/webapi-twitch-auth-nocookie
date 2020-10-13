using System.Text.Json.Serialization;

namespace WebApiTwitchAuth.Authorization
{
    public class TwitchGetUserInfoResponse
    {
        [JsonPropertyName("aud")]
        public string Audience { get; set; }

        [JsonPropertyName("exp")]
        public long Expiration { get; set; }

        [JsonPropertyName("iat")]
        public long IssuedAt { get; set; }

        [JsonPropertyName("iss")]
        public string Issuer { get; set; }

        [JsonPropertyName("sub")]
        public string UserId { get; set; }

        [JsonPropertyName("azp")]
        public string AuthorizedParty { get; set; }

        [JsonPropertyName("preferred_username")]
        public string PreferredUsername { get; set; }
    }
}
