using System.Collections.Generic;
using Microsoft.AspNetCore.Authentication;

namespace HmacAuthentication.Hmac
{
    public class HmacAuthenticationSchemeOptions : AuthenticationSchemeOptions
    {
        public long MaxRequestAgeInSeconds { get; set; }

        public string AuthenticationScheme { get; set; }

        public IDictionary<string, string> HmacAuthenticatedApps { get; set; } = new Dictionary<string, string>();

        public HmacAuthenticationSchemeOptions()
        {
            MaxRequestAgeInSeconds = HmacAuthenticationDefaults.MaxRequestAgeInSeconds;
            AuthenticationScheme = HmacAuthenticationDefaults.AuthenticationScheme;
        }
    }
}
