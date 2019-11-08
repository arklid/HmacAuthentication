using System;
using Microsoft.AspNetCore.Authentication;

namespace HmacAuthentication.Hmac
{
    public static class HmacAuthenticationExtensions
    {
        public static AuthenticationBuilder AddHmacAuthentication(
            this AuthenticationBuilder builder,
            string authenticationScheme,
            string displayName,
            Action<HmacAuthenticationSchemeOptions> configureOptions)
        {
            return builder.AddScheme<HmacAuthenticationSchemeOptions, HmacAuthenticationHandler>(authenticationScheme, displayName, configureOptions);
        }
    }
}
