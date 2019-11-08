using System;
using System.IO;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace HmacAuthentication.Hmac
{
    internal class HmacAuthenticationHandler : AuthenticationHandler<HmacAuthenticationSchemeOptions>
    {
        private readonly IMemoryCache _memoryCache = new MemoryCache(new MemoryCacheOptions());

        public HmacAuthenticationHandler(IOptionsMonitor<HmacAuthenticationSchemeOptions> options, ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock)
            : base(options, logger, encoder, clock)
        {
        }

        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            if (!Request.Headers.TryGetValue("Authorization", out _))
            {
                return AuthenticateResult.Fail("Missing 'Authorization' header.");
            }

            var valid = await ValidateAsync(Request);

            if (!valid)
            {
                return AuthenticateResult.Fail("Authentication failed");
            }

            var principal = new ClaimsPrincipal(new ClaimsIdentity(HmacAuthenticationDefaults.AuthenticationType));
            var ticket = new AuthenticationTicket(principal, new AuthenticationProperties(), Options.AuthenticationScheme);
            return AuthenticateResult.Success(ticket);

        }

        private async Task<bool> ValidateAsync(HttpRequest request)
        {
            if (!Request.Headers.TryGetValue("Authorization", out var header))
            {
                return false;
            }

            var authenticationHeader = AuthenticationHeaderValue.Parse(header);

            if (!Options.AuthenticationScheme.Equals(authenticationHeader.Scheme, StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            var rawAuthenticationHeader = authenticationHeader.Parameter;
            var authenticationHeaderArray = GetAuthenticationValues(rawAuthenticationHeader);

            if (authenticationHeaderArray == null)
            {
                return false;
            }

            var appId = authenticationHeaderArray[0];
            var incomingBase64Signature = authenticationHeaderArray[1];
            var nonce = authenticationHeaderArray[2];
            var requestTimeStamp = authenticationHeaderArray[3];

            // Note that we must not dispose the memoryStream here, because the stream is needed in subsequent handlers
            var memoryStream = new MemoryStream();

            await Request.Body.CopyToAsync(memoryStream);
            Request.Body = memoryStream;

            try
            {
                return IsValidRequest(request, memoryStream.ToArray(), appId, incomingBase64Signature, nonce, requestTimeStamp);
            }
            finally
            {
                // We need to reset the stream so that subsequent handlers have a fresh stream which they can consume.
                memoryStream.Seek(0, SeekOrigin.Begin);
            }
        }

        private bool IsValidRequest(HttpRequest req, byte[] body, string appId, string incomingBase64Signature, string nonce, string requestTimeStamp)
        {
            var requestContentBase64String = string.Empty;
            var absoluteUri = string.Concat(
                        req.Scheme,
                        "://",
                        req.Host.ToUriComponent(),
                        req.PathBase.ToUriComponent(),
                        req.Path.ToUriComponent(),
                        req.QueryString.ToUriComponent());
            var requestUri = WebUtility.UrlEncode(absoluteUri.ToLower());
            var requestHttpMethod = req.Method;

            if (!Options.HmacAuthenticatedApps.TryGetValue(appId, out var apiKey))
            {
                return false;
            }

            if (IsReplayRequest(nonce, requestTimeStamp))
            {
                return false;
            }

            var hash = ComputeHash(body);

            if (hash != null)
            {
                requestContentBase64String = Convert.ToBase64String(hash);
            }

            var data = $"{appId}{requestHttpMethod}{requestUri}{requestTimeStamp}{nonce}{requestContentBase64String}";

            var apiKeyBytes = Convert.FromBase64String(apiKey);

            var signature = Encoding.UTF8.GetBytes(data);

            using (var hmac = new HMACSHA256(apiKeyBytes))
            {
                var signatureBytes = hmac.ComputeHash(signature);

                return incomingBase64Signature.Equals(Convert.ToBase64String(signatureBytes), StringComparison.Ordinal);
            }
        }

        private static string[] GetAuthenticationValues(string rawAuthenticationHeader)
        {
            var credArray = rawAuthenticationHeader.Split(':');
            return credArray.Length == 4 ? credArray : null;
        }

        private bool IsReplayRequest(string nonce, string requestTimeStamp)
        {
            var nonceInMemory = _memoryCache.Get(nonce);
            if (nonceInMemory != null)
            {
                return true;
            }

            var epochStart = new DateTime(1970, 01, 01, 0, 0, 0, 0, DateTimeKind.Utc);
            var currentTs = DateTime.UtcNow - epochStart;

            var serverTotalSeconds = Convert.ToInt64(currentTs.TotalSeconds);
            var requestTotalSeconds = Convert.ToInt64(requestTimeStamp);
            var diff = Math.Abs(serverTotalSeconds - requestTotalSeconds);

            if (diff > Options.MaxRequestAgeInSeconds)
            {
                return true;
            }

            _memoryCache.Set(nonce, requestTimeStamp, DateTimeOffset.UtcNow.AddSeconds(Options.MaxRequestAgeInSeconds));
            return false;
        }

        private static byte[] ComputeHash(byte[] body)
        {
            using (var md5 = MD5.Create())
            {
                byte[] hash = null;
                if (body.Length != 0)
                {
                    hash = md5.ComputeHash(body);
                }

                return hash;
            }
        }
    }
}
