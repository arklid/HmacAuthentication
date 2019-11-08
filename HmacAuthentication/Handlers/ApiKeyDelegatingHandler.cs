using System;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace HmacAuthentication.Handlers
{
    public class ApiKeyDelegatingHandler : DelegatingHandler
    {
        private readonly string _appId;
        private readonly string _apiKey;

        public ApiKeyDelegatingHandler(string appId, string apiKey)
        {
            _appId = !string.IsNullOrWhiteSpace(appId) ? appId : throw new ArgumentNullException(nameof(appId));
            _apiKey = !string.IsNullOrWhiteSpace(apiKey) ? apiKey : throw new ArgumentNullException(nameof(apiKey));

            try
            {
                Convert.FromBase64String(_apiKey);
            }
            catch (FormatException)
            {
                throw new ArgumentException($"{nameof(apiKey)} must be a valid base64 string.");
            }
        }

        public ApiKeyDelegatingHandler(string appId, string apiKey, HttpMessageHandler innerHandler)
            : base(innerHandler)
        {
            this._appId = appId ?? throw new ArgumentNullException(nameof(appId));
            this._apiKey = apiKey ?? throw new ArgumentNullException(nameof(apiKey));
        }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var requestContentBase64String = string.Empty;

            var requestUri = WebUtility.UrlEncode(request.RequestUri.AbsoluteUri.ToLower());

            var requestHttpMethod = request.Method.Method;

            // Calculate UNIX time
            var epochStart = new DateTime(1970, 01, 01, 0, 0, 0, 0, DateTimeKind.Utc);
            var timeSpan = DateTime.UtcNow - epochStart;
            var requestTimeStamp = Convert.ToUInt64(timeSpan.TotalSeconds).ToString();

            // Create random nonce for each request
            var nonce = Guid.NewGuid().ToString("N");

            // Checking if the request contains body, usually will be null with HTTP GET and DELETE
            if (request.Content != null)
            {
                var content = await request.Content.ReadAsByteArrayAsync();
                var md5 = MD5.Create();

                // Hashing the request body, any change in request body will result in different hash, we'll secure message integrity
                var requestContentHash = md5.ComputeHash(content);
                requestContentBase64String = Convert.ToBase64String(requestContentHash);
            }

            // Creating the raw signature string
            var signatureRawData = $"{_appId}{requestHttpMethod}{requestUri}{requestTimeStamp}{nonce}{requestContentBase64String}";

            var apiKeyBytes = Convert.FromBase64String(_apiKey);
            var signature = Encoding.UTF8.GetBytes(signatureRawData);

            using (var hmac = new HMACSHA256(apiKeyBytes))
            {
                var signatureBytes = hmac.ComputeHash(signature);
                var requestSignatureBase64String = Convert.ToBase64String(signatureBytes);

                // Setting the values in the Authorization header using custom scheme (Hmac)
                request.Headers.Authorization = new AuthenticationHeaderValue(
                    "Hmac",
                    $"{_appId}:{requestSignatureBase64String}:{nonce}:{requestTimeStamp}");
            }

            var response = await base.SendAsync(request, cancellationToken);

            return response;
        }
    }
}
