# HmacAuthentication
Hash-based message authentication code (HMAC) is a mechanism for calculating a message authentication code involving a hash function in combination with a secret key. This can be used to verify the integrity and authenticity of a a message.

This implementation is highly influenced by the main authentication method used by Amazon Web Services as it is very well understood, and there are a number of libraries which implement it. To use this form of authentication you utilise a key identifier and a secret key, with both of these typically generated in an admin interface.

**HmacAuthentication** provides an [`AuthenticationHandler`](https://docs.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.authentication.authenticationhandler-1?view=aspnetcore-2.1) which supports [HMAC](https://en.wikipedia.org/wiki/HMAC) authentication in an ASP.NET Core project.

Usage:

1. Get your HMAC authenticated clients, for example from the `appsettings.json` file. For HMAC authentication, an `AppId` and an `ApiKey` is required for each client which should get access.

```csharp
var hmacAuthenticatedApps = this.Configuration
    .GetSection("Authentication")
    .GetSection("HmacAuthenticatedApps")
    .Get<HmacAuthenticationClientConfiguration[]>()
    .ToDictionary(e => e.AppId, e => e.ApiKey);
```

```json
{
  "Authentication": {
    "HmacAuthenticatedApps": [
        {
            "AppId": "<some-app-id>",
            "ApiKey": "<some-api-key>"
        }
    ]
  }
}
```

2. Enable HMAC authentication in `Startup.cs` in the `ConfigureServices` method:

```csharp
services
    .AddAuthentication(o =>
    {
        o.DefaultScheme = HmacAuthenticationDefaults.AuthenticationScheme;
    })
    .AddHmacAuthentication(HmacAuthenticationDefaults.AuthenticationScheme, "HMAC Authentication", o =>
    {
        o.MaxRequestAgeInSeconds = HmacAuthenticationDefaults.MaxRequestAgeInSeconds;
        o.HmacAuthenticatedApps = hmacAuthenticatedApps;
    });
```

3. Add `MemoryCache` (from [Microsoft.Extensions.Caching.Memory](https://www.nuget.org/packages/Microsoft.Extensions.Caching.Memory/)) in `Startup.cs` in the `ConfigureServices` method.
The `MemoryCache` is used by the HMAC `AuthenticationHandler` to determine replay attacks.

```csharp
services.AddMemoryCache();
```

4. Enable authentication in `Startup.cs` in the `Configure` method:

```csharp
app.UseAuthentication();
```

5. Optional: Specify HMAC as the authentication scheme for certain controllers:

```csharp
[Authorize(AuthenticationSchemes = HmacAuthenticationDefaults.AuthenticationScheme)]
[Route("api/[controller]")]
public class HomeController : Controller
{
   // ...
}
```

**HmacAuthenticaion** also provides a `DelegatingHandler` for adding an HMAC authorization header to HTTP requests.

Instantiate your `HttpClient` instance with the `ApiKeyDelegatingHandler`.
Make sure, that you don't create new `HttpClient` instances for every request (see also [this blog post](https://aspnetmonsters.com/2016/08/2016-08-27-httpclientwrong/) for details):

```csharp
new HttpClient(new ApiKeyDelegatingHandler(appId, apiKey));
```

Or in case your WebAPI client is another ASP.NET WebAPI (>= [ASP.NET Core 2.1](https://docs.microsoft.com/en-us/dotnet/api/microsoft.extensions.dependencyinjection.httpclientfactoryservicecollectionextensions.addhttpclient?view=aspnetcore-2.1)), register your `HttpClient` in the `Startup.cs` for example as follows:

```csharp
services.AddTransient(sp => new ApiKeyDelegatingHandler(appId, apiKey));

services
    .AddHttpClient("HmacHttpClient")
    .AddHttpMessageHandler<ApiKeyDelegatingHandler>();
```

### Generate HMAC AppId and ApiKey

To generate an API Key, the following simple Console Application can be used.
This implementation is also provided on [.NET Fiddle](https://dotnetfiddle.net/hJcYB2).

```csharp
using System.Security.Cryptography;

public class Program
{
    public static void Main()
    {
        Console.WriteLine($"AppID: {Guid.NewGuid()} or <some-speaking-name>");
        Console.WriteLine($"ApiKey: {GenerateApiKey()}");
    }

    private static string GenerateApiKey()
    {
        using (var cryptoProvider = new RNGCryptoServiceProvider())
        {
            byte[] secretKeyByteArray = new byte[32]; //256 bit
            cryptoProvider.GetBytes(secretKeyByteArray);
            return Convert.ToBase64String(secretKeyByteArray);
        }
    }
}

```


## Security Considerations

The greatest sources of security risks are usually found not in the Auth Protocol but in the policies and procedures surrounding its use.
Implementers are strongly encouraged to assess how this module addresses their security requirements. This section includes
an incomplete list of security considerations that must be reviewed and understood before deploying this Auth protocol on the server.
Many of the protections provided in the specifications depends on whether and how they are used.

### MAC Keys Transmission

**HmacAuthentication** does not provide any mechanism for obtaining or transmitting the set of shared credentials required. Any mechanism used to obtain **HmacAuthentication** credentials must ensure that these transmissions are protected using transport-layer mechanisms such as TLS.

### Confidentiality of Requests

While **HmacAuthentication** provides a mechanism for verifying the integrity of HTTP requests, it provides no guarantee of request confidentiality. Unless other precautions are taken, eavesdroppers will have full access to the request content. Servers should carefully consider the types of data likely to be sent as part of such requests, and employ transport-layer security mechanisms to protect sensitive resources.

### Spoofing by Counterfeit Servers

**HmacAuthentication** provides limited verification of the server authenticity. When receiving a response back from the server.

A hostile party could take advantage of this by intercepting the client's requests and returning misleading or otherwise
incorrect responses. Service providers should consider such attacks when developing services using this protocol, and should
require transport-layer security for any requests where the authenticity of the resource server or of server responses is an issue.

### Plaintext Storage of Credentials

The **HmacAuthentication** key functions the same way passwords do in traditional authentication systems. In order to compute the request MAC, the server must have access to the key in plaintext form. This is in contrast, for example, to modern operating systems, which store only a one-way hash of user credentials.

If an attacker were to gain access to these keys - or worse, to the server's database of all such keys - he or she would be able to perform any action on behalf of any resource owner. Accordingly, it is critical that servers protect these keys from unauthorized access.

### Entropy of Keys

Unless a transport-layer security protocol is used, eavesdroppers will have full access to authenticated requests and request
MAC values, and will thus be able to mount offline brute-force attacks to recover the key used. Servers should be careful to
assign keys which are long enough, and random enough, to resist such attacks for at least the length of time that the **HmacAuthentication** credentials are valid.

For example, if the credentials are valid for two weeks, servers should ensure that it is not possible to mount a brute force
attack that recovers the key in less than two weeks. Of course, servers are urged to err on the side of caution, and use the
longest key reasonable.

It is equally important that the pseudo-random number generator (PRNG) used to generate these keys be of sufficiently high
quality. Many PRNG implementations generate number sequences that may appear to be random, but which nevertheless exhibit
patterns or other weaknesses which make cryptanalysis or brute force attacks easier. Implementers should be careful to use
cryptographically secure PRNGs to avoid these problems.

### Coverage Limitations

The request MAC only covers the HTTP `Host` header, the `Content-Type` header and optionally a given set of Headers. It does not cover any other headers that it does not know about which can often affect how the request body is interpreted by the server. If the server behavior is influenced by the presence or value of such headers, an attacker can manipulate the request headers without being detected. Implementers should use the `headers` feature to pass headers to be added to the signature via the `Authorization` header which is protected by the request MAC. The Signature Base String will then be responsible of adding these given headers to the Signature so they become part of the MAC.

The response authentication, when performed, only covers the response Body (payload) and some of the request information
provided by the client in it's request such as timestamp and nonce. It does not cover the HTTP status code or
any other response header field (e.g. Location) which can affect the client's behaviour.

### Future Time Manipulation

If an attacker is able to manipulate this information and cause the client to use an incorrect time, it would be able to cause the client to generate authenticated requests using time in the future. Such requests will fail when sent by the client, and will not likely leave a trace on the server (given the common implementation of nonce, if at all enforced). The attacker will then be able to replay the request at the correct time without detection.

A solution to this problem would be a clock sync between the client and server. To accomplish this, the server informs the client of its current time when an invalid timestamp is received. This happens in the form of a Date header in the response. See [RFC2616](http://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html#sec14.18) as a motivation for this.

The client should only use the time information provided by the server if:
* it was delivered over a TLS connection and the server identity has been verified, or
* the MAC digest calculated using the same client credentials over the timestamp has been verified. (eg Response validation was successful)

### Client Clock Poisoning

When receiving a request with a bad timestamp, the server provides the client with its current time. The client must never use the time received from the server to adjust its own clock, and must only use it to calculate an offset for communicating with that particular server.

### Host Header Forgery

**HmacAuthentication** validates the incoming request MAC against the incoming HTTP Host header. A malicous client can mint new host names pointing to the server's IP address and use that to craft an attack by sending a valid request that's meant for another hostname than the one used by the server. Server implementors must manually verify that the host header received matches their expectation. Eg, if you expect API calls on test.myapi.com, verify that that is the domain the request was sent to in the server implementation.
