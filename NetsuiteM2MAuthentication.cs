using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Net.Http;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace NetSuiteAPI.Helpers
{
    public class NetSuiteIntegration
    {
        public string AccountId { get; set; }
        public string ConsumerKey { get; set; }
        public string PrivateKeyPem { get; set; }
        public string ClientCredentialsCertificateId { get; set; }
    }

    public class NetSuiteToken
    {
        [JsonProperty("access_token")]
        public string AccessToken { get; set; }

        [JsonProperty("token_type")]
        public string TokenType { get; set; }

        [JsonProperty("expires_in")]
        public int ExpiresIn { get; set; }

        [JsonProperty("scope")]
        public string Scope { get; set; }
    }

    public class NetsuiteM2MAuthentication
    {
        private readonly NetSuiteIntegration netSuiteCredentials;
        private readonly string tokenEndPointUrl;
        private readonly HttpClient httpClient;

        public NetsuiteM2MAuthentication(NetSuiteIntegration netSuiteCredentials, HttpClient httpClient)
        {
            this.netSuiteCredentials = netSuiteCredentials;
            tokenEndPointUrl = $"https://{this.netSuiteCredentials.AccountId}.suitetalk.api.netsuite.com/services/rest/auth/oauth2/v1/token";
            this.httpClient = httpClient;
        }

        public async Task<NetSuiteToken> GetAccessToken()
        {
            string clientAssertion = GetJwtToken();

            var requestParams = new List<KeyValuePair<string, string>>
            {
                new KeyValuePair<string, string>("grant_type", "client_credentials"),
                new KeyValuePair<string, string>("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"),
                new KeyValuePair<string, string>("client_assertion", clientAssertion)
            };

            var httpRequest = new HttpRequestMessage(HttpMethod.Post, tokenEndPointUrl)
            {
                Content = new FormUrlEncodedContent(requestParams)
            };

            var httpResponse = await httpClient.SendAsync(httpRequest);

            var responseJson = await httpResponse.Content.ReadAsStringAsync();
            if (!httpResponse.IsSuccessStatusCode)
            {
                throw new Exception($"Authentication failed for the following reason: {responseJson}");
            }

            NetSuiteToken token = JsonConvert.DeserializeObject<NetSuiteToken>(responseJson);

            if (token == null)
            {
                throw new Exception($"Authentication failed. Can't deserialize response: {responseJson}");
            }

            if (string.IsNullOrEmpty(token.AccessToken))
            {
                throw new Exception($"Authentication failed. AccessToken can't be empty. Response: {responseJson}");
            }

            return token;
        }

        private string GetJwtToken()
        {
            RsaPrivateCrtKeyParameters keyPair;

            using (var reader = new StringReader(netSuiteCredentials.PrivateKeyPem))
            {
                var pemReader = new PemReader(reader);
                keyPair = (RsaPrivateCrtKeyParameters)pemReader.ReadObject();
            }

            if (keyPair == null)
            {
                throw new Exception("Invalid private key format.");
            }

            RSAParameters rsaParams = DotNetUtilities.ToRSAParameters(keyPair);
            var provider = new RSACryptoServiceProvider();
            provider.ImportParameters(rsaParams);

            var rsaSecurityKey = new RsaSecurityKey(provider)
            {
                KeyId = netSuiteCredentials.ClientCredentialsCertificateId
            };

            var now = DateTime.UtcNow;

            var tokenHandler = new JwtSecurityTokenHandler();

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Issuer = netSuiteCredentials.ConsumerKey,
                Audience = tokenEndPointUrl,
                Expires = now.AddMinutes(5),
                IssuedAt = now,
                Claims = new Dictionary<string, object> { { "scope", new[] { "rest_webservices" } } },
                SigningCredentials = new SigningCredentials(rsaSecurityKey, SecurityAlgorithms.RsaSha256)
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);

            return tokenHandler.WriteToken(token);
        }
    }
}
