using IdentityModel.Client;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Owin.Security.Notifications;
using Microsoft.Owin.Security.OpenIdConnect;
using Owin;
using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;

namespace Tcg.Owin.Security.OpenIdConnect
{

    public static class StsTokenHelper
    {
        public static async Task<TokenResponse> RequestToken(this HttpClient client, string tokenEndpoint, string clientId, string clientSecret, string code, string redirectUri)
        {
            var tokenResponse = await client.RequestAuthorizationCodeTokenAsync(new AuthorizationCodeTokenRequest
            {
                Address = tokenEndpoint,
                ClientId = clientId,
                ClientSecret = clientSecret,
                Code = code,
                RedirectUri = redirectUri
            });

            if (tokenResponse.IsError)
            {
                throw new Exception(tokenResponse.Error);
            }

            return tokenResponse;
        }

        public static async Task<TokenResponse> RefreshToken(this HttpClient client, string tokenEndpoint, string clientId, string clientSecret, string refreshToken)
        {
            var tokenResponse = await client.RequestRefreshTokenAsync(new RefreshTokenRequest {
               Address = tokenEndpoint,
               ClientId = clientId,
               ClientSecret = clientSecret,
               RefreshToken = refreshToken
            });

            if (tokenResponse.IsError)
            {
                throw new Exception(tokenResponse.Error);
            }

            return tokenResponse;
        }
    }
}
