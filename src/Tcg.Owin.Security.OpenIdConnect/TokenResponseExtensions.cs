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

    public static class TokenResponseExtensions
    {
        public static DateTimeOffset ExpiresUtc(this TokenResponse tokenResponse)
        {
            return DateTimeOffset.UtcNow.AddSeconds(tokenResponse.ExpiresIn);
        }

        //public static string ExpiresAt(this TokenResponse tokenResponse)
        //{
        //    return DateTime.UtcNow.

        //    return DateTime.UtcNow.AddSeconds(tokenResponse.ExpiresIn).ToString();
        //}
    }
}
