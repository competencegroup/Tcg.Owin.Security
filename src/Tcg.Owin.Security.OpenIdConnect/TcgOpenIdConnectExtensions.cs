using IdentityModel.Client;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.Notifications;
using Microsoft.Owin.Security.OpenIdConnect;
using Owin;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;

namespace Tcg.Owin.Security.OpenIdConnect
{

    public static class TcgOpenIdConnectExtensions
    {
        readonly static HttpClient _client = new HttpClient();
        public static IAppBuilder UseTcgOpenIdConnectAuthentication(this IAppBuilder app, TcgOpenIdConnectAuthenticationOptions options)
        {
            var tokenEndpoint = $"{options.Authority}/connect/token";

            app.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                AuthenticationType = "DomainSecurity STS Cookie",
                SessionStore = options.SessionStore,
                Provider = new CookieAuthenticationProvider
                {
                    OnValidateIdentity = n => ValidateAccessToken(n, tokenEndpoint, options.ClientId, options.ClientSecret),
                },
            });

            app.UseOpenIdConnectAuthentication(new OpenIdConnectAuthenticationOptions
            {
                ClientId = options.ClientId,
                ClientSecret = options.ClientSecret,

                Authority = options.Authority,

                AuthenticationType = options.AuthenticationType ?? "STS",

                ResponseType = options.ResponseType,
                Scope = options.Scope,

                RedirectUri = options.RedirectUri,
                PostLogoutRedirectUri = options.PostLogoutRedirectUri,

                TokenValidationParameters = new TokenValidationParameters
                {
                    NameClaimType = "idString",
                    RoleClaimType = "role",
                },

                //Do not use the lifetime of the id_token, use the Cookie middleware expiration instead.
                UseTokenLifetime = false,

                SignInAsAuthenticationType = "DomainSecurity STS Cookie",

                Notifications = new OpenIdConnectAuthenticationNotifications
                {
                    AuthenticationFailed = async n =>
                    {
                        await options.Notifications?.AuthenticationFailed(n);
                    },

                    AuthorizationCodeReceived = async n =>
                    {
                        await AuthorizationCodeReceived(n, options.Authority, options.ClientId, options.ClientSecret);
                        await options.Notifications?.AuthorizationCodeReceived(n);
                    },

                    MessageReceived  = async n =>
                    {
                        await options.Notifications?.MessageReceived(n);
                    },

                    SecurityTokenReceived = async n =>
                    {
                        await options.Notifications?.SecurityTokenReceived(n);
                    },

                    SecurityTokenValidated = async n =>
                    {
                        await SecurityTokenValidated(n, options.Authority);
                        await options.Notifications?.SecurityTokenValidated(n);
                    },

                    RedirectToIdentityProvider = async n =>
                    {
                        await RedirectToIdentityProvider(n, options);
                        await options.Notifications?.RedirectToIdentityProvider(n);
                    }
                }
            });

            return app;
        }

        private static async Task ValidateAccessToken(CookieValidateIdentityContext ctx, string tokenEndpoint,string clientId, string clientSecret)
        {
            var claimsIdentity = ctx?.Identity;

            if (claimsIdentity == null) { return; }

            DateTimeOffset expiresAt;
            DateTimeOffset.TryParse(claimsIdentity.FindFirst("expires_at")?.Value, out expiresAt);

            try
            {
                //Check for expired token
                if (DateTimeOffset.UtcNow.AddMinutes(5) >= expiresAt)
                {
                    string refreshToken = claimsIdentity.FindFirst("refresh_token")?.Value;

                    if (refreshToken == null)
                    {
                        ctx.RejectIdentity();
                        return;
                    }

                    var tokenResponse = await StsTokenHelper.RefreshToken(_client, tokenEndpoint, clientId, clientSecret, refreshToken);

                    if (tokenResponse.IsError)
                    { 
                        ctx.RejectIdentity();
                        return;
                    }

                    claimsIdentity.AddOrUpdateClaim("access_token", tokenResponse.AccessToken);
                    claimsIdentity.AddOrUpdateClaim("expires_at", tokenResponse.ExpiresUtc().ToString());
                    claimsIdentity.AddOrUpdateClaim("refresh_token", tokenResponse.RefreshToken);

                    //ctx.ReplaceIdentity(claimsIdentity);

                    // kill old cookie
                    ctx.OwinContext.Authentication.SignOut(ctx.Options.AuthenticationType);

                    // sign in again
                    var authenticationProperties = new AuthenticationProperties { IsPersistent = ctx.Properties.IsPersistent };
                    ctx.OwinContext.Authentication.SignIn(authenticationProperties, claimsIdentity);

                }
            }
            catch (Exception ex)
            {
                ctx.RejectIdentity();
            }
        }

        private static async Task AuthorizationCodeReceived(AuthorizationCodeReceivedNotification n, string authority, string clientId, string clientSecret)
        {
            var tokenEndpoint = $"{authority}/connect/token";
            if (n.Code != null)
            {
                // use the code to get the access and refresh token
                var tokenResponse = await StsTokenHelper.RequestToken(_client, tokenEndpoint, clientId, clientSecret, n.Code, n.RedirectUri);

                // create new identity
                //var claimsIdent = new ClaimsIdentity(n.AuthenticationTicket.Identity.AuthenticationType);
                var claimsIdent = n.AuthenticationTicket.Identity;

                bool includeUserClaims = claimsIdent.FindFirst("role") == null;
                if (includeUserClaims)
                {
                    //Add userClaims from userInfoEndpoint with the access token
                    await AddUserClaimsAsync(claimsIdent, authority, tokenResponse.AccessToken);


                    //Add portal
                    //AddPortalGroupInfo(claimsIdent);
                }

                claimsIdent.AddOrUpdateClaim("access_token", tokenResponse.AccessToken);
                claimsIdent.AddOrUpdateClaim("expires_at", tokenResponse.ExpiresUtc().ToString());
                claimsIdent.AddOrUpdateClaim("refresh_token", tokenResponse.RefreshToken);
                claimsIdent.AddOrUpdateClaim("id_token", n.ProtocolMessage.IdToken);

                n.AuthenticationTicket.Properties.ExpiresUtc = tokenResponse.ExpiresUtc();
            }
        }
        private static async Task SecurityTokenValidated(SecurityTokenValidatedNotification<OpenIdConnectMessage, OpenIdConnectAuthenticationOptions> n, string authority)
        {

            var id_token = n.ProtocolMessage.IdToken;
            var claimsIdent = n.AuthenticationTicket.Identity;
            if (claimsIdent != null)
            {
                //If Implicit Flow
                if (n.ProtocolMessage.AccessToken != null)
                {
                    //Add userClaims from userInfoEndpoint
                    await AddUserClaimsAsync(claimsIdent, authority, n.ProtocolMessage.AccessToken);

                    //Add portal
                    //AddPortalGroupInfo(claimsIdent);

                    //Calculate AccessToken Expiration
                    int expiresIn = int.Parse(n.ProtocolMessage.ExpiresIn);
                    DateTimeOffset expiresUtc = DateTimeOffset.UtcNow.AddSeconds(expiresIn);

                    //Add access_token for DomSec Api call"
                    claimsIdent.AddOrUpdateClaim("access_token", n.ProtocolMessage.AccessToken);
                    claimsIdent.AddOrUpdateClaim("expires_at", expiresUtc.ToString());

                    //Add id_token for logout hint
                    claimsIdent.AddOrUpdateClaim("id_token", id_token);

                    //Add expiration to AuthenticationTicket
                    n.AuthenticationTicket.Properties.ExpiresUtc = expiresUtc;
                }

            }
        }

        private static Task RedirectToIdentityProvider(
            RedirectToIdentityProviderNotification<OpenIdConnectMessage, OpenIdConnectAuthenticationOptions> n,
            TcgOpenIdConnectAuthenticationOptions options
            )
        {

            // if signing out, add the id_token_hint
            if (n.ProtocolMessage.RequestType == OpenIdConnectRequestType.Logout)
            {
                var idTokenHint = n.OwinContext.Authentication.User.FindFirst("id_token");

                if (idTokenHint != null)
                {
                    n.ProtocolMessage.IdTokenHint = idTokenHint.Value;
                }

                n.ProtocolMessage.PostLogoutRedirectUri = $"{n.OwinContext.Request.Uri.Scheme}://{n.OwinContext.Request.Uri.Authority}";

                //Session.Abandon();
            }

            // Add Tennant specific info to AuthenticationRequest
            if (n.ProtocolMessage.RequestType == OpenIdConnectRequestType.Authentication)
            {
                //////TODO: Do something with the state to redirect to the correct URL
                //n.ProtocolMessage.State = string.Empty;

                if (n.OwinContext.Authentication.User.Identity.IsAuthenticated)
                {
                    n.ProtocolMessage.Prompt = "login";
                }

                n.ProtocolMessage.RedirectUri = $"{n.OwinContext.Request.Uri.Scheme}://{n.OwinContext.Request.Uri.Authority}";

                string host = n.OwinContext.Request.Uri.Host;

                string preferredIdp = options.PreferedIdps?.FirstOrDefault(x => string.Equals(host, x.HostName, StringComparison.OrdinalIgnoreCase))?.Idp
                    ?? options.FallbackPreferedIdp;

                var forceDomain = options.ForceDomains?.FirstOrDefault(x => string.Equals(host, x.HostName, StringComparison.OrdinalIgnoreCase))?.Domain;

                string loginDomains = null;
                if (options.LoginDomains != null)
                {
                    loginDomains = string.Join(";", options.LoginDomains.Select(x => $"#{x.ToString("N")}"));
                }

                List<string> acrValues = options.ExtraAcrValues ?? new List<string>();

                if (!string.IsNullOrWhiteSpace(preferredIdp))
                {
                    acrValues.Add($"idp:{preferredIdp}");
                }

                if (!string.IsNullOrWhiteSpace(loginDomains))
                {
                    acrValues.Add($"loginDomains:{loginDomains}");
                }

                if (forceDomain.HasValue)
                {
                    acrValues.Add($"forceDomain:#{forceDomain.Value.ToString("N")}");
                }

                //string otac = n.OwinContext.Get<string>("otac");
                //if (otac != null) {
                //    acrValues.Add($"otac:{otac}");
                //}
                
                n.ProtocolMessage.AcrValues = string.Join(" ", acrValues);
            }

            return Task.FromResult(0);
        }

        private static async Task AddUserClaimsAsync(ClaimsIdentity claimsIdent, string accessToken, string authority)
        {
            string userInfoEndpoint = $"{authority}/connect/userinfo";
            var userInfoResponse = await _client.GetUserInfoAsync(new UserInfoRequest
            {
                Address = userInfoEndpoint,
                Token = accessToken
            });


            if (userInfoResponse.IsError)
            {
                if (userInfoResponse.IsError) { throw new Exception($"{userInfoResponse.Error}"); }
            }

            //Use the FixedClaims that are parsed with DateParseHandling.None
            //https://github.com/JamesNK/Newtonsoft.Json/issues/862
            //claimsIdent.AddClaims(userInfoResponse.GetFixedClaimsIdentity().Claims);

            claimsIdent.AddClaims(userInfoResponse.Claims);
        }
    }
}
