using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.Notifications;
using Microsoft.Owin.Security.OpenIdConnect;
using Owin;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace Tcg.Owin.Security.OpenIdConnect
{
    public class TcgOpenIdConnectAuthenticationOptions
    {
        public string ClientId { get; set; }
        public string ClientSecret { get; set; }
        public string Authority { get; set; }
        public string AuthenticationType { get; set; }
        public string ResponseType { get; set; }
        public string Scope { get; set; }
        public string RedirectUri { get; set; }
        public string PostLogoutRedirectUri { get; set; }

        public TcgOpenIdConnectAuthenticationNotifications Notifications { get; set; }

        public List<ForceDomain> ForceDomains { get; set; }
        public List<PreferedIdp> PreferedIdps { get; set; }
        public string FallbackPreferedIdp { get; set; }
        public List<string> ExtraAcrValues { get; set; }
        public List<Guid> LoginDomains { get; set; }
        public IAuthenticationSessionStore SessionStore { get; set; }
        public AuthenticationMode AuthenticationMode { get; set; }
        public bool CookieHttpOnly { get; set; }
        public string CookieDomain { get; set; }
        public CookieSecureOption CookieSecure { get; set; }
        public SameSiteMode? CookieSameSite { get; set; }
    }

    public class PreferedIdp
    {
        public string HostName { get; set; }
        public string Idp { get; set; }
    }

    public class ForceDomain
    {
        public string HostName { get; set; }
        public Guid Domain { get; set; }
    }
}
