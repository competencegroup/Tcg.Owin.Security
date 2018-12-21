using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Owin.Security.Notifications;
using Microsoft.Owin.Security.OpenIdConnect;
using Owin;
using System;
using System.Threading.Tasks;

namespace Tcg.Owin.Security.OpenIdConnect
{

    public class TcgOpenIdConnectAuthenticationNotifications
    {
        //
        // Summary:
        //     Invoked if exceptions are thrown during request processing. The exceptions will
        //     be re-thrown after this event unless suppressed.
        public Func<AuthenticationFailedNotification<OpenIdConnectMessage, OpenIdConnectAuthenticationOptions>, Task> AuthenticationFailed { get; set; } = notification => Task.FromResult(0);
        //
        // Summary:
        //     Invoked after security token validation if an authorization code is present in
        //     the protocol message.
        public Func<AuthorizationCodeReceivedNotification, Task> AuthorizationCodeReceived { get; set; } = notification => Task.FromResult(0);
        //
        // Summary:
        //     Invoked when a protocol message is first received.
        public Func<MessageReceivedNotification<OpenIdConnectMessage, OpenIdConnectAuthenticationOptions>, Task> MessageReceived { get; set; } = notification => Task.FromResult(0);
        //
        // Summary:
        //     Invoked to manipulate redirects to the identity provider for SignIn, SignOut,
        //     or Challenge.
        public Func<RedirectToIdentityProviderNotification<OpenIdConnectMessage, OpenIdConnectAuthenticationOptions>, Task> RedirectToIdentityProvider { get; set; } = notification => Task.FromResult(0);
        //
        // Summary:
        //     Invoked with the security token that has been extracted from the protocol message.
        public Func<SecurityTokenReceivedNotification<OpenIdConnectMessage, OpenIdConnectAuthenticationOptions>, Task> SecurityTokenReceived { get; set; } = notification => Task.FromResult(0);
        //
        // Summary:
        //     Invoked after the security token has passed validation and a ClaimsIdentity has
        //     been generated.
        public Func<SecurityTokenValidatedNotification<OpenIdConnectMessage, OpenIdConnectAuthenticationOptions>, Task> SecurityTokenValidated { get; set; } = notification => Task.FromResult(0);
    }
}
