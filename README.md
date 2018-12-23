# Tcg.Owin.Security
For this to work properly you need to configure an [IAuthenticationSessionStore][1] provider. 

The [Tcg.Owin.Cookies.SessionStore][2] project has 2 implementations available:
* Tcg.Owin.Cookies.SessionStore.Memory
* Tcg.Owin.Cookies.SessionStore.Redis

# Installation
```
Install-Package Tcg.Owin.Security.OpenIdConnect
```

# Configuration
```
app.UseTcgOpenIdConnectAuthentication(new TcgOpenIdConnectAuthenticationOptions
{
    ClientId = <clientId>,    
    ClientSecret = <clientSecret>,
    ResponseType = "id_token token",
    Authority = <authority>,
    Scope = <required scopes>,
    RedirectUri = <redirect url>,
    PostLogoutRedirectUri = <post logout redirect url>,
    SessionStore = new RedisAuthenticationSessionStore(<redis connection string>)
    // or
    SessionStore = new MemoryAuthenticationSessionStore()
});

```

# Extra ACR values
* `tenant` - the portalIdentifier of the academy portal
* `externalCss` - to load external CSS


[1]: https://docs.microsoft.com/en-us/previous-versions/aspnet/dn800244(v%3Dvs.113)
[2]: https://github.com/competencegroup/Tcg.Owin.Cookies.SessionStore
