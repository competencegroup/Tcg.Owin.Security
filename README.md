# Tcg.Owin.Security
For this to work properly you need to configure an [IAuthenticationSessionStore][1] provider. 

The [Tcg.Owin.Cookies.SessionStore][2] project has 2 implementations available:
* Tcg.Owin.Cookies.SessionStore.Memory
* Tcg.Owin.Cookies.SessionStore.Redis

# ACR values to be set externally
* `tenant` - the portalIdentifier of the academy portal
* `externalCss` - to load external CSS


[1]: https://docs.microsoft.com/en-us/previous-versions/aspnet/dn800244(v%3Dvs.113)
[2]: https://github.com/competencegroup/Tcg.Owin.Cookies.SessionStore