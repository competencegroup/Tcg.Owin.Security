using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Text;

namespace Tcg.Owin.Security.OpenIdConnect
{
    public static class ClaimsIdentityExtensions
    {
        public static void AddOrUpdateClaim(this ClaimsIdentity identity, string key, string value)
        {
            if (identity == null)
                return;

            // check for existing claim and remove it
            var existingClaim = identity.FindFirst(key);
            if (existingClaim != null)
                identity.RemoveClaim(existingClaim);

            // add new claim
            identity.AddClaim(new Claim(key, value));
        }
    }
}
