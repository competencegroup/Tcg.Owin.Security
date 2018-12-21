using IdentityModel.Client;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Owin.Security.Notifications;
using Microsoft.Owin.Security.OpenIdConnect;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Owin;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Http;
using System.Security.Claims;
using System.Threading.Tasks;

namespace Tcg.Owin.Security.OpenIdConnect
{

    //public static class UserInfoResponseExtensions
    //{
    //    public static void FixClaims(this UserInfoResponse response)
    //    {

    //        try
    //        {
    //            JsonReader reader = new JsonTextReader(new StringReader(response.Raw));
    //            reader.DateParseHandling = DateParseHandling.None;
    //            JObject jsonObject = JObject.Load(reader);


    //            var claims = new List<Tuple<string, string>>();

    //            foreach (var x in jsonObject)
    //            {
    //                var array = x.Value as JArray;

    //                if (array != null)
    //                {
    //                    foreach (var item in array)
    //                    {
    //                        claims.Add(Tuple.Create(x.Key, item.ToString()));
    //                    }
    //                }
    //                else
    //                {
    //                    claims.Add(Tuple.Create(x.Key, x.Value.ToString()));
    //                }
    //            }

    //            response.Claims = claims;
    //        }
    //        catch (Exception ex)
    //        {
    //            //////response.IsError = true;
    //            response.ErrorMessage = ex.Message;
    //        }
    //    }

    //    public static ClaimsIdentity GetFixedClaimsIdentity(this UserInfoResponse response)
    //    {
    //        response.FixClaims();
    //        return response.GetClaimsIdentity();
    //    }
    //}
}
