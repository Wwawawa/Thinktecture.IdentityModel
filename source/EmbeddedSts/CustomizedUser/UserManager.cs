using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Claims;
using System.Web.Hosting;
using System.Web.Script.Serialization;
using Thinktecture.IdentityModel.EmbeddedSts.User;

namespace Thinktecture.IdentityModel.EmbeddedSts
{
    public class UserManager
    {
        public static string[] GetAllUserNames()
        {
            IDictionary<string, ExpandedIdentity> userList = AuthenticationUserReader.Users;
            return (from user in userList
                    select user.Key).ToArray<string>();
        }

        public static IEnumerable<Claim> GetClaimsForUser(string name)
        {
            ExpandedIdentity enterpriseIdentity = AuthenticationUserReader.Users[name];
            List<Claim> claims = new List<Claim>();
            claims.Add(new Claim("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name", name));
            using (IEnumerator<KeyValuePair<string, string>> enumerator = enterpriseIdentity.Values.GetEnumerator())
            {
                while (enumerator.MoveNext())
                {
                    KeyValuePair<string, string> value = enumerator.Current;
                    KeyValuePair<string, string> value4 = value;
                    if (value4.Key != "Group")
                    {
                        List<Claim> arg_A4_0 = claims;
                        KeyValuePair<string, string> value2 = value;
                        arg_A4_0.AddRange(ClaimMapper.MapClaim(value2.Key).Select(delegate (Claim x)
                        {
                            string arg_14_0 = x.Type;
                            KeyValuePair<string, string> value3 = value;
                            return new Claim(arg_14_0, value3.Value);
                        }));
                    }
                }
            }
            claims.AddRange(from x in ClaimMapper.MapClaim("Group")
                            from y in enterpriseIdentity.GetGroups()
                            select new Claim(x.Type, y));
            return claims;
        }
    }
}
