using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace Thinktecture.IdentityModel.EmbeddedSts.User
{
    internal static class ClaimMapper
    {
        private static readonly string ClaimsNamespace = "http://schemas.xmlsoap.org/claims";
        private static readonly Dictionary<string, Func<string, string[]>> Mappings;
        internal static Claim[] MapClaim(string shortName)
        {
            if (ClaimMapper.Mappings.ContainsKey(shortName))
            {
                string[] claimUris = ClaimMapper.Mappings[shortName](shortName);
                return (from x in claimUris
                        select new Claim(x, string.Empty)).ToArray<Claim>();
            }
            return new Claim[]
            {
                new Claim(ClaimMapper.ClaimsNamespace + "/" + shortName.ToLowerInvariant(), string.Empty)
            };
        }
        static ClaimMapper()
        {
            // Note: this type is marked as 'beforefieldinit'.
            Dictionary<string, Func<string, string[]>> dictionary = new Dictionary<string, Func<string, string[]>>(StringComparer.OrdinalIgnoreCase);
            dictionary.Add("GROUP", (string x) => new string[]
            {
                ClaimMapper.ClaimsNamespace + "/Group"
            });            
            dictionary.Add("emailaddress", (string x) => new string[]
            {
                ClaimMapper.ClaimsNamespace + "/EmailAddress"
            });            
            dictionary.Add("displayname", (string x) => new string[]
            {
                ClaimMapper.ClaimsNamespace + "/displayname"
            });           
            dictionary.Add("key", (string x) => new string[]
            {
                ClaimMapper.ClaimsNamespace + "/key"
            });           

            dictionary.Add("id", (string x) => new string[]
            {
                ClaimMapper.ClaimsNamespace + "/id"
            });
           
            dictionary.Add("name", (string x) => new string[]
            {
                ClaimMapper.ClaimsNamespace + "/name"
            });
            dictionary.Add("node1", (string x) => new string[]
            {
                ClaimMapper.ClaimsNamespace + "/node1"
            });
            dictionary.Add("node2", (string x) => new string[]
            {
                ClaimMapper.ClaimsNamespace + "/node2"
            });
            ClaimMapper.Mappings = dictionary;
        }
    }

}
