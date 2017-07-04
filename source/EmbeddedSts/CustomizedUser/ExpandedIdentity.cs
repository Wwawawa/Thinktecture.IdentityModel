using System;
using System.Collections.Generic;
using System.Security.Principal;

namespace Thinktecture.IdentityModel.EmbeddedSts.User
{
    public class ExpandedIdentity : IExpandedIdentity, IIdentity
    {
        public Dictionary<string, string> AllClaims
        {
            get
            {
                Dictionary<string, string> result = new Dictionary<string, string>(this.Values.Count + this.MultiValues.Count);
                foreach (KeyValuePair<string, string> kv in this.Values)
                {
                    result[kv.Key] = kv.Value;
                }
                foreach (KeyValuePair<string, string[]> kv2 in this.MultiValues)
                {
                    result[kv2.Key] = string.Join(",", kv2.Value);
                }
                return result;
            }
        }
        public string node1
        {
            get;
            set;
        }
        public string node2
        {
            get;
            set;
        }       

        public IPrincipal InnerPrincipal
        {
            get;
            set;
        }

        public string Name
        {
            get
            {
                return this.InnerPrincipal.Identity.Name;
            }
        }

        public string AuthenticationType
        {
            get
            {
                return "Forms";
            }
        }

        public bool IsAuthenticated
        {
            get
            {
                return true;
            }
        }
        public string UserName
        {
            get;
            set;
        }
        public string Password
        {
            get;
            set;
        }
        public IDictionary<string, string[]> MultiValues
        {
            get;
            set;
        }
        public IDictionary<string, string> Values
        {
            get;
            set;
        }
        public ExpandedIdentity()
        {
            this.Values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            this.MultiValues = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase);
            this.UserName = string.Empty;
            this.Password = string.Empty;
        }

        public ExpandedIdentity(ExpandedIdentity existingUser, IPrincipal originalPrincipal)
        {
            if (existingUser != null)
            {
                this.UserName = existingUser.UserName;
                this.Password = existingUser.Password;
                this.Values = existingUser.Values;
                this.MultiValues = existingUser.MultiValues;
            }
            else
            {
                this.Values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                this.MultiValues = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase);
                this.UserName = string.Empty;
                this.Password = string.Empty;
            }
            this.InnerPrincipal = originalPrincipal;
        }

        public string[] GetGroups()
        {
            return this.GetDefault<string[]>("Groups", new string[0], this.MultiValues);
        }
        protected virtual string GetDefault(string key, string defaultValue = null, IDictionary<string, string> values = null)
        {
            return this.GetDefault<string>(key, defaultValue ?? string.Empty, values ?? this.Values);
        }
        protected virtual T GetDefault<T>(string key, T defaultValue = default(T), IDictionary<string, T> values = null)
        {
            if (values == null || !values.ContainsKey(key))
            {
                return defaultValue;
            }
            return values[key];
        }
    }
}
