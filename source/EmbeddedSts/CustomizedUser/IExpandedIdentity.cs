using System;
using System.Collections.Generic;
using System.Security.Principal;

namespace Thinktecture.IdentityModel.EmbeddedSts.User
{
    internal interface IExpandedIdentity: IIdentity
    {
        Dictionary<string, string> AllClaims
        {
            get;
        }
        string node1
        {
            get;
        }
        string node2
        {
            get;
        }
    }
}
