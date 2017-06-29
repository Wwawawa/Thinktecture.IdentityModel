using System;

namespace Thinktecture.IdentityModel.EmbeddedSts.Tokens.ControllerModule
{
    public class TokenRequest
    {
        public string Grant_Type
        {
            get;
            set;
        }

        public string Scope
        {
            get;
            set;
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

        public string Code
        {
            get;
            set;
        }
        public string Refresh_Token
        {
            get;
            set;
        }

        public string Assertion
        {
            get;
            set;
        }
    }
}
