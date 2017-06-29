using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IdentityModel.Tokens;
using System.Security.Claims;

namespace Thinktecture.IdentityModel.EmbeddedSts.Tokens
{
    //JwtSecurityTokenHandler need Assembly of System.IdentityModel.Tokens.Jwt, Version=3.0.0.0
    internal class JWTSecurityTokenHandlerWrapper : JwtSecurityTokenHandler
    {
        private TokenValidationParameters validationParams;

        public JWTSecurityTokenHandlerWrapper() :
            this("")
        {
        }

        public JWTSecurityTokenHandlerWrapper(string audience)
        {
            TokenValidationParameters tokenValidationParameters = new TokenValidationParameters();
            tokenValidationParameters.AllowedAudience = audience;
            tokenValidationParameters.SigningToken = new X509SecurityToken(EmbeddedStsConstants.SigningCertificate);
            tokenValidationParameters.ValidIssuer = "urn:Thinktecture:EmbeddedSTS";
            this.validationParams = tokenValidationParameters;
        }
        public JWTSecurityTokenHandlerWrapper(TokenValidationParameters validationParams)
        {
            this.validationParams = validationParams;
        }

        public override ReadOnlyCollection<ClaimsIdentity> ValidateToken(SecurityToken token)
        {
            JwtSecurityToken jwt = token as JwtSecurityToken;
            List<ClaimsIdentity> list = new List<ClaimsIdentity>(this.ValidateToken(jwt, this.validationParams).Identities);
            return list.AsReadOnly();
        }
    }
}
