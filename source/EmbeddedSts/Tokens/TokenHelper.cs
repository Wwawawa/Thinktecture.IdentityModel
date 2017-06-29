using System;
using System.IdentityModel.Protocols.WSTrust;
using System.IdentityModel.Services;
using System.IdentityModel.Tokens;
using System.IO;
using System.Linq;
using System.Security.Claims;
using System.Xml;

namespace Thinktecture.IdentityModel.EmbeddedSts.Tokens
{
    public class TokenHelper
    {
        internal static SamlSecurityToken CreateSamlToken(ClaimsIdentity subject, string audience)
        {
            SecurityTokenDescriptor descriptor = TokenHelper.CreateDescriptor(subject, audience, 600);
            SamlSecurityTokenHandler handler = TokenHelper.GetSamlHandler();
            return handler.CreateToken(descriptor) as SamlSecurityToken;
        }
        internal static SamlSecurityToken ParseSaml(string tokenString)
        {
            SamlSecurityTokenHandler handler = TokenHelper.GetSamlHandler();
            return handler.ReadToken(new XmlTextReader(new StringReader(tokenString))) as SamlSecurityToken;
        }

        internal static ClaimsIdentity ValidateSaml(SamlSecurityToken token)
        {
            SamlSecurityTokenHandler handler = TokenHelper.GetSamlHandler();
            return handler.ValidateToken(token).FirstOrDefault<ClaimsIdentity>();
        }

        internal static JwtSecurityToken CreateJWT(ClaimsIdentity subject, string audience)
        {
            SecurityTokenDescriptor descriptor = TokenHelper.CreateDescriptor(subject, audience, 60);
            JWTSecurityTokenHandlerWrapper handler = new JWTSecurityTokenHandlerWrapper();
            return handler.CreateToken(descriptor) as JwtSecurityToken;
        }

        internal static JwtSecurityToken ParseJwt(string tokenString)
        {
            JWTSecurityTokenHandlerWrapper handler = new JWTSecurityTokenHandlerWrapper();
            return handler.ReadToken(tokenString) as JwtSecurityToken;
        }

        internal static ClaimsIdentity ValidateJwt(JwtSecurityToken token)
        {
            JWTSecurityTokenHandlerWrapper handler = new JWTSecurityTokenHandlerWrapper(token.Audience);
            return handler.ValidateToken(token).Identities.FirstOrDefault<ClaimsIdentity>();
        }

        internal static string SerializeJwt(JwtSecurityToken token)
        {
            JWTSecurityTokenHandlerWrapper handler = new JWTSecurityTokenHandlerWrapper(token.Audience);
            return handler.WriteToken(token);
        }

        private static SamlSecurityTokenHandler GetSamlHandler()
        {
            SecurityTokenHandler handler = FederatedAuthentication.FederationConfiguration.IdentityConfiguration.SecurityTokenHandlers[typeof(SamlSecurityToken)];
            if (handler == null)
            {
                throw new Exception("No handler found for token type: SamlSecurityToken");
            }
            return handler as SamlSecurityTokenHandler;
        }

        private static SecurityTokenDescriptor CreateDescriptor(ClaimsIdentity subject, string audience, int lifetime)
        {
            return new SecurityTokenDescriptor
            {
                AppliesToAddress = audience,
                TokenIssuerName = "urn:thinktecture:EmbeddedSTS",
                SigningCredentials = new X509SigningCredentials(EmbeddedStsConstants.SigningCertificate),
                Lifetime = new Lifetime(DateTime.UtcNow, DateTime.UtcNow.AddMinutes((double)lifetime)),
                Subject = subject
            };
        }
    }
}
