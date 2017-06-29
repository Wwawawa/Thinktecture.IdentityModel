using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Net;
using System.Security.Claims;
using System.Text;
using System.Web.Mvc;
using Thinktecture.IdentityModel.EmbeddedSts.WsFed;


namespace Thinktecture.IdentityModel.EmbeddedSts.Tokens.ControllerModule
{
    public class TokenController : Controller
    {
        public ActionResult Index(TokenRequest request)
        {
            if (request == null)
            {
                return this.Error("invalid_request");
            }
            Uri uri;
            if (string.IsNullOrEmpty(request.Scope) || !Uri.TryCreate(request.Scope, UriKind.Absolute, out uri))
            {
                return this.Error("invalid_scope");
            }
            try
            {
                if (request.Grant_Type.Equals("password"))
                {
                    ActionResult result = this.ProcessUserNameRequest(request);
                    return result;
                }
                if (request.Grant_Type.Equals("urn:ietf:params:oauth:grant-type:saml2-bearer"))
                {
                    ActionResult result = this.ProcessSamlRequest(request);
                    return result;
                }
                if (request.Grant_Type.Equals("urn:ietf:params:oauth:grant-type:jwt-bearer"))
                {
                    ActionResult result = this.ProcessJwtRequest(request);
                    return result;
                }
            }
            catch (Exception)
            {
                ActionResult result = this.Error("invalid_request");
                return result;
            }
            return this.Error("unsupported_grant_type");
        }
        
        public ActionResult Error(string error)
        {
            return new OAuthResult(HttpStatusCode.BadRequest, new
            {
                error
            });
        }

        private ActionResult ProcessUserNameRequest(TokenRequest request)
        {
            if (string.IsNullOrEmpty(request.UserName) || string.IsNullOrEmpty(request.Password))
            {
                return this.Error("invalid_grant");
            }
            IEnumerable<Claim> claims = UserManager.GetClaimsForUser(request.UserName);
            if (claims == null || !claims.Any<Claim>())
            {
                return this.Error("invalid_grant");
            }
            ClaimsIdentity id = EmbeddedTokenService.CreateClaimsIdentity(claims);
            return this.CreateTokenResponse(id, request.Scope);
        }
        
        private ActionResult CreateTokenResponse(ClaimsIdentity subject, string audience)
        {
            string nameid = subject.Claims.GetValue("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifierTest");
            if (!subject.HasClaim((Claim x) => x.Type == "sub") && !string.IsNullOrWhiteSpace(nameid))
            {
                subject.AddClaim(new Claim("sub", nameid));
            }
            JwtSecurityToken jwt = TokenHelper.CreateJWT(subject, audience);
            string token = TokenHelper.SerializeJwt(jwt);
            TokenResponse response = new TokenResponse
            {
                AccessToken = token,
                ExpiresIn = (int)jwt.ValidTo.Subtract(jwt.ValidFrom).TotalMinutes
            };
            var result = new
            {
                access_token = response.AccessToken,
                expires_in = response.ExpiresIn,
                refresh_token = response.RefreshToken,
                token_type = response.TokenType
            };
            return new OAuthResult(result);
        }

        private ActionResult ProcessJwtRequest(TokenRequest request)
        {
            if (string.IsNullOrEmpty(request.Assertion))
            {
                return this.Error("invalid_grant");
            }
            JwtSecurityToken token = TokenHelper.ParseJwt(request.Assertion);
            ClaimsIdentity subject = TokenHelper.ValidateJwt(token);
            return this.CreateTokenResponse(subject, request.Scope);
        }
      
        private ActionResult ProcessSamlRequest(TokenRequest request)
        {
            if (string.IsNullOrEmpty(request.Assertion))
            {
                return this.Error("invalid_grant");
            }
            string incomingSamlToken;
            try
            {
                incomingSamlToken = Encoding.UTF8.GetString(Convert.FromBase64String(request.Assertion));
            }
            catch
            {
                return this.Error("invalid_grant");
            }
            SamlSecurityToken token = TokenHelper.ParseSaml(incomingSamlToken);
            ClaimsIdentity subject = TokenHelper.ValidateSaml(token);
            return this.CreateTokenResponse(subject, request.Scope);
        }
    }
}
