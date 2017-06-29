using System.Net;
using System.Web.Mvc;

namespace Thinktecture.IdentityModel.EmbeddedSts.Tokens.ControllerModule
{
    public class OAuthResult : JsonResult
    {
        private HttpStatusCode status;

        public OAuthResult(object data) : this(HttpStatusCode.OK, data)
        {
        }

        public OAuthResult(HttpStatusCode status, object data)
        {
            this.status = status;
            base.Data = data;
        }
      
        public override void ExecuteResult(ControllerContext context)
        {
            base.ExecuteResult(context);
            context.HttpContext.Response.StatusCode = (int)this.status;
        }
    }
}
