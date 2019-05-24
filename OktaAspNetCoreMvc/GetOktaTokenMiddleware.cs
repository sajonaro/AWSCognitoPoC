using Microsoft.AspNetCore.Http;
using System.Threading.Tasks;

namespace OktaAspNetCoreMvc
{
    using Microsoft.AspNetCore.Authentication;

    internal class GetOktaTokenMiddleware
    {
        public static string OktaToken { get; private set; }

        private readonly RequestDelegate _next;

        public GetOktaTokenMiddleware(RequestDelegate next)
        {
            _next = next;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            if (context.User.Identity.IsAuthenticated)
            {
                OktaToken = await context.GetTokenAsync("access_token");
            }

            // Call the next delegate/middleware in the pipeline
            await _next(context);
        }
    }
}