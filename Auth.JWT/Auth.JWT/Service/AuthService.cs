using Auth.JWT.Model;
using Microsoft.Extensions.DependencyInjection;
using Model;


namespace Auth.JWT
{
    public static class AuthService
    {
        public static void AddAuthService(this IServiceCollection services)
        {
            services.AddTransient<JWTModule>();
            services.AddTransient<TokenRequestModel>();
            services.AddTransient<TokenResponseModel>();            
            services.AddTransient<ValidateModel>();
        }
    }
}
