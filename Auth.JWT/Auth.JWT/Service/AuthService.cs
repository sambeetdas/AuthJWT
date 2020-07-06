using Auth.JWT.Model;
using Microsoft.Extensions.DependencyInjection;
using Model;
using System;
using System.Collections.Generic;
using System.Text;

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
