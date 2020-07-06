using Auth.JWT.Model;
using Auth.JWT.Test;
using Microsoft.Extensions.DependencyInjection;
using Model;
using System;

namespace Auth.JWT
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var services = new ServiceCollection();
            services.AddAuthService();

            TestAuthJwt objTest = new TestAuthJwt(new JWTModule(), new TokenRequestModel(), new ValidateModel());
            objTest.Execute();
        }
    }

}
