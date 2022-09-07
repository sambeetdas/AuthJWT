using Microsoft.Extensions.DependencyInjection;
using Auth.JWT;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Auth.JWT.Test
{
    public class TestSetupFixture : IDisposable
    {
        public TestSetupFixture()
        {
            var serviceProvider = new ServiceCollection();
            serviceProvider.AddAuthService();
            serviceProvider.BuildServiceProvider();
        }
        public void Dispose()
        {

        }
    }
}
