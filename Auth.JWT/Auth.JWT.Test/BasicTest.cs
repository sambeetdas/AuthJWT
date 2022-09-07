using Auth.JWT.Common;
using Auth.JWT.Model;
using Model;
using Xunit.Extensions.AssemblyFixture;

namespace Auth.JWT.Test
{
    public class BasicTest : IAssemblyFixture<TestSetupFixture>, IClassFixture<JWTModule>
    {
        private readonly JWTModule _module;

        public BasicTest(JWTModule module)
        {
            _module = module;
        }

        [Fact]
        public void Positive()
        {
            var secrect = TestHelper.GetJwtSecrect1();

            var tokenModel = TestHelper.GetTokenRequestModel_Positive();

            var result = _module.CreateToken(tokenModel, secrect, AlgorithmType.SHA256);
            Assert.NotNull(result);

            var validateModel = TestHelper.GetValidateModel_Positive();

            var verifyResult = _module.VerifyToken(result.Content, secrect, validateModel);
            Assert.NotNull(verifyResult);
        }
    }
}