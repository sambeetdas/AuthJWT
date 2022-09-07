using Auth.JWT.Common;
using Auth.JWT.Model;
using Model;
using System.Diagnostics.Metrics;
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
            var secret = TestHelper.GetJwtSecret1();

            var tokenModel = TestHelper.GetTokenRequestModel_Positive();

            var result = _module.CreateToken(tokenModel, secret, AlgorithmType.SHA256);

            Assert.NotNull(result);
            Assert.NotNull(result.Content);
            Assert.NotNull(result.Status);
            Assert.Equal(result.Status,"OK");

            var validateModel = TestHelper.GetValidateModel_Positive();

            var verifyResult = _module.VerifyToken(result.Content, secret, validateModel);

            Assert.NotNull(verifyResult);
            Assert.NotNull(verifyResult.Status);
            Assert.Equal(verifyResult.Status, "OK");

            Assert.Equal(result.Content, verifyResult.Content);
        }

        [Fact]
        public void InvalidToken()
        {
            var secret = TestHelper.GetJwtSecret1();

            var tokenModel = TestHelper.GetTokenRequestModel_Positive();

            var result = _module.CreateToken(tokenModel, secret, AlgorithmType.SHA256);

            Assert.NotNull(result);
            Assert.NotNull(result.Content);
            Assert.NotNull(result.Status);
            Assert.Equal(result.Status, "OK");

            var validateModel = TestHelper.GetValidateModel_Positive();

            result.Content = result.Content.Remove(result.Content.Length - 1, 1) + "n";
            var verifyResult = _module.VerifyToken(result.Content, secret, validateModel);

            Assert.NotNull(verifyResult);
            Assert.NotNull(verifyResult.Status);
            Assert.Equal(verifyResult.Status, "FAILED");

            Assert.Equal(verifyResult.Content, "Token Hash didnot match.");
        }

        [Fact]
        public void InvalidSecrect()
        {
            var secret1 = TestHelper.GetJwtSecret1();

            var tokenModel = TestHelper.GetTokenRequestModel_Positive();

            var result = _module.CreateToken(tokenModel, secret1, AlgorithmType.SHA256);

            Assert.NotNull(result);
            Assert.NotNull(result.Content);
            Assert.NotNull(result.Status);
            Assert.Equal(result.Status, "OK");

            var validateModel = TestHelper.GetValidateModel_Positive();

            var secret2 = TestHelper.GetJwtSecret2();
            var verifyResult = _module.VerifyToken(result.Content, secret2, validateModel);

            Assert.NotNull(verifyResult);
            Assert.NotNull(verifyResult.Status);
            Assert.Equal(verifyResult.Status, "FAILED");

            Assert.Equal(verifyResult.Content, "Token Hash didnot match.");
        }

        [Fact]
        public async void TokenExpiration()
        {
            string expiryInSeconds = "2";
            var secret = TestHelper.GetJwtSecret1();

            var tokenModel = TestHelper.GetTokenRequestModel_Expiration(expiryInSeconds);

            var result = _module.CreateToken(tokenModel, secret, AlgorithmType.SHA256);

            Assert.NotNull(result);
            Assert.NotNull(result.Content);
            Assert.NotNull(result.Status);
            Assert.Equal(result.Status, "OK");

            
            await Task.Delay(Convert.ToInt32(expiryInSeconds) * 1000);

            var validateModel = TestHelper.GetValidateModel_Positive();

            var verifyResult = _module.VerifyToken(result.Content, secret, validateModel);

            Assert.NotNull(verifyResult);
            Assert.NotNull(verifyResult.Status);
            Assert.Equal(verifyResult.Status, "FAILED");

            Assert.Equal(verifyResult.Content, "Token is Expired.");
        }

        [Fact]
        public async void InvalidIssuer()
        {
            var secret = TestHelper.GetJwtSecret1();

            var tokenModel = TestHelper.GetTokenRequestModel_Positive();

            var result = _module.CreateToken(tokenModel, secret, AlgorithmType.SHA256);

            Assert.NotNull(result);
            Assert.NotNull(result.Content);
            Assert.NotNull(result.Status);
            Assert.Equal(result.Status, "OK");

            var validateModel = TestHelper.GetValidateModel_Positive();
            validateModel.Issuer = tokenModel.Issuer + "New";

            var verifyResult = _module.VerifyToken(result.Content, secret, validateModel);

            Assert.NotNull(verifyResult);
            Assert.NotNull(verifyResult.Status);
            Assert.Equal(verifyResult.Status, "FAILED");

            Assert.Equal(verifyResult.Content, "Issuer mismatch");
        }
    }
}