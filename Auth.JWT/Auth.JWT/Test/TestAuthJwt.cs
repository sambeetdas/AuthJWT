using Auth.JWT.Common;
using Auth.JWT.Model;
using Model;
using System;
using System.Collections.Generic;
using System.Text;

namespace Auth.JWT.Test
{
    class TestAuthJwt
    {
        private readonly JWTModule _module;
        private readonly TokenRequestModel _reqModel;
        private readonly ValidateModel _validateModel;

        public TestAuthJwt(JWTModule module, TokenRequestModel reqModel, ValidateModel validateModel)
        {
            _module = module;
            _reqModel = reqModel;
            _validateModel = validateModel;
        }
        public void Execute()
        {
            string issuer = "issuer";
            string expirySeconds = "1000";
            string secrect = "F4760D";

            _reqModel.issuer = issuer;
            _reqModel.expiryInSeconds = expirySeconds;
            var result = _module.CreateToken(_reqModel, secrect, AlgorithmType.SHA256);

            Console.WriteLine("************* Create Token Result***************");
            Console.WriteLine(Newtonsoft.Json.JsonConvert.SerializeObject(result));

            _validateModel.issuer = "issuer";

            var verifyResult = _module.VerifyToken(result.Content, secrect, _validateModel);

            Console.WriteLine("************* Verify Token Result***************");
            Console.WriteLine(Newtonsoft.Json.JsonConvert.SerializeObject(verifyResult));

            Console.ReadKey();
        }
    }
}
