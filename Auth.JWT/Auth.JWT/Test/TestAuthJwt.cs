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
            string secret = "F4760D";

            _reqModel.Issuer = "authjwt_team";
            _reqModel.ExpiryInSeconds = "1000";
            _reqModel.UserId = "U1324322";
            _reqModel.User = "sambeet";
            _reqModel.Role = "admin";
            _reqModel.Audience = "authjwt_app";
            _reqModel.JwtId = "J4433421";
            _reqModel.Subject = "authjwt_subject";
            _reqModel.CustomProperty.Add("CustomField1","auth_custom1");
            _reqModel.CustomProperty.Add("CustomField2", "auth_custom2");

            var result = _module.CreateToken(_reqModel, secret, AlgorithmType.SHA256);

            Console.WriteLine("************* Create Token Result***************");
            Console.WriteLine(Newtonsoft.Json.JsonConvert.SerializeObject(result));

            _validateModel.Issuer = "authjwt_team";
            _validateModel.UserId = "U1324322";
            _validateModel.User = "sambeet";
            _validateModel.Role = "admin";
            _validateModel.Audience = "authjwt_app";
            _validateModel.JwtId = "J4433421";
            _validateModel.Subject = "authjwt_subject";
            _validateModel.CustomProperty.Add("CustomField1", "auth_custom1");
            _validateModel.CustomProperty.Add("CustomField2", "auth_custom2");

            var verifyResult = _module.VerifyToken(result.Content, secret, _validateModel);

            Console.WriteLine("************* Verify Token Result***************");
            Console.WriteLine(Newtonsoft.Json.JsonConvert.SerializeObject(verifyResult));

            Console.ReadKey();
        }
    }
}
