using Model;
using System;

namespace Auth.JWT
{
    class Program
    {
        static void Main(string[] args)
        {

            string issuer = "issuer";
            string expirySeconds = "10";
            string secrect = "F4760D";

            JWTModule module = new JWTModule();
            TokenRequestModel reqModel = new TokenRequestModel();
            reqModel.issuer = issuer;
            reqModel.expiryInSeconds = expirySeconds;
            var result = module.CreateToken(reqModel, secrect);

            Console.WriteLine("************* Create Token Result***************");
            Console.WriteLine(Newtonsoft.Json.JsonConvert.SerializeObject(result));


            ValidateModel validateModel = new ValidateModel();
            validateModel.issuer = "issuer";

            var verifyResult = module.VerifyToken(result.Content, secrect, validateModel);

            Console.WriteLine("************* Verify Token Result***************");
            Console.WriteLine(Newtonsoft.Json.JsonConvert.SerializeObject(verifyResult));

            Console.ReadKey();
        }
    }
}
