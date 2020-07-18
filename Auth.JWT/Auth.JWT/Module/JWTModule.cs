using Auth.JWT.Model;
using Common;
using Handler.Implementation;
using Handler.Interface;
using Model;

namespace Auth.JWT
{
    public class JWTModule
    {
        IJwtHandler jwtHandler = new JwtHandler();

        public TokenResponseModel CreateToken(TokenRequestModel reqModel, string secret, string algorithmKey)
        {
            Util.ErrorMessage = string.Empty;
            dynamic payload = jwtHandler.BuildPayload(reqModel);
            string jwtToken = jwtHandler.CreateToken(payload, secret, algorithmKey);
            var result = jwtHandler.BuildResponse(jwtToken);
            return result;
        }

        public TokenResponseModel VerifyToken(string token, string secret, ValidateModel validateModel = null)
        {
            Util.ErrorMessage = string.Empty;
            dynamic payLoadObj = jwtHandler.ExtractToken(token, secret);
            jwtHandler.ValidatePayload(payLoadObj, validateModel);
            var result = jwtHandler.BuildResponse(token);
            return result;
        }
        //public TokenResponseModel CreateTokenWithAes(TokenRequestModel reqModel, string secret, string encryptionKey)
        //{
        //    string strPayloadJson = jwtHandler.BuildPayload(reqModel);
        //    string jwtToken = jwtHandler.CreateToken(strPayloadJson, secret);
        //    string encryptedToken = jwtHandler.EncryptToken(jwtToken, encryptionKey);
        //    var result = jwtHandler.BuildResponse(encryptedToken);
        //    return result;
        //}

        //public TokenResponseModel VerifyTokenWithAes(string token, string secret, string decryptionKey)
        //{
        //    string jwtToken = jwtHandler.DecryptToken(token, decryptionKey);

        //    dynamic payLoadObj = jwtHandler.ExtractToken(jwtToken, secret);

        //    string validatedStr = jwtHandler.ValidatePayload(payLoadObj);
        //    var result = jwtHandler.BuildResponse(validatedStr);
        //    return result;
        //}
    }
}
