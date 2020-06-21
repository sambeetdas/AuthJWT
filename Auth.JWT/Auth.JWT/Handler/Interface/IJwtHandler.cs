using Model;
using System;
using System.Collections.Generic;
using System.Text;

namespace Handler.Interface
{
    interface IJwtHandler
    {
        dynamic BuildPayload(TokenRequestModel reqModel);
        string CreateToken(dynamic payLoad, string secret);
        string EncryptToken(string jwtToken, string encryptionKey);
        TokenResponseModel BuildResponse(string token);
        string DecryptToken(string encryptedToken, string encryptionKey);
        dynamic ExtractToken(string token, string secret);
        void ValidatePayload(JwtPayload payloadObj, ValidateModel validateModel);
    }
}
