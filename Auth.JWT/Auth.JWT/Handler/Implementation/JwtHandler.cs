using Handler.Interface;
using Common;
using Model;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;

namespace Handler.Implementation
{
    class JwtHandler : IJwtHandler
    {
        dynamic IJwtHandler.BuildPayload(TokenRequestModel reqModel)
        {
            JwtPayload jwtModel = new JwtPayload();            
            try
            {
                DateTime currentDateTime = DateTime.UtcNow;
                jwtModel.iss = reqModel.issuer;
                jwtModel.iat = currentDateTime.ToString("yyyyMMddHHmmssfff");
                jwtModel.exp = currentDateTime.AddSeconds(Convert.ToDouble(reqModel.expiryInSeconds)).ToString("yyyyMMddHHmmssfff");
                jwtModel.user = reqModel.user;
                jwtModel.role = reqModel.role;
                jwtModel.customField1 = reqModel.customField1;
                jwtModel.customField2 = reqModel.customField2;
                jwtModel.customField3 = reqModel.customField3;
                jwtModel.customField4 = reqModel.customField4;
                jwtModel.customField5 = reqModel.customField5;
                
            }
            catch (Exception ex)
            {
                Util.ErrorBuilder(ex.Message);                
            }
            return jwtModel;
        }

        string IJwtHandler.CreateToken(dynamic payLoad, string secret)
        {
            try
            {
                var header = new JwtHeader
                {
                    Typ = AppConstant.Type,
                    Alg = AppConstant.Alg
                };

                string jwt = Util.Base64Encode(JsonConvert.SerializeObject(header))
                    + "."
                    + Util.Base64Encode(JsonConvert.SerializeObject(payLoad));
                jwt += "." + Util.ComputeSha256Hash(jwt, secret);

                return jwt;
            }
            catch (Exception ex)
            {
                Util.ErrorBuilder(ex.Message);
                return string.Empty;
            }
           
        }

        string IJwtHandler.EncryptToken(string jwtToken, string encryptionKey)
        {
            return Util.EncryptStringToBytesAes(jwtToken, encryptionKey, encryptionKey);
        }

        TokenResponseModel IJwtHandler.BuildResponse(string token)
        {
            TokenResponseModel tokenModel = new TokenResponseModel();
            if (String.IsNullOrWhiteSpace(Util.ErrorMessage))
            {
                tokenModel.Content = token;
                tokenModel.Status = AppConstant.Success;
            }
            else
            {
                tokenModel.Content = Util.ErrorMessage;
                tokenModel.Status = AppConstant.Failure;

                Util.ErrorMessage = null;
            }
            

            return tokenModel;

        }

        string IJwtHandler.DecryptToken(string encryptedToken, string encryptionKey)
        {
            return Util.DecryptStringFromBytesAes(encryptedToken, encryptionKey, encryptionKey);
        }

        dynamic IJwtHandler.ExtractToken(string token, string secret)
        {
            JwtPayload payloadObj = new JwtPayload();
            JwtHeader headerObj = new JwtHeader();

            try
            {
                string[] arr = token.Split('.');
                string strHeader = Util.Base64Decode(arr[0]);
                string strPayload = Util.Base64Decode(arr[1]);
                string strSignatureHashed = arr[2];

                headerObj = JsonConvert.DeserializeObject<JwtHeader>(strHeader);
                payloadObj = JsonConvert.DeserializeObject<JwtPayload>(strPayload);

                var strHashInput = Util.Base64Encode(JsonConvert.SerializeObject(headerObj))
                    + "."
                    + Util.Base64Encode(JsonConvert.SerializeObject(payloadObj));
                string generateHash = Util.ComputeSha256Hash(strHashInput, secret);

                if (strSignatureHashed != generateHash)
                {
                    Util.ErrorBuilder("Token Hash didnot match.");
                }
            }
            catch (Exception ex)
            {
                Util.ErrorBuilder(ex.Message);
                return null;
            }
           
            return payloadObj;
           
        }

        void IJwtHandler.ValidatePayload(JwtPayload payloadObj, ValidateModel validateModel = null)
        {
            if (payloadObj != null)
            {
                if (!String.IsNullOrWhiteSpace(payloadObj.exp) && DateTime.UtcNow >= DateTime.ParseExact(payloadObj.exp, "yyyyMMddHHmmssfff", CultureInfo.InvariantCulture))
                {
                    Util.ErrorBuilder("Token is Expired.");
                }

                if (validateModel != null)
                {
                    if (!String.IsNullOrWhiteSpace(validateModel.issuer) && validateModel.issuer != payloadObj.iss)
                    {
                        Util.ErrorBuilder("Issuer in the token and ValidateModel mismatch.");
                    }
                    if (!String.IsNullOrWhiteSpace(validateModel.user) && validateModel.user != payloadObj.user)
                    {
                        Util.ErrorBuilder("User in the token and ValidateModel mismatch.");
                    }
                    if (!String.IsNullOrWhiteSpace(validateModel.role) && validateModel.role != payloadObj.role)
                    {
                        Util.ErrorBuilder("Role in the token and ValidateModel mismatch.");
                    }
                }
            }
            else
            {
                Util.ErrorBuilder("Invalid Payload.");
            }
          
        }
    }
}
