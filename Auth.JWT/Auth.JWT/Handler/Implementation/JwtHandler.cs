using Handler.Interface;
using Common;
using Model;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;
using Auth.JWT.Model;
using Auth.JWT.Common;

namespace Handler.Implementation
{
    class JwtHandler : IJwtHandler
    {
        public delegate string AlgorithDelegate(string str, string key);
        dynamic IJwtHandler.BuildPayload(TokenRequestModel reqModel)
        {
            JwtPayload jwtModel = new JwtPayload();            
            try
            {
                DateTime currentDateTime = DateTime.UtcNow;
                jwtModel.iss = reqModel.Issuer;
                jwtModel.iat = currentDateTime.ToString("yyyyMMddHHmmssfff");
                jwtModel.exp = currentDateTime.AddSeconds(Convert.ToDouble(reqModel.ExpiryInSeconds)).ToString("yyyyMMddHHmmssfff");
                jwtModel.userId = reqModel.UserId;
                jwtModel.user = reqModel.User;
                jwtModel.role = reqModel.Role;
                jwtModel.aud = reqModel.Audience;
                jwtModel.jwtId = reqModel.JwtId;
                jwtModel.subject = reqModel.Subject;
                jwtModel.customField1 = reqModel.CustomField1;
                jwtModel.customField2 = reqModel.CustomField2;
                jwtModel.customField3 = reqModel.CustomField3;
                jwtModel.customField4 = reqModel.CustomField4;
                jwtModel.customField5 = reqModel.CustomField5;
                
            }
            catch (Exception ex)
            {
                Util.ErrorBuilder(ex.Message);                
            }
            return jwtModel;
        }

        string IJwtHandler.CreateToken(dynamic payLoad, string secret, string algorithmKey)
        {
            try
            {
                string algoritmType = AlgorithmType.SHA256;
                if (!String.IsNullOrWhiteSpace(algorithmKey))
                {
                    algoritmType = algorithmKey;
                }                
                AlgorithDelegate algoritmFunction = Util.ComputeSha256Hash;
                Util.ComputeAlgorithm(algoritmType, ref algoritmFunction);
                var header = new JwtHeader
                {
                    Typ = AppConstant.Type,
                    Alg = algoritmType
                };

                string jwt = Util.Base64Encode(JsonConvert.SerializeObject(header))
                    + "."
                    + Util.Base64Encode(JsonConvert.SerializeObject(payLoad));
                jwt += "." + algoritmFunction(jwt, secret);

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

                string algoritmType = headerObj.Alg;
                AlgorithDelegate algoritmFunction = Util.ComputeSha256Hash;

                Util.ComputeAlgorithm(algoritmType, ref algoritmFunction);

                var strHashInput = Util.Base64Encode(JsonConvert.SerializeObject(headerObj))
                    + "."
                    + Util.Base64Encode(JsonConvert.SerializeObject(payloadObj));
                string generateHash = algoritmFunction(strHashInput, secret);

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
                    if (!String.IsNullOrWhiteSpace(validateModel.Issuer) && validateModel.Issuer != payloadObj.iss)
                    {
                        Util.ErrorBuilder("Issuer in the token and ValidateModel mismatch.");
                    }
                    if (!String.IsNullOrWhiteSpace(validateModel.User) && validateModel.User != payloadObj.user)
                    {
                        Util.ErrorBuilder("User in the token and ValidateModel mismatch.");
                    }
                    if (!String.IsNullOrWhiteSpace(validateModel.UserId) && validateModel.UserId != payloadObj.userId)
                    {
                        Util.ErrorBuilder("User Id in the token and ValidateModel mismatch.");
                    }
                    if (!String.IsNullOrWhiteSpace(validateModel.Role) && validateModel.Role != payloadObj.role)
                    {
                        Util.ErrorBuilder("Role in the token and ValidateModel mismatch.");
                    }
                    if (!String.IsNullOrWhiteSpace(validateModel.Audience) && validateModel.Audience != payloadObj.aud)
                    {
                        Util.ErrorBuilder("Audience in the token and ValidateModel mismatch.");
                    }
                    if (!String.IsNullOrWhiteSpace(validateModel.JwtId) && validateModel.JwtId != payloadObj.jwtId)
                    {
                        Util.ErrorBuilder("JwtId in the token and ValidateModel mismatch.");
                    }
                    if (!String.IsNullOrWhiteSpace(validateModel.Subject) && validateModel.Subject != payloadObj.subject)
                    {
                        Util.ErrorBuilder("Subject in the token and ValidateModel mismatch.");
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
