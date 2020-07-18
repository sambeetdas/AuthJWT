 using Handler.Interface;
using Common;
using Model;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;
using Auth.JWT.Model;
using Auth.JWT.Common;
using System.Linq;

namespace Handler.Implementation
{
    class JwtHandler : IJwtHandler
    {
        internal delegate string AlgorithDelegate(string str, string key);
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
                jwtModel.customProperty = Util.ConvertObjectToJson(reqModel.CustomProperty);                
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

                string jwt = Util.Base64Encode(Util.ConvertObjectToJson(header))
                    + "."
                    + Util.Base64Encode(Util.ConvertObjectToJson(payLoad));
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

                headerObj = Util.ConvertJsonToObject<JwtHeader>(strHeader);
                payloadObj = Util.ConvertJsonToObject<JwtPayload>(strPayload);

                string algoritmType = headerObj.Alg;
                AlgorithDelegate algoritmFunction = Util.ComputeSha256Hash;

                Util.ComputeAlgorithm(algoritmType, ref algoritmFunction);

                var strHashInput = Util.Base64Encode(Util.ConvertObjectToJson(headerObj))
                    + "."
                    + Util.Base64Encode(Util.ConvertObjectToJson(payloadObj));
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
                        Util.ErrorBuilder("Issuer mismatch");
                    }
                    if (!String.IsNullOrWhiteSpace(validateModel.User) && validateModel.User != payloadObj.user)
                    {
                        Util.ErrorBuilder("User mismatch");
                    }
                    if (!String.IsNullOrWhiteSpace(validateModel.UserId) && validateModel.UserId != payloadObj.userId)
                    {
                        Util.ErrorBuilder("UserId mismatch");
                    }
                    if (!String.IsNullOrWhiteSpace(validateModel.Role) && validateModel.Role != payloadObj.role)
                    {
                        Util.ErrorBuilder("Role mismatch");
                    }
                    if (!String.IsNullOrWhiteSpace(validateModel.Audience) && validateModel.Audience != payloadObj.aud)
                    {
                        Util.ErrorBuilder("Audience mismatch");
                    }
                    if (!String.IsNullOrWhiteSpace(validateModel.JwtId) && validateModel.JwtId != payloadObj.jwtId)
                    {
                        Util.ErrorBuilder("JwtId mismatch");
                    }
                    if (!String.IsNullOrWhiteSpace(validateModel.Subject) && validateModel.Subject != payloadObj.subject)
                    {
                        Util.ErrorBuilder("Subject mismatch");
                    }
                    if (validateModel.CustomProperty != null && !String.IsNullOrWhiteSpace(payloadObj.customProperty))
                    {
                        var payLoadCustomProperty = Util.ConvertJsonToObject<Dictionary<string, string>>(payloadObj.customProperty);
                        var CompareResult = validateModel.CustomProperty.Except(payLoadCustomProperty).ToDictionary(x => x.Key, x => x.Value);
                        if (CompareResult != null && CompareResult.Count > 0)
                        {
                            foreach (var customKey in CompareResult)
                            {
                                Util.ErrorBuilder($"CustomProperty: '{customKey.Key}' mismatch");
                            }
                            
                        }
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
