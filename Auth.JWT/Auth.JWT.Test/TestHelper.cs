using Auth.JWT.Model;
using Model;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Auth.JWT.Test
{
    public static class TestHelper
    {
        public static TokenRequestModel GetTokenRequestModel_Positive()
        {
            TokenRequestModel reqModel = new TokenRequestModel()
            {
                Issuer = "authjwt_team",
                ExpiryInSeconds = "1000",
                UserId = "U132432",
                User = "sambeet",
                Role = "admin",
                Audience = "authjwt_app",
                JwtId = "J4433421",
                Subject = "authjwt_subject",
                CustomProperty = new Dictionary<string, string>()
            };
            reqModel.CustomProperty.Add("CustomField1", "auth_custom1");
            reqModel.CustomProperty.Add("CustomField2", "auth_custom2");
            return reqModel;
        }

        public static ValidateModel GetValidateModel_Positive()
        {
            ValidateModel validateModel = new ValidateModel()
            {
                Issuer = "authjwt_team",
                UserId = "U132432",
                User = "sambeet",
                Role = "admin",
                Audience = "authjwt_app",
                JwtId = "J4433421",
                Subject = "authjwt_subject",
                CustomProperty = new Dictionary<string, string>()
            };
            validateModel.CustomProperty.Add("CustomField1", "auth_custom1");
            validateModel.CustomProperty.Add("CustomField2", "auth_custom2");
            return validateModel;
        }

        public static string GetJwtSecrect1()
        {
            return "F4760D";
        }

        public static string GetJwtSecrect2()
        {
            return "M4760E";
        }
    }
}
