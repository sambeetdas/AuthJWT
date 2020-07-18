using System;
using System.Collections.Generic;
using System.Text;

namespace Auth.JWT.Model
{
    public class TokenRequestModel
    {
        public TokenRequestModel()
        {
            CustomProperty = new Dictionary<string, string>();
        }
        public string Issuer { get; set; }
        public string ExpiryInSeconds { get; set; }
        public string UserId { get; set; }
        public string User { get; set; }
        public string Role { get; set; }
        public string Audience { get; set; }
        public string JwtId { get; set; }
        public string Subject { get; set; }
        public Dictionary<string,string> CustomProperty { get; set; }
    }
}
