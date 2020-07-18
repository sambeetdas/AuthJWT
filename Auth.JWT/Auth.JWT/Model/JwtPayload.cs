using System;
using System.Collections.Generic;
using System.Text;

namespace Model
{
    class JwtPayload
    {
        public string iss { get; set; }
        public string iat { get; set; }
        public string exp { get; set; }
        public string userId { get; set; }
        public string user { get; set; }       
        public string role { get; set; }
        public string aud { get; set; }
        public string jwtId { get; set; }
        public string subject { get; set; }
        public string customProperty { get; set; }
    }
}
