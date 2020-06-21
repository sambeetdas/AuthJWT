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
        public string user { get; set; }
        public string role { get; set; }
        public string customField1 { get; set; }
        public string customField2 { get; set; }
        public string customField3 { get; set; }
        public string customField4 { get; set; }
        public string customField5 { get; set; }
    }
}
