using System;
using Microsoft.AspNetCore.Authentication;

namespace ApiKeyAuthentication.Authentication
{
    public class ApiKeyAuthenticationOptions : AuthenticationSchemeOptions
    {
        public const string DefaultScheme = "API Key";
        public static string Scheme => DefaultScheme;
        
    }
}

