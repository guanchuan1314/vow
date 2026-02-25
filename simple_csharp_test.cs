using System;

class SimpleTest 
{
    void SqlTest()
    {
        string.Format("SELECT * FROM users");
    }
    
    void XssTest()  
    {
        Response.Write("test");
    }
    
    void SecretTest()
    {
        const string API_KEY = "test123";
    }
}