// Test C# file with various security vulnerabilities for testing detection rules
using System;
using System.Data.SqlClient;
using System.Web;
using System.Xml;
using System.IO;
using System.Net.Http;
using System.Security.Cryptography;
using System.Runtime.Serialization.Formatters.Binary;
using System.Reflection;

namespace VulnerableCode
{
    public class SecurityTests
    {
        // SQL Injection vulnerabilities (Issue #215)
        public void SqlInjectionTest(string userInput)
        {
            string sql = string.Format("SELECT * FROM users WHERE name = '{0}'", userInput);
            string sql2 = "SELECT * FROM " + userInput;
            string sql3 = $"SELECT * FROM users WHERE id = {userInput}";
            
            SqlCommand cmd = new SqlCommand();
            cmd.CommandText = "SELECT * FROM users WHERE name = '" + userInput + "'";
        }

        // XSS vulnerabilities (Issue #216)
        public void XssTest(string userInput)
        {
            // In ASP.NET view
            // @Html.Raw(userInput)
            Response.Write("<div>" + userInput + "</div>");
            myDiv.InnerHtml = userInput;
        }

        // XXE vulnerabilities (Issue #218)  
        public void XxeTest()
        {
            XmlDocument doc = new XmlDocument();
            XmlReader reader = XmlReader.Create("user-input.xml");
            XPathDocument xpath = new XPathDocument("user-input.xml");
        }

        // XML Injection (Issue #234)
        public void XmlInjectionTest(string userInput)
        {
            string xml = string.Format("<user>{0}</user>", userInput);
            string xml2 = $"<response>{userInput}</response>";
            string xml3 = "<data>" + userInput + "</data>";
        }

        // CRLF Injection (Issue #239)
        public void CrlfInjectionTest(string userInput)
        {
            Response.AddHeader("Custom-Header", userInput);
            Response.Headers.Add("Location", userInput);
            HttpContext.Response.Headers["Set-Cookie"] = userInput;
        }

        // SSRF vulnerabilities (Issue #217)
        public async void SsrfTest(string url)
        {
            HttpClient client = new HttpClient();
            var response = await client.GetAsync(url);
            WebRequest request = WebRequest.Create(url);
            HttpWebRequest httpRequest = new HttpWebRequest(new Uri(url));
        }

        // Open Redirect (Issue #219) / Unvalidated Redirect (Issue #233)
        public void RedirectTest(string returnUrl)
        {
            Response.Redirect(returnUrl);
            return Redirect(returnUrl);
            return RedirectToAction(url);
            return new RedirectResult(returnUrl);
        }

        // CSRF vulnerabilities (Issue #222)
        [HttpPost]
        public ActionResult DeleteUser(int id)  // Missing [ValidateAntiForgeryToken]
        {
            return View();
        }

        [HttpDelete]
        public ActionResult Delete(int id) // Missing CSRF protection
        {
            return View();
        }

        // Hardcoded Secrets (Issue #220)
        public void HardcodedSecretsTest()
        {
            const string API_KEY = "sk-1234567890abcdef";
            private string password = "admin123";
            string connectionString = "Server=localhost;Database=test;User Id=sa;Password=password123;";
            static readonly string SECRET = "my-secret-key";
        }

        // Weak Cryptography (Issue #227)
        public void WeakCryptoTest()
        {
            MD5 md5 = MD5.Create();
            SHA1 sha1 = SHA1.Create();
            DESCryptoServiceProvider des = new DESCryptoServiceProvider();
            RC2CryptoServiceProvider rc2 = new RC2CryptoServiceProvider();
            Random rand = new Random(); // Weak for crypto use
        }

        // Weak Authentication (Issue #230)
        public bool WeakAuthTest(string password, string requestPassword)
        {
            if (password == requestPassword) return true; // Plain text comparison
            FormsAuthentication.SetAuthCookie("user", false);
            if (token.Length > 0) return true; // Insufficient validation
        }

        // Insecure Deserialization (Issue #221)
        public void InsecureDeserializationTest()
        {
            BinaryFormatter formatter = new BinaryFormatter();
            JavaScriptSerializer serializer = new JavaScriptSerializer();
            var result = JsonConvert.DeserializeObject<object>(userInput);
        }

        // Unsafe Reflection (Issue #226)
        public void UnsafeReflectionTest(string userInput)
        {
            Type type = Type.GetType(userInput);
            Assembly assembly = Assembly.LoadFrom(userInput);
            object instance = Activator.CreateInstance(type);
            MethodInfo method = type.GetMethod(userInput);
        }

        // Insecure File Permissions (Issue #231)
        public void FilePermissionsTest()
        {
            File.Create("/tmp/test.txt", 1024, FileOptions.None);
            Directory.CreateDirectory("/tmp/test");
            FileSystemAccessRule rule = new FileSystemAccessRule("Everyone", FileSystemRights.FullControl, AccessControlType.Allow);
        }

        // Unrestricted File Upload (Issue #232)
        public void FileUploadTest(HttpPostedFile file, IFormFile formFile)
        {
            file.SaveAs("/uploads/" + file.FileName);
            File.WriteAllBytes("/uploads/" + formFile.FileName, new byte[100]);
        }

        // Buffer Overflow (Issue #223)
        public unsafe void BufferOverflowTest()
        {
            fixed (byte* ptr = buffer)
            {
                Marshal.Copy(sourceArray, 0, ptr, sourceArray.Length);
            }
            byte* stackBuffer = stackalloc byte[1024];
        }

        // Race Condition (Issue #224)
        static int counter = 0;
        private static MyClass Instance;
        
        public void RaceConditionTest()
        {
            if (Instance == null) Instance = new MyClass();
            ++counter;
            Dictionary<string, int> dict = new Dictionary<string, int>();
        }

        // Integer Overflow (Issue #225)
        public void IntegerOverflowTest()
        {
            int result = int.MaxValue + 1;
            byte smallValue = (byte)intValue;
            unchecked(result = largeNumber * anotherLargeNumber);
            int converted = Convert.ToInt32(stringInput);
        }

        // Memory Leak (Issue #235)
        public void MemoryLeakTest()
        {
            SomeEvent += EventHandler; // Event not unsubscribed
            Timer timer = new Timer(callback, null, 0, 1000); // Not disposed
            FileStream stream = new FileStream("test.txt", FileMode.Open); // Not disposed
        }

        // Null Pointer Dereference (Issue #236)
        public void NullPointerTest()
        {
            int value = nullableInt.Value;
            string result = (obj as string).ToLower();
            string first = list.First().Name;
            char firstChar = array[0];
        }

        // Deadlock (Issue #237)
        public void DeadlockTest()
        {
            lock (lock1)
            {
                lock (lock2) { }
            }
            
            var result = asyncMethod().Result; // Can cause deadlock
            asyncMethod().Wait(); // Can cause deadlock
            Monitor.Enter(lockObject);
        }

        // Uncontrolled Recursion (Issue #238)
        public void RecursiveMethod(int depth)
        {
            return RecursiveMethod(depth + 1); // No depth limit
        }
        
        public void Process(Node node)
        {
            this.Process(node.Parent); // Self-recursive without limit
        }

        // Insufficient Logging (Issue #228)
        public ActionResult DeleteUser(int userId)
        {
            // Delete user without logging
            return View();
        }

        [Authorize(Roles = "Admin")]
        public ActionResult AdminAction()
        {
            // Admin action without logging
            return View();
        }

        // Improper Error Handling (Issue #229)
        public void ErrorHandlingTest()
        {
            try
            {
                // Some operation
            }
            catch (Exception ex)
            {
                Response.Write(ex.Message); // Exposes sensitive info
                throw ex; // Loses stack trace
            }
            
            try
            {
                // Another operation  
            }
            catch { } // Empty catch block
        }
    }
}