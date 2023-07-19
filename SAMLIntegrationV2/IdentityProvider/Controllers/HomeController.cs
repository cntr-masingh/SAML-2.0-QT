using System;
using System.Collections.Generic;
using System.Configuration;
using System.Security.Cryptography.X509Certificates;
using System.Web;
using System.Web.Mvc;
using System.Web.Security;
using System.Xml;
using ComponentSpace.SAML2;
using ComponentSpace.SAML2.Protocols;
using ComponentSpace.SAML2.Assertions;
using System.Collections.Specialized;

namespace IdentityProvider.Controllers
{
    public class HomeController : Controller
    {
        [HttpGet]
        public String Index(string SAMLRequest)
        {
            HttpCookie authCookie;
            if (Request.IsAuthenticated && !string.IsNullOrEmpty(Request.Cookies[FormsAuthentication.FormsCookieName].Value))
                authCookie = Request.Cookies[FormsAuthentication.FormsCookieName];
            else
            {
                string[] cookArray = ConfigurationManager.AppSettings["authCookies"].ToString().Split(',');
                authCookie = GetValidAuthCookie(cookArray);
            }

            if (authCookie != null)
            {
                FormsAuthenticationTicket authTicket = FormsAuthentication.Decrypt(authCookie.Value);
                Session["SSOUser"] = authTicket.Name;//create session to store the username used to fetch membership on community.aspx
                string[] userInfo = authTicket.UserData.Split('|');
                Session["SSOStudentId"] = Convert.ToString(userInfo[0]);
            }
            return "";
        }

        private HttpCookie GetValidAuthCookie(string[] allowedCookie)
        {
            HttpCookie validCookie = null, cookie;
            FormsAuthenticationTicket authTicket;
            string[] userInfo;
            foreach(string item in allowedCookie)
            {
                cookie = Request.Cookies[item];
                if (cookie != null)
                {
                    authTicket = FormsAuthentication.Decrypt(cookie.Value);
                    userInfo = authTicket.UserData.Split('|');
                    if(!string.IsNullOrWhiteSpace(userInfo[0]) && !string.IsNullOrWhiteSpace(authTicket.Name))
                    {
                        validCookie = cookie;
                        break;
                    }
                }
            }
            return validCookie;
        }

        public void SAMLResponse()
        {
            NameValueCollection queryStrings = new NameValueCollection();
            queryStrings = Request.QueryString;
            string _signature = queryStrings["signature"];
            string Target = queryStrings["target"];
            string orgDefinedID = queryStrings["orgdefinedid"];
            string data = queryStrings.ToString();
            data = HttpUtility.UrlDecode(data.Substring(0, (data.IndexOf("signature=") - 1)));

            //if (Decryption.Decrypt(data, _signature, ConfigurationManager.AppSettings["DecKey"].ToString()))
            //{
                SendSAMLResponse(CreateSAMLResponseUsingConfiguraton(orgDefinedID), Target);
           // }
            //else
            //{
              //  Response.Write("Invalid Data");
            //}
        }

        private SAMLResponse CreateSAMLResponseUsingConfiguraton(string orgDefinedID)
        {
            int ValidHours = Convert.ToInt32(ConfigurationManager.AppSettings["SAMLRequestValidity"]);
            SAMLResponse samlResponse = new SAMLResponse();
            samlResponse.Destination = ConfigurationManager.AppSettings["GraderSSOAsserConsumingURL"].ToString();
            Issuer issuer = new Issuer(ConfigurationManager.AppSettings["GraderSSOIssuer"].ToString());
            samlResponse.Issuer = issuer;
            samlResponse.Status = new Status(SAMLIdentifiers.PrimaryStatusCodes.Success, null);

            SAMLAssertion samlAssertion = new SAMLAssertion();
            samlAssertion.Issuer = issuer;

            Subject subject = new Subject(new NameID(orgDefinedID));
            SubjectConfirmation subjectConfirmation = new SubjectConfirmation(SAMLIdentifiers.SubjectConfirmationMethods.Bearer);
            SubjectConfirmationData subjectConfirmationData = new SubjectConfirmationData();
            subjectConfirmationData.Recipient = ConfigurationManager.AppSettings["GraderSSOAsserConsumingURL"].ToString();
            subjectConfirmation.SubjectConfirmationData = subjectConfirmationData;
            subjectConfirmation.SubjectConfirmationData.NotOnOrAfter = DateTime.UtcNow + new TimeSpan(ValidHours, 0, 0);
            subject.SubjectConfirmations.Add(subjectConfirmation);
            samlAssertion.Subject = subject;

            Conditions conditions = new Conditions(DateTime.UtcNow, DateTime.UtcNow + new TimeSpan(ValidHours, 0, 0));

            AudienceRestriction audienceRestriction = new AudienceRestriction();

            audienceRestriction.Audiences.Add(new Audience(ConfigurationManager.AppSettings["GraderAudience"].ToString()));

            conditions.ConditionsList.Add(audienceRestriction);

            samlAssertion.Conditions = conditions;

            AuthnStatement authnStatement = new AuthnStatement();
            authnStatement.AuthnContext = new AuthnContext();
            authnStatement.AuthnContext.AuthnContextClassRef = new AuthnContextClassRef(SAMLIdentifiers.AuthnContextClasses.Password);
            samlAssertion.Statements.Add(authnStatement);


            X509Certificate2 x509Certificate = new X509Certificate2();
            X509Store store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
            store.Open(OpenFlags.ReadOnly);

            X509Certificate2Collection col = store.Certificates.Find(X509FindType.FindBySerialNumber, ConfigurationManager.AppSettings["CertificateSerialNumber"].ToString(), false);
            if (col.Count > 0)
            {
                x509Certificate = col[0];
            }
            else if (store.Certificates.Count > 0)
            {
                x509Certificate = store.Certificates[0];
            }

            XmlElement xmlSAMLAssertion = samlAssertion.ToXml();
            SAMLAssertionSignature.Generate(xmlSAMLAssertion, x509Certificate.PrivateKey, x509Certificate);
            samlResponse.Assertions.Add(xmlSAMLAssertion);
            return samlResponse;
        }

        private void SendSAMLResponse(SAMLResponse samlResponse, string relayState)
        {
            XmlElement samlResponseXml = samlResponse.ToXml();
            ComponentSpace.SAML2.Profiles.SSOBrowser.IdentityProvider.SendSAMLResponseByHTTPPost(Response, ConfigurationManager.AppSettings["GraderSSOAsserConsumingURL"].ToString(), samlResponseXml, relayState);
        }
        
        //Receives request
        private void ReceiveAuthnRequest(ref AuthnRequest authnRequest)
        {
            XmlElement authnRequestXml = null;
            bool signed = false;
            string relayState;
            ComponentSpace.SAML2.Profiles.SSOBrowser.IdentityProvider.ReceiveAuthnRequestByHTTPRedirect(Request, out authnRequestXml, out relayState, out signed, null);
            authnRequest = new AuthnRequest(authnRequestXml);
        }

        
        //service provider gets the request
        public void GetServiceProvider()
        {
            bool isInResponseTo = false;
            string partnerIdP = null;
            string userName = null;
            IDictionary<string, string> attributes = null;
            string targetUrl = null;
            string authContext = null;

            
            SAMLServiceProvider.ReceiveSSO(Request, out isInResponseTo, out partnerIdP, out authContext, out userName, out attributes, out targetUrl);

            
            if (targetUrl == null)
            {
                targetUrl = "~/";
            }
            FormsAuthentication.SetAuthCookie(userName, false);
            Session["Attributes"] = attributes;
            Response.Redirect(targetUrl, false);
        }
    }
}