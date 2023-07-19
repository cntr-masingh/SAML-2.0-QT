using Microsoft.Practices.EnterpriseLibrary.Logging;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Data;
using System.Data.SqlClient;
using System.Diagnostics;
using System.Linq;
using System.Web;

namespace IdentityProvider.BusinessLogic
{
    public class DataObjects
    {
        List<LogEntry> lstLogEntry = new List<LogEntry>();
        public DataSet GetUserProfile(string userName, string studentId)
        {
            try
            {
                //  fillLogEntry("DataObjects_GetUserProfile", "started GetUserProfile function", TraceEventType.Information);
                SqlConnection conn = new SqlConnection(ConfigurationManager.ConnectionStrings["FosterPortalConnectionString"].ToString());
                SqlCommand cmd = new SqlCommand("SecureAuth_GetUserProfile", conn);
                cmd.CommandType = CommandType.StoredProcedure;
                cmd.Parameters.AddWithValue("@UserName", userName);
                cmd.Parameters.AddWithValue("@StudID", studentId);
                SqlDataAdapter da = new SqlDataAdapter(cmd);
                DataSet ds = new DataSet();
                da.Fill(ds);
                //   fillLogEntry("DataObjects_GetUserProfile", "finished GetUserProfile function", TraceEventType.Information);
                return ds;
            }
            catch (Exception ex)
            {
                fillLogEntry("DataObjects_GetUserProfile", "Error: " + ex.Message, TraceEventType.Error);
                return null;
            }

        }
        public void fillLogEntry(string title, string message, TraceEventType severity)
        {
            string currUserName = string.Empty;
            if (HttpContext.Current.Session["SSOUser"] != null)
                currUserName = HttpContext.Current.Session["SSOUser"].ToString();

            LogEntry objLog = new LogEntry()
            {
                Priority = -1,
                EventId = Convert.ToInt32(ConfigurationManager.AppSettings["applicationEventId"].ToString()),
                TimeStamp = DateTime.Now,
                Severity = severity,
                Title = currUserName + " - " + title,
                Message = message
            };
            if (HttpContext.Current.Session["LogList"] != null)
                lstLogEntry = (List<LogEntry>)HttpContext.Current.Session["LogList"];

            lstLogEntry.Add(objLog);
            HttpContext.Current.Session["LogList"] = lstLogEntry;
        }
    }
}