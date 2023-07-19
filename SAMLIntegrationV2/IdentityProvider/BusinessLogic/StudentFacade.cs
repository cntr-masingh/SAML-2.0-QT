using System;
using System.Collections.Generic;
using System.Data;
using System.Linq;
using System.Web;

namespace IdentityProvider.BusinessLogic
{
    public class StudentFacade
    {
        private DataObjects userDao = new DataObjects();
        public DataSet GetUserProfile(string userName, string studentId = "")
        {
            DataSet ds = userDao.GetUserProfile(userName, studentId);
            return ds;
        }

    }
}