using System;
using System.Collections.Generic;
using System.Text;

namespace PE.LdapManager
{
    class DnObj
    {
        public string BaseDn;
        public string Name;
        public string TypeName;
        public string Filter;

        public static DnObj Parse(string dn)
        {
            DnObj dnObj = new DnObj();
          
               
                int idx = dn.IndexOf(',');
                dnObj.BaseDn = dn.Substring(idx + 1);
            //if(dnObj.BaseDn=="Comptes")
            //{

            //    dnObj.BaseDn = dn;
            //    dnObj.Filter = "(ObjectClass = *)";
            //}
            //else
            //{
                dnObj.Filter = $"({dn.Substring(0, idx)})";
                int idx2 = dnObj.Filter.IndexOf('=');
                dnObj.Name = dnObj.Filter.Substring(idx2 + 1);
                dnObj.Name = dnObj.Name.Substring(0, dnObj.Name.Length - 1);
                dnObj.TypeName = dnObj.Filter.Substring(1, idx2 - 1);
            //}
               
            return dnObj;
        }
    }
}
