using PE.LdapManager;
using System;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Net;
using System.Text;

namespace PE.LdapManager
{
    public class LdapObj
    {
        public string name { get; }
        public string dn { get; set; }
        public string mainAttrib { get; }
        public Dictionary<String, LdapAttribut> ldapAttributs { get; }

        public LdapObj()
        {

        }
        public void SetDn(String newDn)
        {
            dn = newDn;
        }
        public LdapObj(String dn)
        {
            this.dn = dn;
            name = dn.Split(',')[0].Split('=')[1];
            mainAttrib = dn.Split(',')[0].Split('=')[0];
            ldapAttributs = new Dictionary<String, LdapAttribut>(StringComparer.InvariantCultureIgnoreCase);
        }

        public LdapObj(String dnRoot, String mainAttrib, String valueAttrib)
        {
            name = valueAttrib;
            this.mainAttrib = mainAttrib;
            ldapAttributs = new Dictionary<String, LdapAttribut>();
            dn = String.Format("{0}={1},{2}", mainAttrib, valueAttrib, dnRoot);
        }
        public void AddLdapAttribut(string name, byte[] values)
        {
            if (!ldapAttributs.ContainsKey(name))

                ldapAttributs.Add(name, new LdapAttribut(name, values));
            else
            {
                ldapAttributs[name].Add(values);

            }
        }
        public void AddLdapAttribut(string name, string value)
        {
            if (!ldapAttributs.ContainsKey(name))

                ldapAttributs.Add(name, new LdapAttribut(name, value));
            else
            {
                ldapAttributs[name].Add(value);

            }
        }
        public void AddLdapAttribut(string name, params string[] attributs)
        { AddLdapAttribut(name, attributs.ToList());
        }
        public void AddLdapAttribut(string name, List<string> values)
        {
            
            if (ldapAttributs != null && !ldapAttributs.ContainsKey(name))
            {
                LdapAttribut ldapAttribut = new LdapAttribut(name, values);
                ldapAttributs.Add(name, ldapAttribut);
            }
            else
            {
                ldapAttributs[name].Add(values);

            }
        }
        internal void AddLdapAttribut(LdapAttribut ldapAttribut)
        {

            if (ldapAttributs.ContainsKey(ldapAttribut.name))
                ldapAttributs[ldapAttribut.name].AddRange(ldapAttribut.values.ToArray());
            else
            {
                ldapAttributs.Add(ldapAttribut.name, ldapAttribut);
            }
        }


        internal Boolean HasAttribut(String name)
        {
            return ((ldapAttributs.ContainsKey(name)) && (ldapAttributs[name].values.Count > 0));
        }

        internal String GetJoinString(String attributName)
        {

            List<String> lstV = new List<string>();
            if (ldapAttributs.ContainsKey(attributName))
            {
                LdapAttribut ldapAttribut = ldapAttributs[attributName];
                return ldapAttribut.GetJoinString();

            }
            return String.Empty;
        }

        internal String[] GetTabString(String attributName)
        {

            List<String> lstV = new List<string>();
            if (ldapAttributs.ContainsKey(attributName))
            {
                LdapAttribut ldapAttribut = ldapAttributs[attributName];
                return ldapAttribut.GetTabString();

            }
            return null;
        }

        public List<string> ExistAttributWithValue(string attributName, string valeur)
        {
            if (ldapAttributs.ContainsKey(attributName))
                return ldapAttributs[attributName].ExistWithValue(valeur);
            else
                return null;
        }

        public List<string> ExistAttributWithValue(string attributName, string[] valeur)
        {
            if (ldapAttributs.ContainsKey(attributName))
                return ldapAttributs[attributName].ExistWithValue(valeur);
            else
                return new List<string>();
        }

        public List<string> NotExistAttributWithValue(string attributName, string valeur)
        {

            if (ldapAttributs.ContainsKey(attributName))
                return ldapAttributs[attributName].NotExistWithValue(valeur);
            else
                return null;
        }

        public List<string> NotExistAttributWithValue(string attributName, string[] valeur)
        {
            if (ldapAttributs.ContainsKey(attributName))
                return ldapAttributs[attributName].NotExistWithValue(valeur);
            else
                return valeur.ToList();
        }
        internal LdapAttribut GetAttributs(string attributName)
        {
            foreach (KeyValuePair<String, LdapAttribut> kp in ldapAttributs)
                if (kp.Key.Equals(attributName, StringComparison.OrdinalIgnoreCase))
                    return kp.Value;

            return null;
        }

        internal List<String> GetAttributNames()
        {
            return ldapAttributs.Keys.ToList<String>();
        }

        internal bool IsPresent(string attributName, String valeur)
        {
            if (ldapAttributs.ContainsKey(attributName))
                return ldapAttributs[attributName].IsPresent(valeur);
            else
                return false;
        }

        internal bool IsNotPresent(string attributName, String valeur)
        {
            if (ldapAttributs.ContainsKey(attributName))
                return ldapAttributs[attributName].IsNotPresent(valeur);
            else
                return true;
        }

       
    }
}
