using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace PE.LdapManager
{
    public class LdapAttribut
    {
        public string name { get; }
        public List<byte[]> values { get; set; }

        public LdapAttribut(string name)
        {
            this.name = name;
            values = new List<byte[]>();
        }
        public LdapAttribut(string name,List<string> valuesAtt)
        {
            this.name = name;
            this.values = new List<byte[]>();
             Add(valuesAtt);

          
           
        }
        public LdapAttribut(string name, string value)
        {
            values = new List<byte[]>();
            this.name = name;
            Add(value);
        }
        public LdapAttribut(string name, string[] _values)
        {
            values = new List<byte[]>();
            this.name = name;
            foreach (string v in _values) Add(v);
        }

        public LdapAttribut(string name, int value)
        {
            values = new List<byte[]>();
            this.name = name; Add(value);
        }
        public LdapAttribut(string name, int[] _values)
        {
            values = new List<byte[]>();
            this.name = name;
            foreach (int v in _values) Add(v);
        }

        public LdapAttribut(string name, byte[] value)
        {
            values = new List<byte[]>();
            this.name = name; Add(value);
        }
        public LdapAttribut(string name, byte[][] _values)
        {
            values = new List<byte[]>();
            this.name = name;
            foreach (byte[] v in _values) Add(v);
        }

        public LdapAttribut(string name, X509Certificate2 value)
        {
            values = new List<byte[]>();
            this.name = name; Add(value);
        }
        public LdapAttribut(string name, X509Certificate2[] _values)
        {
            values = new List<byte[]>();
            this.name = name;
            foreach (X509Certificate2 v in _values) Add(v);
        }

        public string GetBase64()
        {
            return GetBase64(0);
        }
        public string GetBase64(int indice)
        {
            return (Convert.ToBase64String(values[indice]));
        }
        public void Add(String value) { this.Add(Encoding.UTF8.GetBytes(value)); }
        public void Add(List<String> values) {
            foreach(string value in values)
            {
                this.Add(Encoding.UTF8.GetBytes(value));
            }
         

        }
        public void Add(int value) { this.Add(Encoding.UTF8.GetBytes(value.ToString())); }
        public void Add(byte[] value) { if (!values.Contains(value)) values.Add(value); }
        public void Add(X509Certificate2 value) { this.Add(value.GetRawCertData()); }

        internal string GetJoinString(char sep)
        {
            List<String> lst = values.Select(e => Encoding.UTF8.GetString(e)).ToList();
            return String.Join(sep.ToString(), lst);
        }
        internal string GetJoinString()
        {
            return GetJoinString(',');
        }



        public void AddRange(byte[][] _values)
        {
            foreach (byte[] value in _values)
                values.Add(value);
        }


        public String GetString() { return GetString(0); }
        public String GetString(int idx) { return Encoding.UTF8.GetString(values[idx]); }
        internal List<string> ExistWithValue(string valeur) { return ExistWV(new String[] { valeur }, true); }
        internal List<string> ExistWithValue(string[] valeur) { return ExistWV(valeur, true); }
        internal List<string> NotExistWithValue(string valeur) { return ExistWV(new String[] { valeur }, false); }
        internal List<string> NotExistWithValue(string[] valeur) { return ExistWV(valeur, false); }

        private List<String> ExistWV(string[] valeur, bool exist)
        {
            List<String> valeurs = new List<string>();
            foreach (String st in this.GetTabString())
                foreach (String st2 in valeur)
                {
                    Boolean bExist = CompareWildcard(st, st2);
                    if (exist && bExist)
                        if (!valeurs.Contains(st))
                            valeurs.Add(st);
                    if (!exist && !bExist)
                        if (!valeurs.Contains(st2))
                            valeurs.Add(st2);
                }
            return valeurs;
        }

        internal bool IsPresent(string valeur)
        {
            foreach (String st in this.GetTabString())
            {
                if (st.Equals(valeur))
                    return true;
            }
            return false;
        }

        internal bool IsNotPresent(string valeur) { return !IsPresent(valeur); }
        public String[] GetTabString()
        {
            if (values != null)
                return values.Select(e => Encoding.UTF8.GetString(e)).ToArray();
            else
                return null;
        }

        public List<Byte[]> GetTabByte() { return values; }

        public List<X509Certificate2> GetTabX509()
        {
            List<X509Certificate2> lstCertif = new List<X509Certificate2>();
            if (values != null)
                return values.Select(e => new X509Certificate2(e)).ToList<X509Certificate2>();
            else
                return null;
        }

        public DateTime GetDate() { return GetDate(0); }

        public DateTime GetDate(int idx) { return DateTime.Parse(Encoding.UTF8.GetString(values[idx])); }

        public DateTime GetDate(String format) { return GetDate(0, format); }

        public DateTime GetDate(int idx, String format)
        {
            return DateTime.ParseExact(Encoding.UTF8.GetString(values[idx]),
                                       format,
                                        CultureInfo.InvariantCulture,
                                        DateTimeStyles.None);
        }

        internal void Clear() { values = new List<byte[]>(); }
        internal void SetValue(String obj) { Clear(); Add(obj); }
        internal void SetValue(X509Certificate2 obj) { Clear(); Add(obj); }
        internal void SetValue(byte[] obj) { Clear(); Add(obj); }
        internal void SetValue(int obj) { Clear(); Add(obj); }

        public static bool CompareWildcard(IEnumerable<char> input, string mask)
        {
            for (int i = 0; i < mask.Length; i++)
            {
                switch (mask[i])
                {
                    case '?':
                        if (!input.Any())
                            return false;

                        input = input.Skip(1);
                        break;
                    case '*':
                        while (input.Any() && !CompareWildcard(input, mask.Substring(i + 1)))
                            input = input.Skip(1);
                        break;
                    default:
                        if (!input.Any() || input.First() != mask[i])
                            return false;

                        input = input.Skip(1);
                        break;
                }
            }

            return !input.Any();
        }
    }
}
