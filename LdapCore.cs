using PE.LdapManager;
using System;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;

namespace PE.LdapManager
{
    public class LdapCore : IDisposable
    {
        
        private LdapConnection ldapConnexion;

        public String domain { get; set; }
        public String username { get; set; }
        public String password { get; set; }
        public String url { get; set; }
        private String hostName { get; set; }

        public int ldapPort { get; set; }

        private bool ldapSSLConnect = false;
        private int nbTryBinding = 3;
        private bool bindingSuccess = false;
        private bool disposed = false;
        public LdapCore()
        {
            
        }

        public LdapCore(String url, String svcName, String svcPassword)
        {
            this.url = url;
            this.username = svcName;
            this.password = svcPassword;

            ldapSSLConnect = url.ToUpper().StartsWith("LDAPS://");
            int posSS = url.IndexOf("//");
            int pos2p = url.IndexOf(":", posSS);
            int posS = url.IndexOf("/", pos2p);
            hostName = url.Substring(posSS + 2, pos2p - posSS - 2);
            if (posS == -1)
                ldapPort = Convert.ToInt32(url.Substring(pos2p + 1));
            else
                ldapPort = Convert.ToInt32(url.Substring(pos2p + 1, posS - pos2p - 1));
        }

        public bool isConnected()
        {
            return bindingSuccess;
        }
        #region Connexion
        private void Connect2()
        {
            if (!bindingSuccess)
                Connect();
        }
        public void Connect()
        {
            ldapConnexion = new LdapConnection(new LdapDirectoryIdentifier(hostName, ldapPort, false, false));
            ldapConnexion.SessionOptions.ProtocolVersion = 3;
            ldapConnexion.Timeout = TimeSpan.FromSeconds(120);
            String[] tb = username.Split('\\');
            if (tb.Count()<2)
                ldapConnexion.Credential = new System.Net.NetworkCredential(username, password);
            else
                ldapConnexion.Credential = new System.Net.NetworkCredential(tb[1], password, tb[0]);

            if (ldapSSLConnect)
            {
                ldapConnexion.SessionOptions.SecureSocketLayer = true;
                ldapConnexion.SessionOptions.VerifyServerCertificate = new VerifyServerCertificateCallback(ServerCallback);
            }

            ldapConnexion.AuthType = AuthType.Basic;

            int bindingTry = 0;
            while (!bindingSuccess && bindingTry < nbTryBinding)
            {
                try
                {
                    Console.WriteLine(String.Format("Starting Binding {0} to {1} ...", bindingTry, hostName));
                    ldapConnexion.Bind();


                    bindingSuccess = true;
                    Console.WriteLine("Binded ...");
                }
                catch (LdapException ex)
                {
                    Console.WriteLine(String.Format("Error LdapException Binding {0} to {1} ...", bindingTry, hostName));
                    Console.WriteLine(ex.StackTrace);

                }
                catch (DirectoryOperationException ex)
                {
                    Console.WriteLine(String.Format("Error DirectoryOperationException Binding {0} to {1} ...", bindingTry, hostName));
                    Console.WriteLine(ex.StackTrace);
                }
                catch (Exception ex)
                {
                    Console.WriteLine(String.Format("Error Exception Binding {0} to {1} ...", bindingTry, hostName));
                    Console.WriteLine(ex.StackTrace);


                }
                finally
                {
                    if (!bindingSuccess)
                    {
                        if (bindingTry == nbTryBinding)
                        {
                            if (bindingTry == nbTryBinding)
                                throw new Exception("ERROR_CONNECT_APE");
                        }

                        Console.WriteLine(String.Format("Tentative avec l'IP :{0}", hostName));
                        Thread.Sleep(200);
                    }
                    bindingTry++;
                }
            }

        }
        public void Disconnect()
        {
            bindingSuccess = false;
            if (ldapConnexion != null)
                ldapConnexion.Dispose();
        }
        public bool ServerCallback(LdapConnection connection, X509Certificate certificate)
        {
            return true;
        }
        #endregion

        #region Recherche Objets 

        public String findDnOne(String baseDn, String ldapFilter)
        {
            List<string> lstDn = findDn(baseDn, ldapFilter);
            if ((lstDn != null ) && (lstDn.Count>0))
            {
                return lstDn[0];
            }
            return null;
        }
        public LdapObj SearchDnOne(String baseDn, String ldapFilter, String[] attribs = null)
        {
            List<LdapObj> lstObjects = SearchDn( baseDn,  ldapFilter, attribs);
            if ((lstObjects != null) && (lstObjects.Count > 0))
            {
                return lstObjects[0];
            }
            return null;
        }
        public LdapObj SearchDnOne(String baseDn, String ldapFilter, System.DirectoryServices.Protocols.SearchScope scope, String[] attribs)
        {
            List<LdapObj> lstObjects = SearchDn(baseDn, ldapFilter, scope, attribs);
            if ((lstObjects != null) && (lstObjects.Count > 0))
            {
                return lstObjects[0];
            }
            return null;
        }
        public List<String> findDn(String baseDn, String ldapFilter)
        {
            List<String> lstDn = new List<string>();

            if (!bindingSuccess)
                Connect();
            string dnUser = String.Empty;

            System.DirectoryServices.Protocols.SearchScope scope = System.DirectoryServices.Protocols.SearchScope.Subtree;
            try
            {
                String dn;
                SearchRequest request = new SearchRequest(baseDn, ldapFilter, scope);
                SearchResponse response = (SearchResponse)ldapConnexion.SendRequest(request);
                if (response.Entries.Count > 0)
                {
                    for (int i = 0; i < response.Entries.Count; i++)
                    {
                        dn = response.Entries[i].DistinguishedName;
                        //Console.WriteLine(dn);
                        lstDn.Add(dn);
                    }
                }

            }
            catch (LdapException ex)
            {
                Console.WriteLine(String.Format("Error LdapException FindPeDateMajCert {0}...", ex.Message));
                Console.WriteLine(ex.StackTrace);
                throw ex;
            }
            catch (DirectoryOperationException ex)
            {
                Console.WriteLine(String.Format("Error DirectoryOperationException FindPeDateMajCert {0}...", ex.Message));
                Console.WriteLine(ex.StackTrace);
                throw ex;
            }
            catch (Exception ex)
            {
                Console.WriteLine(String.Format("Error Exception FindPeDateMajCert {0}...", ex.Message));
                Console.WriteLine(ex.StackTrace);
                throw ex;
            }


            return lstDn;
        }

        public List<LdapObj> SearchDn(String baseDn, String ldapFilter, String[] attribs = null)
        {
            return SearchDn(baseDn, ldapFilter, System.DirectoryServices.Protocols.SearchScope.Subtree, attribs);
        }
        private List<LdapObj> SearchDn(String baseDn, String ldapFilter, System.DirectoryServices.Protocols.SearchScope scope, String[] attribs)
        {
            List<LdapObj> lstLdapObj = null;
            try
            {
                if (!bindingSuccess)
                    Connect();
                if (attribs != null)
                    for (int i = 0;i<attribs.Length;i++)
                        attribs[i] = attribs[i].Trim();
                SearchRequest request;
                if (attribs == null)
                    request = new SearchRequest(baseDn, ldapFilter, scope);
                else
                    request = new SearchRequest(baseDn, ldapFilter, scope, attribs);
           
                SearchResponse result = (SearchResponse)ldapConnexion.SendRequest(request);
                if ((result != null) && result.Entries.Count > 0)
                {
                    lstLdapObj = new List<LdapObj>();

                    foreach (SearchResultEntry sResult in result.Entries)
                    {
                        String dn = sResult.DistinguishedName;
                        LdapObj ldapObj = new LdapObj(dn);
                        if (attribs != null)
                            foreach (String attr in attribs)
                                ldapObj.AddLdapAttribut(new LdapAttribut(attr));

                        foreach (DirectoryAttribute attribute in sResult.Attributes.Values)
                        {
                            /*Console.WriteLine(attribute.Name + " ==> " + attribute.Count);
                            if (attribute.Name.Equals("objectClass"))
                                Console.WriteLine(attribute.Name + " ==> " + attribute.Count);
                                */
                            LdapAttribut ldapAttribut = new LdapAttribut(attribute.Name);
                            ldapAttribut.AddRange((byte[][])attribute.GetValues(typeof(byte[])));
                            ldapObj.AddLdapAttribut(ldapAttribut);
                        }
                        lstLdapObj.Add(ldapObj);
                    }
                }
                return lstLdapObj;
            }
            catch (LdapException ex)
            {
                Console.WriteLine(String.Format("Error LdapException FindPeDateMajCert {0}...", ex.Message));
                Console.WriteLine(ex.StackTrace);
                throw ex;
            }
            catch (DirectoryOperationException ex)
            {
                Console.WriteLine(String.Format("Error DirectoryOperationException FindPeDateMajCert {0}...", ex.Message));
                Console.WriteLine(ex.StackTrace);
                throw ex;
            }
            catch (Exception ex)
            {
                Console.WriteLine(String.Format("Error Exception FindPeDateMajCert {0}...", ex.Message));
                Console.WriteLine(ex.StackTrace);
                throw ex;
            }
        }
        #endregion

        #region Ajout Objets
        public void AddDn(LdapObj ldapObj)
        {
            
            List<DirectoryAttribute> dirAttribs = new List<DirectoryAttribute>();
            foreach (KeyValuePair<String, LdapAttribut> ldapAttribut in ldapObj.ldapAttributs)
            {
                if (ldapAttribut.Value.values.Count > 0)
                {
                    foreach (Byte[] tb in ldapAttribut.Value.values)
                        Console.WriteLine(ldapAttribut.Key + " <=> " + Encoding.UTF8.GetString(tb));
                    dirAttribs.Add(new DirectoryAttribute(ldapAttribut.Key, ldapAttribut.Value.values.ToArray()));
                }
            }

            // create an addrequest object
            AddRequest addRequest = new AddRequest(ldapObj.dn, dirAttribs.ToArray());

            Connect2();
            try
            {
                AddResponse addreponse = ldapConnexion.SendRequest(addRequest) as AddResponse;
            }
            catch (DirectoryOperationException e)
            {
                Console.WriteLine(e.Message);
                throw e;
            }
        }

        public void AddDn(String dn)
        {

            // create an addrequest object
            AddRequest addRequest = new AddRequest(dn);
            if (!bindingSuccess)
                Connect();
            try
            {
                ldapConnexion.SendRequest(addRequest);
            }
            catch (DirectoryOperationException e)
            {
                Console.WriteLine(e.Message);
                throw e;
            }
        }

        public void AddDn(string dnRoot, string attrMain, string valueMain, List<LdapAttribut> lstLdapAttribut)
        {
            AddDn(String.Format("{0}={1},{2}", attrMain, valueMain, dnRoot), lstLdapAttribut);
        }




        public void AddDn(string dn, List<LdapAttribut> lstLdapAttribut)
        {
            List<DirectoryAttribute> dirAttribs = new List<DirectoryAttribute>();
            foreach (LdapAttribut ldapAttribut in lstLdapAttribut)
                dirAttribs.Add(new DirectoryAttribute(ldapAttribut.name, ldapAttribut.values.ToArray()));

            // create an addrequest object
            AddRequest addRequest = new AddRequest(dn, dirAttribs.ToArray());
            if (!bindingSuccess)
                Connect();
            try
            {
                ldapConnexion.SendRequest(addRequest);
            }
            catch (DirectoryOperationException e)
            {
                Console.WriteLine(e.Message);
                throw e;
            }
        }

        #endregion

        #region Suppresion Objets
        public void DeleteDn(string dn)
        {
            try
            {
                  Connect2();
                LdapObj ldapObj = ReadDn(dn,"cn");
                if (ldapObj != null)
                {
                    DeleteRequest deleteRequest = new DeleteRequest(dn);
                    DeleteResponse deleteResponse = (DeleteResponse)ldapConnexion.SendRequest(deleteRequest);
                }
            }
            catch (DirectoryOperationException e)
            {
                Console.WriteLine(e.Message);
            //    throw e;
            }
        }
        #endregion

     
        #region Read Objet

        public bool ExistDn(string dn)
        {
            SearchRequest request;
            try
            {
                Connect2();
                DnObj dnObj = DnObj.Parse(dn);
                request = new SearchRequest(dnObj.BaseDn, dnObj.Filter, SearchScope.Subtree);
                SearchResponse result = (SearchResponse)ldapConnexion.SendRequest(request);
                return ((result != null) && result.Entries.Count > 0);
            }
            catch (LdapException ex)
            {
                Console.WriteLine(String.Format("Error LdapException FindPeDateMajCert {0}...", ex.Message));
                Console.WriteLine(ex.StackTrace);
                throw ex;
            }
            catch (DirectoryOperationException ex)
            {
                Console.WriteLine(String.Format("Error DirectoryOperationException FindPeDateMajCert {0}...", ex.Message));
                Console.WriteLine(ex.StackTrace);
                throw ex;
            }
            catch (Exception ex)
            {
                Console.WriteLine(String.Format("Error Exception FindPeDateMajCert {0}...", ex.Message));
                Console.WriteLine(ex.StackTrace);
                throw ex;
            }
        }

        public LdapObj ReadDn(String dn, String attrib)
        {
            return ReadDn(dn, new string[] { attrib });
        }
        public LdapObj ReadDn(String dn, String[] attribs = null)
        {
            DnObj dnObj = DnObj.Parse(dn);
            List<LdapObj> lstLdapObj = SearchDn(dnObj.BaseDn, dnObj.Filter, SearchScope.OneLevel, attribs);
            if ((lstLdapObj != null) && lstLdapObj.Count > 0)
                return lstLdapObj[0];

            return null;
        }

        #endregion

        #region Opérations Attribut

        public LdapAttribut GetAttributs(String dn, String attribut)
        {
            List<LdapAttribut> lstAtrr = GetAttributs(dn, new String[] { attribut });
            if (lstAtrr != null)
                return lstAtrr[0];
            else
                return null;

        }
        public List<LdapAttribut> GetAttributs(String dn, List<LdapAttribut> ldapAttributs)
        {
            return GetAttributs(dn, ldapAttributs.Select(x => x.name).ToArray());
        }

        public List<LdapAttribut> GetAttributs(String dn, String[] attributs)
        {
            try
            {
                DnObj dnObj = DnObj.Parse(dn);
                List<LdapObj> lstObj = SearchDn(dnObj.BaseDn, dnObj.Filter, SearchScope.OneLevel, attributs);
                if (lstObj.Count > 0)
                    return lstObj[0].ldapAttributs.Select(e => e.Value).ToList();

            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                throw ex;
            }
            return null;
        }
        public void AddAttribut(String dn, String name, String value)
        {
            AddAttribut(dn, name, new byte[][] { Encoding.UTF8.GetBytes(value) });
        }
        public void AddAttribut(String dn, String name, String[] value)
        {
            List<byte[]> tb = new List<byte[]>();
            foreach (string st in value)
                tb.Add(Encoding.UTF8.GetBytes(st));
            AddAttribut(dn, name, tb.ToArray());
        }
        public void AddAttribut(String dn, String name, byte[] value)
        {
            AddAttribut(dn, name, new byte[][] { value });
        }
        public void AddAttribut(String dn, String name, byte[][] value)
        {
            Connect2();
            try
            {
                LdapObj ldapObj = ReadDn(dn, new String[] { name });
                if (!ldapObj.HasAttribut(name))
                {
                    ModifyRequest modRequest = new ModifyRequest(dn, DirectoryAttributeOperation.Add, name, value);
                    // example of modifyrequest not using the response object...
                    ModifyResponse modifyResponse = (ModifyResponse)ldapConnexion.SendRequest(modRequest);
                    Console.WriteLine(String.Format("{0} of {1} added successfully.", ldapConnexion, value));
                }
                else
                {
                    DirectoryAttributeModification directoryAttributeModification = new DirectoryAttributeModification();
                    directoryAttributeModification.Operation = DirectoryAttributeOperation.Replace;
                    directoryAttributeModification.Name = name;
                    ldapObj.ldapAttributs[name].AddRange(value);
                    foreach (byte[] tbb in ldapObj.ldapAttributs[name].values)
                        directoryAttributeModification.Add(tbb);
                    ModifyRequest modRequest = new ModifyRequest(dn, new DirectoryAttributeModification[] { directoryAttributeModification });
                    ModifyResponse modifyResponse = (ModifyResponse)ldapConnexion.SendRequest(modRequest);
                    Console.WriteLine(String.Format("{0} of {1} added successfully.", ldapConnexion, value));

                }


            }
            catch (DirectoryOperationException e)
            {
                Console.WriteLine(e.Message);
                throw e;
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
                throw e;
            }
        }
        public void AddAttribut(String dn, String name, X509Certificate2 value)
        {
            AddAttribut(dn, name, value.GetRawCertData());
        }
        public void AddAttribut(String dn, LdapAttribut ldapAttribut)
        {
            AddAttribut(dn, ldapAttribut.name, ldapAttribut.values.ToArray());
        }
        public void AddAttribut(String dn, List<LdapAttribut> ldapAttributs)
        {
            foreach (LdapAttribut ldapAttribut in ldapAttributs)
                AddAttribut(dn, ldapAttribut);
        }

        public void ReplaceAttribut(String dn, String name, string oldValue, string newValue)
        {
            DeleteAttribut(dn, name, oldValue);
            AddAttribut(dn, name, newValue);
        }
        public void ReplaceAttribut(String dn, String name, byte[] value)
        {
            Connect2();
            try
            {
                ModifyRequest modRequest = new ModifyRequest(dn, DirectoryAttributeOperation.Replace, name, value);
                ModifyResponse modifyResponse = (ModifyResponse)ldapConnexion.SendRequest(modRequest);
                Console.WriteLine(String.Format("{0} of {1} added successfully.", ldapConnexion, value));
            }
            catch (DirectoryOperationException e)
            {
                Console.WriteLine(e.Message);
                throw e;
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
                throw e;
            }
        }

        public void ReplaceAttribut(String dn, String name, byte[] oldValue, byte[] newValue)
        {
          
           
            DeleteAttribut(dn, name, oldValue);
            AddAttribut(dn, name, newValue);
        }
        public void ReplaceAttribut(String dn, LdapAttribut ldapAttribut)
        {
            DeleteAttribut(dn, ldapAttribut.name);
            AddAttribut(dn, ldapAttribut);
        }
        public void ReplaceAttribut(String dn, List<LdapAttribut> ldapAttributs)
        { }

        public void DeleteAttribut(String dn, List<LdapAttribut> ldapAttributs, bool allValues = false)
        {
            foreach (LdapAttribut ldapAttribut in ldapAttributs)
                DeleteAttribut(dn, ldapAttribut, allValues);
        }
        public void DeleteAttribut(String dn, LdapAttribut ldapAttribut, bool allValues = false)
        {
            if (allValues)
            {
                DeleteAttribut(dn, ldapAttribut.name);
            }
            else
            {
                foreach (byte[] b in ldapAttribut.values)
                {
                    DeleteAttribut(dn, ldapAttribut.name, b);
                }
            }
        }
        public void DeleteAttribut(String dn, String name)
        {
            try
            {
                Connect2();
                DirectoryAttributeModification directoryAttributModification = new DirectoryAttributeModification();
                directoryAttributModification.Name = name;
                directoryAttributModification.Operation = DirectoryAttributeOperation.Delete;

                ModifyRequest modRequest = new ModifyRequest(dn, directoryAttributModification);
                ModifyResponse modifyResponse = (ModifyResponse)ldapConnexion.SendRequest(modRequest);
            }
            catch (DirectoryOperationException e)
            {
                Console.WriteLine(e.Message);
                throw e;
            }
        }
        public void DeleteAttribut(String dn, String name, byte[] value)
        {
            try
            {
                Connect2();
                DirectoryAttributeModification directoryAttributModification = new DirectoryAttributeModification();
                ModifyRequest modRequest = new ModifyRequest(dn, DirectoryAttributeOperation.Delete, name,  value );
                ModifyResponse modifyResponse = (ModifyResponse)ldapConnexion.SendRequest(modRequest);
            }
            catch (DirectoryOperationException e)
            {
                Console.WriteLine(e.Message);
                throw e;
            }
        }
        public void DeleteAttribut(String dn, String name, String value)
        {
            try
            {
                Connect2();
                DirectoryAttributeModification directoryAttributModification = new DirectoryAttributeModification();
                ModifyRequest modRequest = new ModifyRequest(dn, DirectoryAttributeOperation.Delete, name, new String[] { value });
                ModifyResponse modifyResponse = (ModifyResponse)ldapConnexion.SendRequest(modRequest);
            }
            catch (DirectoryOperationException e)
            {
                Console.WriteLine(e.Message);
                throw e;
            }
        }


        internal List<string> ExistAttributWithValue(string dn, string attribut, string valeur)
        {
            List<string> lstValue = new List<string>();
            LdapAttribut ldapAttribut = GetAttributs(dn, attribut);
            if (ldapAttribut != null)
            {
                return ldapAttribut.ExistWithValue(valeur);

            }
            else
                return null;




        }


        #endregion


        #region Groupes
        protected void AddGroupMember(string dnGroup, string dnUser,string member,string memberOf)
        {
            AddAttribut(dnGroup, member, dnUser);
            //AddAttribut(dnUser, memberOf, dnGroup);
         
        }

        protected void DelGroupMember(string dnGroup, string dnUser,string member,string memberOf)
        {
            DeleteAttribut(dnGroup, member, dnUser);
            //DeleteAttribut(dnUser, memberOf, dnUser);
        }

        protected bool IsGroupMember(string dnGroup, string dnUser, string member)
        {
            LdapAttribut ldapAttribut = GetAttributs(dnGroup,member);
            if (ldapAttribut != null)
            {
                List<String> lstValues = ldapAttribut.ExistWithValue(dnUser);
                if (lstValues != null)
                    return lstValues.Contains(dnUser, StringComparer.OrdinalIgnoreCase);
            }
            return false;
        }
        #endregion
        public void Dispose()
        {
         
                if(!disposed)
                {
                    ((IDisposable)ldapConnexion).Dispose();
                   
                    disposed = true;
                    GC.SuppressFinalize(this);
                    Dispose();
                }
            
          
           
        }
      
    }
}
