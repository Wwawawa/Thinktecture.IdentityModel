using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Xml.Linq;

namespace Thinktecture.IdentityModel.EmbeddedSts.User
{
    public class AuthenticationUserReader
    {
        internal class SecurityTemplate
        {
            public List<AuthenticationUserReader.SecurityTemplate> Dependencies
            {
                get;
                set;
            }

            public IDictionary<string, string> Expressions
            {
                get;
                set;
            }

            public IDictionary<string, string[]> MultiValues
            {
                get;
                set;
            }

            public string Name
            {
                get;
                set;
            }

            public IDictionary<string, string> Values
            {
                get;
                set;
            }
        }

        internal class UserBlockTemplate
        {
            public int Count
            {
                get;
                set;
            }
            public string Name
            {
                get;
                set;
            }

            public string PasswordExpression
            {
                get;
                set;
            }

            public AuthenticationUserReader.SecurityTemplate SecurityTemplate
            {
                get;
                set;
            }

            public int Start
            {
                get;
                set;
            }

            public string UserNameExpression
            {
                get;
                set;
            }
        }

        internal class UserTemplate
        {
            public string Password
            {
                get;
                set;
            }

            public AuthenticationUserReader.SecurityTemplate SecurityTemplate
            {
                get;
                set;
            }

            public string UserName
            {
                get;
                set;
            }
        }

        private static string file;

        private static FileSystemWatcher watcher;

        private static Lazy<IDictionary<string, ExpandedIdentity>> users = new Lazy<IDictionary<string, ExpandedIdentity>>(new Func<IDictionary<string, ExpandedIdentity>>(AuthenticationUserReader.LoadUsers));

        public static IDictionary<string, ExpandedIdentity> Users
        {
            get
            {
                return AuthenticationUserReader.users.Value;
            }
        }

        public static IDictionary<string, ExpandedIdentity> LoadUsers()
        {
            return AuthenticationUserReader.LoadUsers(null);
        }

        public static IDictionary<string, ExpandedIdentity> LoadUsers(string userFileName)
        {
            string fileName = userFileName ?? (AuthenticationUserReader.file ?? Path.Combine((string)AppDomain.CurrentDomain.GetData("DataDirectory"), "Users.xml"));
            AuthenticationUserReader.file = fileName;
            Dictionary<string, ExpandedIdentity> userList = new Dictionary<string, ExpandedIdentity>(StringComparer.OrdinalIgnoreCase);
            foreach (KeyValuePair<string, ExpandedIdentity> user in new AuthenticationUserReader().ReadUsers(fileName))
            {
                userList[user.Value.UserName] = user.Value;
            }
            AuthenticationUserReader.CreateFileWatcher(fileName);
            return userList;
        }

        public IDictionary<string, ExpandedIdentity> ReadUsers(Stream stream)
        {
            return this.ReadUsers(XDocument.Load(stream));
        }
        public IDictionary<string, ExpandedIdentity> ReadUsers(string fileName = null)
        {
            fileName = (fileName ?? Path.Combine(AppDomain.CurrentDomain.GetData("DataDirectory").ToString(), "Users.xml"));
            XDocument xdoc = XDocument.Load(fileName);
            return this.ReadUsers(xdoc);
        }

        public IDictionary<string, ExpandedIdentity> ReadUsers(XDocument xmlDocument)
        {
            Dictionary<string, AuthenticationUserReader.SecurityTemplate> templateTemplates = AuthenticationUserReader.ReadTemplates(xmlDocument);
            IList<AuthenticationUserReader.UserBlockTemplate> userBlockTemplates = AuthenticationUserReader.ReadUserBlocks(templateTemplates, xmlDocument);
            IDictionary<string, AuthenticationUserReader.UserTemplate> userTemplates = AuthenticationUserReader.ReadUserTemplates(templateTemplates, xmlDocument);
            Dictionary<string, ExpandedIdentity> enterpriseUsers = new Dictionary<string, ExpandedIdentity>();
            this.ExpandUserBlocks(enterpriseUsers, userBlockTemplates);
            this.ExpandUsers(enterpriseUsers, userTemplates);
            return enterpriseUsers;
        }
        private static void CreateFileWatcher(string fileToWatch)
        {
            if (!File.Exists(fileToWatch))
            {
                throw new FileNotFoundException("File not found", fileToWatch);
            }
            if (AuthenticationUserReader.watcher != null)
            {
                AuthenticationUserReader.watcher.Dispose();
                AuthenticationUserReader.watcher = null;
            }
            AuthenticationUserReader.watcher = new FileSystemWatcher(Path.GetDirectoryName(fileToWatch))
            {
                NotifyFilter = NotifyFilters.LastWrite,
                Filter = Path.GetFileName(fileToWatch),
                EnableRaisingEvents = true
            };
            AuthenticationUserReader.watcher.Changed += delegate (object sender, FileSystemEventArgs args)
            {
                if (fileToWatch.Equals(args.FullPath, StringComparison.OrdinalIgnoreCase))
                {
                    AuthenticationUserReader.users = new Lazy<IDictionary<string, ExpandedIdentity>>(new Func<IDictionary<string, ExpandedIdentity>>(AuthenticationUserReader.LoadUsers));
                }
            };
        }

        private static string ExpandExpression(string expression, IDictionary<string, string> values, IDictionary<string, string> otherExpressions = null)
        {
            StringBuilder result = new StringBuilder(expression);
            MatchCollection matches = Regex.Matches(expression, "\\${([^}]+)}");
            foreach (Match match in matches)
            {
                string token = match.Groups[1].Value.Trim();
                if (!values.ContainsKey(token) && otherExpressions != null && otherExpressions.ContainsKey(token))
                {
                    result.Replace(match.Value, AuthenticationUserReader.ExpandExpression(otherExpressions[token], values, otherExpressions));
                }
                else if (values.ContainsKey(token))
                {
                    result.Replace(match.Value, values[token]);
                }
                else
                {
                    result.Replace(match.Value, string.Empty);
                }
            }
            return result.ToString();
        }

        private static AuthenticationUserReader.SecurityTemplate ReadSecurityTemplate(XElement element, IDictionary<string, AuthenticationUserReader.SecurityTemplate> templates)
        {
            AuthenticationUserReader.SecurityTemplate template = AuthenticationUserReader.ReadSecurityTemplate(element);
            AuthenticationUserReader.ResolveDependencies(template, templates);
            return template;
        }

        private static AuthenticationUserReader.SecurityTemplate ReadSecurityTemplate(XElement element)
        {
            AuthenticationUserReader.SecurityTemplate securityTemplate2 = new AuthenticationUserReader.SecurityTemplate();
            securityTemplate2.Name = (string)element.Attribute("name");
            securityTemplate2.Dependencies = (from x in (((string)element.Attribute("templates")) ?? string.Empty).Split(new char[]
            {
                ';'
            })
                                              select new AuthenticationUserReader.SecurityTemplate
                                              {
                                                  Name = x
                                              }).ToList<AuthenticationUserReader.SecurityTemplate>();
            securityTemplate2.Expressions = new Dictionary<string, string>();
            securityTemplate2.MultiValues = new Dictionary<string, string[]>();
            securityTemplate2.Values = new Dictionary<string, string>();
            AuthenticationUserReader.SecurityTemplate securityTemplate = securityTemplate2;
            foreach (XElement item in element.Descendants())
            {
                string name = item.Name.LocalName;
                if (item.HasElements)
                {
                    string[] values = (from x in item.Descendants()
                                       select x.Value).ToArray<string>();
                    securityTemplate.MultiValues[name] = values;
                }
                else if (Regex.IsMatch(item.Value, "\\${([^}]+)}"))
                {
                    securityTemplate.Expressions[name] = item.Value;
                }
                else
                {
                    securityTemplate.Values[name] = item.Value;
                }
            }
            return securityTemplate;
        }

        private static Dictionary<string, AuthenticationUserReader.SecurityTemplate> ReadTemplates(XDocument xdoc)
        {
            Dictionary<string, AuthenticationUserReader.SecurityTemplate> templates = xdoc.Descendants("Template").Select(new Func<XElement, AuthenticationUserReader.SecurityTemplate>(AuthenticationUserReader.ReadSecurityTemplate)).ToDictionary((AuthenticationUserReader.SecurityTemplate x) => x.Name);
            foreach (KeyValuePair<string, AuthenticationUserReader.SecurityTemplate> item in templates)
            {
                AuthenticationUserReader.ResolveDependencies(item.Value, templates);
            }
            return templates;
        }

        private static IList<AuthenticationUserReader.UserBlockTemplate> ReadUserBlocks(Dictionary<string, AuthenticationUserReader.SecurityTemplate> templates, XDocument xdoc)
        {
            List<AuthenticationUserReader.UserBlockTemplate> userBlocks = new List<AuthenticationUserReader.UserBlockTemplate>();
            foreach (XElement userBlock in xdoc.Descendants("UserBlock"))
            {
                userBlocks.Add(new AuthenticationUserReader.UserBlockTemplate
                {
                    Name = (string)userBlock.Attribute("name"),
                    Start = ((int?)userBlock.Attribute("id-start")) ?? 1,
                    Count = ((int?)userBlock.Attribute("count")) ?? 10,
                    UserNameExpression = (string)userBlock.Element("UserName"),
                    PasswordExpression = (string)userBlock.Element("Password"),
                    SecurityTemplate = AuthenticationUserReader.ReadSecurityTemplate(userBlock.Element("Identity"), templates)
                });
            }
            return userBlocks;
        }

        private static IDictionary<string, AuthenticationUserReader.UserTemplate> ReadUserTemplates(Dictionary<string, AuthenticationUserReader.SecurityTemplate> templates, XDocument xdoc)
        {
            Dictionary<string, AuthenticationUserReader.UserTemplate> userTemplates = new Dictionary<string, AuthenticationUserReader.UserTemplate>();
            foreach (XElement userElement in xdoc.Descendants("User"))
            {
                string userName = (string)userElement.Attribute("name");
                string password = (string)userElement.Attribute("password");
                AuthenticationUserReader.SecurityTemplate template = AuthenticationUserReader.ReadSecurityTemplate(userElement.Element("Identity"), templates);
                userTemplates[userName] = new AuthenticationUserReader.UserTemplate
                {
                    UserName = userName,
                    Password = password,
                    SecurityTemplate = template
                };
            }
            return userTemplates;
        }

        private static void ResolveDependencies(AuthenticationUserReader.SecurityTemplate template, IDictionary<string, AuthenticationUserReader.SecurityTemplate> templates)
        {
            List<AuthenticationUserReader.SecurityTemplate> resolvedDependencies = (from x in template.Dependencies
                                                                                              where !string.IsNullOrEmpty(x.Name)
                                                                                              select templates[x.Name]).ToList<AuthenticationUserReader.SecurityTemplate>();
            template.Dependencies = resolvedDependencies;
        }

        private void ExpandTemplate(ExpandedIdentity user, AuthenticationUserReader.SecurityTemplate template, IDictionary<string, string> expressions = null, bool expandExpressions = true)
        {
            expressions = (expressions ?? new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase));
            foreach (KeyValuePair<string, string> item in template.Values)
            {
                if (!user.Values.ContainsKey(item.Key))
                {
                    user.Values[item.Key] = item.Value;
                }
            }
            foreach (KeyValuePair<string, string[]> item2 in template.MultiValues)
            {
                if (user.MultiValues.ContainsKey(item2.Key))
                {
                    user.MultiValues[item2.Key] = user.MultiValues[item2.Key].Concat(item2.Value).ToArray<string>();
                }
                else
                {
                    user.MultiValues[item2.Key] = item2.Value;
                }
            }
            foreach (KeyValuePair<string, string> expression in template.Expressions)
            {
                if (!expressions.ContainsKey(expression.Key))
                {
                    expressions[expression.Key] = expression.Value;
                }
            }
            foreach (AuthenticationUserReader.SecurityTemplate dependency in template.Dependencies)
            {
                this.ExpandTemplate(user, dependency, expressions, false);
            }
            if (expandExpressions)
            {
                foreach (KeyValuePair<string, string> expression2 in expressions)
                {
                    user.Values[expression2.Key] = AuthenticationUserReader.ExpandExpression(expression2.Value, user.Values, expressions);
                }
            }
        }

        private ExpandedIdentity ExpandUser(AuthenticationUserReader.UserTemplate userTemplate)
        {
            ExpandedIdentity user = new ExpandedIdentity
            {
                UserName = userTemplate.UserName,
                Password = userTemplate.Password,
                Values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase),
                MultiValues = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase)
            };
            this.ExpandTemplate(user, userTemplate.SecurityTemplate, null, true);
            return user;
        }

        private void ExpandUserBlocks(Dictionary<string, ExpandedIdentity> userRepository, IEnumerable<AuthenticationUserReader.UserBlockTemplate> userBlockTemplates)
        {
            foreach (AuthenticationUserReader.UserBlockTemplate blockTemplate in userBlockTemplates)
            {
                for (int i = blockTemplate.Start; i < blockTemplate.Count + blockTemplate.Start; i++)
                {
                    AuthenticationUserReader.UserTemplate userTemplate = new AuthenticationUserReader.UserTemplate
                    {
                        SecurityTemplate = blockTemplate.SecurityTemplate
                    };
                    userTemplate.SecurityTemplate.Values["id"] = i.ToString(CultureInfo.InvariantCulture);
                    ExpandedIdentity user = new ExpandedIdentity();
                    this.ExpandTemplate(user, userTemplate.SecurityTemplate, null, true);
                    user.UserName = AuthenticationUserReader.ExpandExpression(blockTemplate.UserNameExpression, user.Values, null);
                    user.Password = AuthenticationUserReader.ExpandExpression(blockTemplate.PasswordExpression, user.Values, null);
                    userRepository[user.UserName] = user;
                }
            }
        }

        private void ExpandUsers(Dictionary<string, ExpandedIdentity> userRepository, IDictionary<string, AuthenticationUserReader.UserTemplate> userTemplates)
        {
            foreach (AuthenticationUserReader.UserTemplate userTemplate in userTemplates.Values)
            {
                ExpandedIdentity expandedUser = this.ExpandUser(userTemplate);
                userRepository[expandedUser.UserName] = expandedUser;
            }
        }
    }
}
