using System;
using System.Collections.Generic;
using System.IO;
using System.Xml;

namespace AaronLocker
{
    /// <summary>
    /// An AppLocker policy, containing rules and offering tools to convert / integrate into output generation.
    /// </summary>
    [Serializable]
    public class Policy
    {
        /// <summary>
        /// List of all rules that are part of this policy
        /// </summary>
        public List<RuleBase> Rules = new List<RuleBase>();

        /// <summary>
        /// Number of rules stored in the policy
        /// </summary>
        public int RulesCount
        {
            get { return Rules.Count; }
            set { }
        }

        /// <summary>
        /// An arbitrary name for this policy. Internal use only, to help distinguishing between different policies.
        /// </summary>
        public string Name;

        /// <summary>
        /// Add a neat description, telling your future self what this was all about
        /// </summary>
        public string Description;

        /// <summary>
        /// When was the last update to the policy
        /// </summary>
        public DateTime LastUpdate = DateTime.Now;

        /// <summary>
        /// List of rules that failed to execute during the last compilation effort
        /// </summary>
        public List<RuleFailure> FailedRules = new List<RuleFailure>();

        /// <summary>
        /// Returns XML string of the finished AppLocker policy
        /// </summary>
        /// <param name="EnforcementMode">How the policy should be enforced</param>
        /// <returns>XML Text</returns>
        public string GetXml(EnforcementMode EnforcementMode = EnforcementMode.NotConfigured)
        {
            FailedRules = new List<RuleFailure>();
            XmlDocument document = new XmlDocument();
            document.LoadXml(String.Format(@"
<AppLockerPolicy Version=""1"">
    <RuleCollection Type=""Exe"" EnforcementMode=""{0}""/>
    <RuleCollection Type=""Dll"" EnforcementMode=""{0}""/>
    <RuleCollection Type=""Script"" EnforcementMode=""{0}""/>
    <RuleCollection Type=""Msi"" EnforcementMode=""{0}""/>
    <RuleCollection Type=""AppX"" EnforcementMode=""{0}""/>
</AppLockerPolicy>
", EnforcementMode.ToString()));
            foreach (RuleBase ruleItem in Rules)
                ruleItem.AddToPolicy(document, this);

            XmlWriterSettings settings = new XmlWriterSettings();
            settings.NewLineHandling = NewLineHandling.Replace;
            settings.NewLineChars = "\r\n";
            settings.Indent = true;

            using (var stringWriter = new StringWriter())
            using (var xmlTextWriter = XmlWriter.Create(stringWriter, settings))
            {
                document.WriteTo(xmlTextWriter);
                xmlTextWriter.Flush();
                return stringWriter.GetStringBuilder().ToString();
            }
        }
    }
}
