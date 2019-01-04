using System;
using System.Collections.Generic;
using System.Xml;

namespace AaronLocker
{
    /// <summary>
    /// A rule enforcing compliance based on path.
    /// </summary>
    [Serializable]
    public class PathRule : RuleBase
    {
        /// <summary>
        /// The path to which to apply this rule
        /// </summary>
        public string Path;

        /// <summary>
        /// Items or folders under the path to exclude from this rule
        /// </summary>
        public List<string> Exceptions = new List<string>();

        /// <summary>
        /// Attach rule to policy
        /// </summary>
        /// <param name="Document">The AppLocker policy to integrate into.</param>
        /// <param name="Policy">The policy object that calls for this integration.</param>
        public override void AddToPolicy(XmlDocument Document, Policy Policy)
        {
            #region Create Element
            XmlElement element = Document.CreateElement("FilePathRule");
            if (Id != Guid.Empty)
                element.SetAttribute("Id", Id.ToString());
            else
                element.SetAttribute("Id", Guid.NewGuid().ToString());
            element.SetAttribute("Name", Label);
            element.SetAttribute("Description", Description);
            element.SetAttribute("UserOrGroupSid", UserOrGroupSid);
            element.SetAttribute("Action", Action.ToString());
            XmlElement condition = Document.CreateElement("Conditions");
            XmlElement filePathCondition = Document.CreateElement("FilePathCondition");
            filePathCondition.SetAttribute("Path", Path);
            condition.AppendChild(filePathCondition);
            element.AppendChild(condition);

            if (Exceptions.Count > 0)
            {
                XmlElement exceptions = Document.CreateElement("Exceptions");
                element.AppendChild(exceptions);
                foreach (string pathItem in Exceptions)
                {
                    XmlElement exception = Document.CreateElement("FilePathCondition");
                    exception.SetAttribute("Path", pathItem);
                    exceptions.AppendChild(exception);
                }
            }
            #endregion Create Element

            #region Attach based on Collection
            if ((Collection & Scope.AppX) != 0)
                Document.SelectNodes("//RuleCollection[@Type='Appx']")[0].AppendChild(element.Clone());
            if ((Collection & Scope.Dll) != 0)
                Document.SelectNodes("//RuleCollection[@Type='Dll']")[0].AppendChild(element.Clone());
            if ((Collection & Scope.Exe) != 0)
                Document.SelectNodes("//RuleCollection[@Type='Exe']")[0].AppendChild(element.Clone());
            if ((Collection & Scope.Msi) != 0)
                Document.SelectNodes("//RuleCollection[@Type='Msi']")[0].AppendChild(element.Clone());
            if ((Collection & Scope.Script) != 0)
                Document.SelectNodes("//RuleCollection[@Type='Script']")[0].AppendChild(element.Clone());
            #endregion Attach based on Collection
        }

        /// <inheritdoc />
        public override object Clone()
        {
            PathRule tempRule = new PathRule();
            CopyBaseProperties(tempRule);
            tempRule.Path = Path;
            tempRule.Exceptions = new List<string>(Exceptions.ToArray());
            return tempRule;
        }
    }
}
