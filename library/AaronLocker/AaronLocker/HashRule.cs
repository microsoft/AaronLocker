using System;
using System.Xml;

namespace AaronLocker
{
    /// <summary>
    /// A rule to apply based on hash values
    /// </summary>
    [Serializable]
    public class HashRule : RuleBase
    {
        /// <summary>
        /// The hash value to apply the rule by
        /// </summary>
        public string HashValue;

        /// <summary>
        /// The name of the actual file the hash targets
        /// </summary>
        public string FileName;

        /// <summary>
        /// The original input file's length
        /// </summary>
        public int SourceFileLength;

        /// <summary>
        /// Attach rule to policy
        /// </summary>
        /// <param name="Document">The AppLocker policy to integrate into.</param>
        /// <param name="Policy">The policy object that calls for this integration.</param>
        public override void AddToPolicy(XmlDocument Document, Policy Policy)
        {
            #region Create Element
            XmlElement element = Document.CreateElement("FileHashRule");
            if (Id != Guid.Empty)
                element.SetAttribute("Id", Id.ToString());
            else
                element.SetAttribute("Id", Guid.NewGuid().ToString());
            element.SetAttribute("Name", Label);
            element.SetAttribute("Description", Description);
            element.SetAttribute("UserOrGroupSid", UserOrGroupSid);
            element.SetAttribute("Action", Action.ToString());
            XmlElement condition = Document.CreateElement("Conditions");
            XmlElement filePathCondition = Document.CreateElement("FileHashCondition");
            XmlElement hashCondition = Document.CreateElement("FileHash");
            hashCondition.SetAttribute("Type", "SHA256");
            hashCondition.SetAttribute("Data", HashValue);
            hashCondition.SetAttribute("SourceFileName", FileName);
            if (SourceFileLength > 0)
                hashCondition.SetAttribute("SourceFileLength", SourceFileLength.ToString());
            filePathCondition.AppendChild(hashCondition);
            condition.AppendChild(filePathCondition);
            element.AppendChild(condition);

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
            HashRule tempRule = new HashRule();
            CopyBaseProperties(tempRule);
            tempRule.HashValue = HashValue;
            tempRule.FileName = FileName;
            tempRule.SourceFileLength = SourceFileLength;
            return tempRule;
        }
    }
}
