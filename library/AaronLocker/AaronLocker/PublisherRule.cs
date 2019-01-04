using System;
using System.Diagnostics;
using System.Security.Cryptography.X509Certificates;
using System.Xml;

namespace AaronLocker
{
    /// <summary>
    /// Rule acting based on publisher that signed a file.
    /// </summary>
    [Serializable]
    public class PublisherRule : RuleBase
    {
        #region Full Specs
        /// <summary>
        /// The name of the publisher
        /// </summary>
        public string PublisherName;

        /// <summary>
        /// Name of the product
        /// </summary>
        public string ProductName;

        /// <summary>
        /// Name of the file
        /// </summary>
        public string BinaryName;

        /// <summary>
        /// Minimum version to apply this to
        /// </summary>
        public Version MinimumVersion;

        /// <summary>
        /// Last version to apply this rule to.
        /// </summary>
        public Version MaximumVersion;
        #endregion Full Specs

        #region Exemplar Mode
        /// <summary>
        /// Path to an exampel file to use to generate publisher information
        /// </summary>
        public string Exemplar;

        /// <summary>
        /// Whether to also use the product information, when recording from an example file.
        /// </summary>
        public bool UseProduct;
        #endregion Exemplar Mode

        /// <summary>
        /// Resolves an Exemplar into the publisher rule relevant data
        /// </summary>
        public void Resolve()
        {
            if (String.IsNullOrEmpty(Exemplar))
                return;

            X509Certificate certificate = null;

            try { certificate = X509Certificate.CreateFromSignedFile(Exemplar); }
            catch (Exception e) { throw new InvalidOperationException(String.Format("Failed to read certificate from signed file. {0}", e.Message), e); }

            PublisherName = certificate.Subject;

            if (!UseProduct)
                return;

            FileVersionInfo info = null;
            try { info = FileVersionInfo.GetVersionInfo(Exemplar); }
            catch (Exception e) { throw new InvalidOperationException(String.Format("Failed to read file info from file. {0}", e.Message), e); }

            ProductName = info.ProductName;
            BinaryName = info.FileName;
            MinimumVersion = Version.Parse(info.FileVersion);
        }

        /// <summary>
        /// Attach rule to policy
        /// </summary>
        /// <param name="Document">The AppLocker policy to integrate into.</param>
        /// <param name="Policy">The policy object that calls for this integration.</param>
        public override void AddToPolicy(XmlDocument Document, Policy Policy)
        {
            if (String.IsNullOrEmpty(PublisherName))
            {
                try { Resolve(); }
                catch (Exception e)
                {
                    Policy.FailedRules.Add(new RuleFailure(this, e));
                    return;
                }
            }

            #region Create Element
            XmlElement element = Document.CreateElement("FilePublisherRule");
            if (Id != Guid.Empty)
                element.SetAttribute("Id", Id.ToString());
            else
                element.SetAttribute("Id", Guid.NewGuid().ToString());
            element.SetAttribute("Name", Label);
            element.SetAttribute("Description", Description);
            element.SetAttribute("UserOrGroupSid", UserOrGroupSid);
            element.SetAttribute("Action", Action.ToString());
            XmlElement condition = Document.CreateElement("Conditions");
            XmlElement filePublisherCondition = Document.CreateElement("FilePublisherCondition");
            filePublisherCondition.SetAttribute("PublisherName", PublisherName);
            filePublisherCondition.SetAttribute("ProductName", ProductName);
            filePublisherCondition.SetAttribute("BinaryName", BinaryName);
            XmlElement binaryVersionRange = Document.CreateElement("BinaryVersionRange");
            if (MinimumVersion != null)
                binaryVersionRange.SetAttribute("LowSection", MinimumVersion.ToString());
            else
                binaryVersionRange.SetAttribute("LowSection", "*");
            if (MaximumVersion != null)
                binaryVersionRange.SetAttribute("HighSection", MaximumVersion.ToString());
            else
                binaryVersionRange.SetAttribute("HighSection", "*");
            filePublisherCondition.AppendChild(binaryVersionRange);
            condition.AppendChild(filePublisherCondition);
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
            PublisherRule tempRule = new PublisherRule();
            CopyBaseProperties(tempRule);
            tempRule.PublisherName = PublisherName;
            tempRule.ProductName = ProductName;
            tempRule.BinaryName = BinaryName;
            tempRule.MinimumVersion = MinimumVersion;
            tempRule.MaximumVersion = MaximumVersion;
            tempRule.Exemplar = Exemplar;
            tempRule.UseProduct = UseProduct;
            return tempRule;
        }
    }
}
