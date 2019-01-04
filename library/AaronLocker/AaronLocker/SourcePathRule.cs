using System;
using System.Collections.Generic;
using System.Management.Automation;
using System.Xml;

namespace AaronLocker
{
    /// <summary>
    /// A rule based on a source file, can be converted to the most constrained rule object type.
    /// </summary>
    [Serializable]
    public class SourcePathRule : RuleBase
    {
        /// <summary>
        /// The path to the item
        /// </summary>
        public string Path;

        /// <summary>
        /// Whether the specified path should be resolved recursively
        /// </summary>
        public bool Recurse;

        /// <summary>
        /// Whether the found version of a product should be enforced, if the rule resolves into a Publisher Rule.
        /// </summary>
        public bool EnforceMinimumVersion;

        /// <summary>
        /// Processes the path specified and generates rules based on it.
        /// </summary>
        /// <returns>Rules that are as restrictive as possible</returns>
        public List<RuleBase> Resolve()
        {
            if (ResolutionScript == null)
                throw new InvalidOperationException("Resolution script has not been assigned! This generally means the module was not imported correctly.");

            List<RuleBase> results = new List<RuleBase>();

            foreach (PSObject obj in ResolutionScript.Invoke(this))
                results.Add((RuleBase)obj.BaseObject);

            return results;
        }

        /// <summary>
        /// Scriptblock used to resolve the specified path into rule objects
        /// </summary>
        public static ScriptBlock ResolutionScript;

        /// <summary>
        /// Attach rule to policy
        /// </summary>
        /// <param name="Document">The AppLocker policy to integrate into.</param>
        /// <param name="Policy">The policy object that calls for this integration.</param>
        public override void AddToPolicy(XmlDocument Document, Policy Policy)
        {
            List<RuleBase> results = null;
            try { results = Resolve(); }
            catch (Exception e)
            {
                Policy.FailedRules.Add(new RuleFailure(this, e));
                return;
            }
            foreach (RuleBase rule in results)
                rule.AddToPolicy(Document, Policy);
        }

        /// <inheritdoc />
        public override object Clone()
        {
            SourcePathRule tempRule = new SourcePathRule();
            CopyBaseProperties(tempRule);
            tempRule.Path = Path;
            tempRule.Recurse = Recurse;
            tempRule.EnforceMinimumVersion = EnforceMinimumVersion;
            return tempRule;
        }
    }
}
