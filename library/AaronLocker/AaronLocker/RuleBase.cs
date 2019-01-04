using System;
using System.Xml;

namespace AaronLocker
{
    /// <summary>
    /// Base class for AppLocker rules
    /// </summary>
    [Serializable]
    public abstract class RuleBase : ICloneable
    {
        /// <summary>
        /// The name of the rule
        /// </summary>
        public string Label;

        /// <summary>
        /// A description of what this rule is all about
        /// </summary>
        public string Description;

        /// <summary>
        /// Group or user the rule applies to
        /// </summary>
        public string UserOrGroupSid;

        /// <summary>
        /// An ID of the rule. Leave this empty, if you do not want to hardcode a specific GUid for a specific rule.
        /// </summary>
        public Guid Id;

        /// <summary>
        /// What scope does the rule apply to (specifically: Is it designed to affect dlls, executables or scripts).
        /// </summary>
        public Scope Collection = Scope.Default;

        /// <summary>
        /// What kind of rule is this?
        /// </summary>
        public RuleType Type
        {
            get
            {
                if ((this as HashRule) != null)
                    return RuleType.Hash;
                if ((this as PublisherRule) != null)
                    return RuleType.Publisher;
                if ((this as SourcePathRule) != null)
                    return RuleType.SourcePath;
                return RuleType.Path;
            }
            set { }
        }

        /// <summary>
        /// Whether to allow (Whitelist) or deny (Blacklist) the target of this rule
        /// </summary>
        public Action Action = Action.Allow;

        /// <summary>
        /// Each rule must be able to attach itself to an XML document representing an AppLocker rule.
        /// </summary>
        /// <param name="Document">The AppLocker policy to integrate into.</param>
        /// <param name="Policy">The policy object that calls for this integration.</param>
        public abstract void AddToPolicy(XmlDocument Document, Policy Policy);

        /// <summary>
        /// Clones the current rule
        /// </summary>
        public abstract object Clone();

        /// <summary>
        /// Copies the base properties of a rule object. Used by Clone() implementations.
        /// </summary>
        /// <param name="Target">The object to copy properties into.</param>
        internal void CopyBaseProperties(RuleBase Target)
        {
            Target.Label = Label;
            Target.Description = Description;
            Target.UserOrGroupSid = UserOrGroupSid;
            Target.Id = Id;
            Target.Collection = Collection;
            Target.Action = Action;
        }
    }
}
