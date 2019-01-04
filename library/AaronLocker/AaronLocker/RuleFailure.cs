using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AaronLocker
{
    /// <summary>
    /// Class representing a rule that failed to properly resolve.
    /// Used when resolving rules from a Policy object.
    /// </summary>
    [Serializable]
    public class RuleFailure
    {
        /// <summary>
        /// The type of rule it was
        /// </summary>
        public RuleType Type { get { return Rule.Type; } }

        /// <summary>
        /// The label the rule was meant to carry
        /// </summary>
        public string Label {  get { return Rule.Label; } }

        /// <summary>
        /// The source rule object
        /// </summary>
        public RuleBase Rule;

        /// <summary>
        /// The actual exception that prevented success
        /// </summary>
        public Exception Error;

        /// <summary>
        /// Creates an empty rule failure
        /// </summary>
        public RuleFailure() { }

        /// <summary>
        /// Creates a preconfigured rule failure
        /// </summary>
        /// <param name="Rule">The rule that failed</param>
        /// <param name="Error">The exception describing the failure</param>
        public RuleFailure(RuleBase Rule, Exception Error)
        {
            this.Rule = Rule;
            this.Error = Error;
        }
    }
}
